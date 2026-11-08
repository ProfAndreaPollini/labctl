"""
labctl.db.config

Inizializzazione schema SQLite (WAL) con SQLAlchemy Core e pre-allocazione dei pool /29.
"""

import argparse
import ipaddress
import json
import logging
import os
import stat
import typing
from pathlib import Path

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
    event,
    insert,
    select,
    text,
)
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/labctl/state.db"

# Definizione esemplificativa delle classi da pre-caricare (personalizzabile via JSON esterno)
DEFAULT_CLASSES = [
    {
        "codice_classe": "3A-INF",
        "ad_group_dn": "CN=GRP_3AINF,OU=Classi,DC=istituto,DC=local",
        "vnet_name": "vnet3a",
        "supernet_cidr": "10.103.0.0/24",  # Genera 32 blocchi /29 (160 IP studenti)
        "vlan_tag": 103,
        "max_containers_per_student": 2,
    },
    {
        "codice_classe": "4A-INF",
        "ad_group_dn": "CN=GRP_4AINF,OU=Classi,DC=istituto,DC=local",
        "vnet_name": "vnet4a",
        "supernet_cidr": "10.104.0.0/24",
        "vlan_tag": 104,
        "max_containers_per_student": 2,
    },
    {
        "codice_classe": "5A-INF",
        "ad_group_dn": "CN=GRP_5AINF,OU=Classi,DC=istituto,DC=local",
        "vnet_name": "vnet5a",
        "supernet_cidr": "10.105.0.0/24",
        "vlan_tag": 105,
        "max_containers_per_student": 3,
    },
]

metadata = MetaData()

# 1. Tabella Classi
classi = Table(
    "classi",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("codice_classe", Text, nullable=False, unique=True),
    Column("ad_group_dn", Text, nullable=False, unique=True),
    Column("vnet_name", Text, nullable=False, unique=True),
    Column("supernet_cidr", Text, nullable=False, unique=True),
    Column("vlan_tag", Integer, unique=True),
    Column("max_containers_per_student", Integer, nullable=False, server_default="2"),
    Column(
        "created_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint(
        "max_containers_per_student >= 1 AND max_containers_per_student <= 5",
        name="chk_max_containers_range",
    ),
)

# 2. Tabella Stato Classi (Modalità Verifica, Domini Ammessi, Comunicazione Intra-Classe)
stato_classi = Table(
    "stato_classi",
    metadata,
    Column(
        "classe_id",
        Integer,
        ForeignKey("classi.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("intra_class_comm", Integer, nullable=False, server_default="0"),
    Column("exam_mode", Integer, nullable=False, server_default="0"),
    Column("internet_enabled", Integer, nullable=False, server_default="1"),
    Column("exam_allowed_domains", Text, nullable=False, server_default="'[]'"),
    Column("desired_config_version", Integer, nullable=False, server_default="1"),
    Column("applied_config_version", Integer, nullable=False, server_default="0"),
    Column("sync_status", Text, nullable=False, server_default="'PENDING'"),
    Column("last_changed_by", Text, nullable=False, server_default="'system'"),
    Column(
        "updated_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint("intra_class_comm IN (0, 1)", name="chk_intra_comm_bool"),
    CheckConstraint("exam_mode IN (0, 1)", name="chk_exam_mode_bool"),
    CheckConstraint("internet_enabled IN (0, 1)", name="chk_internet_bool"),
    CheckConstraint("sync_status IN ('SYNCED', 'PENDING', 'ERROR')", name="chk_class_sync_status"),
)

# 3. Tabella Utenti AD
utenti_ad = Table(
    "utenti_ad",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", Text, nullable=False, unique=True),
    Column("object_guid", Text, nullable=False, unique=True),
    Column("display_name", Text, nullable=False),
    Column("email", Text),
    Column("ruolo", Text, nullable=False),
    Column("classe_id", Integer, ForeignKey("classi.id", ondelete="SET NULL")),
    Column("max_containers_override", Integer, nullable=True),
    Column("is_active", Integer, nullable=False, server_default="1"),
    Column("first_login_at", Text),
    Column("last_login_at", Text),
    Column(
        "created_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint("ruolo IN ('STUDENT', 'TEACHER', 'ADMIN')", name="chk_ruolo_valido"),
    CheckConstraint("is_active IN (0, 1)", name="chk_user_active_bool"),
)
Index("idx_utenti_ad_classe", utenti_ad.c.classe_id)
Index("idx_utenti_ad_username", utenti_ad.c.username)

# 4. Tabella Subnet /29 Studenti
subnet_studenti = Table(
    "subnet_studenti",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "classe_id",
        Integer,
        ForeignKey("classi.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "studente_id",
        Integer,
        ForeignKey("utenti_ad.id", ondelete="SET NULL"),
        unique=True,
    ),
    Column("subnet_cidr", Text, nullable=False, unique=True),
    Column("network_ip", Text, nullable=False, unique=True),
    Column("gateway_ip", Text, nullable=False, unique=True),
    Column("first_usable_ip", Text, nullable=False),
    Column("last_usable_ip", Text, nullable=False),
    Column("broadcast_ip", Text, nullable=False),
    Column("stato", Text, nullable=False, server_default="'AVAILABLE'"),
    Column("assigned_at", Text),
    CheckConstraint("stato IN ('AVAILABLE', 'ASSIGNED', 'QUARANTINED')", name="chk_stato_subnet"),
)
Index("idx_subnet_studenti_classe", subnet_studenti.c.classe_id, subnet_studenti.c.stato)

# 5. Tabella Container LXC Registrati
container_studenti = Table(
    "container_studenti",
    metadata,
    Column("vmid", Integer, primary_key=True),
    Column(
        "studente_id",
        Integer,
        ForeignKey("utenti_ad.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "classe_id",
        Integer,
        ForeignKey("classi.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("hostname_hint", Text),
    Column("pve_node", Text),
    Column("mac_address", Text, unique=True),
    Column("vnet_name", Text, nullable=False),
    Column("hook_installed", Integer, nullable=False, server_default="0"),
    Column("is_enabled", Integer, nullable=False, server_default="1"),
    Column(
        "created_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    Column(
        "updated_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint("vmid >= 100 AND vmid <= 999999999", name="chk_vmid_range"),
    CheckConstraint("hook_installed IN (0, 1)", name="chk_hook_bool"),
    CheckConstraint("is_enabled IN (0, 1)", name="chk_ct_enabled_bool"),
)
Index("idx_container_studente", container_studenti.c.studente_id)

# 6. Tabella Prenotazioni IP (1:1 con VMID)
prenotazioni_ip = Table(
    "prenotazioni_ip",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "subnet_id",
        Integer,
        ForeignKey("subnet_studenti.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "studente_id",
        Integer,
        ForeignKey("utenti_ad.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "vmid",
        Integer,
        ForeignKey("container_studenti.vmid", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    ),
    Column("reserved_ip", Text, nullable=False, unique=True),
    Column("stato_prenotaz", Text, nullable=False, server_default="'ACTIVE'"),
    Column(
        "created_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    Column(
        "updated_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint(
        "stato_prenotaz IN ('ACTIVE', 'SUSPENDED', 'REVOKED')",
        name="chk_stato_prenotaz",
    ),
)
Index(
    "idx_prenotazioni_ip_lookup",
    prenotazioni_ip.c.reserved_ip,
    prenotazioni_ip.c.stato_prenotaz,
)
Index("idx_prenotazioni_studente", prenotazioni_ip.c.studente_id)

# 7. Tabella Stato Provisioning (Desired vs Actual State per fwdd)
provisioning_status = Table(
    "provisioning_status",
    metadata,
    Column(
        "vmid",
        Integer,
        ForeignKey("container_studenti.vmid", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("desired_state", Text, nullable=False),
    Column("desired_ip", Text, nullable=False),
    Column("desired_mac", Text),
    Column("desired_vnet", Text, nullable=False),
    Column("desired_version", Integer, nullable=False, server_default="1"),
    Column("actual_state", Text, nullable=False, server_default="'UNKNOWN'"),
    Column("actual_ip", Text),
    Column("actual_mac", Text),
    Column("applied_version", Integer, nullable=False, server_default="0"),
    Column("last_hook_event", Text),
    Column("last_error_code", Text),
    Column("last_error_msg", Text),
    Column("last_attempt_at", Text),
    Column("last_verified_at", Text),
    CheckConstraint("desired_state IN ('PRESENT', 'ABSENT')", name="chk_desired_state"),
    CheckConstraint(
        "actual_state IN ('SYNCED', 'DRIFTED', 'ABSENT', 'ERROR', 'UNKNOWN')",
        name="chk_actual_state",
    ),
)
Index("idx_provisioning_actual_state", provisioning_status.c.actual_state)

# 8. Tabella Regole Comunicazione Dinamiche (East-West)
regole_comunicazione = Table(
    "regole_comunicazione",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("nome_regola", Text, nullable=False),
    Column("creata_da", Text, nullable=False),
    Column("source_type", Text, nullable=False),
    Column("source_cidr", Text, nullable=False),
    Column("dest_type", Text, nullable=False),
    Column("dest_cidr", Text, nullable=False),
    Column("protocollo", Text, nullable=False, server_default="'ALL'"),
    Column("dest_ports", Text),
    Column("bidirectional", Integer, nullable=False, server_default="1"),
    Column("is_active", Integer, nullable=False, server_default="1"),
    Column("expires_at", Text),
    Column("desired_version", Integer, nullable=False, server_default="1"),
    Column("applied_version", Integer, nullable=False, server_default="0"),
    Column("sync_status", Text, nullable=False, server_default="'PENDING'"),
    Column(
        "created_at",
        Text,
        nullable=False,
        server_default=text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"),
    ),
    CheckConstraint(
        "source_type IN ('SUBNET_29', 'CLASS_VNET', 'SINGLE_IP')",
        name="chk_src_type",
    ),
    CheckConstraint(
        "dest_type IN ('SUBNET_29', 'CLASS_VNET', 'SINGLE_IP')",
        name="chk_dst_type",
    ),
    CheckConstraint("protocollo IN ('ALL', 'TCP', 'UDP', 'ICMP')", name="chk_proto"),
    CheckConstraint("bidirectional IN (0, 1)", name="chk_bidir_bool"),
    CheckConstraint("is_active IN (0, 1)", name="chk_rule_active_bool"),
)


def configure_sqlite_pragmas(dbapi_conn, connection_record):
    """Imposta i PRAGMA fondamentali su ogni connessione SQLite aperta."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("PRAGMA synchronous = NORMAL;")
    cursor.execute("PRAGMA busy_timeout = 5000;")
    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.execute("PRAGMA temp_store = MEMORY;")
    cursor.execute("PRAGMA wal_autocheckpoint = 1000;")
    cursor.close()


def get_engine(db_path: str) -> Engine:
    engine = create_engine(
        f"sqlite:///{db_path}",
        future=True,
        pool_pre_ping=True,
    )
    event.listen(engine, "connect", configure_sqlite_pragmas)
    return engine


def seed_classes_and_subnets(engine: Engine, class_definitions: typing.List[typing.Dict[str, typing.Any]]):
    """Inserisce in modo idempotente le classi e suddivide ciascun supernet in subnet /29."""
    with engine.begin() as conn:
        for cdef in class_definitions:
            codice = cdef["codice_classe"]
            existing = conn.execute(select(classi.c.id).where(classi.c.codice_classe == codice)).fetchone()

            if existing:
                classe_id = existing.id
                logger.info("Classe %s già presente (id=%d), verifico subnet /29...", codice, classe_id)
            else:
                res = conn.execute(
                    insert(classi).values(
                        codice_classe=codice,
                        ad_group_dn=cdef["ad_group_dn"],
                        vnet_name=cdef["vnet_name"],
                        supernet_cidr=cdef["supernet_cidr"],
                        vlan_tag=cdef.get("vlan_tag"),
                        max_containers_per_student=cdef.get("max_containers_per_student", 2),
                    )
                )
                classe_id = res.inserted_primary_key[0]
                conn.execute(
                    insert(stato_classi).values(
                        classe_id=classe_id,
                        intra_class_comm=0,
                        exam_mode=0,
                        internet_enabled=1,
                        exam_allowed_domains=json.dumps(["deb.debian.org", "security.debian.org"]),
                        sync_status="PENDING",
                        last_changed_by="init_db",
                    )
                )
                logger.info("Creata classe %s (id=%d, VNet=%s)", codice, classe_id, cdef["vnet_name"])

            # Calcolo di tutte le /29 dentro il supernet della classe
            supernet = ipaddress.IPv4Network(cdef["supernet_cidr"], strict=True)
            if supernet.prefixlen > 29:
                raise ValueError(f"Supernet {supernet} troppo piccolo per generare blocchi /29")

            created_count = 0
            for sub29 in supernet.subnets(new_prefix=29):
                cidr_str = str(sub29)
                exists_sub = conn.execute(
                    select(subnet_studenti.c.id).where(subnet_studenti.c.subnet_cidr == cidr_str)
                ).fetchone()
                if exists_sub:
                    continue

                hosts = list(sub29.hosts())
                # In una /29 ci sono 6 host utili:
                # hosts[0] (.1, .9, .17...) -> Gateway sul router Debian
                # hosts[1..5] (.2-.6, .10-.14...) -> 5 IP utilizzabili dallo studente
                gateway_ip = str(hosts[0])
                first_usable = str(hosts[1])
                last_usable = str(hosts[-1])

                conn.execute(
                    insert(subnet_studenti).values(
                        classe_id=classe_id,
                        studente_id=None,
                        subnet_cidr=cidr_str,
                        network_ip=str(sub29.network_address),
                        gateway_ip=gateway_ip,
                        first_usable_ip=first_usable,
                        last_usable_ip=last_usable,
                        broadcast_ip=str(sub29.broadcast_address),
                        stato="AVAILABLE",
                    )
                )
                created_count += 1

            logger.info(
                "Classe %s: generate %d nuove subnet /29 (totale capacità: %d subnet /29).",
                codice,
                created_count,
                supernet.num_addresses // 8,
            )
