"""
labctl.api.app

Backend REST JSON in FastAPI + SQLAlchemy Core per:
- Studente (/api/student/*): primo login con allocazione /29 automatica, prenotazione IP/VMID
- Docente  (/api/teacher/*): stato classe, attivazione Modalità Verifica + domini ammessi, regole East-West
- Admin    (/api/admin/*)  : quote max_containers_per_student, drift detection, riconciliazione fwdd
- Resolver (/api/v1/resolve): correlazione IP -> Utente + domini esame per Squid 3130 su Hyper-V
"""

import hmac
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Literal, Optional  # noqa: UP035

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import String, and_, cast, delete, func, insert, or_, select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from labctl.api.services import (
    FwddClientError,
    FwddUnixClient,
    ProxmoxClusterClient,
    export_vector_enrichment_csvs,
)
from labctl.db.config import (
    DEFAULT_DB_PATH,
    classi,
    container_studenti,
    get_engine,
    prenotazioni_ip,
    provisioning_status,
    regole_comunicazione,
    stato_classi,
    subnet_studenti,
    utenti_ad,
)

logger = logging.getLogger("labctl.api")

# Configurazione tramite variabili d'ambiente
DB_PATH = os.getenv("LABCTL_DB_PATH", DEFAULT_DB_PATH)
FWDD_SOCKET = os.getenv("LABCTL_FWDD_SOCKET", "/run/fwdd/control.sock")
VECTOR_EXPORT_DIR = os.getenv("LABCTL_EXPORT_DIR", "/var/lib/labctl/exports")
SQUID_API_TOKEN = os.getenv("LABCTL_SQUID_TOKEN", "dev-squid-secret-token-change-me")
SQUID_ALLOWED_IPS = {
    ip.strip() for ip in os.getenv("LABCTL_SQUID_IPS", "127.0.0.1,::1,10.0.10.10,10.0.10.11").split(",") if ip.strip()
}

PVE_BASE_URL = os.getenv("LABCTL_PVE_URL", "https://127.0.0.1:8006")
PVE_TOKEN_ID = os.getenv("LABCTL_PVE_TOKEN_ID", "root@pam!labctl")
PVE_TOKEN_SECRET = os.getenv("LABCTL_PVE_TOKEN_SECRET", "secret")
PVE_MOCK_MODE = os.getenv("LABCTL_PVE_MOCK", "1") == "1"

engine: Engine = get_engine(DB_PATH)
fwdd_client = FwddUnixClient(socket_path=FWDD_SOCKET)
pve_client = ProxmoxClusterClient(
    base_url=PVE_BASE_URL,
    token_id=PVE_TOKEN_ID,
    token_secret=PVE_TOKEN_SECRET,
    mock_mode=PVE_MOCK_MODE,
)

app = FastAPI(
    title="LabCtl SDN & Container Guard API",
    version="1.0.0",
    description="API JSON per gestione /29 studenti, enforcement fwdd/nftables e resolver Squid 3130.",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# =====================================================================
# MODELLI PYDANTIC V2 (Contratti JSON Request / Response)
# =====================================================================


class CurrentUser(BaseModel):
    id: int
    username: str
    display_name: str
    object_guid: str
    ruolo: Literal["STUDENT", "TEACHER", "ADMIN"]
    classe_id: Optional[int] = None
    codice_classe: Optional[str] = None
    vnet_name: Optional[str] = None
    max_containers: int = 2


class ReservationCreateRequest(BaseModel):
    vmid: int = Field(..., ge=100, le=999999999, description="VMID del container LXC su Proxmox")
    reserved_ip: str = Field(..., description="Uno dei 5 IP utilizzabili della propria /29")
    hostname_hint: Optional[str] = Field(None, max_length=64, description="Descrizione o hostname")

    @field_validator("reserved_ip")
    @classmethod
    def check_ipv4(cls, v: str) -> str:
        return str(ipaddress.IPv4Address(v.strip()))


class ReservationUpdateRequest(BaseModel):
    reserved_ip: str = Field(..., description="Nuovo IP scelto dentro la propria /29")
    hostname_hint: Optional[str] = Field(None, max_length=64)

    @field_validator("reserved_ip")
    @classmethod
    def check_ipv4(cls, v: str) -> str:
        return str(ipaddress.IPv4Address(v.strip()))


class ReservationItemResponse(BaseModel):
    vmid: int
    reserved_ip: str
    mac_address: Optional[str]
    pve_node: Optional[str]
    vnet_name: str
    hostname_hint: Optional[str]
    stato_prenotaz: str
    actual_state: str
    last_verified_at: Optional[str]


class StudentNetworkResponse(BaseModel):
    username: str
    display_name: str
    class_code: str
    vnet_name: str
    max_active_containers: int
    active_containers_count: int
    subnet_29: Dict[str, Any]
    reservations: List[ReservationItemResponse]


class ClassModeUpdateRequest(BaseModel):
    exam_mode: bool = Field(..., description="Attiva/disattiva isolamento Modalità Verifica")
    intra_class_comm: bool = Field(False, description="Consente traffico diretto L3 tra studenti della stessa classe")
    internet_enabled: bool = Field(True, description="Abilita uscita verso Internet/Proxy")
    exam_allowed_domains: List[str] = Field(
        default_factory=lambda: ["deb.debian.org", "security.debian.org"],
        description="Lista di domini consentiti da Squid 3130 durante la verifica",
    )

    @field_validator("exam_allowed_domains")
    @classmethod
    def normalize_domains(cls, domains: List[str]) -> List[str]:
        cleaned = []
        for d in domains:
            d_clean = d.strip().lower().lstrip(".")
            if d_clean and d_clean not in cleaned:
                cleaned.append(d_clean)
        return cleaned


class CommRuleCreateRequest(BaseModel):
    nome_regola: str = Field(..., min_length=3, max_length=80)
    source_type: Literal["SUBNET_29", "CLASS_VNET", "SINGLE_IP"]
    source_cidr: str
    dest_type: Literal["SUBNET_29", "CLASS_VNET", "SINGLE_IP"]
    dest_cidr: str
    protocollo: Literal["ALL", "TCP", "UDP", "ICMP"] = "ALL"
    dest_ports: Optional[str] = None
    bidirectional: bool = True
    expires_at: Optional[str] = None

    @field_validator("source_cidr", "dest_cidr")
    @classmethod
    def check_cidr(cls, v: str) -> str:
        return str(ipaddress.IPv4Network(v.strip(), strict=False))


class AdminQuotaUpdateRequest(BaseModel):
    max_containers_per_student: int = Field(..., ge=1, le=5)


class AdminStudentMigrationRequest(BaseModel):
    target_class_code: str = Field(..., description="Codice della nuova classe, es. 4A-INF")


# =====================================================================
# DEPENDENCIES: Connessione DB & Autenticazione / Onboarding Automatico
# =====================================================================


def get_db_conn() -> Generator[Connection, None, None]:
    """Fornisce una connessione transazionale SQLAlchemy Core (commit automatico a fine request)."""
    with engine.begin() as conn:
        yield conn


def get_current_user(
    conn: Connection = Depends(get_db_conn),
    x_remote_user: Optional[str] = Header(None, description="Username AD passato da Caddy/Authentik"),
    x_remote_name: Optional[str] = Header(None, description="Display Name AD"),
    x_remote_groups: Optional[str] = Header(None, description="Gruppi AD o codice classe (es. '3A-INF' o 'TEACHERS')"),
    x_remote_guid: Optional[str] = Header(None, description="objectGUID Active Directory"),
) -> CurrentUser:
    """
    Risolve l'utente corrente dagli header del Reverse Proxy (es. Caddy + Authentik/Kerberos)
    ed esegue l'onboarding trasparente al primo login.
    """
    if not x_remote_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header di autenticazione X-Remote-User mancante.",
        )

    username = x_remote_user.strip().lower()
    now = utc_now()

    stmt = (
        select(
            utenti_ad,
            classi.c.codice_classe,
            classi.c.vnet_name,
            classi.c.max_containers_per_student,
        )
        .select_from(utenti_ad.outerjoin(classi, classi.c.id == utenti_ad.c.classe_id))
        .where(utenti_ad.c.username == username)
    )
    row = conn.execute(stmt).fetchone()

    if row:
        if not row.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account utente disabilitato dall'amministratore.",
            )
        conn.execute(update(utenti_ad).where(utenti_ad.c.id == row.id).values(last_login_at=now))
        effective_max = (
            row.max_containers_override
            if row.max_containers_override is not None
            else (row.max_containers_per_student or 2)
        )
        return CurrentUser(
            id=row.id,
            username=row.username,
            display_name=row.display_name,
            object_guid=row.object_guid,
            ruolo=row.ruolo,
            classe_id=row.classe_id,
            codice_classe=row.codice_classe,
            vnet_name=row.vnet_name,
            max_containers=effective_max,
        )

    # --- ONBOARDING AL PRIMO LOGIN ---
    groups_raw = [g.strip() for g in re.split(r"[,|]", x_remote_groups or "") if g.strip()]
    normalized_groups = {group.upper() for group in groups_raw}
    role_groups: Dict[Literal["ADMIN", "TEACHER", "STUDENT"], set[str]] = {
        "ADMIN": {"ADMINS", "DOMAIN ADMINS", "ADMIN", "LAB_ADMIN"},
        "TEACHER": {"TEACHERS", "DOCENTI", "TEACHER", "LAB_TEACHER"},
        "STUDENT": {"STUDENTS", "STUDENTI", "STUDENT", "LAB_STUDENT"},
    }
    matched_roles = [role for role, names in role_groups.items() if normalized_groups & names]
    if len(matched_roles) != 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Primo login fallito: l'utente deve appartenere a un solo gruppo di ruolo LabCtl.",
        )
    ruolo = matched_roles[0]

    classe_row = None
    if ruolo == "STUDENT":
        # Cerca corrispondenza per codice_classe (es. "3A-INF") o ad_group_dn
        all_classes = conn.execute(select(classi)).fetchall()
        for cl in all_classes:
            if cl.codice_classe in groups_raw or cl.ad_group_dn in groups_raw:
                classe_row = cl
                break
        if not classe_row:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Primo login fallito: nessuna classe valida associata ai gruppi Active Directory dell'utente.",
            )

    guid = (x_remote_guid or f"auto-guid-{username}").strip()
    display_name = (x_remote_name or username).strip()

    res = conn.execute(
        insert(utenti_ad).values(
            username=username,
            object_guid=guid,
            display_name=display_name,
            ruolo=ruolo,
            classe_id=classe_row.id if classe_row else None,
            is_active=1,
            first_login_at=now,
            last_login_at=now,
        )
    )
    new_user_id = res.inserted_primary_key[0]

    return CurrentUser(
        id=new_user_id,
        username=username,
        display_name=display_name,
        object_guid=guid,
        ruolo=ruolo,
        classe_id=classe_row.id if classe_row else None,
        codice_classe=classe_row.codice_classe if classe_row else None,
        vnet_name=classe_row.vnet_name if classe_row else None,
        max_containers=classe_row.max_containers_per_student if classe_row else 5,
    )


def require_role(*allowed_roles: str):
    def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.ruolo not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operazione riservata ai ruoli: {', '.join(allowed_roles)}",
            )
        return user

    return _dep


def ensure_student_subnet(conn: Connection, user: CurrentUser) -> Any:
    """Restituisce la /29 dello studente o ne alloca atomicamente la prima disponibile della classe."""
    sub_row = conn.execute(select(subnet_studenti).where(subnet_studenti.c.studente_id == user.id)).fetchone()
    if sub_row:
        return sub_row

    free_sub = conn.execute(
        select(subnet_studenti)
        .where(
            and_(
                subnet_studenti.c.classe_id == user.classe_id,
                subnet_studenti.c.stato == "AVAILABLE",
                subnet_studenti.c.studente_id.is_(None),
            )
        )
        .order_by(subnet_studenti.c.id.asc())
        .limit(1)
    ).fetchone()

    if not free_sub:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=f"Pool di sottoreti /29 esaurito per la classe {user.codice_classe}.",
        )

    now = utc_now()
    conn.execute(
        update(subnet_studenti)
        .where(subnet_studenti.c.id == free_sub.id)
        .values(studente_id=user.id, stato="ASSIGNED", assigned_at=now)
    )
    return conn.execute(select(subnet_studenti).where(subnet_studenti.c.id == free_sub.id)).fetchone()


def get_student_pool_id(user: CurrentUser) -> str:
    """Deriva l'ID del pool Proxmox dall'UID Authentik, verificato da Caddy."""
    if not re.fullmatch(r"\d{8}", user.object_guid):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UID Authentik non valido: per gli studenti sono richieste esattamente 8 cifre.",
        )
    return f"p-{user.object_guid}"


# =====================================================================
# 1. ROUTER STUDENTE (/api/student/*)
# =====================================================================


@app.get("/api/student/me/network", response_model=StudentNetworkResponse, tags=["Studente"])
def get_my_network_parameters(
    user: CurrentUser = Depends(require_role("STUDENT")),
    conn: Connection = Depends(get_db_conn),
):
    """
    Restituisce i parametri della /29 assegnata allo studente (inclusa la lista esplicita dei
    5 IP utilizzabili e il gateway .1) e l'elenco dei container registrati.
    """
    get_student_pool_id(user)
    sub = ensure_student_subnet(conn, user)
    net_obj = ipaddress.IPv4Network(sub.subnet_cidr)
    usable_ips = [str(ip) for ip in list(net_obj.hosts())[1:]]  # Esclude il .1 (gateway)

    stmt_res = (
        select(
            prenotazioni_ip.c.vmid,
            prenotazioni_ip.c.reserved_ip,
            prenotazioni_ip.c.stato_prenotaz,
            container_studenti.c.mac_address,
            container_studenti.c.pve_node,
            container_studenti.c.vnet_name,
            container_studenti.c.hostname_hint,
            provisioning_status.c.actual_state,
            provisioning_status.c.last_verified_at,
        )
        .select_from(
            prenotazioni_ip.join(container_studenti, container_studenti.c.vmid == prenotazioni_ip.c.vmid).outerjoin(
                provisioning_status, provisioning_status.c.vmid == prenotazioni_ip.c.vmid
            )
        )
        .where(prenotazioni_ip.c.studente_id == user.id)
        .order_by(prenotazioni_ip.c.vmid.asc())
    )
    res_rows = conn.execute(stmt_res).fetchall()

    reservations = [
        ReservationItemResponse(
            vmid=r.vmid,
            reserved_ip=r.reserved_ip,
            mac_address=r.mac_address,
            pve_node=r.pve_node,
            vnet_name=r.vnet_name,
            hostname_hint=r.hostname_hint,
            stato_prenotaz=r.stato_prenotaz,
            actual_state=r.actual_state or "UNKNOWN",
            last_verified_at=r.last_verified_at,
        )
        for r in res_rows
    ]

    reserved_set = {r.reserved_ip for r in res_rows if r.stato_prenotaz == "ACTIVE"}

    return StudentNetworkResponse(
        username=user.username,
        display_name=user.display_name,
        class_code=user.codice_classe or "",
        vnet_name=user.vnet_name or "",
        max_active_containers=user.max_containers,
        active_containers_count=len(reserved_set),
        subnet_29={
            "cidr": sub.subnet_cidr,
            "netmask": str(net_obj.netmask),
            "prefixlen": 29,
            "network_ip": sub.network_ip,
            "gateway_ip": sub.gateway_ip,
            "broadcast_ip": sub.broadcast_ip,
            "usable_student_ips": usable_ips,
            "free_student_ips": [ip for ip in usable_ips if ip not in reserved_set],
        },
        reservations=reservations,
    )


@app.post(
    "/api/student/reservations",
    response_model=ReservationItemResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Studente"],
)
def create_student_reservation(
    payload: ReservationCreateRequest,
    user: CurrentUser = Depends(require_role("STUDENT")),
    conn: Connection = Depends(get_db_conn),
):
    """
    Associa un VMID creato su Proxmox a uno dei 5 IP della /29 dello studente:
    1. Verifica il rispetto del limite `max_containers_per_student`;
    2. Verifica che l'IP appartenga ai 5 IP host della /29 dello studente;
    3. Interroga Proxmox per estrarre il MAC address e iniettare l'hookscript `pre-start`;
    4. Registra la prenotazione su SQLite, aggiorna i CSV di Vector e programma subito `fwdd`.
    """
    expected_pool_id = get_student_pool_id(user)
    sub = ensure_student_subnet(conn, user)
    net_obj = ipaddress.IPv4Network(sub.subnet_cidr)
    usable_ips = {str(ip) for ip in list(net_obj.hosts())[1:]}

    if payload.reserved_ip not in usable_ips:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"L'IP {payload.reserved_ip} non è valido. Devi scegliere uno dei 5 IP assegnabili "
                f"della tua /29 ({sub.first_usable_ip} - {sub.last_usable_ip}), escludendo il gateway {sub.gateway_ip}."
            ),
        )

    # Controllo quota container attivi per studente
    active_count = conn.execute(
        select(func.count(prenotazioni_ip.c.id)).where(
            and_(
                prenotazioni_ip.c.studente_id == user.id,
                prenotazioni_ip.c.stato_prenotaz == "ACTIVE",
            )
        )
    ).scalar_one()

    if active_count >= user.max_containers:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Hai già raggiunto il numero massimo di container attivi consentito ({user.max_containers}). "
                "Rimuovi una prenotazione esistente prima di associare un nuovo VMID."
            ),
        )

    # Verifica e preparazione container su Proxmox VE (pool, MAC e hookscript)
    try:
        pve_node, mac_addr, pve_hostname = pve_client.inspect_and_prepare_lxc(
            vmid=payload.vmid,
            expected_username=user.username,
            expected_vnet=user.vnet_name or "",
            expected_pool_id=expected_pool_id,
        )
    except ValueError as verr:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(verr)) from verr
    except Exception as exc:
        logger.exception("Errore comunicazione con API Proxmox per VMID=%d", payload.vmid)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Impossibile verificare il container VMID {payload.vmid} su Proxmox: {exc}",
        ) from exc

    now = utc_now()
    hint = payload.hostname_hint or pve_hostname

    try:
        conn.execute(
            insert(container_studenti).values(
                vmid=payload.vmid,
                studente_id=user.id,
                classe_id=user.classe_id,
                hostname_hint=hint,
                pve_node=pve_node,
                mac_address=mac_addr,
                vnet_name=user.vnet_name,
                hook_installed=1,
                is_enabled=1,
                created_at=now,
                updated_at=now,
            )
        )
        conn.execute(
            insert(prenotazioni_ip).values(
                subnet_id=sub.id,
                studente_id=user.id,
                vmid=payload.vmid,
                reserved_ip=payload.reserved_ip,
                stato_prenotaz="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        conn.execute(
            insert(provisioning_status).values(
                vmid=payload.vmid,
                desired_state="PRESENT",
                desired_ip=payload.reserved_ip,
                desired_mac=mac_addr,
                desired_vnet=user.vnet_name,
                desired_version=1,
                actual_state="DRIFTED",
                applied_version=0,
                last_attempt_at=now,
            )
        )
    except IntegrityError as ierr:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Il VMID o l'indirizzo IP selezionato è già associato a un altro container.",
        ) from ierr

    # Il blocco `with engine.begin()` committerà all'uscita, ma per far leggere i dati a fwdd
    # eseguiamo commit esplicito sulla connessione corrente prima della chiamata socket
    conn.commit()

    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)

    actual_state = "DRIFTED"
    try:
        fwdd_resp = fwdd_client.call(
            "provision_anti_spoofing",
            vmid=payload.vmid,
            vnet=user.vnet_name,
            mac=mac_addr,
        )
        actual_state = fwdd_resp.get("state", "SYNCED")
    except FwddClientError as ferr:
        logger.warning(
            "Prenotazione salvata per VMID=%d ma fwdd non raggiungibile subito (%s): ci penserà l'hook pre-start.",
            payload.vmid,
            ferr.message,
        )

    return ReservationItemResponse(
        vmid=payload.vmid,
        reserved_ip=payload.reserved_ip,
        mac_address=mac_addr,
        pve_node=pve_node,
        vnet_name=user.vnet_name or "",
        hostname_hint=hint,
        stato_prenotaz="ACTIVE",
        actual_state=actual_state,
        last_verified_at=now if actual_state == "SYNCED" else None,
    )


@app.put(
    "/api/student/reservations/{vmid}",
    response_model=ReservationItemResponse,
    tags=["Studente"],
)
def update_student_reservation_ip(
    vmid: int,
    payload: ReservationUpdateRequest,
    user: CurrentUser = Depends(require_role("STUDENT")),
    conn: Connection = Depends(get_db_conn),
):
    """Cambia l'IP prenotato per un VMID esistente (restando dentro la propria /29) e riallinea fwdd."""
    sub = ensure_student_subnet(conn, user)
    net_obj = ipaddress.IPv4Network(sub.subnet_cidr)
    usable_ips = {str(ip) for ip in list(net_obj.hosts())[1:]}

    if payload.reserved_ip not in usable_ips:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"L'IP {payload.reserved_ip} non appartiene ai 5 IP utilizzabili della tua /29.",
        )

    existing = conn.execute(
        select(container_studenti, prenotazioni_ip.c.stato_prenotaz)
        .select_from(container_studenti.join(prenotazioni_ip, prenotazioni_ip.c.vmid == container_studenti.c.vmid))
        .where(
            and_(
                container_studenti.c.vmid == vmid,
                container_studenti.c.studente_id == user.id,
            )
        )
    ).fetchone()

    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container VMID {vmid} non trovato tra le tue prenotazioni.",
        )

    now = utc_now()
    try:
        conn.execute(
            update(prenotazioni_ip)
            .where(prenotazioni_ip.c.vmid == vmid)
            .values(reserved_ip=payload.reserved_ip, updated_at=now)
        )
        if payload.hostname_hint is not None:
            conn.execute(
                update(container_studenti)
                .where(container_studenti.c.vmid == vmid)
                .values(hostname_hint=payload.hostname_hint, updated_at=now)
            )
        conn.execute(
            update(provisioning_status)
            .where(provisioning_status.c.vmid == vmid)
            .values(
                desired_ip=payload.reserved_ip,
                desired_version=provisioning_status.c.desired_version + 1,
                actual_state="DRIFTED",
                last_attempt_at=now,
            )
        )
    except IntegrityError as ierr:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"L'IP {payload.reserved_ip} è già assegnato a un altro tuo container.",
        ) from ierr

    conn.commit()
    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)

    actual_state = "DRIFTED"
    if existing.mac_address:
        try:
            fwdd_client.call(
                "provision_anti_spoofing",
                vmid=vmid,
                vnet=existing.vnet_name,
                mac=existing.mac_address,
            )
            actual_state = "SYNCED"
        except FwddClientError as ferr:
            logger.warning("Errore aggiornamento live fwdd per VMID=%d: %s", vmid, ferr.message)

    return ReservationItemResponse(
        vmid=vmid,
        reserved_ip=payload.reserved_ip,
        mac_address=existing.mac_address,
        pve_node=existing.pve_node,
        vnet_name=existing.vnet_name,
        hostname_hint=payload.hostname_hint or existing.hostname_hint,
        stato_prenotaz=existing.stato_prenotaz,
        actual_state=actual_state,
        last_verified_at=now if actual_state == "SYNCED" else None,
    )


@app.delete("/api/student/reservations/{vmid}", tags=["Studente"])
def delete_student_reservation(
    vmid: int,
    user: CurrentUser = Depends(require_role("STUDENT")),
    conn: Connection = Depends(get_db_conn),
):
    """Elimina la prenotazione del VMID e rimuove immediatamente la tripla da nftables tramite fwdd."""
    row = conn.execute(
        select(container_studenti.c.vmid).where(
            and_(
                container_studenti.c.vmid == vmid,
                container_studenti.c.studente_id == user.id,
            )
        )
    ).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prenotazione per VMID {vmid} non trovata.",
        )

    try:
        fwdd_client.call("deprovision_anti_spoofing", vmid=vmid)
    except FwddClientError as ferr:
        logger.warning("Deprovisioning fwdd per VMID=%d fallito: %s", vmid, ferr.message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Impossibile revocare la regola di rete per il VMID {vmid}: {ferr.message}",
        ) from ferr

    conn.execute(delete(container_studenti).where(container_studenti.c.vmid == vmid))
    conn.commit()

    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)
    return {"status": "deleted", "vmid": vmid}


# =====================================================================
# 2. ROUTER DOCENTE (/api/teacher/*)
# =====================================================================


@app.get("/api/teacher/classes/{class_code}/status", tags=["Docente"])
def get_class_overview(
    class_code: str,
    user: CurrentUser = Depends(require_role("TEACHER", "ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Restituisce lo stato della classe, la configurazione Modalità Verifica e tutti i container studenti."""
    cl = conn.execute(
        select(classi, stato_classi)
        .select_from(classi.join(stato_classi, stato_classi.c.classe_id == classi.c.id))
        .where(classi.c.codice_classe == class_code.upper())
    ).fetchone()

    if not cl:
        raise HTTPException(status_code=404, detail=f"Classe {class_code} non trovata.")

    stmt_students = (
        select(
            utenti_ad.c.id.label("student_id"),
            utenti_ad.c.username,
            utenti_ad.c.display_name,
            utenti_ad.c.is_active,
            subnet_studenti.c.subnet_cidr,
            subnet_studenti.c.gateway_ip,
            container_studenti.c.vmid,
            container_studenti.c.mac_address,
            container_studenti.c.is_enabled,
            prenotazioni_ip.c.reserved_ip,
            provisioning_status.c.actual_state,
            provisioning_status.c.last_verified_at,
        )
        .select_from(
            utenti_ad.outerjoin(subnet_studenti, subnet_studenti.c.studente_id == utenti_ad.c.id)
            .outerjoin(container_studenti, container_studenti.c.studente_id == utenti_ad.c.id)
            .outerjoin(prenotazioni_ip, prenotazioni_ip.c.vmid == container_studenti.c.vmid)
            .outerjoin(provisioning_status, provisioning_status.c.vmid == container_studenti.c.vmid)
        )
        .where(utenti_ad.c.classe_id == cl.id)
        .order_by(utenti_ad.c.username.asc(), container_studenti.c.vmid.asc())
    )
    rows = conn.execute(stmt_students).fetchall()

    return {
        "class_code": cl.codice_classe,
        "vnet_name": cl.vnet_name,
        "supernet_cidr": cl.supernet_cidr,
        "max_containers_per_student": cl.max_containers_per_student,
        "policy_state": {
            "exam_mode": bool(cl.exam_mode),
            "intra_class_comm": bool(cl.intra_class_comm),
            "internet_enabled": bool(cl.internet_enabled),
            "exam_allowed_domains": json.loads(cl.exam_allowed_domains or "[]"),
            "sync_status": cl.sync_status,
            "last_changed_by": cl.last_changed_by,
            "updated_at": cl.updated_at,
        },
        "allocations": [dict(r._mapping) for r in rows],
    }


@app.post("/api/teacher/classes/{class_code}/mode", tags=["Docente"])
def set_class_operational_mode(
    class_code: str,
    payload: ClassModeUpdateRequest,
    user: CurrentUser = Depends(require_role("TEACHER", "ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """
    Attiva/disattiva la Modalità Verifica, aggiorna i domini ammessi su Squid 3130 e
    applica immediatamente l'isolamento L3 e il flush conntrack tramite `fwdd`.
    """
    cl = conn.execute(select(classi).where(classi.c.codice_classe == class_code.upper())).fetchone()
    if not cl:
        raise HTTPException(status_code=404, detail=f"Classe {class_code} non trovata.")

    now = utc_now()
    effective_intra = False if payload.exam_mode else payload.intra_class_comm

    conn.execute(
        update(stato_classi)
        .where(stato_classi.c.classe_id == cl.id)
        .values(
            exam_mode=int(payload.exam_mode),
            intra_class_comm=int(effective_intra),
            internet_enabled=int(payload.internet_enabled),
            exam_allowed_domains=json.dumps(payload.exam_allowed_domains),
            desired_config_version=stato_classi.c.desired_config_version + 1,
            sync_status="PENDING",
            last_changed_by=user.username,
            updated_at=now,
        )
    )
    conn.commit()

    try:
        fwdd_resp = fwdd_client.call(
            "set_isolation",
            vnet=cl.vnet_name,
            exam_mode=payload.exam_mode,
            intra_class_comm=effective_intra,
        )
    except FwddClientError as ferr:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stato salvato su DB ma errore durante l'applicazione su fwdd: {ferr.message}",
        ) from ferr

    return {
        "status": "applied",
        "class_code": cl.codice_classe,
        "vnet_name": cl.vnet_name,
        "exam_mode": payload.exam_mode,
        "intra_class_comm": effective_intra,
        "exam_allowed_domains": payload.exam_allowed_domains,
        "fwdd": fwdd_resp,
    }


@app.post(
    "/api/teacher/comm-rules",
    status_code=status.HTTP_201_CREATED,
    tags=["Docente"],
)
def create_east_west_comm_rule(
    payload: CommRuleCreateRequest,
    user: CurrentUser = Depends(require_role("TEACHER", "ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Abilita la comunicazione diretta L3 tra due /29 o tra due classi."""
    now = utc_now()
    res = conn.execute(
        insert(regole_comunicazione).values(
            nome_regola=payload.nome_regola,
            creata_da=user.username,
            source_type=payload.source_type,
            source_cidr=payload.source_cidr,
            dest_type=payload.dest_type,
            dest_cidr=payload.dest_cidr,
            protocollo=payload.protocollo,
            dest_ports=payload.dest_ports,
            bidirectional=int(payload.bidirectional),
            is_active=1,
            expires_at=payload.expires_at,
            desired_version=1,
            applied_version=1,
            sync_status="SYNCED",
            created_at=now,
        )
    )
    rule_id = res.inserted_primary_key[0]
    conn.commit()

    fwdd_resp = fwdd_client.call(
        "add_rule",
        rule_id=rule_id,
        src_cidr=payload.source_cidr,
        dst_cidr=payload.dest_cidr,
        bidirectional=payload.bidirectional,
    )
    return {"rule_id": rule_id, "fwdd": fwdd_resp}


@app.delete("/api/teacher/comm-rules/{rule_id}", tags=["Docente"])
def delete_east_west_comm_rule(
    rule_id: int,
    user: CurrentUser = Depends(require_role("TEACHER", "ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Rimuove una regola di comunicazione tra gruppi/studenti e tronca le sessioni conntrack."""
    row = conn.execute(select(regole_comunicazione).where(regole_comunicazione.c.id == rule_id)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Regola {rule_id} non trovata.")

    fwdd_client.call(
        "remove_rule",
        rule_id=rule_id,
        src_cidr=row.source_cidr,
        dst_cidr=row.dest_cidr,
        bidirectional=bool(row.bidirectional),
    )
    conn.execute(delete(regole_comunicazione).where(regole_comunicazione.c.id == rule_id))
    return {"status": "deleted", "rule_id": rule_id}


# =====================================================================
# 3. ROUTER ADMIN (/api/admin/*)
# =====================================================================


@app.get("/api/admin/containers", tags=["Admin"])
def list_registered_containers(
    search: str = Query("", max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Elenca i container registrati con proprietario, rete e stato di provisioning."""
    joins = (
        container_studenti.join(utenti_ad, utenti_ad.c.id == container_studenti.c.studente_id)
        .join(classi, classi.c.id == container_studenti.c.classe_id)
        .outerjoin(prenotazioni_ip, prenotazioni_ip.c.vmid == container_studenti.c.vmid)
        .outerjoin(provisioning_status, provisioning_status.c.vmid == container_studenti.c.vmid)
    )
    stmt = (
        select(
            container_studenti.c.vmid,
            container_studenti.c.hostname_hint,
            container_studenti.c.pve_node,
            container_studenti.c.mac_address,
            container_studenti.c.vnet_name,
            container_studenti.c.is_enabled,
            container_studenti.c.created_at,
            utenti_ad.c.username,
            utenti_ad.c.display_name,
            classi.c.codice_classe.label("class_code"),
            prenotazioni_ip.c.reserved_ip,
            prenotazioni_ip.c.stato_prenotaz,
            provisioning_status.c.actual_state,
            provisioning_status.c.last_verified_at,
        )
        .select_from(joins)
    )
    count_stmt = select(func.count()).select_from(joins)

    term = search.strip()
    if term:
        pattern = f"%{term}%"
        search_filter = or_(
            cast(container_studenti.c.vmid, String).ilike(pattern),
            container_studenti.c.hostname_hint.ilike(pattern),
            container_studenti.c.vnet_name.ilike(pattern),
            utenti_ad.c.username.ilike(pattern),
            utenti_ad.c.display_name.ilike(pattern),
            classi.c.codice_classe.ilike(pattern),
            prenotazioni_ip.c.reserved_ip.ilike(pattern),
        )
        stmt = stmt.where(search_filter)
        count_stmt = count_stmt.where(search_filter)

    total = conn.execute(count_stmt).scalar_one()
    rows = conn.execute(
        stmt.order_by(utenti_ad.c.username.asc(), container_studenti.c.vmid.asc()).limit(limit).offset(offset)
    ).fetchall()
    return {
        "items": [dict(row._mapping) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.delete("/api/admin/containers/{vmid}", tags=["Admin"])
def delete_registered_container(
    vmid: int,
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Revoca il container in fwdd e lo elimina dal registro."""
    with engine.connect() as lookup_conn:
        row = lookup_conn.execute(
            select(container_studenti.c.vmid).where(container_studenti.c.vmid == vmid)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Container VMID {vmid} non trovato.")

    try:
        fwdd_client.call("deprovision_anti_spoofing", vmid=vmid)
    except FwddClientError as ferr:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Impossibile revocare il container VMID {vmid} su fwdd: {ferr.message}",
        ) from ferr

    conn.execute(delete(container_studenti).where(container_studenti.c.vmid == vmid))
    conn.commit()
    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)
    return {"status": "deleted", "vmid": vmid}


@app.get("/api/admin/network-state", tags=["Admin"])
def get_admin_network_state(
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Mostra gli endpoint nel set nftables e i flussi conntrack correnti per quegli IP."""
    try:
        fwdd_state = fwdd_client.call("network_state")
    except FwddClientError as ferr:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Impossibile leggere lo stato di rete da fwdd: {ferr.message}",
        ) from ferr

    rows = conn.execute(
        select(
            container_studenti.c.vmid,
            container_studenti.c.hostname_hint,
            container_studenti.c.vnet_name,
            container_studenti.c.mac_address,
            utenti_ad.c.username,
            utenti_ad.c.display_name,
            classi.c.codice_classe.label("class_code"),
            prenotazioni_ip.c.reserved_ip,
        )
        .select_from(
            container_studenti.join(utenti_ad, utenti_ad.c.id == container_studenti.c.studente_id)
            .join(classi, classi.c.id == container_studenti.c.classe_id)
            .outerjoin(prenotazioni_ip, prenotazioni_ip.c.vmid == container_studenti.c.vmid)
        )
    ).fetchall()
    containers_by_endpoint = {
        (
            row.vnet_name.lower(),
            (row.mac_address or "").lower(),
            row.reserved_ip,
        ): {
            "vmid": row.vmid,
            "hostname_hint": row.hostname_hint,
            "username": row.username,
            "display_name": row.display_name,
            "class_code": row.class_code,
        }
        for row in rows
        if row.reserved_ip and row.mac_address
    }

    authorized_endpoints = []
    containers_by_ip = {}
    for endpoint in fwdd_state["authorized_endpoints"]:
        container = containers_by_endpoint.get(
            (endpoint["vnet"].lower(), endpoint["mac_address"].lower(), endpoint["ip"])
        )
        authorized_endpoints.append({**endpoint, "container": container})
        if container:
            containers_by_ip[endpoint["ip"]] = container

    active_connections = [
        {
            **connection,
            "source_container": containers_by_ip.get(connection["source_ip"]),
            "destination_container": containers_by_ip.get(connection["destination_ip"]),
        }
        for connection in fwdd_state["active_connections"]
    ]

    return {
        "authorized_endpoints": authorized_endpoints,
        "authorized_endpoint_count": fwdd_state["authorized_endpoint_count"],
        "active_connections": active_connections,
        "active_connection_count": fwdd_state["active_connection_count"],
        "connections_truncated": fwdd_state["connections_truncated"],
        "observed_at": fwdd_state["observed_at"],
    }


@app.put("/api/admin/classes/{class_code}/quota", tags=["Admin"])
def update_class_container_quota(
    class_code: str,
    payload: AdminQuotaUpdateRequest,
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Imposta il numero massimo di container attivabili per studente in una classe (da 1 a 5)."""
    res = conn.execute(
        update(classi)
        .where(classi.c.codice_classe == class_code.upper())
        .values(max_containers_per_student=payload.max_containers_per_student)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail=f"Classe {class_code} non trovata.")
    return {
        "class_code": class_code.upper(),
        "max_containers_per_student": payload.max_containers_per_student,
    }


@app.get("/api/admin/provisioning/drift", tags=["Admin"])
def check_provisioning_drift(
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Confronta lo stato SQLite con lo stato reale di nftables interrogando `fwdd verify_state`."""
    db_drifted = conn.execute(
        select(provisioning_status).where(provisioning_status.c.actual_state != "SYNCED")
    ).fetchall()

    try:
        fwdd_verify = fwdd_client.call("verify_state", scope="full")
    except FwddClientError as ferr:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Verifica fwdd non disponibile: {ferr.message}",
        ) from ferr

    return {
        "checked_at": utc_now(),
        "in_sync": fwdd_verify.get("in_sync", False) and not db_drifted,
        "fwdd_in_sync": fwdd_verify.get("in_sync", False),
        "kernel_drifted_items": fwdd_verify.get("drifted_items", []),
        "db_pending_items": [dict(r._mapping) for r in db_drifted],
    }


@app.get("/api/admin/system/health", tags=["Admin"])
def get_admin_system_health(
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """Controlla la raggiungibilità del database, fwdd e Proxmox."""
    services = [
        {"id": "api", "label": "API", "status": "ok", "detail": "Richiesta health ricevuta."},
    ]

    try:
        conn.execute(select(1)).scalar_one()
    except SQLAlchemyError as exc:
        services.append({"id": "database", "label": "Database", "status": "error", "detail": str(exc)})
    else:
        services.append(
            {"id": "database", "label": "Database", "status": "ok", "detail": "Connessione disponibile."}
        )

    try:
        fwdd_client.call("verify_state", scope="full")
    except FwddClientError as ferr:
        services.append({"id": "fwdd", "label": "fwdd", "status": "error", "detail": ferr.message})
    else:
        services.append(
            {"id": "fwdd", "label": "fwdd", "status": "ok", "detail": "Socket e verifica nftables disponibili."}
        )

    try:
        proxmox = pve_client.check_health()
    except (httpx.HTTPError, ValueError) as exc:
        services.append({"id": "proxmox", "label": "Proxmox", "status": "error", "detail": str(exc)})
    else:
        if proxmox["mode"] == "mock":
            services.append(
                {"id": "proxmox", "label": "Proxmox", "status": "mock", "detail": "Modalità mock attiva."}
            )
        else:
            services.append(
                {
                    "id": "proxmox",
                    "label": "Proxmox",
                    "status": "ok",
                    "detail": f"API raggiungibile · versione {proxmox['version']}",
                }
            )

    return {"checked_at": utc_now(), "services": services}


@app.post("/api/admin/fwdd/reconcile", tags=["Admin"])
def trigger_full_reconciliation(
    user: CurrentUser = Depends(require_role("ADMIN")),
):
    """Forza la rigenerazione dei CSV per Vector e il `sync_set` globale su fwdd."""
    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)
    summary = fwdd_client.call("sync_set", set_name="allowed_endpoints")
    return {"status": "reconciled", "fwdd_summary": summary}


@app.post("/api/admin/students/{username}/migrate-class", tags=["Admin"])
def migrate_student_class(
    username: str,
    payload: AdminStudentMigrationRequest,
    user: CurrentUser = Depends(require_role("ADMIN")),
    conn: Connection = Depends(get_db_conn),
):
    """
    Sposta uno studente in una nuova classe: revoca le vecchie prenotazioni e la vecchia /29,
    rimuove le triple da nftables e assegna una nuova /29 nella classe di destinazione.
    """
    stu = conn.execute(select(utenti_ad).where(utenti_ad.c.username == username.lower())).fetchone()
    if not stu:
        raise HTTPException(status_code=404, detail=f"Studente {username} non trovato.")

    target_cl = conn.execute(
        select(classi).where(classi.c.codice_classe == payload.target_class_code.upper())
    ).fetchone()
    if not target_cl:
        raise HTTPException(status_code=404, detail=f"Classe {payload.target_class_code} non trovata.")

    # 1. Deprovisiona tutti i container attuali dello studente
    old_cts = conn.execute(
        select(container_studenti.c.vmid).where(container_studenti.c.studente_id == stu.id)
    ).fetchall()
    for ct in old_cts:
        try:
            fwdd_client.call("deprovision_anti_spoofing", vmid=ct.vmid)
        except FwddClientError:
            pass
        conn.execute(delete(container_studenti).where(container_studenti.c.vmid == ct.vmid))

    # 2. Libera la vecchia /29
    conn.execute(
        update(subnet_studenti)
        .where(subnet_studenti.c.studente_id == stu.id)
        .values(studente_id=None, stato="AVAILABLE", assigned_at=None)
    )

    # 3. Aggiorna la classe dello studente e alloca la nuova /29
    conn.execute(update(utenti_ad).where(utenti_ad.c.id == stu.id).values(classe_id=target_cl.id))
    temp_user = CurrentUser(
        id=stu.id,
        username=stu.username,
        display_name=stu.display_name,
        object_guid=stu.object_guid,
        ruolo="STUDENT",
        classe_id=target_cl.id,
        codice_classe=target_cl.codice_classe,
        vnet_name=target_cl.vnet_name,
        max_containers=target_cl.max_containers_per_student,
    )
    new_sub = ensure_student_subnet(conn, temp_user)
    conn.commit()

    export_vector_enrichment_csvs(engine, VECTOR_EXPORT_DIR)
    return {
        "username": stu.username,
        "new_class_code": target_cl.codice_classe,
        "new_vnet": target_cl.vnet_name,
        "new_subnet_29": new_sub.subnet_cidr,
        "new_gateway": new_sub.gateway_ip,
    }


# =====================================================================
# 4. ENDPOINT RESOLVER PER SQUID 3130 SU HYPER-V (/api/v1/resolve)
# =====================================================================


@app.get("/api/v1/resolve", tags=["Squid Resolver"])
def resolve_student_ip_for_squid(
    request: Request,
    ip: str = Query(..., description="Indirizzo IPv4 sorgente visto da Squid sulla porta 3130"),
    authorization: Optional[str] = Header(None),
    conn: Connection = Depends(get_db_conn),
):
    """
    Interrogato dall'external_acl_type di Squid (porta 3130 su Hyper-V).
    Restituisce l'utente AD associato all'IP, la classe, il VMID e i flag di Modalità Verifica
    (inclusa la whitelist dinamica `exam_allowed_domains` configurata dal docente).
    """
    client_host = request.client.host if request.client else ""
    if client_host not in SQUID_ALLOWED_IPS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"IP chiamante {client_host} non autorizzato a interrogare il resolver.",
        )

    expected_header = f"Bearer {SQUID_API_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected_header):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token non valido o mancante.",
        )

    try:
        clean_ip = str(ipaddress.IPv4Address(ip.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Indirizzo IPv4 malformato.") from exc

    stmt = (
        select(
            prenotazioni_ip.c.reserved_ip,
            prenotazioni_ip.c.vmid,
            utenti_ad.c.username,
            utenti_ad.c.display_name,
            utenti_ad.c.ruolo,
            classi.c.codice_classe,
            classi.c.vnet_name,
            subnet_studenti.c.subnet_cidr,
            stato_classi.c.exam_mode,
            stato_classi.c.internet_enabled,
            stato_classi.c.exam_allowed_domains,
        )
        .select_from(
            prenotazioni_ip.join(container_studenti, container_studenti.c.vmid == prenotazioni_ip.c.vmid)
            .join(utenti_ad, utenti_ad.c.id == prenotazioni_ip.c.studente_id)
            .join(classi, classi.c.id == container_studenti.c.classe_id)
            .join(subnet_studenti, subnet_studenti.c.id == prenotazioni_ip.c.subnet_id)
            .join(stato_classi, stato_classi.c.classe_id == classi.c.id)
        )
        .where(
            and_(
                prenotazioni_ip.c.reserved_ip == clean_ip,
                prenotazioni_ip.c.stato_prenotaz == "ACTIVE",
                container_studenti.c.is_enabled == 1,
                utenti_ad.c.is_active == 1,
            )
        )
    )
    row = conn.execute(stmt).fetchone()

    if not row:
        return {
            "found": False,
            "ip": clean_ip,
            "error": "IP_NOT_ACTIVE",
            "ttl_seconds": 5,
        }

    return {
        "found": True,
        "ip": row.reserved_ip,
        "username": row.username,
        "display_name": row.display_name,
        "role": row.ruolo,
        "class_code": row.codice_classe,
        "vnet": row.vnet_name,
        "subnet_29": row.subnet_cidr,
        "vmid": row.vmid,
        "policy_flags": {
            "exam_mode": bool(row.exam_mode),
            "internet_enabled": bool(row.internet_enabled),
            "exam_allowed_domains": json.loads(row.exam_allowed_domains or "[]"),
        },
        "ttl_seconds": 15 if row.exam_mode else 30,
    }
