#!/usr/bin/env python3
"""
fwdd.py - Lab Network Firewall & Routing Enforcement Daemon
Espone un socket Unix autenticato tramite SO_PEERCRED per sincronizzare in modo
idempotente e atomico i set nftables e le rotte local /32 dei gateway /29 a partire da SQLite.
"""

import argparse
import asyncio
import grp
import ipaddress
import json
import logging
import os
import pwd
import re
import signal
import socket
import stat
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine

from labctl.db.config import DEFAULT_DB_PATH, get_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [fwdd] %(message)s",
)
logger = logging.getLogger("fwdd")

# Costanti nftables
NFT_BIN = "/usr/sbin/nft"
IP_BIN = "/usr/sbin/ip"
CONNTRACK_BIN = "/usr/sbin/conntrack"
NFT_FAMILY = "inet"
NFT_TABLE = "lab_filter"

SET_ALLOWED_ENDPOINTS = "allowed_endpoints"
SET_EXAM_VNETS = "exam_isolated_vnets"
SET_INTRA_COMM_VNETS = "intra_comm_vnets"
SET_ALLOWED_EAST_WEST = "allowed_east_west"

# Regex di validazione rigorosa (Zero-Shell Injection)
RE_VNET = re.compile(r"^vnet[a-z0-9]{1,8}$")
RE_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAX_MSG_BYTES = 65536


class FwddError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def validate_vnet(vnet: str) -> str:
    v = str(vnet).strip().lower()
    if not RE_VNET.match(v):
        raise FwddError("ERR_VALIDATION_FAILED", f"Nome VNet non valido: {vnet!r}")
    return v


def validate_mac(mac: str) -> str:
    m = str(mac).strip().lower()
    if not RE_MAC.match(m):
        raise FwddError("ERR_VALIDATION_FAILED", f"MAC address non valido: {mac!r}")
    return m


def validate_ipv4(ip_str: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(ip_str).strip()))
    except ValueError as exc:
        raise FwddError("ERR_VALIDATION_FAILED", f"IPv4 non valido: {ip_str!r}") from exc


def validate_cidr(cidr_str: str) -> str:
    try:
        return str(ipaddress.IPv4Network(str(cidr_str).strip(), strict=False))
    except ValueError as exc:
        raise FwddError("ERR_VALIDATION_FAILED", f"CIDR non valido: {cidr_str!r}") from exc


class NftablesManager:
    """Interfaccia atomica verso /usr/sbin/nft (-j) e /usr/sbin/ip senza invocazione shell."""

    def __init__(self):
        self._lock = asyncio.Lock()

    def _run_cmd(self, cmd: List[str], stdin_data: Optional[str] = None, check: bool = True) -> str:
        res = subprocess.run(
            cmd,
            input=stdin_data,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if check and res.returncode != 0:
            raise FwddError(
                "ERR_NFT_TRANSACTION",
                f"Comando {cmd[0]} fallito (rc={res.returncode}): {res.stderr.strip()}",
            )
        return res.stdout

    def ensure_gateway_route(self, vnet: str, gateway_ip: str, supernet_cidr: Optional[str] = None):
        """
        Configura sul kernel la rotta scope link per il supernet della classe e la rotta
        puntuale `local <gw_ip>/32 dev <vnet>` per rispondere come gateway della /29 senza alias IP.
        """
        vnet = validate_vnet(vnet)
        gw = validate_ipv4(gateway_ip)

        if supernet_cidr:
            snet = validate_cidr(supernet_cidr)
            self._run_cmd([IP_BIN, "route", "replace", snet, "dev", vnet, "scope", "link"], check=False)

        # Rotta local /32 nella tabella local per il solo IP gateway della /29
        self._run_cmd(
            [IP_BIN, "route", "replace", "local", f"{gw}/32", "dev", vnet, "proto", "static"],
            check=False,
        )

    def flush_conntrack_for_ip_or_subnet(self, cidr_or_ip: str):
        """Tronca le connessioni attive per un IP o una subnet quando isolata/revocata."""
        if not Path(CONNTRACK_BIN).exists():
            return
        self._run_cmd([CONNTRACK_BIN, "-D", "-s", cidr_or_ip], check=False)
        self._run_cmd([CONNTRACK_BIN, "-D", "-d", cidr_or_ip], check=False)

    def get_current_allowed_endpoints(self) -> Set[Tuple[str, str, str]]:
        """
        Legge tramite `nft -j list set inet lab_filter allowed_endpoints` tutte le triple
        (vnet, mac, ip) attualmente caricate nel kernel.
        """
        out = self._run_cmd([NFT_BIN, "-j", "list", "set", NFT_FAMILY, NFT_TABLE, SET_ALLOWED_ENDPOINTS])
        data = json.loads(out)
        triples: Set[Tuple[str, str, str]] = set()

        for item in data.get("nftables", []):
            set_obj = item.get("set")
            if not set_obj:
                continue
            for elem in set_obj.get("elem", []):
                # Un elemento composito in nft -j è rappresentato come {"concat": ["vnet4a", "bc:24:...", "10.104.0.18"]}
                if isinstance(elem, dict) and "concat" in elem:
                    parts = elem["concat"]
                    if len(parts) == 3:
                        triples.add((str(parts[0]).lower(), str(parts[1]).lower(), str(parts[2])))
        return triples

    def get_active_connections(self, endpoint_ips: Set[str], limit: int = 500) -> Tuple[List[Dict[str, Any]], int]:
        """Legge conntrack filtrando i flussi che coinvolgono un endpoint autorizzato."""
        if not Path(CONNTRACK_BIN).is_file():
            raise FwddError("ERR_CONNTRACK_UNAVAILABLE", f"Comando {CONNTRACK_BIN} non disponibile.")

        output = self._run_cmd([CONNTRACK_BIN, "-L", "-o", "extended"])
        connections: List[Dict[str, Any]] = []
        total = 0

        for line in output.splitlines():
            fields = re.findall(r"\b(src|dst|sport|dport)=([^\s]+)", line)
            values: Dict[str, List[str]] = {"src": [], "dst": [], "sport": [], "dport": []}
            for name, value in fields:
                values[name].append(value)

            if len(values["src"]) < 2 or len(values["dst"]) < 2:
                continue
            if not (set(values["src"] + values["dst"]) & endpoint_ips):
                continue

            tokens = line.split()
            if len(tokens) < 3:
                continue
            total += 1
            if len(connections) >= limit:
                continue

            state = tokens[5] if len(tokens) > 5 and "=" not in tokens[5] else "ACTIVE"
            connection: Dict[str, Any] = {
                "family": tokens[0],
                "protocol": tokens[2].upper(),
                "state": state,
                "source_ip": values["src"][0],
                "destination_ip": values["dst"][0],
                "reply_source_ip": values["src"][1],
                "reply_destination_ip": values["dst"][1],
                "assured": "[ASSURED]" in tokens,
                "unreplied": "[UNREPLIED]" in tokens,
            }
            if len(values["sport"]) >= 2 and len(values["dport"]) >= 2:
                connection.update(
                    source_port=int(values["sport"][0]),
                    destination_port=int(values["dport"][0]),
                    reply_source_port=int(values["sport"][1]),
                    reply_destination_port=int(values["dport"][1]),
                )
            connections.append(connection)

        return connections, total

    def get_current_ifname_set(self, set_name: str) -> Set[str]:
        """Legge un set di tipo ifname (es. exam_isolated_vnets o intra_comm_vnets)."""
        out = self._run_cmd([NFT_BIN, "-j", "list", "set", NFT_FAMILY, NFT_TABLE, set_name])
        data = json.loads(out)
        vnets: Set[str] = set()
        for item in data.get("nftables", []):
            set_obj = item.get("set")
            if not set_obj:
                continue
            for elem in set_obj.get("elem", []):
                if isinstance(elem, str):
                    vnets.add(elem.lower())
        return vnets

    def apply_nft_commands(self, nft_commands: List[str]):
        """Applica una lista di comandi nft in una singola transazione atomica via stdin (`nft -f -`)."""
        if not nft_commands:
            return
        batch_script = "\n".join(nft_commands) + "\n"
        self._run_cmd([NFT_BIN, "-f", "-"], stdin_data=batch_script, check=True)


class FwddController:
    """Logica di business e riconciliazione tra SQLite e NftablesManager."""

    def __init__(self, engine: Engine, nft: NftablesManager, allowed_uids: Dict[str, Set[int]]):
        self.engine = engine
        self.nft = nft
        self.allowed_uids = allowed_uids

    def check_authorization(self, peer_uid: int, action: str):
        if peer_uid == 0:
            return  # root è sempre autorizzato
        if action in ("provision_anti_spoofing", "deprovision_anti_spoofing", "verify_state"):
            if peer_uid in self.allowed_uids["hook_or_webapp"]:
                return
        elif peer_uid in self.allowed_uids["webapp_only"]:
            return
        raise FwddError(
            "ERR_UNAUTHORIZED_PEER",
            f"UID {peer_uid} non autorizzato ad eseguire l'azione {action!r}",
        )

    async def handle_request(self, peer_uid: int, req: Dict[str, Any]) -> Dict[str, Any]:
        action = str(req.get("action", "")).strip()
        req_id = str(req.get("req_id", "no-id"))

        self.check_authorization(peer_uid, action)

        async with self.nft._lock:
            if action == "provision_anti_spoofing":
                res = self._op_provision_anti_spoofing(req)
            elif action == "deprovision_anti_spoofing":
                res = self._op_deprovision_anti_spoofing(req)
            elif action == "set_isolation":
                res = self._op_set_isolation(req)
            elif action == "sync_set":
                res = self._op_sync_all()
            elif action == "verify_state":
                res = self._op_verify_state(req)
            elif action == "network_state":
                res = self._op_network_state(req)
            elif action == "add_rule":
                res = self._op_add_comm_rule(req)
            elif action == "remove_rule":
                res = self._op_remove_comm_rule(req)
            else:
                raise FwddError("ERR_VALIDATION_FAILED", f"Azione sconosciuta: {action!r}")

        res["req_id"] = req_id
        res["status"] = "ok"
        return res

    def _op_provision_anti_spoofing(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invocato dall'hookscript `pre-start` di Proxmox o dalla Webapp.
        Verifica che il VMID abbia una prenotazione valida in SQLite e programma:
        1) Rotta local /32 per il gateway della /29 dello studente;
        2) Tripla (vnet, mac, reserved_ip) nel set `@allowed_endpoints`.
        """
        vmid = int(req.get("vmid", 0))
        hook_vnet = validate_vnet(req["vnet"])
        hook_mac = validate_mac(req["mac"])
        now = utc_now_iso()

        with self.engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT
                        c.vmid,
                        c.is_enabled AS ct_enabled,
                        c.vnet_name AS expected_vnet,
                        c.mac_address AS stored_mac,
                        u.username,
                        u.is_active AS user_active,
                        p.reserved_ip,
                        p.stato_prenotaz,
                        s.gateway_ip,
                        cl.supernet_cidr
                    FROM container_studenti c
                    JOIN utenti_ad u ON u.id = c.studente_id
                    JOIN prenotazioni_ip p ON p.vmid = c.vmid
                    JOIN subnet_studenti s ON s.id = p.subnet_id
                    JOIN classi cl ON cl.id = c.classe_id
                    WHERE c.vmid = :vmid
                    """
                ),
                {"vmid": vmid},
            ).fetchone()

            if not row:
                raise FwddError(
                    "ERR_UNREGISTERED_VMID",
                    f"Il container VMID {vmid} non ha alcuna prenotazione IP attiva sulla Webapp.",
                )

            if not row.user_active or not row.ct_enabled or row.stato_prenotaz != "ACTIVE":
                raise FwddError(
                    "ERR_STUDENT_SUSPENDED",
                    f"Studente {row.username} o container VMID {vmid} disabilitato/sospeso.",
                )

            if row.expected_vnet.lower() != hook_vnet:
                raise FwddError(
                    "ERR_VNET_MISMATCH",
                    f"VMID {vmid} è collegato a {hook_vnet}, ma la classe dello studente richiede {row.expected_vnet}.",
                )

            reserved_ip = validate_ipv4(row.reserved_ip)
            gateway_ip = validate_ipv4(row.gateway_ip)

            # Se il MAC salvato al momento della registrazione era vuoto o è cambiato, aggiorniamolo
            if row.stored_mac != hook_mac:
                conn.execute(
                    text("UPDATE container_studenti SET mac_address = :mac, updated_at = :now WHERE vmid = :vmid"),
                    {"mac": hook_mac, "now": now, "vmid": vmid},
                )

            # 1. Assicura la rotta local /32 per il gateway della /29
            self.nft.ensure_gateway_route(hook_vnet, gateway_ip, row.supernet_cidr)

            # 2. Verifica idempotente stato attuale in nftables
            current_triples = self.nft.get_current_allowed_endpoints()
            desired_triple = (hook_vnet, hook_mac, reserved_ip)

            nft_cmds: List[str] = []
            # Rimuovi eventuali vecchie triple orfane con lo stesso IP o lo stesso MAC
            for t_vnet, t_mac, t_ip in current_triples:
                if (t_ip == reserved_ip or t_mac == hook_mac) and (t_vnet, t_mac, t_ip) != desired_triple:
                    nft_cmds.append(
                        f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_ENDPOINTS} "
                        f"{{ {t_vnet} . {t_mac} . {t_ip} }}"
                    )

            changed = False
            if desired_triple not in current_triples or nft_cmds:
                nft_cmds.append(
                    f"add element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_ENDPOINTS} "
                    f"{{ {hook_vnet} . {hook_mac} . {reserved_ip} }}"
                )
                self.nft.apply_nft_commands(nft_cmds)
                changed = True

            # 3. Seconda lettura di verifica (Fail-Closed guarantee)
            post_triples = self.nft.get_current_allowed_endpoints()
            if desired_triple not in post_triples:
                raise FwddError(
                    "ERR_NFT_TRANSACTION",
                    f"Impossibile verificare la presenza di {desired_triple} in nftables dopo l'applicazione.",
                )

            # 4. Aggiorna provisioning_status in SQLite
            conn.execute(
                text(
                    """
                    INSERT INTO provisioning_status (
                        vmid, desired_state, desired_ip, desired_mac, desired_vnet,
                        desired_version, actual_state, actual_ip, actual_mac,
                        applied_version, last_hook_event, last_attempt_at, last_verified_at
                    ) VALUES (
                        :vmid, 'PRESENT', :ip, :mac, :vnet,
                        1, 'SYNCED', :ip, :mac,
                        1, 'pre-start', :now, :now
                    )
                    ON CONFLICT(vmid) DO UPDATE SET
                        desired_state = 'PRESENT',
                        desired_ip = excluded.desired_ip,
                        desired_mac = excluded.desired_mac,
                        desired_vnet = excluded.desired_vnet,
                        actual_state = 'SYNCED',
                        actual_ip = excluded.actual_ip,
                        actual_mac = excluded.actual_mac,
                        applied_version = provisioning_status.desired_version,
                        last_hook_event = 'pre-start',
                        last_error_code = NULL,
                        last_error_msg = NULL,
                        last_attempt_at = :now,
                        last_verified_at = :now
                    """
                ),
                {"vmid": vmid, "ip": reserved_ip, "mac": hook_mac, "vnet": hook_vnet, "now": now},
            )

        logger.info(
            "Provisioning OK per VMID=%d (user=%s): %s . %s . %s (changed=%s)",
            vmid,
            row.username,
            hook_vnet,
            hook_mac,
            reserved_ip,
            changed,
        )
        return {
            "vmid": vmid,
            "username": row.username,
            "vnet": hook_vnet,
            "mac": hook_mac,
            "ip": reserved_ip,
            "gateway": gateway_ip,
            "changed": changed,
            "state": "SYNCED",
        }

    def _op_deprovision_anti_spoofing(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Rimuove un VMID dal set @allowed_endpoints (es. al post-stop o revoca prenotazione)."""
        vmid = int(req.get("vmid", 0))
        now = utc_now_iso()
        with self.engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT c.vnet_name, c.mac_address, p.reserved_ip
                    FROM container_studenti c
                    LEFT JOIN prenotazioni_ip p ON p.vmid = c.vmid
                    WHERE c.vmid = :vmid
                    """
                ),
                {"vmid": vmid},
            ).fetchone()

            current_triples = self.nft.get_current_allowed_endpoints()
            nft_cmds: List[str] = []
            if row and row.reserved_ip:
                for t_vnet, t_mac, t_ip in current_triples:
                    if t_ip == row.reserved_ip or (row.mac_address and t_mac == row.mac_address.lower()):
                        nft_cmds.append(
                            f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_ENDPOINTS} "
                            f"{{ {t_vnet} . {t_mac} . {t_ip} }}"
                        )
                self.nft.apply_nft_commands(nft_cmds)
                self.nft.flush_conntrack_for_ip_or_subnet(row.reserved_ip)

            conn.execute(
                text(
                    """
                    UPDATE provisioning_status
                    SET actual_state = 'ABSENT', last_hook_event = 'post-stop', last_verified_at = :now
                    WHERE vmid = :vmid
                    """
                ),
                {"vmid": vmid, "now": now},
            )
        return {"vmid": vmid, "removed": bool(nft_cmds)}

    def _op_set_isolation(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Attiva/disattiva la Modalità Verifica e la comunicazione Intra-Classe per una VNet."""
        vnet = validate_vnet(req["vnet"])
        exam_mode = bool(req.get("exam_mode", False))
        intra_comm = bool(req.get("intra_class_comm", False))
        now = utc_now_iso()

        current_exam = self.nft.get_current_ifname_set(SET_EXAM_VNETS)
        current_intra = self.nft.get_current_ifname_set(SET_INTRA_COMM_VNETS)

        cmds: List[str] = []
        if exam_mode and vnet not in current_exam:
            cmds.append(f"add element {NFT_FAMILY} {NFT_TABLE} {SET_EXAM_VNETS} {{ {vnet} }}")
        elif not exam_mode and vnet in current_exam:
            cmds.append(f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_EXAM_VNETS} {{ {vnet} }}")

        # In modalità verifica la comunicazione intra-classe viene sempre spenta
        effective_intra = False if exam_mode else intra_comm
        if effective_intra and vnet not in current_intra:
            cmds.append(f"add element {NFT_FAMILY} {NFT_TABLE} {SET_INTRA_COMM_VNETS} {{ {vnet} }}")
        elif not effective_intra and vnet in current_intra:
            cmds.append(f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_INTRA_COMM_VNETS} {{ {vnet} }}")

        self.nft.apply_nft_commands(cmds)

        with self.engine.begin() as conn:
            cl = conn.execute(
                text("SELECT id, supernet_cidr FROM classi WHERE vnet_name = :vnet"),
                {"vnet": vnet},
            ).fetchone()
            if cl:
                if exam_mode:
                    # Tronca istantaneamente tutte le connessioni attive della classe (SSH, nc, ecc.)
                    self.nft.flush_conntrack_for_ip_or_subnet(cl.supernet_cidr)
                conn.execute(
                    text(
                        """
                        UPDATE stato_classi
                        SET exam_mode = :exam,
                            intra_class_comm = :intra,
                            applied_config_version = desired_config_version,
                            sync_status = 'SYNCED',
                            updated_at = :now
                        WHERE classe_id = :cid
                        """
                    ),
                    {"exam": int(exam_mode), "intra": int(effective_intra), "now": now, "cid": cl.id},
                )

        logger.info("Isolamento aggiornato su %s: exam_mode=%s, intra_comm=%s", vnet, exam_mode, effective_intra)
        return {"vnet": vnet, "exam_mode": exam_mode, "intra_class_comm": effective_intra}

    def _op_add_comm_rule(self, req: Dict[str, Any]) -> Dict[str, Any]:
        src = validate_cidr(req["src_cidr"])
        dst = validate_cidr(req["dst_cidr"])
        bidir = bool(req.get("bidirectional", True))
        cmds = [f"add element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_EAST_WEST} {{ {src} . {dst} }}"]
        if bidir:
            cmds.append(f"add element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_EAST_WEST} {{ {dst} . {src} }}")
        self.nft.apply_nft_commands(cmds)
        return {"src_cidr": src, "dst_cidr": dst, "bidirectional": bidir}

    def _op_remove_comm_rule(self, req: Dict[str, Any]) -> Dict[str, Any]:
        src = validate_cidr(req["src_cidr"])
        dst = validate_cidr(req["dst_cidr"])
        bidir = bool(req.get("bidirectional", True))
        cmds = [f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_EAST_WEST} {{ {src} . {dst} }}"]
        if bidir:
            cmds.append(f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_EAST_WEST} {{ {dst} . {src} }}")
        self.nft.apply_nft_commands(cmds)
        self.nft.flush_conntrack_for_ip_or_subnet(src)
        return {"src_cidr": src, "dst_cidr": dst, "removed": True}

    def _op_sync_all(self) -> Dict[str, Any]:
        """
        Riconciliazione completa e auto-riparante tra SQLite, rotte kernel `local /32`
        e set nftables (`@allowed_endpoints`, `@exam_isolated_vnets`, `@intra_comm_vnets`).
        """
        now = utc_now_iso()
        with self.engine.begin() as conn:
            # 1. Configura le rotte per tutte le classi e per tutti i gateway /29
            sub_rows = conn.execute(
                text(
                    """
                    SELECT cl.vnet_name, cl.supernet_cidr, s.gateway_ip
                    FROM subnet_studenti s
                    JOIN classi cl ON cl.id = s.classe_id
                    """
                )
            ).fetchall()
            seen_supernets: Set[str] = set()
            for r in sub_rows:
                snet = r.supernet_cidr if r.vnet_name not in seen_supernets else None
                self.nft.ensure_gateway_route(r.vnet_name, r.gateway_ip, snet)
                seen_supernets.add(r.vnet_name)

            # 2. Calcola il set desiderato per @allowed_endpoints
            active_rows = conn.execute(
                text(
                    """
                    SELECT c.vmid, c.vnet_name, c.mac_address, p.reserved_ip
                    FROM container_studenti c
                    JOIN utenti_ad u ON u.id = c.studente_id
                    JOIN prenotazioni_ip p ON p.vmid = c.vmid
                    WHERE c.is_enabled = 1
                      AND u.is_active = 1
                      AND p.stato_prenotaz = 'ACTIVE'
                      AND c.mac_address IS NOT NULL
                    """
                )
            ).fetchall()

            desired_triples: Set[Tuple[str, str, str]] = set()
            for r in active_rows:
                desired_triples.add((r.vnet_name.lower(), r.mac_address.lower(), r.reserved_ip))

            current_triples = self.nft.get_current_allowed_endpoints()
            to_add = desired_triples - current_triples
            to_remove = current_triples - desired_triples

            cmds: List[str] = []
            for vnet, mac, ip in to_remove:
                cmds.append(
                    f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_ENDPOINTS} {{ {vnet} . {mac} . {ip} }}"
                )
            for vnet, mac, ip in to_add:
                cmds.append(
                    f"add element {NFT_FAMILY} {NFT_TABLE} {SET_ALLOWED_ENDPOINTS} {{ {vnet} . {mac} . {ip} }}"
                )

            # 3. Sincronizza stato classi (Exam Mode & Intra-Class Comm)
            class_rows = conn.execute(
                text(
                    """
                    SELECT cl.id, cl.vnet_name, sc.exam_mode, sc.intra_class_comm
                    FROM classi cl
                    JOIN stato_classi sc ON sc.classe_id = cl.id
                    """
                )
            ).fetchall()

            desired_exam = {r.vnet_name.lower() for r in class_rows if r.exam_mode == 1}
            desired_intra = {
                r.vnet_name.lower() for r in class_rows if r.intra_class_comm == 1 and r.exam_mode == 0
            }

            curr_exam = self.nft.get_current_ifname_set(SET_EXAM_VNETS)
            curr_intra = self.nft.get_current_ifname_set(SET_INTRA_COMM_VNETS)

            for v in curr_exam - desired_exam:
                cmds.append(f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_EXAM_VNETS} {{ {v} }}")
            for v in desired_exam - curr_exam:
                cmds.append(f"add element {NFT_FAMILY} {NFT_TABLE} {SET_EXAM_VNETS} {{ {v} }}")

            for v in curr_intra - desired_intra:
                cmds.append(f"delete element {NFT_FAMILY} {NFT_TABLE} {SET_INTRA_COMM_VNETS} {{ {v} }}")
            for v in desired_intra - curr_intra:
                cmds.append(f"add element {NFT_FAMILY} {NFT_TABLE} {SET_INTRA_COMM_VNETS} {{ {v} }}")

            self.nft.apply_nft_commands(cmds)

            # Aggiorna stato sincronizzazione in SQLite
            for r in active_rows:
                conn.execute(
                    text(
                        """
                        UPDATE provisioning_status
                        SET actual_state = 'SYNCED',
                            actual_ip = :ip,
                            actual_mac = :mac,
                            applied_version = desired_version,
                            last_verified_at = :now
                        WHERE vmid = :vmid
                        """
                    ),
                    {"vmid": r.vmid, "ip": r.reserved_ip, "mac": r.mac_address.lower(), "now": now},
                )

        return {
            "added_endpoints": len(to_add),
            "removed_endpoints": len(to_remove),
            "total_active_endpoints": len(desired_triples),
            "exam_vnets": sorted(list(desired_exam)),
        }

    def _op_verify_state(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Verifica in sola lettura se lo stato di nftables coincide con SQLite."""
        current_triples = self.nft.get_current_allowed_endpoints()
        with self.engine.begin() as conn:
            active_rows = conn.execute(
                text(
                    """
                    SELECT c.vmid, c.vnet_name, c.mac_address, p.reserved_ip
                    FROM container_studenti c
                    JOIN utenti_ad u ON u.id = c.studente_id
                    JOIN prenotazioni_ip p ON p.vmid = c.vmid
                    WHERE c.is_enabled = 1
                      AND u.is_active = 1
                      AND p.stato_prenotaz = 'ACTIVE'
                      AND c.mac_address IS NOT NULL
                    """
                )
            ).fetchall()

        drifted = []
        for r in active_rows:
            triple = (r.vnet_name.lower(), r.mac_address.lower(), r.reserved_ip)
            if triple not in current_triples:
                drifted.append({"vmid": r.vmid, "expected": triple})

        return {"in_sync": len(drifted) == 0, "drifted_items": drifted}

    def _op_network_state(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Espone endpoint autorizzati e conntrack corrente, limitato agli IP autorizzati."""
        endpoints = self.nft.get_current_allowed_endpoints()
        endpoint_ips = {ip for _, _, ip in endpoints}
        connections, total_connections = self.nft.get_active_connections(endpoint_ips)

        return {
            "authorized_endpoints": [
                {"vnet": vnet, "mac_address": mac, "ip": ip}
                for vnet, mac, ip in sorted(endpoints)
            ],
            "authorized_endpoint_count": len(endpoints),
            "active_connections": connections,
            "active_connection_count": total_connections,
            "connections_truncated": total_connections > len(connections),
            "observed_at": utc_now_iso(),
        }


def get_peer_credentials(sock: socket.socket) -> Tuple[int, int, int]:
    """Estrae (pid, uid, gid) del processo client tramite getsockopt(SO_PEERCRED)."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return pid, uid, gid


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    controller: FwddController,
):
    sock: socket.socket = writer.get_extra_info("socket")
    try:
        pid, uid, gid = get_peer_credentials(sock)
        raw_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
        if not raw_line:
            return
        if len(raw_line) > MAX_MSG_BYTES:
            raise FwddError("ERR_VALIDATION_FAILED", "Payload JSON eccede 64 KB")

        req = json.loads(raw_line.decode("utf-8"))
        response = await controller.handle_request(uid, req)
    except FwddError as ferr:
        logger.warning("Errore gestito (uid=%s): [%s] %s", uid if "uid" in locals() else "?", ferr.code, ferr.message)
        response = {
            "req_id": req.get("req_id", "unknown") if "req" in locals() and isinstance(req, dict) else "unknown",
            "status": "error",
            "error_code": ferr.code,
            "message": ferr.message,
        }
    except Exception as exc:
        logger.exception("Errore imprevisto durante la gestione della richiesta socket")
        response = {
            "status": "error",
            "error_code": "ERR_INTERNAL",
            "message": str(exc),
        }

    writer.write((json.dumps(response) + "\n").encode("utf-8"))
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def periodic_reconcile_loop(controller: FwddController, interval_sec: int = 60):
    """Loop in background che ripara automaticamente qualsiasi drift su nftables o rotte."""
    while True:
        await asyncio.sleep(interval_sec)
        try:
            async with controller.nft._lock:
                summary = controller._op_sync_all()
            if summary["added_endpoints"] > 0 or summary["removed_endpoints"] > 0:
                logger.info("Auto-guarigione periodica completata: %s", summary)
        except Exception:
            logger.exception("Errore durante il loop di riconciliazione periodica")


def resolve_allowed_uids(webapp_user: str, hook_user: str) -> Dict[str, Set[int]]:
    webapp_uids: Set[int] = {0}
    hook_uids: Set[int] = {0}
    try:
        webapp_uids.add(pwd.getpwnam(webapp_user).pw_uid)
    except KeyError:
        logger.warning("Utente webapp %r non trovato nel sistema, solo root potrà usare le API webapp.", webapp_user)

    try:
        hook_uids.add(pwd.getpwnam(hook_user).pw_uid)
    except KeyError:
        logger.warning("Utente hook %r non trovato nel sistema.", hook_user)

    return {
        "webapp_only": webapp_uids,
        "hook_or_webapp": webapp_uids | hook_uids,
    }


async def main_async(args):
    engine = get_engine(args.db)
    nft = NftablesManager()
    allowed_uids = resolve_allowed_uids(args.webapp_user, args.hook_user)
    controller = FwddController(engine, nft, allowed_uids)

    # Bootstrap iniziale: sincronizza tutte le rotte local /32 e tutti i set nftables da SQLite
    logger.info("Bootstrap iniziale: sincronizzazione rotte /29 e set nftables da SQLite...")
    async with nft._lock:
        boot_summary = controller._op_sync_all()
    logger.info("Bootstrap completato: %s", boot_summary)

    sock_path = Path(args.socket)
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()

    server = await asyncio.start_unix_server(
        lambda r, w: handle_client(r, w, controller),
        path=str(sock_path),
    )

    # Imposta gruppo e permessi 0660 sul socket Unix
    os.chmod(sock_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    try:
        gid = grp.getgrnam(args.socket_group).gr_gid
        os.chown(sock_path, 0, gid)
    except KeyError:
        logger.warning("Gruppo %r non trovato, permessi socket lasciati a root:root.", args.socket_group)

    logger.info("fwdd in ascolto su %s (PID=%d)", sock_path, os.getpid())

    reconcile_task = asyncio.create_task(periodic_reconcile_loop(controller, args.reconcile_interval))

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()
    logger.info("Arresto di fwdd in corso...")
    reconcile_task.cancel()
    server.close()
    await server.wait_closed()
    if sock_path.exists():
        sock_path.unlink()


def main():
    parser = argparse.ArgumentParser(description="fwdd - Lab Network Firewall Daemon")
    parser.add_argument("--socket", default="/run/fwdd/control.sock", help="Percorso del socket Unix")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Percorso del DB SQLite")
    parser.add_argument("--webapp-user", default="labwebapp", help="Utente Unix della webapp")
    parser.add_argument("--hook-user", default="pvehook", help="Utente Unix per gli hookscript PVE")
    parser.add_argument("--socket-group", default="fwdd-access", help="Gruppo Unix proprietario del socket")
    parser.add_argument("--reconcile-interval", type=int, default=60, help="Intervallo riconciliazione (s)")
    args = parser.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()