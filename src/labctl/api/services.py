"""
labctl.api.services

Client Unix Socket per fwdd, integrazione API Proxmox VE e generazione atomica CSV per Vector.
"""

import csv
import json
import logging
import os
import re
import socket
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.engine import Connection, Engine

from labctl.db.config import (
    classi,
    container_studenti,
    prenotazioni_ip,
    subnet_studenti,
    utenti_ad,
)

logger = logging.getLogger(__name__)

RE_NET_HWADDR = re.compile(r"(?:hwaddr|macaddr)=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
RE_NET_BRIDGE = re.compile(r"bridge=(vnet[a-zA-Z0-9]+)")


class FwddClientError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class FwddUnixClient:
    """Client sincrono/thread-safe per comunicare con /run/fwdd/control.sock."""

    def __init__(self, socket_path: str = "/run/fwdd/control.sock", timeout: float = 3.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def call(self, action: str, **payload: Any) -> Dict[str, Any]:
        req = {
            "req_id": str(uuid.uuid4()),
            "action": action,
            **payload,
        }
        raw_req = (json.dumps(req) + "\n").encode("utf-8")

        if not Path(self.socket_path).exists():
            raise FwddClientError(
                "ERR_FWDD_UNAVAILABLE",
                f"Socket fwdd non trovato in {self.socket_path}",
            )

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(raw_req)

                chunks = []
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
                raw_resp = b"".join(chunks).decode("utf-8").strip()
        except OSError as exc:
            raise FwddClientError("ERR_FWDD_SOCKET_IO", f"Errore I/O verso fwdd: {exc}") from exc

        if not raw_resp:
            raise FwddClientError("ERR_FWDD_EMPTY", "Risposta vuota dal demone fwdd")

        resp = json.loads(raw_resp)
        if resp.get("status") != "ok":
            raise FwddClientError(
                resp.get("error_code", "ERR_FWDD_UNKNOWN"),
                resp.get("message", "Errore sconosciuto restituito da fwdd"),
            )
        return resp


class ProxmoxClusterClient:
    """
    Interroga il cluster Proxmox VE 9.2 tramite API Token (con privilegi root@pam per
    impostare l'hookscript sui container LXC creati dagli studenti).
    Modalità mock attivabile con PVE_MOCK_MODE=1 per testare le API senza cluster.
    """

    def __init__(
        self,
        base_url: str,
        token_id: str,
        token_secret: str,
        hookscript_volume: str = "local:snippets/student-net-guard.py",
        verify_ssl: bool = False,
        mock_mode: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
        self.hookscript_volume = hookscript_volume
        self.verify_ssl = verify_ssl
        self.mock_mode = mock_mode

    def inspect_and_prepare_lxc(self, vmid: int, expected_username: str, expected_vnet: str) -> Tuple[str, str, str]:
        """
        1. Individua su quale nodo del cluster si trova il container `vmid`.
        2. Legge la configurazione di `net0` per estrarre MAC (`hwaddr`) e `bridge` (`vnet`).
        3. Verifica che il bridge corrisponda alla VNet della classe dello studente.
        4. Inietta `hookscript: local:snippets/student-net-guard.py` se non presente.
        Ritorna: (node_name, mac_address_lower, hostname)
        """
        if self.mock_mode:
            # Generazione deterministica per ambienti di sviluppo/test locale
            oct5 = (vmid >> 8) & 0xFF
            oct6 = vmid & 0xFF
            fake_mac = f"bc:24:11:00:{oct5:02x}:{oct6:02x}"
            return ("pve-node-01", fake_mac, f"ct-{expected_username}-{vmid}")

        with httpx.Client(
            base_url=self.base_url,
            headers=self.headers,
            verify=self.verify_ssl,
            timeout=5.0,
        ) as client:
            # 1. Cerca il VMID nelle risorse del cluster
            r_res = client.get("/api2/json/cluster/resources", params={"type": "vm"})
            r_res.raise_for_status()
            vm_entry = next(
                (
                    item
                    for item in r_res.json().get("data", [])
                    if item.get("vmid") == vmid and item.get("type") == "lxc"
                ),
                None,
            )
            if not vm_entry:
                raise ValueError(f"Container LXC con VMID {vmid} non trovato nel cluster Proxmox.")

            node = vm_entry["node"]

            # 2. Legge la configurazione del container
            r_cfg = client.get(f"/api2/json/nodes/{node}/lxc/{vmid}/config")
            r_cfg.raise_for_status()
            cfg = r_cfg.json().get("data", {})

            net0 = cfg.get("net0", "")
            if not net0:
                raise ValueError(f"Il container VMID {vmid} non ha l'interfaccia net0 configurata in Proxmox.")

            m_mac = RE_NET_HWADDR.search(net0)
            m_br = RE_NET_BRIDGE.search(net0)
            if not m_mac or not m_br:
                raise ValueError(f"Impossibile estrarre MAC address o bridge da net0 ({net0!r}) per VMID {vmid}.")

            mac_addr = m_mac.group(1).lower()
            bridge_vnet = m_br.group(1).lower()

            if bridge_vnet != expected_vnet.lower():
                raise ValueError(
                    f"Interfaccia net0 collegata a '{bridge_vnet}', ma la tua classe richiede '{expected_vnet}'."
                )

            hostname = cfg.get("hostname", f"ct-{vmid}")

            # 3. Inietta l'hookscript come root@pam se mancante o diverso
            if cfg.get("hookscript") != self.hookscript_volume:
                r_put = client.put(
                    f"/api2/json/nodes/{node}/lxc/{vmid}/config",
                    data={"hookscript": self.hookscript_volume},
                )
                r_put.raise_for_status()

            return node, mac_addr, hostname


def export_vector_enrichment_csvs(engine: Engine, export_dir: str = "/var/lib/labctl/exports"):
    """
    Esporta atomicamente (tramite write su file temporaneo + os.replace) le due tabelle CSV
    lette in RAM da Vector per arricchire i log NFLOG/ulogd2, DNS e Squid:
      1. ip_to_student.csv  (per traffico lecito CONN_NEW, DNS, Squid)
      2. mac_to_student.csv (per allarmi SPOOF_DROP in cui l'IP sorgente è falsificato)
    """
    out_dir = Path(export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stmt = (
        select(
            prenotazioni_ip.c.reserved_ip,
            container_studenti.c.mac_address,
            container_studenti.c.vmid,
            utenti_ad.c.username,
            classi.c.codice_classe,
            subnet_studenti.c.subnet_cidr,
        )
        .select_from(
            prenotazioni_ip.join(container_studenti, container_studenti.c.vmid == prenotazioni_ip.c.vmid)
            .join(utenti_ad, utenti_ad.c.id == prenotazioni_ip.c.studente_id)
            .join(classi, classi.c.id == container_studenti.c.classe_id)
            .join(subnet_studenti, subnet_studenti.c.id == prenotazioni_ip.c.subnet_id)
        )
        .where(
            prenotazioni_ip.c.stato_prenotaz == "ACTIVE",
            container_studenti.c.is_enabled == 1,
            utenti_ad.c.is_active == 1,
        )
    )

    with engine.connect() as conn:
        rows = conn.execute(stmt).fetchall()

    # 1. Scrittura atomica ip_to_student.csv
    ip_csv_target = out_dir / "ip_to_student.csv"
    with tempfile.NamedTemporaryFile("w", dir=str(out_dir), delete=False, encoding="utf-8", newline="") as tmp_ip:
        writer = csv.writer(tmp_ip)
        writer.writerow(["ip", "username", "class_code", "vmid", "subnet_29", "mac_address"])
        for r in rows:
            writer.writerow(
                [
                    r.reserved_ip,
                    r.username,
                    r.codice_classe,
                    r.vmid,
                    r.subnet_cidr,
                    r.mac_address or "",
                ]
            )
        tmp_ip_path = Path(tmp_ip.name)
    os.chmod(tmp_ip_path, 0o644)
    os.replace(tmp_ip_path, ip_csv_target)

    # 2. Scrittura atomica mac_to_student.csv
    mac_csv_target = out_dir / "mac_to_student.csv"
    with tempfile.NamedTemporaryFile("w", dir=str(out_dir), delete=False, encoding="utf-8", newline="") as tmp_mac:
        writer = csv.writer(tmp_mac)
        writer.writerow(["mac_address", "username", "class_code", "vmid", "reserved_ip"])
        for r in rows:
            if r.mac_address:
                writer.writerow(
                    [
                        r.mac_address.lower(),
                        r.username,
                        r.codice_classe,
                        r.vmid,
                        r.reserved_ip,
                    ]
                )
        tmp_mac_path = Path(tmp_mac.name)
    os.chmod(tmp_mac_path, 0o644)
    os.replace(tmp_mac_path, mac_csv_target)
