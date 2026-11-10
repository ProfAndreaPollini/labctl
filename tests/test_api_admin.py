import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, insert, select, update

from labctl.api import app as api
from labctl.db.config import (
    classi,
    container_studenti,
    metadata,
    prenotazioni_ip,
    provisioning_status,
    subnet_studenti,
    utenti_ad,
)
from labctl.api.services import FwddClientError


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'admin-test.db'}")
    metadata.create_all(test_engine)

    with test_engine.begin() as conn:
        class_id = conn.execute(
            insert(classi).values(
                codice_classe="4A-INF",
                ad_group_dn="CN=4A-INF",
                vnet_name="vnet4a",
                supernet_cidr="10.104.0.0/24",
                max_containers_per_student=2,
            )
        ).inserted_primary_key[0]
        admin_id = conn.execute(
            insert(utenti_ad).values(
                username="admin",
                object_guid="admin-guid",
                display_name="Test Admin",
                ruolo="ADMIN",
            )
        ).inserted_primary_key[0]
        student_id = conn.execute(
            insert(utenti_ad).values(
                username="student",
                object_guid="12345678",
                display_name="Test Student",
                ruolo="STUDENT",
                classe_id=class_id,
            )
        ).inserted_primary_key[0]
        subnet_id = conn.execute(
            insert(subnet_studenti).values(
                classe_id=class_id,
                studente_id=student_id,
                subnet_cidr="10.104.0.8/29",
                network_ip="10.104.0.8",
                gateway_ip="10.104.0.9",
                first_usable_ip="10.104.0.10",
                last_usable_ip="10.104.0.14",
                broadcast_ip="10.104.0.15",
                stato="ASSIGNED",
            )
        ).inserted_primary_key[0]
        conn.execute(
            insert(subnet_studenti).values(
                classe_id=class_id,
                studente_id=None,
                subnet_cidr="10.104.0.16/29",
                network_ip="10.104.0.16",
                gateway_ip="10.104.0.17",
                first_usable_ip="10.104.0.18",
                last_usable_ip="10.104.0.22",
                broadcast_ip="10.104.0.23",
                stato="AVAILABLE",
            )
        )
        conn.execute(
            insert(container_studenti).values(
                vmid=10401,
                studente_id=student_id,
                classe_id=class_id,
                hostname_hint="student-lab",
                pve_node="pve-01",
                mac_address="bc:24:11:00:28:91",
                vnet_name="vnet4a",
            )
        )
        conn.execute(
            insert(prenotazioni_ip).values(
                subnet_id=subnet_id,
                studente_id=student_id,
                vmid=10401,
                reserved_ip="10.104.0.10",
                stato_prenotaz="ACTIVE",
            )
        )
        conn.execute(
            insert(provisioning_status).values(
                vmid=10401,
                desired_state="PRESENT",
                desired_ip="10.104.0.10",
                desired_vnet="vnet4a",
                actual_state="SYNCED",
            )
        )

    def override_db():
        with test_engine.begin() as conn:
            yield conn

    monkeypatch.setitem(api.app.dependency_overrides, api.get_db_conn, override_db)
    monkeypatch.setattr(api, "engine", test_engine)
    monkeypatch.setattr(api, "export_vector_enrichment_csvs", lambda *args: None)
    client = TestClient(api.app)
    yield client, test_engine
    test_engine.dispose()


def test_admin_can_list_and_search_registered_containers(admin_client):
    client, _ = admin_client
    headers = {"X-Remote-User": "admin"}

    response = client.get("/api/admin/containers", headers=headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["vmid"] == 10401
    assert response.json()["items"][0]["username"] == "student"

    search_response = client.get("/api/admin/containers?search=student-lab", headers=headers)
    assert search_response.status_code == 200
    assert search_response.json()["total"] == 1


def test_container_listing_requires_admin(admin_client):
    client, test_engine = admin_client
    with test_engine.begin() as conn:
        conn.execute(
            insert(utenti_ad).values(
                username="teacher",
                object_guid="teacher-guid",
                display_name="Test Teacher",
                ruolo="TEACHER",
            )
        )

    response = client.get("/api/admin/containers", headers={"X-Remote-User": "teacher"})
    assert response.status_code == 403


def test_first_login_parses_pipe_delimited_authentik_groups(admin_client):
    _, test_engine = admin_client
    with test_engine.begin() as conn:
        user = api.get_current_user(
            conn,
            x_remote_user="new-student",
            x_remote_name=None,
            x_remote_groups="Other|LAB_STUDENT|4A-INF",
            x_remote_guid="12345679",
        )

    assert user.ruolo == "STUDENT"
    assert user.codice_classe == "4A-INF"
    assert user.object_guid == "12345679"


def test_first_login_requires_exactly_one_role_group(admin_client):
    _, test_engine = admin_client
    for username, groups in (
        ("no-role", "4A-INF"),
        ("multi-role", "LAB_STUDENT|LAB_ADMIN|4A-INF"),
    ):
        with test_engine.begin() as conn:
            with pytest.raises(api.HTTPException) as exc_info:
                api.get_current_user(
                    conn,
                    x_remote_user=username,
                    x_remote_name=None,
                    x_remote_groups=groups,
                    x_remote_guid="12345680",
                )
        assert exc_info.value.status_code == 403


def test_student_network_returns_assigned_subnet_and_reserved_slots(admin_client):
    client, _ = admin_client

    response = client.get("/api/student/me/network", headers={"X-Remote-User": "student"})

    assert response.status_code == 200
    body = response.json()
    assert body["subnet_29"]["cidr"] == "10.104.0.8/29"
    assert body["subnet_29"]["gateway_ip"] == "10.104.0.9"
    assert body["subnet_29"]["usable_student_ips"] == [
        "10.104.0.10",
        "10.104.0.11",
        "10.104.0.12",
        "10.104.0.13",
        "10.104.0.14",
    ]
    assert body["subnet_29"]["free_student_ips"] == [
        "10.104.0.11",
        "10.104.0.12",
        "10.104.0.13",
        "10.104.0.14",
    ]


def test_first_student_network_login_allocates_first_free_subnet_persistently(admin_client):
    client, test_engine = admin_client
    headers = {
        "X-Remote-User": "new-student",
        "X-Remote-Groups": "LAB_STUDENT|4A-INF",
        "X-Remote-Guid": "12345681",
    }

    first_response = client.get("/api/student/me/network", headers=headers)
    second_response = client.get("/api/student/me/network", headers=headers)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_response.json()["subnet_29"]["cidr"] == "10.104.0.16/29"
    assert second_response.json()["subnet_29"]["cidr"] == "10.104.0.16/29"
    with test_engine.connect() as conn:
        assigned_subnet = conn.execute(
            select(subnet_studenti.c.subnet_cidr)
            .select_from(subnet_studenti.join(utenti_ad, utenti_ad.c.id == subnet_studenti.c.studente_id))
            .where(utenti_ad.c.username == "new-student")
        ).scalar_one()
    assert assigned_subnet == "10.104.0.16/29"


def test_student_reservation_uses_authentik_uid_pool(admin_client, monkeypatch):
    client, _ = admin_client
    inspected = []
    monkeypatch.setattr(
        api.pve_client,
        "inspect_and_prepare_lxc",
        lambda **kwargs: inspected.append(kwargs) or ("pve-01", "bc:24:11:00:28:92", "student-ct"),
    )
    monkeypatch.setattr(api.fwdd_client, "call", lambda action, **payload: {"state": "SYNCED"})

    response = client.post(
        "/api/student/reservations",
        headers={"X-Remote-User": "student"},
        json={"vmid": 10402, "reserved_ip": "10.104.0.11"},
    )

    assert response.status_code == 201
    assert inspected == [
        {
            "vmid": 10402,
            "expected_username": "student",
            "expected_vnet": "vnet4a",
            "expected_pool_id": "p-12345678",
        }
    ]
    assert response.json()["actual_state"] == "SYNCED"


def test_student_reservation_rejects_non_numeric_authentik_uid_before_proxmox(admin_client, monkeypatch):
    client, test_engine = admin_client
    with test_engine.begin() as conn:
        conn.execute(
            update(utenti_ad).where(utenti_ad.c.username == "student").values(object_guid="student-guid")
        )

    def unexpected_inspection(**kwargs):
        raise AssertionError("Proxmox must not be contacted for an invalid Authentik UID.")

    monkeypatch.setattr(api.pve_client, "inspect_and_prepare_lxc", unexpected_inspection)
    response = client.post(
        "/api/student/reservations",
        headers={"X-Remote-User": "student"},
        json={"vmid": 10402, "reserved_ip": "10.104.0.11"},
    )

    assert response.status_code == 403
    assert "8 cifre" in response.json()["detail"]


def test_student_delete_keeps_reservation_when_fwdd_cannot_revoke_it(admin_client, monkeypatch):
    client, test_engine = admin_client

    def reject_revocation(action, **payload):
        raise FwddClientError("ERR_FWDD_UNAVAILABLE", "socket non disponibile")

    monkeypatch.setattr(api.fwdd_client, "call", reject_revocation)
    response = client.delete(
        "/api/student/reservations/10401",
        headers={"X-Remote-User": "student"},
    )

    assert response.status_code == 502
    with test_engine.connect() as conn:
        assert conn.execute(select(container_studenti.c.vmid).where(container_studenti.c.vmid == 10401)).scalar_one()
        assert conn.execute(select(prenotazioni_ip.c.vmid).where(prenotazioni_ip.c.vmid == 10401)).scalar_one()


def test_admin_deletion_deprovisions_before_removing_database_record(admin_client, monkeypatch):
    client, test_engine = admin_client
    calls = []
    monkeypatch.setattr(api.fwdd_client, "call", lambda action, **payload: calls.append((action, payload)) or {})

    response = client.delete("/api/admin/containers/10401", headers={"X-Remote-User": "admin"})

    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "vmid": 10401}
    assert calls == [("deprovision_anti_spoofing", {"vmid": 10401})]
    with test_engine.connect() as conn:
        assert conn.execute(select(container_studenti.c.vmid)).fetchone() is None


def test_admin_deletion_keeps_record_when_fwdd_rejects_revocation(admin_client, monkeypatch):
    client, test_engine = admin_client

    def reject_revocation(action, **payload):
        raise FwddClientError("ERR_NFT_TRANSACTION", "firewall unavailable")

    monkeypatch.setattr(api.fwdd_client, "call", reject_revocation)
    response = client.delete("/api/admin/containers/10401", headers={"X-Remote-User": "admin"})

    assert response.status_code == 502
    with test_engine.connect() as conn:
        assert conn.execute(select(container_studenti.c.vmid)).scalar_one() == 10401


def test_admin_network_state_enriches_authorized_and_active_endpoints(admin_client, monkeypatch):
    client, _ = admin_client
    monkeypatch.setattr(
        api.fwdd_client,
        "call",
        lambda action, **payload: {
            "authorized_endpoints": [
                {"vnet": "vnet4a", "mac_address": "bc:24:11:00:28:91", "ip": "10.104.0.10"}
            ],
            "authorized_endpoint_count": 1,
            "active_connections": [
                {
                    "family": "ipv4",
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "source_ip": "10.104.0.10",
                    "destination_ip": "1.1.1.1",
                    "source_port": 55321,
                    "destination_port": 443,
                    "assured": True,
                    "unreplied": False,
                }
            ],
            "active_connection_count": 1,
            "connections_truncated": False,
            "observed_at": "2026-11-08T19:00:00Z",
        },
    )

    response = client.get("/api/admin/network-state", headers={"X-Remote-User": "admin"})

    assert response.status_code == 200
    body = response.json()
    assert body["authorized_endpoints"][0]["container"]["vmid"] == 10401
    assert body["active_connections"][0]["source_container"]["username"] == "student"
    assert body["active_connections"][0]["destination_container"] is None


def test_admin_system_health_reports_service_statuses(admin_client, monkeypatch):
    client, _ = admin_client
    monkeypatch.setattr(
        api.fwdd_client,
        "call",
        lambda action, **payload: {"in_sync": True, "drifted_items": []},
    )
    monkeypatch.setattr(api.pve_client, "check_health", lambda: {"mode": "live", "version": "9.2"})

    response = client.get("/api/admin/system/health", headers={"X-Remote-User": "admin"})

    assert response.status_code == 200
    body = response.json()
    assert {service["id"]: service["status"] for service in body["services"]} == {
        "api": "ok",
        "database": "ok",
        "fwdd": "ok",
        "proxmox": "ok",
    }
    assert body["services"][-1]["detail"] == "API raggiungibile · versione 9.2"


def test_admin_system_health_reports_unavailable_fwdd(admin_client, monkeypatch):
    client, _ = admin_client

    def reject_fwdd(action, **payload):
        raise FwddClientError("ERR_FWDD_UNAVAILABLE", "Socket fwdd non trovato")

    monkeypatch.setattr(api.fwdd_client, "call", reject_fwdd)
    monkeypatch.setattr(api.pve_client, "check_health", lambda: {"mode": "mock"})

    response = client.get("/api/admin/system/health", headers={"X-Remote-User": "admin"})

    assert response.status_code == 200
    services = {service["id"]: service for service in response.json()["services"]}
    assert services["fwdd"]["status"] == "error"
    assert services["fwdd"]["detail"] == "Socket fwdd non trovato"
    assert services["proxmox"]["status"] == "mock"


def test_admin_provisioning_drift_reports_kernel_and_database_state(admin_client, monkeypatch):
    client, _ = admin_client
    drifted = [{"vmid": 10401, "expected": ["vnet4a", "bc:24:11:00:28:91", "10.104.0.10"]}]
    monkeypatch.setattr(
        api.fwdd_client,
        "call",
        lambda action, **payload: {"in_sync": False, "drifted_items": drifted},
    )

    response = client.get("/api/admin/provisioning/drift", headers={"X-Remote-User": "admin"})

    assert response.status_code == 200
    body = response.json()
    assert body["in_sync"] is False
    assert body["fwdd_in_sync"] is False
    assert body["kernel_drifted_items"] == drifted
    assert body["db_pending_items"] == []
