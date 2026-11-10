import pytest

from labctl.api import services
from labctl.api.services import ProxmoxClusterClient


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return {"data": self._data}


class FakeProxmoxHttpClient:
    def __init__(self, pool_id, config):
        self.pool_id = pool_id
        self.config = config
        self.config_requested = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def get(self, path, params=None):
        if path == "/api2/json/cluster/resources":
            return FakeResponse(
                [{"vmid": 10401, "type": "lxc", "node": "pve-01", "pool": self.pool_id}]
            )
        if path == "/api2/json/nodes/pve-01/lxc/10401/config":
            self.config_requested = True
            return FakeResponse(self.config)
        raise AssertionError(f"Unexpected Proxmox API path: {path}")


def build_config(**network_overrides):
    config = {
        "net0": "name=eth0,bridge=vnet4a,hwaddr=BC:24:11:00:28:91",
        "hostname": "student-ct",
        "hookscript": "local:snippets/student-net-guard.py",
    }
    config.update(network_overrides)
    return config


def build_client(monkeypatch, fake_http):
    monkeypatch.setattr(services.httpx, "Client", lambda **kwargs: fake_http)
    return ProxmoxClusterClient(
        base_url="https://pve.example.test:8006",
        token_id="labctl@pam!api",
        token_secret="test-secret",
        mock_mode=False,
    )


def test_inspect_lxc_requires_membership_in_students_pool(monkeypatch):
    fake_http = FakeProxmoxHttpClient("p-87654321", build_config())
    client = build_client(monkeypatch, fake_http)

    with pytest.raises(ValueError, match="non al tuo pool p-12345678"):
        client.inspect_and_prepare_lxc(
            vmid=10401,
            expected_username="student",
            expected_vnet="vnet4a",
            expected_pool_id="p-12345678",
        )

    assert fake_http.config_requested is False


def test_inspect_lxc_rejects_additional_network_interfaces(monkeypatch):
    fake_http = FakeProxmoxHttpClient(
        "p-12345678",
        build_config(net1="name=eth1,bridge=vnet4a,hwaddr=BC:24:11:00:28:92"),
    )
    client = build_client(monkeypatch, fake_http)

    with pytest.raises(ValueError, match="una sola interfaccia"):
        client.inspect_and_prepare_lxc(
            vmid=10401,
            expected_username="student",
            expected_vnet="vnet4a",
            expected_pool_id="p-12345678",
        )


def test_inspect_lxc_returns_mac_after_pool_and_network_validation(monkeypatch):
    fake_http = FakeProxmoxHttpClient("p-12345678", build_config())
    client = build_client(monkeypatch, fake_http)

    assert client.inspect_and_prepare_lxc(
        vmid=10401,
        expected_username="student",
        expected_vnet="vnet4a",
        expected_pool_id="p-12345678",
    ) == ("pve-01", "bc:24:11:00:28:91", "student-ct")


def test_inspect_lxc_rejects_invalid_expected_pool_without_proxmox_request(monkeypatch):
    def unexpected_client(**kwargs):
        raise AssertionError("Proxmox must not be contacted for an invalid pool ID.")

    monkeypatch.setattr(services.httpx, "Client", unexpected_client)
    client = ProxmoxClusterClient(
        base_url="https://pve.example.test:8006",
        token_id="labctl@pam!api",
        token_secret="test-secret",
        mock_mode=False,
    )

    with pytest.raises(ValueError, match="Pool Proxmox atteso non valido"):
        client.inspect_and_prepare_lxc(
            vmid=10401,
            expected_username="student",
            expected_vnet="vnet4a",
            expected_pool_id="p-not-a-uid",
        )
