import pytest
from sqlalchemy import create_engine

import labctl.fwdd as fwdd
from labctl.fwdd import (
    FwddController,
    FwddError,
    NftablesManager,
    validate_cidr,
    validate_ipv4,
    validate_mac,
    validate_vnet,
)


@pytest.mark.parametrize(
    ("validator", "value", "expected"),
    [
        (validate_vnet, "VNET4A", "vnet4a"),
        (validate_mac, "BC:24:11:22:33:44", "bc:24:11:22:33:44"),
        (validate_ipv4, "10.104.0.18", "10.104.0.18"),
        (validate_cidr, "10.104.0.18/24", "10.104.0.0/24"),
    ],
)
def test_validators_normalize_input(validator, value, expected):
    assert validator(value) == expected


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (validate_vnet, "vnet;reboot"),
        (validate_mac, "bc:24:11:22:33:zz"),
        (validate_ipv4, "256.0.0.1"),
        (validate_cidr, "10.0.0.1/99"),
    ],
)
def test_validators_reject_invalid_input(validator, value):
    with pytest.raises(FwddError, match="non valido"):
        validator(value)


def test_authorization_distinguishes_webapp_and_hook_actions():
    engine = create_engine("sqlite://")
    controller = FwddController(
        engine=engine,
        nft=NftablesManager(),
        allowed_uids={"webapp_only": {100}, "hook_or_webapp": {100, 200}},
    )

    try:
        controller.check_authorization(200, "provision_anti_spoofing")
        with pytest.raises(FwddError) as exc_info:
            controller.check_authorization(200, "set_isolation")

        assert exc_info.value.code == "ERR_UNAUTHORIZED_PEER"
    finally:
        engine.dispose()


def test_network_state_action_is_webapp_only():
    engine = create_engine("sqlite://")
    controller = FwddController(
        engine=engine,
        nft=NftablesManager(),
        allowed_uids={"webapp_only": {100}, "hook_or_webapp": {100, 200}},
    )

    try:
        with pytest.raises(FwddError) as exc_info:
            controller.check_authorization(200, "network_state")
        assert exc_info.value.code == "ERR_UNAUTHORIZED_PEER"
        controller.check_authorization(100, "network_state")
    finally:
        engine.dispose()


def test_conntrack_reader_only_returns_flows_touching_authorized_ips(monkeypatch):
    output = "\n".join(
        [
            "ipv4 2 tcp 6 431999 ESTABLISHED src=10.104.0.10 dst=1.1.1.1 sport=55321 dport=443 src=1.1.1.1 dst=10.104.0.10 sport=443 dport=55321 [ASSURED] mark=0 use=1",
            "ipv4 2 udp 17 28 src=10.104.0.11 dst=192.168.1.1 sport=59988 dport=53 src=192.168.1.1 dst=10.104.0.11 sport=53 dport=59988 mark=0 use=1",
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.20 dst=1.1.1.1 sport=55321 dport=443 src=1.1.1.1 dst=192.168.1.20 sport=443 dport=55321 [ASSURED] mark=0 use=1",
        ]
    )
    manager = NftablesManager()
    monkeypatch.setattr(fwdd, "CONNTRACK_BIN", "/bin/true")
    monkeypatch.setattr(manager, "_run_cmd", lambda command: output)

    connections, total = manager.get_active_connections({"10.104.0.10"})

    assert total == 1
    assert connections == [
        {
            "family": "ipv4",
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "source_ip": "10.104.0.10",
            "destination_ip": "1.1.1.1",
            "reply_source_ip": "1.1.1.1",
            "reply_destination_ip": "10.104.0.10",
            "assured": True,
            "unreplied": False,
            "source_port": 55321,
            "destination_port": 443,
            "reply_source_port": 443,
            "reply_destination_port": 55321,
        }
    ]
