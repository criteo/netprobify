from datetime import timedelta
from unittest import mock

from netprobify.dynamic_inventories import api
from netprobify.settings import DEFAULT_ADDRESS_FAMILY

TARGETS = {
    "target_1": {
        "owner": "owner1@criteo.com",
        "hostname": "www.google.com",
        "type": "TCPsyn",
        "dst_port": 80,
        "ip_payload_size": 1400,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "127.0.0.1",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
    "target_2": {
        "owner": "owner2@criteo.com",
        "hostname": "www.google.com",
        "type": "ICMPping",
        "dst_port": 0,
        "ip_payload_size": 0,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "127.0.0.1",
        "address_family": "ipv4",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
    "target_2_1": {
        "owner": "owner2@criteo.com",
        "hostname": "www.google.com",
        "type": "ICMPping",
        "dst_port": 0,
        "ip_payload_size": 0,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "::1",
        "address_family": "ipv6",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
    "target_3": {
        "owner": "owner1@criteo.com",
        "hostname": "www.bing.com",
        "type": "UDPunreachable",
        "dst_port": 80,
        "ip_payload_size": 1000,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "127.0.0.1",
        "address_family": "ipv4",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
    "target_3_2": {
        "owner": "owner3@criteo.com",
        "hostname": "www.bing.com",
        "type": "UDPunreachable",
        "dst_port": 80,
        "ip_payload_size": 50,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "127.0.0.1",
        "address_family": "ipv4",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
    "target_3_3": {
        "owner": "owner4@criteo.com",
        "hostname": "www.bing.com",
        "type": "UDPunreachable",
        "dst_port": 80,
        "ip_payload_size": 50,
        "state": "in production",
        "alert_level": "no_alert",
        "destination": "127.0.0.1",
        "address_family": "ipv4",
        "nb_packets": 1,
        "timeout": 1,
        "groups": ["simple"],
        "lifetime": str(timedelta(days=1)),
        "creation_date": None,
    },
}

DELETE_REQUEST_1 = {
    "owner": "owner1@criteo.com",
    "hostname": "www.google.com",
    "address_family": "ipv4",
    "type": "TCPsyn",
    "dst_port": 80,
    "ip_payload_size": 1400,
}

DELETE_REQUEST_2 = {
    "owner": "owner0@criteo.com",
    "hostname": "www.google.com",
    "address_family": "ipv4",
    "type": "TCPsyn",
    "dst_port": 80,
    "ip_payload_size": 1400,
}


def test_compare_targets():
    # we assume address_family has been added tp target_1
    target_1 = TARGETS["target_1"]
    target_1["address_family"] = "ipv4"

    # exact same targets
    assert api.compare_targets(target_1, target_1)

    # completely different targets
    assert not api.compare_targets(target_1, TARGETS["target_3"])

    # targets with same destination different type
    assert not api.compare_targets(target_1, TARGETS["target_2"])

    # targets with same destination different payload
    assert not api.compare_targets(TARGETS["target_3"], TARGETS["target_3_2"])

    # same targets with different owners
    assert api.compare_targets(TARGETS["target_3_2"], TARGETS["target_3_3"])

    # same hostname, different address-family
    assert not api.compare_targets(TARGETS["target_2"], TARGETS["target_2_1"])


def test_match_target_attribute():
    # Same values
    assert api.match_target_attribute(TARGETS["target_1"], "hostname", "www.google.com")

    # Different values
    assert not api.match_target_attribute(TARGETS["target_1"], "hostname", "www.google.fr")

    # No value matches
    assert api.match_target_attribute(TARGETS["target_1"], "hostname", None)

    # No attribute matches
    assert api.match_target_attribute(TARGETS["target_1"], None, "toto")
    assert api.match_target_attribute(TARGETS["target_1"], None, None)


def init_api():
    api.targets_list = []
    api.global_module_name = "api"
    api.shared_targets_list = {}
    api.shared_targets_list["api"] = []
    api.groups = ["simple"]


@mock.patch("netprobify.common.resolve_hostname")
def test_add_target(mock_resolve_hostname):
    mock_resolve_hostname.return_value = "127.0.0.1"
    init_api()

    for i, t in enumerate(TARGETS, 0):
        response = api.add_target(TARGETS[t].copy())
        # last target is a duplicate
        if i == len(TARGETS):
            assert response == ("Conflict", 409, {"x-error": "Conflict: already exists"})

    nb_ok = 0

    api.targets_list.reverse()
    for target in api.targets_list:
        target["creation_date"] = None
        target["lifetime"] = str(target["lifetime"])

    for t in TARGETS.values():
        if not t.get("address_family"):
            # we assume address_family has been added by the API
            t["address_family"] = DEFAULT_ADDRESS_FAMILY
        if t in api.targets_list:
            api.targets_list.remove(t)
            nb_ok += 1

    # we expect 4 targets to be defined (1 is a duplicate)
    assert nb_ok == 4


@mock.patch("netprobify.common.resolve_hostname")
def test_get_targets(mock_resolve_hostname):
    def _resolve_hostname(*args, **kwargs):
        if args[1] == "ipv6":
            return "::1"
        return "127.0.0.1"

    mock_resolve_hostname.side_effect = _resolve_hostname
    init_api()

    for t in TARGETS.values():
        api.add_target(t.copy())

    # we get the targets without the duplicate
    all_targets = [t for k, t in TARGETS.items() if k != "target_3_3"]

    # without parameters, all targets are returned
    get_all_targets = api.get_targets()

    for target in get_all_targets:
        target["creation_date"] = None
    assert get_all_targets == all_targets

    # get targets with filters
    target = api.get_targets(owner="owner1@criteo.com")
    target[0]["creation_date"] = None
    target[1]["creation_date"] = None
    assert target == [TARGETS["target_1"], TARGETS["target_3"]]

    target = api.get_targets(hostname="www.google.com")

    target[0]["creation_date"] = None
    target[1]["creation_date"] = None
    target[2]["creation_date"] = None
    assert target[0]["address_family"] == "ipv4"
    assert target[1]["address_family"] == "ipv4"
    assert target[2]["address_family"] == "ipv6"
    assert target == [TARGETS["target_1"], TARGETS["target_2"], TARGETS["target_2_1"]]

    target = api.get_targets(hostname="www.google.com", owner="owner1@criteo.com")
    target[0]["creation_date"] = None
    assert target == [TARGETS["target_1"]]

    target = api.get_targets(hostname="www.google.com", owner="owner1@criteo.com")
    assert target != [TARGETS["target_2"]]


@mock.patch("connexion.request")
def test_remove_target(mock_json):
    init_api()

    for t in TARGETS.values():
        api.add_target(t.copy())

    # valid request
    mock_json.json = DELETE_REQUEST_1
    assert api.remove_target() == ("OK", 200, {"x-error": "OK: the target has been deleted"})

    for t in api.targets_list:
        assert not (
            t["owner"] == "owner1.criteo.com"
            and t["hostname"] == "www.google.com"
            and t["type"] == "TCPsyn"
            and t["dst_port"] == 80
            and t["ip_payload_size"] == 1400
        )

    assert len(api.targets_list) == 4
