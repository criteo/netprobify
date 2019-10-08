import pytest
from unittest.mock import patch, Mock
from datetime import timedelta

from netprobify.common import explode_datetime, resolve_hostname
from netprobify.protocol.common.protocols import (
    group_source_address,
    af_to_ip_protocol,
    af_to_icmp,
    af_to_ip_header_fields,
    list_self_ips,
    bpf_filter_protocol_af,
    egress_interface,
)


def test_explode_datetime():
    datetime_examples = ["1d2h3m", "1d3m2h", "2h1d3m", "crappppp1d2h3mcrapppp"]
    for example in datetime_examples:
        assert explode_datetime(example) == timedelta(days=1, hours=2, minutes=3)


@patch("netprobify.common.getaddrinfo")
def test_resolve_hostname(mock_getaddrinfo):
    with pytest.raises(ValueError):
        resolve_hostname("example.com", "krp")

    mock_getaddrinfo.return_value = [(1, 1, 1, "", ("127.0.0.1", 1))]
    assert resolve_hostname("localhost", "ipv4") == "127.0.0.1"

    mock_getaddrinfo.return_value = [(1, 1, 1, "", ("::1", 1))]
    assert resolve_hostname("localhost", "ipv6") == "::1"


def test_group_source_address():
    fake_group = Mock()
    fake_group.src_ipv4 = "127.0.0.1"
    fake_group.src_ipv6 = "::1"

    assert group_source_address(fake_group, "ipv4") == "127.0.0.1"
    assert group_source_address(fake_group, "ipv6") == "::1"


def test_af_to_ip_protocol():
    for af in ("ipv4", "ipv6"):
        ip = af_to_ip_protocol(af)
        assert isinstance(ip, object)

    with pytest.raises(ValueError):
        af_to_ip_protocol("krpv10")


def test_af_to_icmp():
    for af in ("ipv4", "ipv6"):
        icmp = af_to_icmp(af)
        assert isinstance(icmp, object)

    with pytest.raises(ValueError):
        af_to_icmp("krpv10")


def test_af_to_ip_header_fields():
    assert af_to_ip_header_fields("ipv4", "tos") == "tos"
    assert af_to_ip_header_fields("ipv6", "tos") == "tc"
    assert af_to_ip_header_fields("ipv4", "id") == "id"
    assert af_to_ip_header_fields("ipv6", "id") == "fl"


def test_list_self_ips():
    fake_conf = Mock()
    fake_conf.route = Mock()
    fake_conf.route6 = Mock()
    fake_conf.route.routes = [
        (0, 1, 2, 3, "127.0.0.1"),
        (0, 1, 2, 3, "127.0.0.2"),
        (0, 1, 2, 3, "127.0.0.3"),
    ]
    fake_conf.route6.routes = [(0, 1, 2, 3, ["::1"]), (0, 1, 2, 3, ["fe80::cafe"])]

    expecteds = {"ipv4": ["127.0.0.1", "127.0.0.2", "127.0.0.3"], "ipv6": ["::1", "fe80::cafe"]}
    for af, expected in expecteds.items():
        result = list_self_ips(af, fake_conf)
        assert set(result) == set(expected)

    with pytest.raises(ValueError):
        list_self_ips("krpv10", fake_conf)


def test_bpf_filter_protocol_af():
    expected = {"ipv4": "icmp", "ipv6": "icmp6"}
    for af in ("ipv4", "ipv6"):
        bpf = bpf_filter_protocol_af(af, "icmp")
        assert bpf == expected[af]

    with pytest.raises(ValueError):
        bpf_filter_protocol_af("krpv10", "bobby")


def test_egress_interface():
    fake_conf = Mock()
    fake_conf.route = Mock()
    fake_conf.route6 = Mock()
    fake_conf.route.route.return_value = ["lo"]
    fake_conf.route6.route.return_value = ["lo1"]

    assert egress_interface("ipv4", fake_conf, "127.0.0.1") == "lo"
    assert egress_interface("ipv6", fake_conf, "::1") == "lo1"
