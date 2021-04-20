import sys
import time
from datetime import datetime, timedelta
from unittest import mock

import pytest

from netprobify.main import NetProbify


def _generate_getaddrinfo_reply(expected_ip_address):
    return [(0, 1, 6, "", (expected_ip_address, 80))]


def test_generator():
    """Test of generator for unique TCP seq."""
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    # testing iteration
    assert netprobify.seq_gen.send(1) == 1
    assert netprobify.seq_gen.send(20) == 21
    assert netprobify.seq_gen.send(2 ** 30) == 2 ** 30 + 21

    # testing counter resetload_conf
    netprobify.instantiate_generator()
    netprobify.first_iter = False
    assert netprobify.seq_gen.send(2 ** 31 + 1) == 0

    netprobify.instantiate_generator()
    netprobify.first_iter = True
    with pytest.raises(Exception):
        netprobify.seq_gen.send(2 ** 31 + 1)


def test_load_target_conf():
    """Test load target conf."""
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    target_tcp = {"type": "TCPsyn", "destination": "test", "dst_port": 8000}
    target_icmp = {"type": "ICMPping", "destination": "test"}
    target_udp = {"type": "UDPunreachable", "destination": "test", "dst_port": 8000}
    target_iperf = {"type": "iperf", "destination": "test", "dst_port": 8000}

    target_fake = {"type": "fake", "destination": "test", "dst_port": 8000}

    netprobify.load_target_conf(target_tcp, "test", None)
    assert len(netprobify.list_targets) == 1

    netprobify.load_target_conf(target_icmp, "test", None)
    assert len(netprobify.list_targets) == 2

    netprobify.load_target_conf(target_udp, "test", None)
    assert len(netprobify.list_targets) == 3

    netprobify.load_target_conf(target_iperf, "test", None)
    assert len(netprobify.list_special_targets) == 1

    netprobify.load_target_conf(target_fake, "test", None)

    # we check we have the right number of targets in the lists
    assert len(netprobify.list_targets) == 3
    assert len(netprobify.list_special_targets) == 1
    assert len(netprobify.list_dynamic_targets) == 0
    assert len(netprobify.list_dynamic_special_targets) == 0


def test_load_conf():
    """Test of configuration loading and group association."""
    ##
    # loading classic configuration file
    ##
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.load_conf()

    # check global variables
    assert netprobify.global_vars == {
        "probe_name": "test",
        "interval": 30,
        "interval_packets": 0,
        "nb_proc": 8,
        "verbose": 0,
        "logging_level": "INFO",
        "prometheus_port": 8000,
        "dns_update_interval": 300,
        "reload_conf_interval": 0,
        "l3_raw_socket": False,
        "percentile": [95, 50],
    }

    # check groups are loaded properly
    netprobify.list_groups.sort(key=lambda group: group.name)
    assert netprobify.list_groups[0].__dict__ == {
        "name": "group1",
        "src_ipv4": "127.0.0.2",
        "src_ipv6": None,
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65000,
        "src_port_z": 65001,
        "ip_payload_size": 1000,
        "dscp": 0,
        "permit_target_auto_register": True,
    }
    assert netprobify.list_groups[1].__dict__ == {
        "name": "group2",
        "src_ipv4": None,
        "src_ipv6": None,
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65100,
        "src_port_z": 65101,
        "ip_payload_size": 1000,
        "dscp": 1,
        "permit_target_auto_register": False,
    }
    assert netprobify.list_groups[2].__dict__ == {
        "name": "group3",
        "src_ipv4": None,
        "src_ipv6": "::1",
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65100,
        "src_port_z": 65101,
        "ip_payload_size": None,
        "dscp": 1,
        "permit_target_auto_register": False,
    }

    # check targets exist
    netprobify.list_targets.sort(key=lambda probe: probe.name)
    assert netprobify.list_targets[0].__dict__ == {
        "active": True,
        "alert_level": "paging",
        "config_ip_payload_size": 1000,
        "config_destination": "127.0.0.0/31",
        "address_family": "ipv4",
        "description": "full_target_conf",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "dst_port": 443,
        "groups": {"group2"},
        "interval": 0,
        "ip_payload_size": 1000,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": True,
        "max_seq": None,
        "min_seq": None,
        "name": "1_full",
        "nb_packets": 1,
        "packets_rst": [],
        "packets": [],
        "state": "in production",
        "proto_payload_size": 980,
        "threshold": {"latency": 0.1, "loss": 0.05},
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[0].time_to_refresh,
        "timeout": 1,
        "lifetime": None,
        "creation_date": None,
    }
    assert netprobify.list_targets[1].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "config_destination": "127.0.1.1",
        "address_family": "ipv4",
        "description": "2_minimal",
        "destination": None,
        "dns_update_interval": 3600,
        "dont_fragment": True,
        "dst_port": 80,
        "groups": {"group1"},
        "interval": 0,
        "ip_payload_size": 20,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": False,
        "max_seq": None,
        "min_seq": None,
        "name": "2_minimal",
        "nb_packets": 1,
        "packets_rst": [],
        "packets": [],
        "state": None,
        "proto_payload_size": 0,
        "threshold": None,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[1].time_to_refresh,
        "timeout": 1,
        "lifetime": None,
        "creation_date": None,
    }
    assert netprobify.list_targets[2].__dict__ == {
        "active": True,
        "alert_level": "paging",
        "config_ip_payload_size": 1000,
        "config_destination": "127.0.0.0/31",
        "address_family": "ipv4",
        "description": "full_target_conf",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "groups": {"group2"},
        "proto_payload_size": 992,
        "interval": 0,
        "ip_payload_size": 1000,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": True,
        "name": "3_full_icmp",
        "nb_packets": 1,
        "packets": [],
        "state": "in production",
        "threshold": {"latency": 0.1, "loss": 0.05},
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[2].time_to_refresh,
        "timeout": 1,
        "lifetime": None,
        "creation_date": None,
    }
    assert netprobify.list_targets[3].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "config_destination": "127.0.1.1",
        "address_family": "ipv4",
        "description": "4_minimal_icmp",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "groups": {"group1"},
        "proto_payload_size": 0,
        "interval": 0,
        "ip_payload_size": 8,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": False,
        "name": "4_minimal_icmp",
        "nb_packets": 1,
        "packets": [],
        "state": None,
        "threshold": None,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[3].time_to_refresh,
        "timeout": 1,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_targets[4].__dict__ == {
        "active": True,
        "alert_level": "paging",
        "config_ip_payload_size": 1000,
        "config_destination": "127.0.0.0/31",
        "address_family": "ipv4",
        "description": "full_target_conf",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "dst_port": 80,
        "groups": {"group2"},
        "interval": 0,
        "ip_payload_size": 1000,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": True,
        "max_seq": None,
        "min_seq": None,
        "name": "5_full_udp",
        "nb_packets": 1,
        "packets": [],
        "state": "in production",
        "threshold": {"latency": 0.1, "loss": 0.05},
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[4].time_to_refresh,
        "timeout": 1,
        "proto_payload_size": 992,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_targets[5].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "config_destination": "127.0.1.1",
        "address_family": "ipv4",
        "description": "6_minimal_udp",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "dst_port": 80,
        "groups": {"group1"},
        "interval": 0,
        "ip_payload_size": 8,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": False,
        "max_seq": None,
        "min_seq": None,
        "name": "6_minimal_udp",
        "nb_packets": 1,
        "packets": [],
        "state": None,
        "threshold": None,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[5].time_to_refresh,
        "timeout": 1,
        "proto_payload_size": 0,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_targets[6].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "config_destination": "127.0.0.1",
        "address_family": "ipv4",
        "description": "9_fake_group",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": True,
        "dst_port": 5000,
        "groups": {"group1"},
        "interval": 0,
        "ip_payload_size": 20,
        "is_dynamic": False,
        "is_special": False,
        "is_subnet": False,
        "max_seq": None,
        "min_seq": None,
        "name": "9_fake_group",
        "nb_packets": 1,
        "packets_rst": [],
        "packets": [],
        "state": None,
        "proto_payload_size": 0,
        "threshold": None,
        "timeout": 30,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_targets[6].time_to_refresh,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_special_targets[0].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "bandwidth": "1M",
        "config_destination": "127.0.0.1",
        "address_family": "ipv4",
        "description": "7_full_iperf",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": None,
        "dst_port": 5000,
        "duration": 30,
        "groups": {"group1"},
        "interval": None,
        "ip_payload_size": None,
        "is_dynamic": False,
        "is_special": True,
        "is_subnet": False,
        "name": "7_full_iperf",
        "nb_packets": None,
        "num_streams": 1,
        "packets": [],
        "proto_payload_size": None,
        "protocol": "-u",
        "state": None,
        "threshold": None,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_special_targets[0].time_to_refresh,
        "timeout": None,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_special_targets[1].__dict__ == {
        "active": True,
        "alert_level": "no_alert",
        "config_ip_payload_size": None,
        "bandwidth": "1M",
        "config_destination": "127.0.0.1",
        "address_family": "ipv4",
        "description": "8_minimal_iperf",
        "destination": None,
        "dns_update_interval": 300,
        "dont_fragment": None,
        "dst_port": 5000,
        "duration": 5,
        "groups": {"group1"},
        "interval": None,
        "ip_payload_size": None,
        "is_dynamic": False,
        "is_special": True,
        "is_subnet": False,
        "name": "8_minimal_iperf",
        "nb_packets": None,
        "num_streams": 1,
        "packets": [],
        "protocol": "-u",
        "proto_payload_size": None,
        "state": None,
        "threshold": None,
        # this one cannot be tested:
        "time_to_refresh": netprobify.list_special_targets[1].time_to_refresh,
        "timeout": None,
        "lifetime": None,
        "creation_date": None,
    }

    ##
    # targets not defined in yaml
    ##
    netprobify = NetProbify("tests/netprobify/config/test_config_no_target.yaml")
    netprobify.load_conf()

    test_global_vars = {
        "probe_name": "test",
        "interval": 30,
        "interval_packets": 0,
        "nb_proc": 8,
        "verbose": 0,
        "logging_level": "INFO",
        "prometheus_port": 8000,
        "dns_update_interval": 300,
        "reload_conf_interval": 0,
        "l3_raw_socket": False,
        "percentile": [95, 50],
    }

    assert netprobify.global_vars == test_global_vars

    # check groups are loaded properly
    netprobify.list_groups.sort(key=lambda group: group.name)
    assert netprobify.list_groups[0].__dict__ == {
        "name": "group1",
        "src_ipv4": "127.0.0.2",
        "src_ipv6": None,
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65000,
        "src_port_z": 65001,
        "ip_payload_size": 1000,
        "dscp": 0,
        "permit_target_auto_register": True,
    }
    assert netprobify.list_groups[1].__dict__ == {
        "name": "group2",
        "src_ipv4": None,
        "src_ipv6": None,
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65100,
        "src_port_z": 65101,
        "ip_payload_size": None,
        "dscp": 1,
        "permit_target_auto_register": False,
    }

    ##
    # test "legacy" group configuration (src_ip)
    ##
    netprobify = NetProbify("tests/netprobify/config/test_config_src_ip.yaml")
    netprobify.load_conf()

    assert netprobify.global_vars == test_global_vars
    assert netprobify.list_groups[0].__dict__ == {
        "name": "group1",
        "src_ipv4": "127.0.0.2",
        "src_ipv6": None,
        "src_subnet_ipv4": None,
        "src_subnet_ipv6": None,
        "src_port_a": 65000,
        "src_port_z": 65001,
        "ip_payload_size": None,
        "dscp": 0,
        "permit_target_auto_register": True,
    }

    ##
    # test address-family auto detection
    ##
    netprobify = NetProbify("tests/netprobify/config/test_config_src_ip.yaml")
    netprobify.load_conf()

    assert netprobify.global_vars == test_global_vars
    for i in range(len(netprobify.list_targets)):
        # check that address_family matches the 4 first char of target description
        af = netprobify.list_targets[i]["description"][:4]
        assert netprobify.list_targets[i]["address_family"] == "ipv{}".format(af)


def check_prometheus_dns_resolution(
    netprobify, probe_name, target_name, address_family, state, changed
):
    """Check Prometheus metrics (by getting global variables from the main module)."""
    assert (
        netprobify.getter("APP_HOST_RESOLUTION")
        .labels(probe_name, target_name, address_family)
        .__dict__["_value"]
        .get()
        == state
    )
    assert (
        netprobify.getter("APP_HOST_RESOLUTION_CHANGE")
        .labels(probe_name, target_name, address_family)
        .__dict__["_value"]
        .get()
        == changed
    )


def test_update_hosts():
    """Test update_hosts."""
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.load_conf()

    netprobify.list_targets.sort(key=lambda target: target.name)
    probe_name = netprobify.global_vars["probe_name"]
    target_name = netprobify.list_targets[1].name
    address_family = netprobify.list_targets[1].address_family

    # get Prometheus metrics before changes
    host_resolution_change = (
        netprobify.getter("APP_HOST_RESOLUTION_CHANGE")
        .labels(probe_name, target_name, address_family)
        .__dict__["_value"]
        .get()
    )

    ##
    # test self target is disabled
    ##
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.0.1")
    ):
        netprobify.update_hosts(True)

    # check attributes
    assert netprobify.list_targets[1].destination == "127.0.0.1"
    assert netprobify.list_targets[1].active is False

    ##
    # test DNS resolution success
    ##
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.1.1")
    ):
        netprobify.update_hosts(True)

    assert netprobify.list_targets[1].destination == "127.0.1.1"
    assert netprobify.list_targets[1].active is True

    check_prometheus_dns_resolution(
        netprobify, probe_name, target_name, address_family, 1, host_resolution_change + 1
    )

    ##
    # test DNS resolution is disabled if the timer is not reached
    ##
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.0.0")
    ):
        netprobify.update_hosts()

    assert netprobify.list_targets[1].destination == "127.0.1.1"
    assert netprobify.list_targets[1].active is True

    ##
    # test DNS resolution is done if the timer is reached
    ##
    netprobify.list_targets[1].time_to_refresh = time.time() - 1
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.0.0")
    ):
        netprobify.update_hosts()

    assert netprobify.list_targets[1].destination == "127.0.0.0"
    assert netprobify.list_targets[1].active is True

    ##
    # test DNS resolution change if forced
    ##
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.0.2")
    ):
        netprobify.update_hosts(True)

    assert netprobify.list_targets[1].destination == "127.0.0.2"
    assert netprobify.list_targets[1].active is True

    check_prometheus_dns_resolution(
        netprobify, probe_name, target_name, address_family, 1, host_resolution_change + 3
    )

    ##
    # test DNS resolution failure
    ##
    with mock.patch("netprobify.common.getaddrinfo", return_value=None):
        netprobify.update_hosts(True)

    assert netprobify.list_targets[1].destination is None
    assert netprobify.list_targets[1].active is False

    check_prometheus_dns_resolution(
        netprobify, probe_name, target_name, address_family, 0, host_resolution_change + 3
    )


def test_get_metrics():
    # initialization
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.load_conf()

    # fake results of probing
    netprobify.result = [
        {
            65100: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65101: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "1_pe01.paris",
            "probing_type": "TCPsyn",
            "groups": {"group2"},
            "destination": "169.254.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            1: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            10: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "2_pe01.paris",
            "probing_type": "ICMPping",
            "groups": {"group2"},
            "destination": "169.254.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            65100: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65101: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "3_pe01.paris",
            "probing_type": "UDPunreachable",
            "address_family": "ipv4",
            "groups": {"group2"},
            "destination": "169.254.0.1",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            "name": "4_pe01.paris",
            "probing_type": "iperf",
            "groups": {"group2"},
            "state": "in production",
            "alert_level": "paging",
            "duration": 10,
            "destination": "169.254.0.1",
            "address_family": "ipv4",
            "bandwidth": 100,
            "loss": 0,
            "sent": 1000,
            "out_of_order": 0,
        },
    ]

    # evaluate metrics and set Prometheus metrics
    netprobify.get_metrics()

    assert ("test", "1_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_SENT"
    ).__dict__["_metrics"]
    assert ("test", "1_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS"
    ).__dict__["_metrics"]
    assert ("test", "1_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]
    assert ("test", "1_pe01.paris", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]
    assert ("test", "1_pe01.paris", "ipv4") in netprobify.getter("TCP_MATCH_ACK_FAIL").__dict__[
        "_metrics"
    ]
    assert ("test", "1_pe01.paris", "ipv4") in netprobify.getter("TCP_PORT_MISTMATCH").__dict__[
        "_metrics"
    ]

    assert ("test", "2_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "ICMP_SENT"
    ).__dict__["_metrics"]
    assert ("test", "2_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "ICMP_LOSS"
    ).__dict__["_metrics"]
    assert ("test", "2_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "ICMP_LOSS_RATIO"
    ).__dict__["_metrics"]
    assert ("test", "2_pe01.paris", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "ICMP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert ("test", "3_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "UDP_UNREACHABLE_SENT"
    ).__dict__["_metrics"]
    assert ("test", "3_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "UDP_UNREACHABLE_LOSS"
    ).__dict__["_metrics"]
    assert ("test", "3_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "UDP_UNREACHABLE_LOSS_RATIO"
    ).__dict__["_metrics"]
    assert ("test", "3_pe01.paris", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "UDP_UNREACHABLE_ROUND_TRIP"
    ).__dict__["_metrics"]
    assert ("test", "3_pe01.paris", "ipv4") in netprobify.getter(
        "UDP_UNREACHABLE_PORT_MISTMATCH"
    ).__dict__["_metrics"]

    assert ("test", "4_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "IPERF_SENT"
    ).__dict__["_metrics"]
    assert ("test", "4_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "IPERF_LOSS"
    ).__dict__["_metrics"]
    assert ("test", "4_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "IPERF_LOSS_RATIO"
    ).__dict__["_metrics"]
    assert ("test", "4_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "IPERF_BANDWIDTH"
    ).__dict__["_metrics"]
    assert ("test", "4_pe01.paris", "ipv4", "in production", "group2") in netprobify.getter(
        "IPERF_OUT_OF_ORDER"
    ).__dict__["_metrics"]


@mock.patch("netprobify.main.os._exit", sys.exit)
def test_signal_handlers():
    """Test signal handler."""
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.reload_request(None, None)

    assert netprobify.reload_conf_needed is True

    with pytest.raises(SystemExit):
        netprobify.stop_request(None, None)


def test_reload_conf():
    """Test configuration reload.

    It also tests clear_metrics.
    """
    # initialization
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.instantiate_generator()
    netprobify.load_conf()
    probe_name = netprobify.global_vars["probe_name"]

    # faking update hosts to have Prometheus metrics set
    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("127.0.0.0")
    ):
        netprobify.update_hosts(True)

    # fake results of probing
    netprobify.result = [
        {
            65100: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65101: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "1_full",
            "probing_type": "TCPsyn",
            "groups": {"group2"},
            "destination": "127.0.0.0/31",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 1000,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            65000: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65001: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "2_minimal",
            "probing_type": "TCPsyn",
            "groups": {"group1"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            1: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "3_full_icmp",
            "probing_type": "ICMPping",
            "groups": {"group2"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 1000,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            0: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "4_minimal_icmp",
            "probing_type": "ICMPping",
            "groups": {"group1"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
    ]

    # evaluate metrics and set Prometheus metrics
    netprobify.get_metrics()

    # check if metrics exist
    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_SENT"
    ).__dict__["_metrics"]
    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "95") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4") in netprobify.getter("APP_HOST_RESOLUTION").__dict__[
        "_metrics"
    ]

    assert (probe_name, "1_full", "ipv4") in netprobify.getter(
        "APP_HOST_RESOLUTION_CHANGE"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "group2") in netprobify.getter("APP_TIME_OOO").__dict__[
        "_metrics"
    ]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "latency",
        "in production",
        "paging",
    ) in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "loss", "in production", "paging") in netprobify.getter(
        "THRESHOLD"
    ).__dict__["_metrics"]

    # reload the configuration with changed target
    netprobify.config_file = "tests/netprobify/config/test_change_config.yaml"
    netprobify.reload_conf()

    # global vars tests
    assert netprobify.global_vars == {
        "probe_name": "test",
        "interval": 30,
        "interval_packets": 0,
        "nb_proc": 8,
        "verbose": 0,
        "logging_level": "INFO",
        "prometheus_port": 8000,
        "dns_update_interval": 300,
        "reload_conf_interval": 0,
        "l3_raw_socket": False,
        "percentile": [50, 95],
    }

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "latency",
        "in production",
        "paging",
    ) not in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "loss",
        "in production",
        "paging",
    ) not in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "latency",
        "in production",
        "no_alert",
    ) in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "loss", "in production", "no_alert") in netprobify.getter(
        "THRESHOLD"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "95") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    # load configuration with error in file
    netprobify.config_file = "tests/netprobify/config/test_wrong_config.yaml"
    netprobify.reload_conf()

    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_SENT"
    ).__dict__["_metrics"]
    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2") in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "50") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "95") in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4") in netprobify.getter("APP_HOST_RESOLUTION").__dict__[
        "_metrics"
    ]

    assert (probe_name, "1_full", "ipv4") in netprobify.getter(
        "APP_HOST_RESOLUTION_CHANGE"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "group2") in netprobify.getter("APP_TIME_OOO").__dict__[
        "_metrics"
    ]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "latency",
        "in production",
        "no_alert",
    ) in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "loss", "in production", "no_alert") in netprobify.getter(
        "THRESHOLD"
    ).__dict__["_metrics"]

    # reload the configuration with deleted targets/groups
    netprobify.config_file = "tests/netprobify/config/test_deletion_config.yaml"
    netprobify.reload_conf()

    # check if metrics exist for removed target
    assert (probe_name, "1_full", "ipv4", "in production", "group2") not in netprobify.getter(
        "TCP_SENT"
    ).__dict__["_metrics"]
    assert (probe_name, "1_full", "ipv4", "in production", "group2") not in netprobify.getter(
        "TCP_LOSS"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2") not in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "50") not in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "in production", "group2", "95") not in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4") not in netprobify.getter("APP_HOST_RESOLUTION").__dict__[
        "_metrics"
    ]

    assert (probe_name, "1_full", "ipv4") not in netprobify.getter(
        "APP_HOST_RESOLUTION_CHANGE"
    ).__dict__["_metrics"]

    assert (probe_name, "1_full", "ipv4", "group2") not in netprobify.getter(
        "APP_TIME_OOO"
    ).__dict__["_metrics"]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "latency",
        "in production",
        "paging",
    ) not in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    assert (
        probe_name,
        "1_full",
        "ipv4",
        "loss",
        "in production",
        "paging",
    ) not in netprobify.getter("THRESHOLD").__dict__["_metrics"]

    # check metrics are removed for removed group
    assert (probe_name, "2_minimal", "ipv4", "", "group1") not in netprobify.getter(
        "TCP_SENT"
    ).__dict__["_metrics"]

    assert (probe_name, "2_minimal", "ipv4", "", "group1") not in netprobify.getter(
        "TCP_LOSS"
    ).__dict__["_metrics"]

    assert (probe_name, "2_minimal", "ipv4", "", "group1") not in netprobify.getter(
        "TCP_LOSS_RATIO"
    ).__dict__["_metrics"]

    assert (probe_name, "2_minimal", "ipv4", "", "group1", "50") not in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "2_minimal", "ipv4", "", "group1", "95") not in netprobify.getter(
        "TCP_ROUND_TRIP"
    ).__dict__["_metrics"]

    assert (probe_name, "2_minimal", "group1", "ipv4") not in netprobify.getter(
        "APP_TIME_OOO"
    ).__dict__["_metrics"]

    # check some metrics exist for removed group
    assert (probe_name, "2_minimal", "ipv4") in netprobify.getter("APP_HOST_RESOLUTION").__dict__[
        "_metrics"
    ]

    assert (probe_name, "2_minimal", "ipv4") in netprobify.getter(
        "APP_HOST_RESOLUTION_CHANGE"
    ).__dict__["_metrics"]

    # check if metrics matches with the new percentile list
    assert (
        probe_name,
        "3_full_icmp",
        "ipv4",
        "in production",
        "group2",
        "50",
    ) in netprobify.getter("ICMP_ROUND_TRIP").__dict__["_metrics"]

    assert (
        probe_name,
        "3_full_icmp",
        "ipv4",
        "in production",
        "group2",
        "95",
    ) not in netprobify.getter("ICMP_ROUND_TRIP").__dict__["_metrics"]

    # reload the configuration with changed probe_name
    netprobify.config_file = "tests/netprobify/config/test_change_name.yaml"
    netprobify.reload_conf()

    # check if metrics matches with the new percentile list
    assert (
        "test",
        "3_full_icmp",
        "ipv4",
        "in production",
        "group2",
        "50",
    ) not in netprobify.getter("ICMP_ROUND_TRIP").__dict__["_metrics"]


def test_get_dynamic_targets():
    """Test get target from dynamic inventory."""
    # initialization
    netprobify = NetProbify("tests/netprobify/config/test_config.yaml")
    netprobify.instantiate_generator()
    netprobify.load_conf()

    netprobify.shared_dynamic_targets = {
        "DCv3Lan": [
            {
                "hostname": "pe01.paris",
                "destination": "169.254.0.1",
                "address_family": "ipv4",
                "type": "TCPsyn",
                "dst_port": 443,
                "nb_packets": 100,
                "ip_payload_size": 0,
                "groups": {"group2"},
                "state": "in production",
                "alert_level": "paging",
                "timeout": 1,
                "lifetime": None,
                "creation_date": None,
            },
            {
                "hostname": "pe02.paris",
                "destination": "169.254.0.1",
                "address_family": "ipv4",
                "type": "TCPsyn",
                "dst_port": 22,
                "nb_packets": 100,
                "ip_payload_size": 0,
                "groups": {"group2"},
                "state": "in production",
                "alert_level": "paging",
                "timeout": 1,
                "lifetime": None,
                "creation_date": None,
            },
            {
                "hostname": "pe02.paris",
                "destination": "169.254.0.1",
                "address_family": "ipv4",
                "type": "iperf",
                "dst_port": 22,
                "groups": {"group2"},
                "lifetime": None,
                "creation_date": None,
            },
            {
                "hostname": "to_expire",
                "destination": "169.254.0.100",
                "address_family": "ipv4",
                "type": "TCPsyn",
                "dst_port": 22,
                "groups": {"group2"},
                "lifetime": timedelta(days=-1),
                "creation_date": datetime.now(),
            },
        ]
    }
    probe_name = netprobify.global_vars["probe_name"]

    netprobify.get_dynamic_targets()

    # assert expired target is not installed
    # (meaning there are only 2 targets in standard list)
    assert len(netprobify.list_dynamic_targets) == 2

    with mock.patch(
        "netprobify.common.getaddrinfo", return_value=_generate_getaddrinfo_reply("169.254.0.1")
    ):
        netprobify.update_hosts()

    # check number of packets
    assert len(netprobify.list_dynamic_targets[0].packets) == 100
    assert len(netprobify.list_dynamic_targets[1].packets) == 100

    assert netprobify.list_dynamic_targets[0].__dict__ == {
        "name": "DCv3Lan_pe01.paris",
        "active": True,
        "config_ip_payload_size": 0,
        "description": "from_DCv3Lan",
        "config_destination": "169.254.0.1",
        "address_family": "ipv4",
        "is_subnet": False,
        "nb_packets": 100,
        "interval": 0,
        "timeout": 1,
        "dst_port": 443,
        "ip_payload_size": 20,
        "threshold": None,
        "state": "in production",
        "is_dynamic": True,
        "groups": {"group2"},
        "alert_level": "paging",
        "destination": "169.254.0.1",
        "dns_update_interval": 300,
        "dont_fragment": True,
        "is_special": False,
        "max_seq": 1083,
        "min_seq": 984,
        "packets": netprobify.list_dynamic_targets[0].packets,
        "packets_rst": netprobify.list_dynamic_targets[0].packets_rst,
        "proto_payload_size": 0,
        "time_to_refresh": netprobify.list_dynamic_targets[0].time_to_refresh,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_dynamic_targets[1].__dict__ == {
        "name": "DCv3Lan_pe02.paris",
        "active": True,
        "config_ip_payload_size": 0,
        "description": "from_DCv3Lan",
        "config_destination": "169.254.0.1",
        "address_family": "ipv4",
        "is_subnet": False,
        "nb_packets": 100,
        "interval": 0,
        "timeout": 1,
        "dst_port": 22,
        "ip_payload_size": 20,
        "threshold": None,
        "state": "in production",
        "is_dynamic": True,
        "groups": {"group2"},
        "alert_level": "paging",
        "destination": "169.254.0.1",
        "dns_update_interval": 300,
        "dont_fragment": True,
        "is_special": False,
        "max_seq": 1183,
        "min_seq": 1084,
        "packets": netprobify.list_dynamic_targets[1].packets,
        "packets_rst": netprobify.list_dynamic_targets[1].packets_rst,
        "proto_payload_size": 0,
        "time_to_refresh": netprobify.list_dynamic_targets[1].time_to_refresh,
        "lifetime": None,
        "creation_date": None,
    }

    assert netprobify.list_dynamic_special_targets[0].__dict__ == {
        "active": True,
        "config_ip_payload_size": None,
        "alert_level": "no_alert",
        "bandwidth": "1M",
        "config_destination": "169.254.0.1",
        "address_family": "ipv4",
        "description": "from_DCv3Lan",
        "destination": "169.254.0.1",
        "dns_update_interval": 300,
        "dont_fragment": None,
        "dst_port": 22,
        "duration": 5,
        "groups": {"group2"},
        "interval": None,
        "ip_payload_size": None,
        "is_dynamic": True,
        "is_special": True,
        "is_subnet": False,
        "name": "DCv3Lan_pe02.paris",
        "nb_packets": None,
        "num_streams": 1,
        "packets": [],
        "protocol": "-u",
        "proto_payload_size": None,
        "state": None,
        "threshold": None,
        "time_to_refresh": netprobify.list_dynamic_special_targets[0].time_to_refresh,
        "timeout": None,
        "lifetime": None,
        "creation_date": None,
    }

    # fake results of probing
    netprobify.result = [
        {
            65100: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65101: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "DCv3Lan_pe01.paris",
            "probing_type": "TCPsyn",
            "groups": {"group2"},
            "destination": "169.254.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
        {
            65100: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            65101: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "DCv3Lan_pe02.paris",
            "probing_type": "TCPsyn",
            "groups": {"group2"},
            "destination": "169.254.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        },
    ]

    # evaluate metrics and set Prometheus metrics
    netprobify.get_metrics()

    # check if metrics exist
    for target_name in ["DCv3Lan_pe01.paris", "DCv3Lan_pe02.paris"]:
        assert (probe_name, target_name, "ipv4", "in production", "group2") in netprobify.getter(
            "TCP_SENT"
        ).__dict__["_metrics"]
        assert (probe_name, target_name, "ipv4", "in production", "group2") in netprobify.getter(
            "TCP_LOSS"
        ).__dict__["_metrics"]

        assert (probe_name, target_name, "ipv4", "in production", "group2") in netprobify.getter(
            "TCP_LOSS_RATIO"
        ).__dict__["_metrics"]

        assert (
            probe_name,
            target_name,
            "ipv4",
            "in production",
            "group2",
            "50",
        ) in netprobify.getter("TCP_ROUND_TRIP").__dict__["_metrics"]

        assert (
            probe_name,
            target_name,
            "ipv4",
            "in production",
            "group2",
            "95",
        ) in netprobify.getter("TCP_ROUND_TRIP").__dict__["_metrics"]

        assert (probe_name, target_name, "ipv4") in netprobify.getter(
            "APP_HOST_RESOLUTION"
        ).__dict__["_metrics"]

        assert (probe_name, target_name, "ipv4") in netprobify.getter(
            "APP_HOST_RESOLUTION_CHANGE"
        ).__dict__["_metrics"]

        assert (probe_name, target_name, "ipv4", "group2") in netprobify.getter(
            "APP_TIME_OOO"
        ).__dict__["_metrics"]

    ##
    # test removing one target
    ##
    netprobify.shared_dynamic_targets = {
        "DCv3Lan": [
            {
                "hostname": "pe01.paris",
                "destination": "169.254.0.1",
                "address_family": "ipv4",
                "type": "TCPsyn",
                "dst_port": 443,
                "nb_packets": 100,
                "ip_payload_size": 0,
                "groups": {"group2"},
                "state": "in production",
                "alert_level": "paging",
                "timeout": 1,
                "lifetime": None,
                "creation_date": None,
            }
        ]
    }

    netprobify.get_dynamic_targets()

    assert netprobify.list_dynamic_targets[0].config_destination == "169.254.0.1"
    assert len(netprobify.list_dynamic_targets) == 1
    assert (
        probe_name,
        "DCv3Lan_pe01.paris",
        "ipv4",
        "in production",
        "group2",
    ) in netprobify.getter("TCP_SENT").__dict__["_metrics"]

    assert (
        probe_name,
        "DCv3Lan_pe02.paris",
        "ipv4",
        "in production",
        "group2",
    ) not in netprobify.getter("TCP_SENT").__dict__["_metrics"]


def test_load_dynamic_inventories():
    """Test load_dynamic_inventories method."""
    netprobify = NetProbify("tests/netprobify/config/test_config_disable_module.yaml")
    netprobify.load_conf()

    with mock.patch("netprobify.main.Process.start", return_value=1) as _:
        netprobify.load_dynamic_inventories()

    assert "netprobify.dynamic_inventories.api" in sys.modules
    assert "netprobify.dynamic_inventories.network_devices" not in sys.modules
