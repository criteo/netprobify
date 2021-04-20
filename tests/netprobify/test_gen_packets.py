"""Test packets generation."""

from netprobify.main import NetProbify
from netprobify.protocol.target import Group
from netprobify.protocol.udp_unreachable import UDPunreachable
from netprobify.protocol.tcpsyn import TCPsyn
from netprobify.protocol.icmp_ping import ICMPping

TARGETS = [
    TCPsyn(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.1",
        config_destination="127.0.0.1",
        address_family="ipv4",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        dst_port=0,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="paging",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
    UDPunreachable(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.1",
        config_destination="127.0.0.1",
        address_family="ipv4",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=10,
        interval=0,
        timeout=1,
        dst_port=80,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="paging",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
    ICMPping(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.1",
        config_destination="127.0.0.1",
        address_family="ipv4",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="no_alert",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
]

TARGETS_V6 = [
    TCPsyn(
        "localhost",
        active=True,
        description="localhost",
        destination="2001:4860:4860::8888",
        config_destination="2001:4860:4860::8888",
        address_family="ipv6",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        dst_port=0,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="paging",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
    UDPunreachable(
        "localhost",
        active=True,
        description="localhost",
        destination="2001:4860:4860::8888",
        config_destination="2001:4860:4860::8888",
        address_family="ipv6",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=9,
        interval=0,
        timeout=1,
        dst_port=80,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="paging",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
    ICMPping(
        "localhost",
        active=True,
        description="localhost",
        destination="2001:4860:4860::8888",
        config_destination="2001:4860:4860::8888",
        address_family="ipv6",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="no_alert",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        lifetime={"days": "1"},
        creation_date=None,
    ),
]

GROUPS = [
    Group(
        name="test",
        src_ipv4=None,
        src_ipv6=None,
        src_subnet_ipv4=None,
        src_subnet_ipv6=None,
        src_port_a=65000,
        src_port_z=65001,
        ip_payload_size=None,
        dscp=1,
        permit_target_auto_register=True,
    )
]


def _generate_packets(netprobify, target, groups):
    if isinstance(target, TCPsyn):
        target.generate_packets(groups, netprobify.seq_gen)
    elif isinstance(target, UDPunreachable):
        target.generate_packets(groups, netprobify.id_gen)
    elif isinstance(target, ICMPping):
        target.generate_packets(groups)


def test_src_ip_round_robin():
    """Test round robin on source IP address."""
    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    groups = GROUPS.copy()
    for target in TARGETS:
        groups[0].src_subnet_ipv4 = None

        # round robin disabled
        _generate_packets(netprobify, target, groups)
        for pkt in target.packets:
            assert pkt.src == "127.0.0.1"

        groups[0].src_subnet_ipv4 = "10.0.0.0/29"

        # round robin enabled
        _generate_packets(netprobify, target, groups)
        i = 0
        for pkt in target.packets:
            # check round robin on source IP
            assert pkt.src == "10.0.0.{}".format(i % 7 + 1)
            i += 1

        if isinstance(target, ICMPping):
            continue

        # round robin of src port should progress only when one round robin cycle
        # of src IP is finished
        for index_pkt in range(0, len(target.packets)):
            assert target.packets[index_pkt].sport == 65000 if index_pkt < 7 else 65001


def test_src_ipv6_round_robin():
    """Test round robin on source IP address."""
    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    groups = GROUPS.copy()
    for target in TARGETS_V6:
        groups[0].src_subnet_ipv6 = None

        # round robin disabled
        _generate_packets(netprobify, target, groups)
        for pkt in target.packets:
            assert pkt.src == "::"

        groups[0].src_subnet_ipv6 = "ff::/125"

        # round robin enabled
        _generate_packets(netprobify, target, groups)
        i = 0
        for pkt in target.packets:
            assert pkt.src == "ff::{}".format(i % 7 + 1)
            i += 1

        if isinstance(target, ICMPping):
            continue

        # round robin of src port should progress only when one round robin cycle
        # of src IP is finished
        for index_pkt in range(0, len(target.packets)):
            assert target.packets[index_pkt].sport == 65000 if index_pkt < 7 else 65001
