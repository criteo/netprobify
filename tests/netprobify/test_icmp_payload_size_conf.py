from unittest import mock

from netprobify.main import NetProbify
from netprobify.protocol.icmp_ping import ICMPping
from netprobify.protocol.target import Group


@mock.patch("netprobify.protocol.icmp_ping")
def test_payload_case(mock_sr):
    """Test packet generation and verify payload size."""
    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    # create group and target
    group = [
        Group(
            name="group1",
            src_ipv4="127.0.0.1",
            src_ipv6=None,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=1024,
            dscp=2,
            permit_target_auto_register=True,
        ),
        Group(
            name="group2",
            src_ipv4="127.0.0.2",
            src_ipv6=None,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=0,
            dscp=2,
            permit_target_auto_register=True,
        ),
        Group(
            name="group3",
            src_ipv4="127.0.0.3",
            src_ipv6=None,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=None,
            dscp=2,
            permit_target_auto_register=True,
        ),
    ]
    target_icmp = ICMPping(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.4",
        address_family="ipv4",
        config_destination="127.0.0.4",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        ip_payload_size=1000,
        threshold=1,
        state="in production",
        alert_level="no_alert",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"group1", "group2", "group3"},
        lifetime={"days": "1"},
        creation_date=None,
    )
    target2_icmp = ICMPping(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.5",
        address_family="ipv4",
        config_destination="127.0.0.5",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=1,
        interval=0,
        timeout=1,
        ip_payload_size=None,
        threshold=1,
        state="in production",
        alert_level="no_alert",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"group1", "group2", "group3"},
        lifetime={"days": "1"},
        creation_date=None,
    )

    # generate packets for case 1
    target_icmp.generate_packets(group)

    # case 1: payload on target set to 1000
    # for group 1
    pkt_ip = target_icmp.packets[0]
    assert len(pkt_ip.payload) == 1000

    # for group 2
    pkt_ip = target_icmp.packets[1]
    assert len(pkt_ip.payload) == 1000

    # for group 3
    pkt_ip = target_icmp.packets[2]
    assert len(pkt_ip.payload) == 1000

    # generate packets for case 2
    target2_icmp.generate_packets(group)

    # case 2: no payload set on target
    # for group 1
    pkt2_ip = target2_icmp.packets[0]
    assert len(pkt2_ip.payload) == 1024

    # for group 2
    pkt2_ip = target2_icmp.packets[1]
    assert len(pkt2_ip.payload) == 8

    # for group 3
    pkt2_ip = target2_icmp.packets[2]
    assert len(pkt2_ip.payload) == 8
