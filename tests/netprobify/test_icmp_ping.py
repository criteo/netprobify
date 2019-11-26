from unittest import mock

from scapy.all import IP, ICMP

from netprobify.main import NetProbify
from netprobify.protocol.icmp_ping import ICMPping, dscp_to_tos
from netprobify.protocol.target import Group


def fake_sr_return():
    """Fake srloop response."""
    # fake unans
    pkt_fail = IP(dst="127.0.0.1", tos=dscp_to_tos(1)) / ICMP(type="echo-request")

    fake_unans = pkt_fail

    # fake ans
    pkt_ok_sent = IP(dst="127.0.0.1", tos=dscp_to_tos(2)) / ICMP(type="echo-request")

    pkt_ok_response = IP(dst="127.0.0.1") / ICMP(type="echo-reply")

    pkt_ok_sent.sent_time = 0
    pkt_ok_response.time = 0.1

    fake_ans = [[pkt_ok_sent, pkt_ok_response]]

    return (fake_ans, fake_unans)


@mock.patch("netprobify.protocol.icmp_ping.sr")
def test_generate_and_send(mock_sr):
    """Test packet generation and fake send."""
    # mock send packets
    mock_sr.return_value = fake_sr_return()

    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    # create group and target
    group = [
        Group(
            name="test",
            src_ipv4=None,
            src_ipv6=None,
            src_subnet_ipv4=None,
            src_subnet_ipv6=None,
            src_ip_round_robin=False,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=None,
            dscp=1,
            permit_target_auto_register=True,
        ),
        Group(
            name="test2",
            src_ipv4="127.0.0.2",
            src_ipv6=None,
            src_subnet_ipv4=None,
            src_subnet_ipv6=None,
            src_ip_round_robin=False,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=None,
            dscp=2,
            permit_target_auto_register=True,
        ),
    ]
    target = ICMPping(
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
        groups={"test", "test2"},
        lifetime={"days": "1"},
        creation_date=None,
    )

    # generate packets
    target.generate_packets(group)
    assert len(target.packets) == 2
    assert target.packets[0].dst == "127.0.0.1"
    assert target.packets[1].src == "127.0.0.2"

    # subnet test
    target_subnet = ICMPping(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.0/30",
        config_destination="127.0.0.0/30",
        address_family="ipv4",
        dont_fragment=True,
        is_subnet=True,
        nb_packets=1,
        interval=0,
        timeout=1,
        ip_payload_size=0,
        threshold=1,
        state="in production",
        alert_level="no_alert",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test", "test2"},
        lifetime={"days": "1"},
        creation_date=None,
    )

    target_subnet.generate_packets(group)
    ip_addresses = ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"]
    for pkt in target_subnet.packets:
        assert pkt.dst in ip_addresses

    # fake packets sending
    result = []
    target.send_packets(result, "WARNING", group)

    assert result == [
        {
            1: {"sent": 1, "loss": 1, "timestamp_ooo": 0, "latency": []},
            2: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "localhost",
            "probing_type": "ICMPping",
            "groups": {"test", "test2"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "alert_level": "no_alert",
            "ip_payload_size": 8,
        }
    ]
