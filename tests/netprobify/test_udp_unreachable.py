from unittest import mock

from scapy.all import IP, IPerror, UDP, UDPerror, ICMP

from netprobify.main import NetProbify
from netprobify.protocol.udp_unreachable import UDPunreachable
from netprobify.protocol.target import Group


TARGET = UDPunreachable(
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
)

TARGET_V6 = UDPunreachable(
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
)

GROUP = [
    Group(
        name="test",
        src_ipv4=None,
        src_ipv6=None,
        src_subnet_ipv4=None,
        src_subnet_ipv6=None,
        src_ip_round_robin=False,
        src_port_a=65000,
        src_port_z=65001,
        ip_payload_size=None,
        dscp=1,
        permit_target_auto_register=True,
    )
]


def fake_sr_return():
    """Fake sr response."""
    # fake unans
    pkt_fail = IP(dst="127.0.0.1") / UDP(dport=80, sport=65000)

    # fake ans
    pkt_ok_sent = IP(dst="127.0.0.1") / UDP(dport=80, sport=65001)

    pkt_ok_response = (
        IP(dst="127.0.0.1")
        / ICMP(type="dest-unreach", code="port-unreachable")
        / IPerror(dst="127.0.0.1")
        / UDPerror(dport=80, sport=65001)
    )

    pkt_ok_sent.sent_time = 0
    pkt_ok_response.time = 0.1

    fake_ans = [[pkt_ok_sent, pkt_ok_response]]

    return (fake_ans, pkt_fail)


@mock.patch("netprobify.protocol.udp_unreachable.sr")
def test_generate_and_send(mock_sr):
    """Test packet generation and fake send."""
    # mock send packets
    mock_sr.return_value = fake_sr_return()

    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    # generate packets
    TARGET.generate_packets(GROUP, netprobify.id_gen)
    assert len(TARGET.packets) == 10
    assert TARGET.packets[0].dst == "127.0.0.1"
    assert TARGET.packets[0].sport == 65000

    # check number of packets
    assert len(TARGET.packets) == 10

    # check if the sport are rotated in the range
    n = 0
    for pkt in TARGET.packets:
        port = n % 2 + 65000
        n += 1
        assert pkt[UDP].sport == port
        assert pkt.id == n

    # subnet test
    UDPunreachable(
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
    )

    TARGET.generate_packets(GROUP, netprobify.id_gen)
    ip_addresses = ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"]
    for pkt in TARGET.packets:
        n += 1
        assert pkt.dst in ip_addresses
        assert pkt.id == n

    # fake packets sending
    result = []
    TARGET.send_packets(result, "WARNING", GROUP)

    assert result == [
        {
            65000: {"sent": 1, "loss": 1, "timestamp_ooo": 0, "latency": []},
            65001: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "localhost",
            "probing_type": "UDPunreachable",
            "groups": {"test"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "alert_level": "paging",
            "ip_payload_size": 8,
            "port_mismatch": 0,
        }
    ]


def test_src_ip_round_robin():
    """Test round robin on source IP address."""
    # init generator
    netprobify = NetProbify()
    netprobify.instantiate_generator()

    GROUP[0].src_subnet_ipv4 = "10.0.0.0/28"
    GROUP[0].src_subnet_ipv6 = "ff::/125"

    # no round robin enabled
    TARGET.generate_packets(GROUP, netprobify.id_gen)
    for pkt in TARGET.packets:
        assert pkt.src == "127.0.0.1"

    # round robin enabled in IPv4
    GROUP[0].src_ip_round_robin = True
    TARGET.generate_packets(GROUP, netprobify.id_gen)
    i = 1
    for pkt in TARGET.packets:
        assert pkt.src == "10.0.0.{}".format(i)
        i += 1

    # round robin enabled in IPv6
    TARGET_V6.generate_packets(GROUP, netprobify.id_gen)
    i = 0
    for pkt in TARGET_V6.packets:
        assert pkt.src == "ff::{}".format(i % 7 + 1)
        i += 1
