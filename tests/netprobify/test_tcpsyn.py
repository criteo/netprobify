from unittest import mock

from scapy.all import IP, TCP, PacketList

from netprobify.main import NetProbify
from netprobify.protocol.tcpsyn import TCPsyn
from netprobify.protocol.target import Group


def fake_sr_return():
    """Fake srl response."""
    # fake unans
    pkt_fail = IP(dst="127.0.0.1") / TCP(flags="S", seq=0, dport=80, sport=65000)

    fake_unans = PacketList(pkt_fail)

    # fake ans
    pkt_ok_sent = IP(dst="127.0.0.1") / TCP(flags="S", seq=1, dport=80, sport=65001)

    pkt_ok_response = IP(dst="127.0.0.1") / TCP(
        flags="S", seq=1, ack=2, dport=65001, sport=80
    )

    pkt_ok_sent.sent_time = 0
    pkt_ok_response.time = 0.1

    fake_ans = [[pkt_ok_sent, pkt_ok_response]]

    return (fake_ans, fake_unans)


@mock.patch("netprobify.protocol.tcpsyn.sr")
@mock.patch("netprobify.protocol.tcpsyn.send")
def test_generate_and_send(mock_send, mock_sr):
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
            src_ipv4="127.0.0.2",
            src_ipv6=None,
            src_subnet_ipv4=None,
            src_subnet_ipv6=None,
            src_port_a=65000,
            src_port_z=65000,
            ip_payload_size=None,
            dscp=1,
            permit_target_auto_register=True,
        ),
        Group(
            name="test2",
            src_ipv4=None,
            src_ipv6=None,
            src_subnet_ipv4=None,
            src_subnet_ipv6=None,
            src_port_a=65001,
            src_port_z=65001,
            ip_payload_size=None,
            dscp=1,
            permit_target_auto_register=True,
        ),
    ]
    target = TCPsyn(
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
        groups={"test", "test2"},
        lifetime={"days": "1"},
        creation_date=None,
    )

    # generate packets
    target.generate_packets(group, netprobify.seq_gen)
    assert len(target.packets) == 2
    assert target.packets[0].src == "127.0.0.2"
    assert target.packets[0].dst == "127.0.0.1"
    assert target.packets[0].sport == 65000

    n = 0
    for pkt in target.packets:
        n += 1
        assert pkt["TCP"].seq == n

    # subnet test
    target_subnet = TCPsyn(
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
        groups={"test", "test2"},
        lifetime={"days": "1"},
        creation_date=None,
    )

    target_subnet.generate_packets(group, netprobify.seq_gen)
    ip_addresses = ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"]
    previous_src_port = None
    for pkt in target_subnet.packets:
        if previous_src_port != pkt["TCP"].sport:
            n = n + 1
            previous_src_port = pkt["TCP"].sport
        assert pkt.dst in ip_addresses
        assert pkt["TCP"].seq == n

    # fake packets sending
    result = []
    target.send_packets(result, "WARNING", group)

    assert result == [
        {
            65000: {"sent": 1, "loss": 1, "timestamp_ooo": 0, "latency": []},
            65001: {"sent": 1, "loss": 0, "timestamp_ooo": 0, "latency": [0.1]},
            "name": "localhost",
            "probing_type": "TCPsyn",
            "groups": {"test", "test2"},
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "state": "in production",
            "alert_level": "paging",
            "ip_payload_size": 20,
            "match_fail": 0,
            "port_mismatch": 0,
        }
    ]


@mock.patch("netprobify.protocol.tcpsyn.sr")
@mock.patch("netprobify.protocol.tcpsyn.send")
@mock.patch("netprobify.protocol.tcpsyn.sr_raw")
@mock.patch("netprobify.protocol.tcpsyn.send_ecmp")
def test_send_raw_socket(mock_send_ecmp, mock_sr_raw, mock_send, mock_sr):
    """Test that l3_raw_socket sends RST like the SYN, at layer 2 via the selected next hop."""
    mock_sr_raw.return_value = fake_sr_return()
    netprobify = NetProbify()
    netprobify.instantiate_generator()
    group = [
        Group(
            name="test",
            src_ipv4="127.0.0.2",
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
    target = TCPsyn(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.1",
        config_destination="127.0.0.1",
        address_family="ipv4",
        dont_fragment=True,
        is_subnet=False,
        nb_packets=2,
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
    target.generate_packets(group, netprobify.seq_gen)

    result = []
    target.send_packets(result, "WARNING", group, force_raw_socket=True)

    mock_sr.assert_not_called()
    mock_send.assert_not_called()
    assert mock_sr_raw.call_args.args[0] == target.packets
    mock_send_ecmp.assert_called_once_with(target.packets_rst, 0, "ipv4")
    assert result[0][65001] == {
        "sent": 1,
        "loss": 0,
        "timestamp_ooo": 0,
        "latency": [0.1],
    }
