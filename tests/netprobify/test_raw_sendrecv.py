import time
from unittest import mock

from scapy.all import (
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPerror,
    IPv6,
)

from netprobify.protocol.common import raw_sendrecv
from netprobify.protocol.common.raw_sendrecv import (
    ResponseMatcher,
    _ip_layer,
    _physical_interfaces,
    sr_raw,
)


class FakeSocket:
    """Listening socket driving the real scapy sniff(): returns its frames, then nothing.

    recv() raises the error instead of returning a frame when one is given.
    """

    nonblocking_socket = True

    def __init__(self, iface, frames=(), error=None):
        self.iface = iface
        self.frames = list(frames)
        self.error = error
        self.closed = False

    @staticmethod
    def select(sockets, remain=None):
        readable = [sock for sock in sockets if sock.frames or sock.error]
        if not readable:
            time.sleep(min(remain or 0.01, 0.01))
        return readable

    def recv(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.frames.pop(0)

    def close(self):
        self.closed = True


@mock.patch("netprobify.protocol.common.raw_sendrecv.IPRoute")
def test_physical_interfaces(mock_iproute):
    mock_iproute.return_value.__enter__.return_value.get_links.return_value = [
        {"ifname": "lo", "operstate": "UNKNOWN", "parent_dev_name": None},
        {"ifname": "veth0", "operstate": "UP", "parent_dev_name": None},  # virtual
        {"ifname": "eth0", "operstate": "UP", "parent_dev_name": "0000:01:00.0"},
        {"ifname": "eth1", "operstate": "UP", "parent_dev_name": "0000:01:00.1"},
        {
            "ifname": "eth2",
            "operstate": "DOWN",
            "parent_dev_name": "0000:02:00.0",
        },  # no carrier
    ]

    assert _physical_interfaces() == ["eth0", "eth1"]


def test_ip_layer():
    frame = Ether() / IP(src="10.1.1.1", dst="10.0.0.1") / ICMP(type=0)
    frame.time = 42.0

    layer = _ip_layer(frame, "ipv4")
    assert isinstance(layer, IP)
    assert layer.time == 42.0
    assert _ip_layer(frame, "ipv6") is None


def test_answer_matcher():
    udp_probes = [
        IP(src="10.0.0.1", dst="10.1.1.1", id=i) / UDP(sport=1000 + i, dport=33434)
        for i in range(2)
    ]
    icmp_probes = [
        IP(src="10.0.0.1", dst="10.1.1.2") / ICMP(id=7, seq=i) for i in range(2)
    ]
    tcp_probe = IP(src="10.0.0.1", dst="10.1.1.3") / TCP(
        sport=2000, dport=80, flags="S", seq=100
    )
    icmp6_probe = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(
        id=3, seq=1
    )
    matcher = ResponseMatcher(udp_probes + icmp_probes + [tcp_probe, icmp6_probe])

    udp_answer = (
        IP(src="10.1.1.1", dst="10.0.0.1")
        / ICMP(type=3, code=3)
        / IPerror(bytes(udp_probes[1]))
    )
    icmp_answer = IP(src="10.1.1.2", dst="10.0.0.1") / ICMP(type=0, id=7, seq=1)
    tcp_answer = IP(src="10.1.1.3", dst="10.0.0.1") / TCP(
        sport=80, dport=2000, flags="SA", ack=101
    )
    icmp6_answer = IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMPv6EchoReply(
        id=3, seq=1
    )
    unrelated = IP(src="10.1.1.9", dst="10.0.0.1") / ICMP(type=0, id=7, seq=1)
    for received in (
        udp_answer,
        icmp_answer,
        icmp_answer,
        tcp_answer,
        icmp6_answer,
        unrelated,
    ):
        matcher.add(received)

    assert matcher.answered == [
        (udp_probes[1], udp_answer),
        (icmp_probes[1], icmp_answer),
        (tcp_probe, tcp_answer),
        (icmp6_probe, icmp6_answer),
    ]
    assert matcher.unanswered() == [udp_probes[0], icmp_probes[0]]
    assert matcher.nb_pending == 2


def echo_probes():
    probes = [IP(src="10.0.0.1", dst="10.1.1.2") / ICMP(id=7, seq=i) for i in range(2)]
    reply = Ether() / IP(src="10.1.1.2", dst="10.0.0.1") / ICMP(type=0, id=7, seq=0)
    reply.time = 2.0
    return probes, reply


@mock.patch("netprobify.protocol.common.raw_sendrecv.send_ecmp")
@mock.patch("netprobify.protocol.common.raw_sendrecv._physical_interfaces")
def test_sr_raw(mock_physical_interfaces, mock_send_ecmp):
    probes, reply = echo_probes()
    eth0, eth1 = FakeSocket("eth0"), FakeSocket("eth1", [reply])
    mock_physical_interfaces.return_value = ["eth0", "eth1"]

    with mock.patch.object(
        raw_sendrecv.conf, "L2listen", side_effect=[eth0, eth1]
    ) as mock_l2listen:
        ans, unans = sr_raw(probes, "icmp", 0.05, 0, "ipv4")

    assert mock_l2listen.call_args_list == [
        mock.call(iface="eth0", filter="icmp"),
        mock.call(iface="eth1", filter="icmp"),
    ]
    mock_send_ecmp.assert_called_once_with(probes, 0, "ipv4")
    assert len(ans) == 1
    assert ans[0][0] is probes[0]
    assert ans[0][1].time == 2.0
    assert unans == [probes[1]]
    assert eth0.closed and eth1.closed


@mock.patch("netprobify.protocol.common.raw_sendrecv.send_ecmp")
def test_sr_raw_stops_when_all_answered(mock_send_ecmp):
    probes, reply = echo_probes()
    eth0 = FakeSocket("eth0", [reply])

    with mock.patch.object(raw_sendrecv.conf, "L2listen", return_value=eth0):
        start = time.monotonic()
        ans, unans = sr_raw(probes[:1], "icmp", 10, 0, "ipv4", ["eth0"])

    assert time.monotonic() - start < 5
    assert len(ans) == 1
    assert unans == []


@mock.patch("netprobify.protocol.common.raw_sendrecv.send_ecmp")
@mock.patch("netprobify.protocol.common.raw_sendrecv._physical_interfaces")
def test_sr_raw_interfaces(mock_physical_interfaces, mock_send_ecmp):
    probe = IP(src="10.0.0.1", dst="10.1.1.2") / ICMP(id=7, seq=0)

    with mock.patch.object(
        raw_sendrecv.conf, "L2listen", return_value=FakeSocket("bond0")
    ) as mock_l2listen:
        ans, unans = sr_raw([probe], "icmp", 0, 0, "ipv4", ["bond0"])

    mock_physical_interfaces.assert_not_called()
    mock_l2listen.assert_called_once_with(iface="bond0", filter="icmp")
    assert ans == []
    assert unans == [probe]


@mock.patch("netprobify.protocol.common.raw_sendrecv.send_ecmp")
def test_sr_raw_socket_error(mock_send_ecmp):
    """A socket failing to receive (e.g. interface down) is dropped, the others are still read."""
    probes, reply = echo_probes()
    eth0 = FakeSocket("eth0", error=OSError(100, "Network is down"))
    eth1 = FakeSocket("eth1", [reply])

    with mock.patch.object(raw_sendrecv.conf, "L2listen", side_effect=[eth0, eth1]):
        ans, unans = sr_raw(probes, "icmp", 0.2, 0, "ipv4", ["eth0", "eth1"])

    assert len(ans) == 1
    assert unans == [probes[1]]


@mock.patch("netprobify.protocol.common.raw_sendrecv.send_ecmp")
def test_sr_raw_no_socket(mock_send_ecmp):
    probe = IP(src="10.0.0.1", dst="10.1.1.2") / ICMP(id=7, seq=0)

    with mock.patch.object(
        raw_sendrecv.conf, "L2listen", side_effect=OSError("no such device")
    ):
        ans, unans = sr_raw([probe], "icmp", 10, 0, "ipv4", ["eth9"])

    mock_send_ecmp.assert_called_once()
    assert ans == []
    assert unans == [probe]
