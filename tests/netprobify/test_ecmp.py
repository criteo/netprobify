import logging
import socket
import time
from unittest import mock

from pyroute2.netlink.exceptions import NetlinkError
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6

from netprobify.protocol.common import ecmp
from netprobify.protocol.common.ecmp import (
    Link,
    NextHop,
    _packets_to_send_per_link,
    _flow_key,
    _resolve_links,
    _route_next_hops,
    _select_link,
    send_ecmp,
    _resolve_on_link_neighbors,
    _usable_neighbors,
)

# Netlink messages are read with pyroute2 msg.get(<short name>), for fields and
# attributes alike: plain dicts with the same short names fake them.


def unicast(attrs, flags=0):
    return {"type": 1, "family": socket.AF_INET, "flags": flags, **attrs}


def next_hop_msg(oif, attrs, hops=0, flags=0):
    return {"oif": oif, "hops": hops, "flags": flags, **attrs}


def link(iface, neighbour, weight=1):
    return Link(iface, neighbour, "02:00:00:00:00:01", "02:00:00:00:00:02", weight)


def next_hops_of(route):
    """Return the next hops found by _route_next_hops when the route lookup returns route."""
    ipr = mock.Mock()
    ipr.route.return_value = [route]
    return _route_next_hops(ipr, "8.8.8.8", "ipv4")


def test_route_next_hops_single_path():
    route = unicast({"oif": 3, "gateway": "10.0.0.1"})
    assert next_hops_of(route) == [NextHop(3, "10.0.0.1", socket.AF_INET, 1)]

    on_link = unicast({"oif": 3})
    assert next_hops_of(on_link) == [NextHop(3, None, None, 1)]

    link_down = unicast({"oif": 3, "gateway": "10.0.0.1"}, flags=16)
    assert next_hops_of(link_down) == []


def test_route_next_hops_multipath():
    route = unicast(
        {
            "multipath": [
                next_hop_msg(3, {"gateway": "10.0.0.1"}),
                next_hop_msg(
                    4, {"via": {"family": socket.AF_INET6, "addr": "fe80::1"}}, 1
                ),
                next_hop_msg(5, {"gateway": "10.0.2.1"}, flags=1),
            ]
        }
    )
    assert next_hops_of(route) == [
        NextHop(3, "10.0.0.1", socket.AF_INET, 1),
        NextHop(4, "fe80::1", socket.AF_INET6, 2),
    ]


def test_route_next_hops_not_unicast():
    blackhole = {"type": 6, "family": socket.AF_INET, "flags": 0}
    assert next_hops_of(blackhole) == []


def test_route_next_hops():
    ipr = mock.Mock()
    ipr.route.return_value = [unicast({"oif": 3, "gateway": "10.0.0.1"})]

    assert _route_next_hops(ipr, "8.8.8.8", "ipv4") == [
        NextHop(3, "10.0.0.1", socket.AF_INET, 1)
    ]
    ipr.route.assert_called_once_with(
        "get", family=socket.AF_INET, dst="8.8.8.8", flags=0x2000
    )

    ipr.route.side_effect = NetlinkError(101, "Network is unreachable")
    assert _route_next_hops(ipr, "8.8.8.8", "ipv4") == []

    ipr.route.side_effect = None
    ipr.route.return_value = []
    assert _route_next_hops(ipr, "8.8.8.8", "ipv4") == []


def fake_ipr(macs, neighbours):
    """IPRoute mock: macs is {ifindex: (name, mac)}, neighbours is {(address, ifindex): (mac, state)}."""
    ipr = mock.Mock()

    def get_links(ifindex):
        name, mac = macs[ifindex]
        return [{"ifname": name, "address": mac}]

    def get_neighbours(family, dst, ifindex):
        if (dst, ifindex) not in neighbours:
            return []
        mac, state = neighbours[(dst, ifindex)]
        return [{"state": state, "lladdr": mac}]

    ipr.get_links.side_effect = get_links
    ipr.get_neighbours.side_effect = get_neighbours
    return ipr


def test_resolve_links():
    ipr = fake_ipr(
        {
            3: ("eth1", "aa:00:00:00:00:01"),
            4: ("eth0", "aa:00:00:00:00:00"),
            5: ("eth2", None),
        },
        {
            ("fe80::1", 3): ("bb:00:00:00:00:01", 2),
            ("10.0.0.1", 4): ("bb:00:00:00:00:00", 4),
            ("10.0.9.1", 4): ("bb:00:00:00:00:09", 32),
        },
    )
    next_hops = [
        NextHop(3, "fe80::1", socket.AF_INET6, 2),
        NextHop(4, "10.0.0.1", socket.AF_INET, 1),
        NextHop(4, "10.0.9.1", socket.AF_INET, 1),  # neighbour failed
        NextHop(5, "10.0.5.1", socket.AF_INET, 1),  # interface without MAC
    ]

    assert _resolve_links(ipr, next_hops, "8.8.8.8", "ipv4") == [
        Link("eth0", "10.0.0.1", "aa:00:00:00:00:00", "bb:00:00:00:00:00", 1),
        Link("eth1", "fe80::1", "aa:00:00:00:00:01", "bb:00:00:00:00:01", 2),
    ]


def test_resolve_links_on_link():
    ipr = fake_ipr(
        {3: ("eth0", "aa:00:00:00:00:00")}, {("10.0.0.7", 3): ("bb:00:00:00:00:07", 2)}
    )

    assert _resolve_links(ipr, [NextHop(3, None, None, 1)], "10.0.0.7", "ipv4") == [
        Link("eth0", "10.0.0.7", "aa:00:00:00:00:00", "bb:00:00:00:00:07", 1)
    ]


def test_flow_key():
    udp = IP(src="192.0.2.1", dst="10.1.1.1") / UDP(sport=65000, dport=33434)
    assert _flow_key(udp, "ipv4") == (
        socket.inet_aton("192.0.2.1")
        + socket.inet_aton("10.1.1.1")
        + b"\x11\xfd\xe8\x82\x9a"
    )

    tcp = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1, dport=80)
    assert _flow_key(tcp, "ipv6")[-5:] == b"\x06\x00\x01\x00\x50"

    icmp = IP(src="192.0.2.1", dst="10.1.1.1") / ICMP()
    assert _flow_key(icmp, "ipv4")[-5:] == b"\x01\x00\x00\x00\x00"


def test_select_link():
    links = [link("eth0", "10.0.0.1"), link("eth1", "10.0.1.1")]
    probes = [
        IP(src="192.0.2.1", dst="10.1.1.1") / UDP(sport=sport, dport=33434)
        for sport in range(65000, 65003)
    ]

    selected = [_select_link(links, pkt, "ipv4").iface for pkt in probes]
    assert selected == ["eth1", "eth0", "eth1"]
    # stable: the same 5-tuple always gets the same link
    assert [_select_link(links, pkt, "ipv4").iface for pkt in probes] == selected


def test_select_link_weights():
    links = [link("eth0", "10.0.0.1", weight=1), link("eth1", "10.0.1.1", weight=3)]
    probes = [
        IP(src="192.0.2.{}".format(i), dst="10.1.1.1") / UDP(sport=sport, dport=33434)
        for i in range(1, 11)
        for sport in range(65000, 65010)
    ]

    counts = {"eth0": 0, "eth1": 0}
    for pkt in probes:
        counts[_select_link(links, pkt, "ipv4").iface] += 1
    assert 15 <= counts["eth0"] <= 35


@mock.patch("netprobify.protocol.common.ecmp.IPRoute")
@mock.patch("netprobify.protocol.common.ecmp._resolve_links")
@mock.patch("netprobify.protocol.common.ecmp._resolve_on_link_neighbors")
@mock.patch("netprobify.protocol.common.ecmp._route_next_hops")
def test_assign_links(
    mock_route_next_hops, mock_resolve_on_link, mock_resolve_links, mock_iproute, caplog
):
    eth0, eth1 = link("eth0", "10.0.0.1"), link("eth1", "10.0.1.1")
    mock_resolve_links.side_effect = lambda ipr, next_hops, dst, af: (
        [eth0, eth1] if dst == "10.1.1.1" else []
    )
    # one probe to a routed destination (hashed onto eth1), one to an unrouted destination
    probes = [
        IP(src="192.0.2.1", dst="10.1.1.1") / UDP(sport=65000, dport=33434),
        IP(src="192.0.2.1", dst="10.9.9.9") / UDP(sport=65000, dport=33434),
    ]

    with caplog.at_level(logging.WARNING, logger=ecmp.__name__):
        to_send = _packets_to_send_per_link(probes, "ipv4")

    assert to_send == [(probes[0], eth1)]
    assert mock_route_next_hops.call_count == 2
    mock_resolve_on_link.assert_called_once()
    assert [record.getMessage() for record in caplog.records] == [
        "no usable next hop for 10.9.9.9 (no route or MAC address): its probes are not sent",
        "no probe sent via 10.0.0.1 on eth0, add source ports or src_subnet addresses",
    ]


@mock.patch("netprobify.protocol.common.ecmp.socket.socket")
@mock.patch("netprobify.protocol.common.ecmp._packets_to_send_per_link")
def test_send_ecmp(mock_assign_links, mock_socket):
    eth0, eth1 = link("eth0", "10.0.0.1"), link("eth1", "10.0.1.1")
    probes = [
        IP(src="192.0.2.1", dst="10.1.1.1") / UDP(sport=sport, dport=33434)
        for sport in range(65000, 65003)
    ]
    # probes[1] has no usable next hop: assign_links leaves it out
    mock_assign_links.return_value = [(probes[0], eth1), (probes[2], eth0)]
    sock = mock_socket.return_value
    sock.sendto.side_effect = [OSError("network is down"), None]

    send_ecmp(probes, 0, "ipv4")

    # socket.socket is patched for the whole process: only check our call
    assert mock_socket.call_args_list[0] == mock.call(
        socket.AF_PACKET, socket.SOCK_RAW, 0
    )
    expected_frames = [
        bytes(Ether(src=eth1.src_mac, dst=eth1.dst_mac, type=0x0800) / probes[0]),
        bytes(Ether(src=eth0.src_mac, dst=eth0.dst_mac, type=0x0800) / probes[2]),
    ]
    assert sock.sendto.call_args_list == [
        mock.call(expected_frames[0], ("eth1", 0x0800)),
        mock.call(expected_frames[1], ("eth0", 0x0800)),
    ]
    assert probes[0].sent_time is not None
    assert probes[1].sent_time is None
    assert probes[2].sent_time is not None
    sock.close.assert_called_once()


def neighbor(dst, ifindex, mac, state):
    return {"dst": dst, "ifindex": ifindex, "lladdr": mac, "state": state}


def test_usable_neighbors():
    ipr = mock.Mock()
    ipr.get_neighbours.return_value = [
        neighbor("10.0.0.7", 3, "bb:00:00:00:00:07", 2),  # reachable
        neighbor("10.0.0.8", 3, "bb:00:00:00:00:08", 4),  # stale
        neighbor("10.0.0.9", 3, None, 1),  # incomplete
        neighbor("10.0.0.10", 3, "bb:00:00:00:00:10", 32),  # failed
    ]

    assert _usable_neighbors(ipr, socket.AF_INET) == {("10.0.0.7", 3), ("10.0.0.8", 3)}
    ipr.get_neighbours.assert_called_once_with(socket.AF_INET)


def test_resolve_on_link_neighbors_nothing_to_do():
    ipr = mock.Mock()
    ipr.get_neighbours.return_value = [neighbor("10.0.0.7", 3, "bb:00:00:00:00:07", 2)]
    next_hops_by_dst = {
        "10.0.0.7": [NextHop(3, None, None, 1)],  # directly connected, resolved
        "8.8.8.8": [NextHop(4, "10.0.1.1", socket.AF_INET, 1)],  # via a gateway
    }

    _resolve_on_link_neighbors(ipr, next_hops_by_dst, "ipv4")

    ipr.neigh.assert_not_called()


def test_resolve_on_link_neighbors_waits_for_mac():
    ipr = mock.Mock()
    # unresolved at first, resolved at the second look
    ipr.get_neighbours.side_effect = [
        [],
        [neighbor("10.0.0.7", 3, "bb:00:00:00:00:07", 2)],
    ]

    start = time.monotonic()
    _resolve_on_link_neighbors(ipr, {"10.0.0.7": [NextHop(3, None, None, 1)]}, "ipv4")

    assert time.monotonic() - start < ecmp.NEIGHBOR_RESOLUTION_TIMEOUT
    ipr.neigh.assert_called_once_with(
        "replace", dst="10.0.0.7", ifindex=3, state=0, flags=ecmp.NTF_USE
    )
    assert ipr.get_neighbours.call_count == 2


def test_resolve_on_link_neighbors_without_privilege(caplog):
    ipr = mock.Mock()
    ipr.get_neighbours.return_value = []
    ipr.neigh.side_effect = NetlinkError(1, "Operation not permitted")
    next_hops_by_dst = {
        "10.0.0.7": [NextHop(3, None, None, 1)],
        "10.0.0.8": [NextHop(3, None, None, 1)],
    }

    with caplog.at_level(logging.WARNING, logger=ecmp.__name__):
        _resolve_on_link_neighbors(ipr, next_hops_by_dst, "ipv4")

    # stop at the first refusal, without waiting
    ipr.neigh.assert_called_once()
    assert ipr.get_neighbours.call_count == 1
    assert "CAP_NET_ADMIN is required" in caplog.records[0].getMessage()


def test_resolve_on_link_neighbors_timeout():
    ipr = mock.Mock()
    ipr.get_neighbours.return_value = []

    with mock.patch.object(ecmp, "NEIGHBOR_RESOLUTION_TIMEOUT", 0.05):
        start = time.monotonic()
        _resolve_on_link_neighbors(
            ipr, {"10.0.0.7": [NextHop(3, None, None, 1)]}, "ipv4"
        )

    assert 0.05 <= time.monotonic() - start < 1


def test_resolve_links_on_link_not_resolved(caplog):
    ipr = fake_ipr({3: ("eth0", "aa:00:00:00:00:00")}, {})

    with caplog.at_level(logging.WARNING, logger=ecmp.__name__):
        links = _resolve_links(ipr, [NextHop(3, None, None, 1)], "10.0.0.7", "ipv4")

    assert links == []
    assert [record.getMessage() for record in caplog.records] == [
        "next hop 10.0.0.7 on eth0 skipped: MAC address unknown "
        "(interface: aa:00:00:00:00:00, neighbor: None)",
    ]


def test_route_next_hops_without_output_interface(caplog):
    # route using nexthop objects with net.ipv4.nexthop_compat_mode=0: only the nexthop id
    route = unicast({"nh_id": 12})

    with caplog.at_level(logging.WARNING, logger=ecmp.__name__):
        assert next_hops_of(route) == []

    assert "net.ipv4.nexthop_compat_mode must be 1" in caplog.records[0].getMessage()


def test_resolve_links_interface_removed(caplog):
    ipr = fake_ipr({}, {})
    ipr.get_links.side_effect = NetlinkError(19, "No such device")

    with caplog.at_level(logging.WARNING, logger=ecmp.__name__):
        links = _resolve_links(
            ipr, [NextHop(3, "10.0.0.1", socket.AF_INET, 1)], "8.8.8.8", "ipv4"
        )

    assert links == []
    assert caplog.records[0].getMessage() == (
        "next hop 10.0.0.1 skipped: interface not found: (19, 'No such device')"
    )
