"""Select the ECMP next hop of each probe in netprobify and send it at layer 2.

The kernel cannot use the source port to select the ECMP next hop of packets sent through a raw socket.
So netprobify does the link selection (including ECMP hashing) by itself.
"""

import logging
import socket
import struct
import time
import zlib
from dataclasses import dataclass

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.rtnl import rt_type
from pyroute2.netlink.rtnl.ndmsg import states as neighbor_states
from pyroute2.netlink.rtnl.rtmsg import RTNH_F_DEAD, RTNH_F_LINKDOWN, nh, rtmsg
from scapy.data import ETH_P_IP, ETH_P_IPV6
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

log_ecmp = logging.getLogger(__name__)

AF_TO_SOCKET_FAMILY: dict[str, int] = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}
AF_TO_ETHER_TYPE = {"ipv4": ETH_P_IP, "ipv6": ETH_P_IPV6}

# return the matched route entry with all its next hops, like "ip route get fibmatch"
# (not defined by pyroute2)
RTM_F_FIB_MATCH = 0x2000

# neighbor states in which the MAC address is known
NEIGHBOR_USABLE_STATES = sum(
    neighbor_states[state] for state in ("reachable", "stale", "delay", "probe", "permanent")
)


@dataclass(frozen=True)
class NextHop:
    """Next hop of a route: the gateway is None when the destination is on link."""

    ifindex: int
    gateway: str | None
    gateway_family: int | None
    weight: int


@dataclass(frozen=True)
class Link:
    """Next hop resolved to the MAC addresses used to send a frame to it."""

    iface: str
    neighbor: str
    src_mac: str
    dst_mac: str
    weight: int


def _next_hop(msg: rtmsg | nh, oif: int, weight: int, route_family: int) -> NextHop | None:
    """Return the next hop of a route or of a multipath entry, or None if it is dead or down.

    The gateway is None when the destination is on link.

    Keyword arguments:
    msg -- route or multipath entry netlink message
    oif -- index of the output interface
    weight -- weight of the next hop
    route_family -- address family of the route
    """
    if msg.get("flags") & (RTNH_F_DEAD | RTNH_F_LINKDOWN):
        return None

    gateway = msg.get("gateway")
    if gateway:
        return NextHop(oif, gateway, route_family, weight)

    # IPv4 route via an IPv6 next hop (BGP unnumbered)
    via = msg.get("via")
    if via:
        return NextHop(oif, via["addr"], via["family"], weight)

    return NextHop(oif, None, None, weight)


def _route_next_hops(ipr: IPRoute, dst: str, address_family: str) -> list[NextHop]:
    """Return the usable next hops of the route matching the destination.

    Keyword arguments:
    ipr -- IPRoute netlink connection
    dst -- destination address
    address_family -- address family of the destination
    """
    try:
        routes = ipr.route(
            "get", family=AF_TO_SOCKET_FAMILY[address_family], dst=dst, flags=RTM_F_FIB_MATCH
        )
    except NetlinkError as error:
        log_ecmp.debug("no route to %s: %s", dst, error)
        return []

    if not routes or routes[0].get("type") != rt_type["unicast"]:
        return []

    route = routes[0]
    multipath = route.get("multipath")
    if multipath:
        next_hops = [
            _next_hop(entry, entry.get("oif"), entry.get("hops") + 1, route.get("family"))
            for entry in multipath
        ]
    else:
        next_hops = [_next_hop(route, route.get("oif"), 1, route.get("family"))]

    return [next_hop for next_hop in next_hops if next_hop is not None]


def _neighbor_mac(ipr: IPRoute, address: str, family: int, ifindex: int) -> str | None:
    """Return the MAC address of a neighbor, or None if it is not resolved.

    Keyword arguments:
    ipr -- IPRoute netlink connection
    address -- neighbor address
    family -- address family of the neighbor address
    ifindex -- index of the interface of the neighbor
    """
    for neighbor in ipr.get_neighbours(family, dst=address, ifindex=ifindex):
        mac = neighbor.get("lladdr")
        if mac and neighbor.get("state") & NEIGHBOR_USABLE_STATES:
            return mac

    return None


def _resolve_links(
    ipr: IPRoute, next_hops: list[NextHop], dst: str, address_family: str
) -> list[Link]:
    """Return the links to send packets to the next hops, sorted for a stable selection.

    Next hops without resolved neighbor or without MAC address are skipped.

    Keyword arguments:
    ipr -- IPRoute netlink connection
    next_hops -- next hops of the destination route
    dst -- destination address, which is the neighbor of on-link next hops
    address_family -- address family of the destination
    """
    links: list[Link] = []
    for next_hop in next_hops:
        if next_hop.gateway is None or next_hop.gateway_family is None:
            # on-link destination: the neighbor is the destination itself
            neighbor, family = dst, AF_TO_SOCKET_FAMILY[address_family]
        else:
            neighbor, family = next_hop.gateway, next_hop.gateway_family

        interface = ipr.get_links(next_hop.ifindex)[0]
        iface = interface.get("ifname")
        src_mac = interface.get("address")
        dst_mac = _neighbor_mac(ipr, neighbor, family, next_hop.ifindex)

        if not src_mac or not dst_mac:
            log_ecmp.warning("next hop %s on %s skipped: MAC address not found", neighbor, iface)
            continue

        links.append(Link(iface, neighbor, src_mac, dst_mac, next_hop.weight))

    return sorted(links, key=lambda link: (link.iface, link.neighbor))


def _flow_key(pkt: Packet, address_family: str) -> bytes:
    """Return the bytes identifying the 5-tuple of a packet."""
    family = AF_TO_SOCKET_FAMILY[address_family]
    proto = pkt.proto if address_family == "ipv4" else pkt.nh
    sport, dport = 0, 0
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)

    if l4 is not None:
        sport, dport = l4.sport, l4.dport

    return (
        socket.inet_pton(family, pkt.src)
        + socket.inet_pton(family, pkt.dst)
        + struct.pack("!BHH", proto, sport, dport)
    )


def _select_link(links: list[Link], pkt: Packet, address_family: str) -> Link:
    """Select the link of a packet by hashing its 5-tuple, according to the link weights.

    crc32 is used because it is stable across restarts, unlike hash().

    Keyword arguments:
    links -- links to the next hops of the packet destination
    pkt -- IP packet
    address_family -- address family of the packet
    """
    bucket = zlib.crc32(_flow_key(pkt, address_family)) % sum(link.weight for link in links)

    for link in links:
        if bucket < link.weight:
            return link
        bucket -= link.weight

    raise ValueError("bucket out of the link weights")


def _packets_to_send_per_link(packets: list[Packet], address_family: str) -> list[tuple[Packet, Link]]:
    """Return the (packet, link) pairs to send.

    Packets whose destination has no usable next hop are left out. Destinations
    without usable next hop, and next hops which get no packet, are logged.

    Keyword arguments:
    packets -- IP packets
    address_family -- address family of the packets
    """
    links_by_dst: dict[str, list[Link]] = {}
    with IPRoute() as ipr:
        for dst in sorted({pkt.dst for pkt in packets}):
            next_hops = _route_next_hops(ipr, dst, address_family)
            links_by_dst[dst] = _resolve_links(ipr, next_hops, dst, address_family)

            if not links_by_dst[dst]:
                log_ecmp.warning(
                    "no usable next hop for %s (no route or MAC address): its probes are not sent",
                    dst,
                )

    to_send: list[tuple[Packet, Link]] = []
    for pkt in packets:
        links = links_by_dst[pkt.dst]
        if links:
            to_send.append((pkt, _select_link(links, pkt, address_family)))

    all_links: set[Link] = set()
    for links in links_by_dst.values():
        all_links.update(links)

    used = {link for _, link in to_send}
    for link in sorted(all_links - used, key=lambda link: (link.iface, link.neighbor)):
        log_ecmp.warning(
            "no probe sent via %s on %s, add source ports or src_subnet addresses",
            link.neighbor,
            link.iface,
        )

    return to_send


def send_ecmp(packets: list[Packet], interval: float, address_family: str) -> None:
    """Send IP packets at layer 2 to the ECMP next hop selected by hashing their 5-tuple.

    Packets without usable next hop are not sent. The sending time is stored in each
    sent packet "sent_time" attribute.

    Keyword arguments:
    packets -- IP packets to send
    interval -- time to wait between two packets
    address_family -- address family of the packets
    """
    to_send = _packets_to_send_per_link(packets, address_family)

    ether_type = AF_TO_ETHER_TYPE[address_family]
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    try:
        for index, (pkt, link) in enumerate(to_send):
            if index and interval:
                time.sleep(interval)

            frame = bytes(Ether(src=link.src_mac, dst=link.dst_mac, type=ether_type) / pkt)
            pkt.sent_time = time.time()

            try:
                sock.sendto(frame, (link.iface, ether_type))
            except OSError as error:
                log_ecmp.error("cannot send packet to %s via %s: %s", pkt.dst, link.iface, error)
    finally:
        sock.close()
