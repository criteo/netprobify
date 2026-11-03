"""Send packets to their ECMP next hop and receive answers on several interfaces.

Used only when l3_raw_socket is enabled.
"""

import logging

from pyroute2 import IPRoute
from scapy.all import conf
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.supersocket import SuperSocket

from .ecmp import send_ecmp
from .protocols import af_to_ip_protocol

log_raw_sendrecv = logging.getLogger(__name__)


def _physical_interfaces() -> list[str]:
    """Return the names of the physical interfaces which are up and running."""
    with IPRoute() as ipr:
        links = ipr.get_links()

    return [
        link.get("ifname")
        for link in links
        if link.get("operstate") == "UP" and link.get("parent_dev_name")
    ]


def _open_listen_sockets(interfaces: list[str], bpf_filter: str) -> list[SuperSocket]:
    """Open one listening socket per interface."""
    sockets: list[SuperSocket] = []
    for iface in interfaces:
        try:
            sockets.append(conf.L2listen(iface=iface, filter=bpf_filter))
        except (OSError, Scapy_Exception) as error:
            log_raw_sendrecv.error("cannot listen on %s: %s", iface, error)

    return sockets


def _ip_layer(pkt: Packet, address_family: str) -> Packet | None:
    """Return the IP layer of a received frame with the frame timestamp."""
    layer = pkt.getlayer(af_to_ip_protocol(address_family))
    if layer is not None:
        layer.time = pkt.time

    return layer


class ResponseMatcher:
    """Match received packets with sent packets, like scapy sr() does."""

    def __init__(self, packets: list[Packet]) -> None:
        """Initialize.

        Keyword arguments:
        packets -- sent packets waiting for an answer
        """
        self.pending: dict[bytes, list[Packet]] = {}
        self.nb_pending = len(packets)
        self.answered: list[tuple[Packet, Packet]] = []

        for pkt in packets:
            # scapy generated hash matching both sent and received packets
            key = pkt.hashret()

            if key not in self.pending:
                self.pending[key] = []

            self.pending[key].append(pkt)

    def add(self, received: Packet) -> None:
        """Record the response if matches with a sent packet."""
        # sent packet with the same hash key
        candidates = self.pending.get(received.hashret(), [])

        for index, sent in enumerate(candidates):
            # check port, id/seq, etc... are matching
            if received.answers(sent):
                del candidates[index]
                self.nb_pending -= 1
                self.answered.append((sent, received))
                return

    def unanswered(self) -> list[Packet]:
        """Return the sent packets without answer."""
        unanswered: list[Packet] = []
        for candidates in self.pending.values():
            unanswered.extend(candidates)

        return unanswered


def _record_response(matcher: ResponseMatcher, pkt: Packet, address_family: str) -> None:
    """Record a received frame in the matcher if it contains an IP packet.

    Keyword arguments:
    matcher -- ResponseMatcher holding the sent packets
    pkt -- received frame
    address_family -- address family of the expected answers
    """
    received = _ip_layer(pkt, address_family)
    if received is not None:
        matcher.add(received)


def sr_raw(
    packets: list[Packet],
    bpf_filter: str,
    timeout: float,
    interval: float,
    address_family: str,
    interfaces: list[str] | None = None,
) -> tuple[list[tuple[Packet, Packet]], list[Packet]]:
    """Send packets to their ECMP next hop and wait for answers on several interfaces.

    Return (answered, unanswered): a list of (sent, received) tuples and a list of
    sent packets without answer, matching what the protocols use from scapy sr().

    Keyword arguments:
    packets -- IP packets to send
    bpf_filter -- BPF filter matching the expected answers
    timeout -- time to wait for answers after the last packet is sent
    interval -- time to wait between two packets
    address_family -- address family of the packets
    interfaces -- interfaces to listen on (default: physical interfaces up and running)
    """
    matcher = ResponseMatcher(packets)
    sockets = _open_listen_sockets(interfaces or _physical_interfaces(), bpf_filter)

    if not sockets:
        log_raw_sendrecv.error("no interface to listen on for answers")

    try:
        send_ecmp(packets, interval, address_family)

        # sniff waits on all the sockets. It stops at the timeout or when every packet is answered.
        if sockets and matcher.nb_pending:
            sniff(
                opened_socket=sockets,
                prn=lambda pkt: _record_response(matcher, pkt, address_family),
                store=False,
                timeout=timeout,
                stop_filter=lambda _: matcher.nb_pending == 0,
            )
    finally:
        for sock in sockets:
            sock.close()

    return matcher.answered, matcher.unanswered()
