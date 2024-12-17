"""Main module for target definition."""

import time
import logging
from ipaddress import IPv4Address, IPv6Address, AddressValueError

log_proto = logging.getLogger(__name__)


def dscp_to_tos(dscp):
    """Convert dscp value to tos."""
    tos = int(bin(dscp * 4), 2)

    return tos


def calculate_payload_size(ip_payload_size, header_size):
    """Calculate payload size.

    It returns:
    - ip payload size (minimum value is header size)
    - the payload size of the protocol used for probing (ICMP, TCP, UDP etc...)

    For example, TCP payload size is ip payload size minus TCP header size.

    Keyword arguments:
    ip_payload_size -- IP payload size configured
    header_size -- Header size regarding the protocol (ICMP, TCP, UDP)
    """
    if not ip_payload_size or ip_payload_size < header_size:
        ip_payload_size = header_size

    proto_payload_size = ip_payload_size - header_size

    return ip_payload_size, proto_payload_size


class Group:
    """Group definition."""

    def __init__(
        self,
        name,
        src_ipv4,
        src_ipv6,
        src_subnet_ipv4,
        src_subnet_ipv6,
        src_port_a,
        src_port_z,
        ip_payload_size,
        dscp,
        permit_target_auto_register,
    ):
        """Group initialization.

        Keyword arguments:
        name -- group name/reference
        src_ipv4 -- Bind probes to a specific source IPv4
        src_ipv6 -- Bind probes to a specific source IPv6
        src_subnet_ipv4 -- Source IPv4 subnet for src ip round robin
        src_subnet_ipv6 -- Source IPv6 subnet for src ip round robin
        src_port_a -- Beginning of the source port range (for PBR)
        src_port_z -- End of the source port range, last port included
        dscp -- DSCP (for PBR)
        permit_target_auto_register -- allow targets to be automatically in the group (default true)
        """
        # check that source IPs are correct addresses
        try:
            IPv4Address(src_ipv4)
        except AddressValueError:
            src_ipv4 = None
        try:
            IPv6Address(src_ipv6)
        except AddressValueError:
            src_ipv6 = None
        self.name = name
        self.src_ipv4 = src_ipv4
        self.src_ipv6 = src_ipv6
        self.src_subnet_ipv4 = src_subnet_ipv4
        self.src_subnet_ipv6 = src_subnet_ipv6
        self.src_port_a = src_port_a
        self.src_port_z = src_port_z
        self.ip_payload_size = ip_payload_size
        self.dscp = dscp
        self.permit_target_auto_register = permit_target_auto_register


class Target:
    """Main class for target definition."""

    # constants
    TCP_HEADER_SIZE = 20
    UDP_HEADER_SIZE = 8
    ICMP_HEADER_SIZE = 8

    def __init__(
        self,
        name,
        active,
        description,
        destination,
        config_destination,
        address_family,
        dont_fragment,
        is_subnet,
        nb_packets,
        interval,
        timeout,
        ip_payload_size,
        threshold,
        state,
        alert_level,
        is_dynamic,
        dns_update_interval,
        groups,
        creation_date,
        lifetime,
    ):
        """Target initialization.

        Keyword arguments:
        name -- name of the target
        active -- state of the target
        description -- short description of the target
        destination -- ip address to target
        config_destination -- original destination before DNS resolution
        address_family -- address family to use for probing
        dont_fragment -- if Don't Fragment bit
        is_subnet -- if destination is a subnet
        nb_packets -- number of packets to send by source port in group
                    -- is also number of round
        interval -- sending interval between round
        timeout -- timeout after having sent the last packets of the target
        ip_payload_size -- IP payload size to generate
        threshold -- threshold for alerts
        state -- state of the target (in production etc...)
        alert_level -- alert level of the target
        is_dynamic -- if coming from a dynamic inventory. False if coming from the main config file.
        dns_update_interval -- interval for DNS resolution
        groups -- groups of the target
        """
        self.name = name
        self.active = active
        self.description = description
        self.destination = destination
        self.config_destination = config_destination
        self.address_family = address_family
        self.dont_fragment = dont_fragment
        self.is_subnet = is_subnet
        self.nb_packets = nb_packets
        self.interval = interval
        self.timeout = timeout
        self.ip_payload_size = ip_payload_size
        self.threshold = threshold
        self.state = state
        self.alert_level = alert_level
        self.is_dynamic = is_dynamic
        self.dns_update_interval = dns_update_interval
        self.groups = groups
        self.lifetime = lifetime
        self.creation_date = creation_date

        self.time_to_refresh = time.time()
        self.packets = []
        self.config_ip_payload_size = ip_payload_size
        self.proto_payload_size = None

    def set_payload_size(self, header_size):
        """Set the protocol payload size from the IP payload size configured.

        Keyword arguments:
        header_size -- Header size regarding the protocol (ICMP, TCP, UDP)
        """
        self.ip_payload_size, self.proto_payload_size = calculate_payload_size(
            self.ip_payload_size, header_size
        )
        log_proto.debug("%s: IP payload size set to %i", self.name, self.ip_payload_size)
