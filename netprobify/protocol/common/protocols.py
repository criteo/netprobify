"""Protocol related functions."""
from ipaddress import ip_network

from scapy.all import ICMP, IP, ICMPv6EchoRequest, IPv6


def group_source_address(grp, address_family):
    """Return the correct source address from a group matching the desired address-family.

    Keyword arguments:
    grp -- the group configuration
    address_family -- desired address-family
    """
    attribute = "src_{}".format(address_family.lower())
    return getattr(grp, attribute)


def af_to_ip_protocol(address_family):
    """Return a Scapy IP object depending on the input address-family.

    Keyword arguments:
    address_family -- desired address-family
    """
    af_map = {"ipv4": IP, "ipv6": IPv6}
    try:
        return af_map[address_family]
    except KeyError:
        raise ValueError("unknown address-family")


def af_to_icmp(address_family):
    """Return a Scapy ICMP object depending on the input address-family.

    Keyword arguments:
    address_family -- desired address-family
    """
    af_map = {"ipv4": ICMP, "ipv6": ICMPv6EchoRequest}
    try:
        return af_map[address_family]
    except KeyError:
        raise ValueError("unknown address-family")


def af_to_ip_header_fields(address_family, header_field):
    """Return the correct header name for an IP field with similar IPv4 and IPv6 usage.

    Keyword arguments:
    address_family -- desired address-family
    header_field -- header field name (use the IPv4 one)
    """
    headers = {"ipv6": {"tos": "tc", "id": "fl"}}
    # return the original ipv4 header field name if it is not found in dict
    return headers.get(address_family, {}).get(header_field, header_field)


def list_self_ips(address_family, conf):
    """Return a list of all addresses on the host by address-family.

    Keyword arguments:
    address_family -- desired address-family
    conf -- input configuration
    """
    if address_family == "ipv4":
        return set([addr[4] for addr in conf.route.routes])
    elif address_family == "ipv6":
        return set([addr[4][0] for addr in conf.route6.routes])
    raise ValueError("unknown address-family")


def bpf_filter_protocol_af(address_family, protocol):
    """Return the correct keyword to filter a protocol in the given address-family.

    Keyword arguments:
    address_family -- address family
    protocol -- family of protocol
    """
    proto_map = {"ipv4": {"icmp": "icmp"}, "ipv6": {"icmp": "icmp6"}}
    try:
        return proto_map[address_family][protocol]
    except KeyError:
        raise ValueError("unknown address-family or protocol")


def egress_interface(address_family, conf, destination):
    """Return the egress interface for the given address-family.

    Keyword arguments:
    address_family -- desired address-family
    conf -- input configuration
    destination -- destination to get route for
    """
    if address_family == "ipv4":
        return conf.route.route(destination)[0]
    elif address_family == "ipv6":
        return conf.route6.route(destination)[0]
    raise ValueError("unsupported address-family")


def get_src_subnet(address_family, group):
    """Return ip_network object of subnet defined in group.

    Keyword arguments:
    address_family -- desired address-family
    group -- target group
    """
    if address_family == "ipv4":
        src_subnet = group.src_subnet_ipv4
    else:
        src_subnet = group.src_subnet_ipv6

    return ip_network(src_subnet) if src_subnet else None
