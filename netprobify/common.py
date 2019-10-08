"""Common functions."""
import re

from socket import getaddrinfo, AF_INET, AF_INET6, IPPROTO_TCP
from datetime import timedelta


def explode_datetime(datetime_str):
    """Extract days minutes and seconds from datetime (days, minutes, seconds).

    Example: "1d 3h 2m" returns {"days": "1", "hours": "3", "minutes": "2"}

    Keyword arguments:
    datetime_str -- date time in string
    """
    base_regex = ".*([0-9]){pattern}.*"

    def extract_timeunit(pattern):
        try:
            result = int(re.match(base_regex.format(pattern=pattern), datetime_str)[1])
        except (ValueError, TypeError):
            result = 0
        return result

    days = extract_timeunit("d")
    hours = extract_timeunit("h")
    minutes = extract_timeunit("m")

    return timedelta(days=days, hours=hours, minutes=minutes)


def resolve_hostname(hostname, address_family):
    """Convert hostname to IP.

    Keyword arguments:
    hostname -- hostname to resolve
    address_family -- preferred address family for resolution
    """
    af_string_to_attribute = {"ipv4": AF_INET, "ipv6": AF_INET6}
    try:
        family = af_string_to_attribute[address_family]
    except KeyError:
        raise ValueError("unknown address family")
    try:
        ip_addr = getaddrinfo(hostname, None, family=family, proto=IPPROTO_TCP)[0][4][0]
        return ip_addr
    except Exception:
        return
