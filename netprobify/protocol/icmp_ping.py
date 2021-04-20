"""Module for ICMP probing."""
import logging
from random import randint

from scapy.all import L3RawSocket, RandString, Raw, conf, sr

from netprobify.protocol.target import Target, calculate_payload_size, dscp_to_tos

from .common.protocols import (
    af_to_icmp,
    af_to_ip_header_fields,
    af_to_ip_protocol,
    bpf_filter_protocol_af,
    egress_interface,
    get_src_subnet,
    group_source_address,
    list_self_ips,
)

log_icmp = logging.getLogger(__name__)


class ICMPping(Target):
    """ICMP target type derivated from Target class."""

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
        """Initialize.

        Keyword arguments:
        name -- name of the target
        active -- state of the target
        description -- short description of the target
        destination -- hostname or ip address to target
        config_destination -- original destination before DNS resolution
        address_family -- address family to use for probing
        dont_fragment -- if Don't Fragment bit
        is_subnet -- if destination is a subnet
        nb_packets -- number of packets to send
        interval -- sending interval between packets
        timeout -- timeout after having sent the last packets of the target
        ip_payload_size -- IP payload size to generate
        threshold -- threshold for alerts
        state -- state of the probe (in production etc...)
        alert_level -- alert level of the target
        is_dynamic -- if coming from a dynamic inventory. False if coming from the main config file.
        dns_update_interval -- interval for DNS resolution
        groups -- groups of the target
        """
        Target.__init__(
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
        )

        self.set_payload_size(self.ICMP_HEADER_SIZE)

    def generate_packets(self, all_groups, logging_level="WARNING"):
        """Create and store packets used for probing.

        Keyword arguments:
        all_groups -- list of all group objects
        logging_level -- logging level for targets class
        """
        # set logging level
        log_icmp.setLevel(logging_level)

        # cleaning existing packets
        del self.packets[:]

        # Check if we want to set the DF bit
        ip_kwargs = {}
        if self.address_family == "ipv4":
            df_value = 0
            if self.dont_fragment:
                df_value = 2
            ip_kwargs["flags"] = df_value

        # ICMP echo-request id
        icmp_id = randint(1, 10000)

        # get an IP object and a source address depending on the desired address-family
        try:
            af_ip_object = af_to_ip_protocol(self.address_family)
        except ValueError as error:
            log_icmp.error("could not get IP object: %s", error)
            return

        # depending on the af, get the correct ICMP protocol
        try:
            icmp_object = af_to_icmp(self.address_family)
        except ValueError as error:
            log_icmp.error("could not get ICMP object: %s", error)
            return

        # we create the packet only for associated groups
        for grp in all_groups:
            if grp.name in self.groups:
                src_ip = group_source_address(grp, self.address_family)
                if not src_ip:
                    log_icmp.debug(
                        "no source address found in group %s to reach %s",
                        grp.name,
                        self.destination,
                    )

                src_network = get_src_subnet(self.address_family, grp)

                # get tos header field name for the current address-family
                tos_header_field = af_to_ip_header_fields(self.address_family, "tos")
                ip_kwargs[tos_header_field] = dscp_to_tos(grp.dscp)

                # if not target payload and group payload exist ==> proto payload (group)
                if not self.config_ip_payload_size and grp.ip_payload_size:
                    payload_size = calculate_payload_size(
                        grp.ip_payload_size, self.ICMP_HEADER_SIZE
                    )[1]
                else:
                    # if target payload is defined ==> proto payload (target)
                    payload_size = self.proto_payload_size

                for i in range(0, self.nb_packets):
                    # we select a source IP address if a range is provided
                    if src_network:
                        ip_index = i % (src_network.num_addresses - 1) + 1
                        src_ip = src_network[ip_index].compressed

                    icmp_payload = Raw(RandString(size=payload_size))
                    if self.is_subnet:
                        # packet creations using the port range for each address in range
                        for ip_pkt in af_ip_object(src=src_ip, dst=self.destination, **ip_kwargs):
                            pkt = ip_pkt / icmp_object(id=icmp_id, seq=i) / icmp_payload

                            # store the packets
                            self.packets.append(pkt)
                    else:
                        # packet creations in one shot using the port range
                        pkt = (
                            af_ip_object(src=src_ip, dst=self.destination, **ip_kwargs)
                            / icmp_object(id=icmp_id, seq=i)
                            / icmp_payload
                        )

                        # store the packets
                        self.packets.append(pkt)

        log_icmp.debug("%s: packets generated", self.name)

    def send_packets(self, res, logging_level, all_groups, verbose=0, force_raw_socket=False):
        """Send the packets stored in self.packets.

        Keyword arguments:
        res -- variable to store results (manager list)
        logging_level -- logging level for targets class
        all_groups -- list of all groups
        verbose -- 0 for no output, 1 for scapy details
        force_raw_socket -- force PF_INET instead of PF_PACKET
        """
        # metrics initialization
        points = {}

        for grp in all_groups:
            if grp.name in self.groups:
                points[grp.dscp] = {}
                points[grp.dscp]["sent"] = 0
                points[grp.dscp]["loss"] = 0
                points[grp.dscp]["timestamp_ooo"] = 0
                points[grp.dscp]["latency"] = []

        # set logging level
        log_icmp.setLevel(logging_level)

        # Force PF_INET usage for compatibility issues
        if force_raw_socket:
            conf.L3socket = L3RawSocket

        # Non promiscuous mode
        conf.promisc = 0
        conf.sniff_promisc = 0

        # set scapy buffers
        conf.bufsize = 2 ** 30

        # sending packets, and waiting for responses
        log_icmp.debug(
            "%s: sending %i ICMPv%s packets", self.name, len(self.packets), self.address_family
        )

        # BPF filter for send/receive
        try:
            # we get our local IP addresses without duplicate
            self_ips = " or ".join(list_self_ips(self.address_family, conf))
            bpf_protocol = bpf_filter_protocol_af(self.address_family, "icmp")
        except ValueError as error:
            log_icmp.error("could not get bpf filter: %s", error)
            return
        bpf_filter = "{0} and src net {1} and not src net ({2})".format(
            bpf_protocol, self.destination, self_ips
        )

        # get the egress interface to use
        if_egress = egress_interface(self.address_family, conf, self.destination)

        # send packets
        ans, unans = sr(
            self.packets,
            iface=if_egress,
            timeout=self.timeout,
            inter=self.interval,
            verbose=verbose,
            filter=bpf_filter,
        )

        log_icmp.debug("%s: packets sent", self.name)

        # results analysis
        tos_header_field = af_to_ip_header_fields(self.address_family, "tos")
        for pkt in ans:
            # we get both sent and received packets
            sent_pkt = pkt[0]
            received_pkt = pkt[1]

            # latency calculation
            latency = received_pkt.time - sent_pkt.sent_time

            dscp = int(getattr(sent_pkt, tos_header_field) / 4)

            # we increment the sent counter
            points[dscp]["sent"] += 1

            # we make sure the calculation is good (timestamping issue)
            if latency >= 0:
                points[dscp]["latency"].append(latency)
            else:
                points[dscp]["timestamp_ooo"] += 1

        # for each unanswered request
        for pkt in unans:
            dscp = int(getattr(pkt, tos_header_field) / 4)
            # we increment the sent counter and the loss counter
            points[dscp]["sent"] += 1
            points[dscp]["loss"] += 1

        # we store the information
        points["name"] = self.name
        points["probing_type"] = "ICMPping"
        points["groups"] = self.groups
        points["state"] = self.state
        points["alert_level"] = self.alert_level
        points["destination"] = self.destination
        points["address_family"] = self.address_family
        points["ip_payload_size"] = self.ip_payload_size
        res.append(points)

        log_icmp.debug("%s: metrics sent to main code", self.name)
