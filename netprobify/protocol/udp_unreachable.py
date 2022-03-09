"""Module for UDP probing."""
import logging

from scapy.all import UDP, L3RawSocket, RandString, Raw, UDPerror, conf, sr

from netprobify.protocol.target import Target, dscp_to_tos

from .common.protocols import (
    af_to_ip_header_fields,
    af_to_ip_protocol,
    bpf_filter_protocol_af,
    egress_interface,
    get_src_subnet,
    group_source_address,
    list_self_ips,
)

log_udp_unreachable = logging.getLogger(__name__)


class UDPunreachable(Target):
    """UDPunreachable target type derivated from Target class."""

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
        dst_port,
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
        dst_port -- destination port for UDP request
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
        self.dst_port = dst_port
        self.min_seq = None
        self.max_seq = None

        self.set_payload_size(self.UDP_HEADER_SIZE)

    def generate_packets(self, all_groups, id_gen, logging_level="WARNING"):
        """Create and store packets used for probing.

        Keyword arguments:
        all_groups -- list of all group objects
        logging_level -- logging level for targets class
        """
        # set logging level
        log_udp_unreachable.setLevel(logging_level)

        # cleaning existing packets
        del self.packets[:]

        # Check if we want to set the DF bit
        ip_kwargs = {}
        if self.address_family == "ipv4":
            df_value = 2 if self.dont_fragment else 0
            ip_kwargs["flags"] = df_value

        # generate payload at the good size
        udp_payload = Raw(RandString(size=self.proto_payload_size))

        ip_kwargs = {}

        # get an IP object and a source address depending on the desired address-family
        af_ip_object = af_to_ip_protocol(self.address_family)

        # we create the packet only for associated groups
        for grp in [group for group in all_groups if group.name in self.groups]:
            src_ip = group_source_address(grp, self.address_family)
            if not src_ip:
                log_udp_unreachable.debug(
                    "no source address found in group %s to reach %s", grp.name, self.destination
                )

            src_network = get_src_subnet(self.address_family, grp)
            src_port = grp.src_port_a

            # get tos header field name for the current address-family
            tos_header_field = af_to_ip_header_fields(self.address_family, "tos")
            ip_kwargs[tos_header_field] = dscp_to_tos(grp.dscp)
            for n_packet in range(self.nb_packets):
                # we select a source IP address if a range is provided
                if src_network:
                    ip_index = n_packet % (src_network.num_addresses - 1) + 1
                    src_ip = src_network[ip_index].compressed

                # if src_subnet is not defined > round robin on source port only
                # if defined > round robin on source IP and source port changes
                #               only when a cycle is finished on the source IP round robin
                if not src_network or ip_index == 1:
                    src_port = n_packet % (grp.src_port_z - grp.src_port_a + 1) + grp.src_port_a

                # we get the next sequence number
                id_header_field = af_to_ip_header_fields(self.address_family, "id")
                ip_kwargs[id_header_field] = id_gen.send(1)

                ip_pkts = af_ip_object(src=src_ip, dst=self.destination, **ip_kwargs)

                pkts = []
                if self.is_subnet:
                    pkts.extend(ip_pkts)
                else:
                    pkts.append(ip_pkts)

                self.packets.extend(
                    [(pkt / UDP(dport=self.dst_port, sport=src_port) / udp_payload) for pkt in pkts]
                )

        log_udp_unreachable.debug("%s: packets generated", self.name)

    def send_packets(self, res, logging_level, all_groups, verbose=0, force_raw_socket=False):
        """Send the packets stored in self.packets.

        Keyword arguments:
        verbose -- 0 for no output, 1 for scapy details
        res -- variable to store results (manager list)
        logging_level -- logging level for targets class
        all_groups -- list of all groups
        force_raw_socket -- force PF_INET instead of PF_PACKET
        """
        # metrics initialization
        points = {}
        port_mismatch = 0

        for grp in [group for group in all_groups if group.name in self.groups]:
            for src_port in range(grp.src_port_a, grp.src_port_z + 1):
                points[src_port] = {}
                points[src_port]["sent"] = 0
                points[src_port]["loss"] = 0
                points[src_port]["timestamp_ooo"] = 0
                points[src_port]["latency"] = []

        # set logging level
        log_udp_unreachable.setLevel(logging_level)

        # Force PF_INET usage for compatibility issues
        if force_raw_socket:
            conf.L3socket = L3RawSocket

        # Non promiscuous mode
        conf.promisc = 0
        conf.sniff_promisc = 0

        # set scapy buffers
        conf.bufsize = 2**30

        # sending packets, and waiting for responses
        log_udp_unreachable.debug("%s: sending %i UDP packets", self.name, len(self.packets))

        # BPF filter for send/receive
        try:
            # we get our local IP addresses without duplicate
            self_ips = " or ".join(list_self_ips(self.address_family, conf))
            bpf_protocol = bpf_filter_protocol_af(self.address_family, "icmp")
        except ValueError as error:
            log_udp_unreachable.error("could not get bpf filter: %s", error)
            return
        """FIXME: simplify when libpcap supports filtering on specific fields for
           IPV6 upper-layer packets (remove condition and apply ipv4 filter)
        """
        if self.address_family == "ipv6":
            bpf_filter = "{0} and src net {1} and not src net ({2})".format(
                bpf_protocol, self.destination, self_ips
            )
        else:
            bpf_filter = "{0}[0] = 3 and src net {1} and not src net ({2})".format(
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

        log_udp_unreachable.debug("%s: packets sent", self.name)

        # results analysis
        for pkt in ans:
            # we get both sent and received packets
            sent_pkt = pkt[0]
            received_pkt = pkt[1]

            received_udperror_port = received_pkt[UDPerror].sport

            # if the port is not the good one, we ignore the packet
            if received_udperror_port not in points:
                log_udp_unreachable.warning(
                    "%s: ignoring packet as UDP error source port in ICMP "
                    "doesn't match with sent packets",
                    self.name,
                )
                continue

            # logs of mismatch sent / received packets
            if received_udperror_port != sent_pkt.sport:
                log_udp_unreachable.error(
                    "%s: mismatch ports between sent packet and received", self.name
                )
                port_mismatch += 1
                continue

            # latency calculation
            latency = received_pkt.time - sent_pkt.sent_time

            # we increment the sent counter
            points[sent_pkt.sport]["sent"] += 1

            # we make sure the calculation is good (timestamping issue)
            if latency >= 0:
                points[sent_pkt.sport]["latency"].append(latency)
            else:
                points[sent_pkt.sport]["timestamp_ooo"] += 1

        # for each unanswered request
        for pkt in unans:
            # we increment the sent counter and the loss counter
            points[pkt.sport]["sent"] += 1
            points[pkt.sport]["loss"] += 1

        # we store the information
        points["name"] = self.name
        points["probing_type"] = "UDPunreachable"
        points["groups"] = self.groups
        points["state"] = self.state
        points["alert_level"] = self.alert_level
        points["destination"] = self.destination
        points["address_family"] = self.address_family
        points["ip_payload_size"] = self.ip_payload_size
        points["port_mismatch"] = port_mismatch
        res.append(points)

        log_udp_unreachable.debug("%s: metrics sent to main code", self.name)
