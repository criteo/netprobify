"""Module for TCP syn probing."""
import logging

from scapy.all import TCP, L3RawSocket, RandString, Raw, conf, send, sr

from netprobify.protocol.target import Target, dscp_to_tos

from .common.protocols import (
    af_to_ip_protocol,
    get_src_subnet,
    group_source_address,
    list_self_ips,
    af_to_ip_header_fields,
    egress_interface,
)

log_tcpsyn = logging.getLogger(__name__)


class TCPsyn(Target):
    """TCPsyn target type derivated from Target class."""

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
        dst_port -- destination port for TCP request
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
        self.packets_rst = []

        self.set_payload_size(self.TCP_HEADER_SIZE)

    def generate_packets(self, all_groups, seq_gen, logging_level="WARNING"):
        """Create and store packets used for probing.

        Keyword arguments:
        all_groups -- list of all group objects
        logging_level -- logging level for targets class
        """
        # set logging level
        log_tcpsyn.setLevel(logging_level)

        # cleaning existing packets
        del self.packets[:]
        del self.packets_rst[:]

        # Check if we want to set the DF bit
        ip_kwargs = {}
        if self.address_family == "ipv4":
            df_value = 0
            if self.dont_fragment:
                df_value = 2
            ip_kwargs["flags"] = df_value

        # get an IP object depending on the desired address-family
        af_ip_object = af_to_ip_protocol(self.address_family)

        # generate payload at the good size
        tcp_payload = Raw(RandString(size=self.proto_payload_size))

        # we create the packet only for associated groups
        for grp in all_groups:
            if grp.name in self.groups:
                # get tos header field name for the current address-family
                tos_header_field = af_to_ip_header_fields(self.address_family, "tos")
                ip_kwargs[tos_header_field] = dscp_to_tos(grp.dscp)

                # packet creations in one shot using the port range
                src_ip = group_source_address(grp, self.address_family)
                if not src_ip:
                    log_tcpsyn.debug(
                        "no source address found in group %s to reach %s",
                        grp.name,
                        self.destination,
                    )

                src_network = get_src_subnet(self.address_family, grp)
                src_port = grp.src_port_a

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
                    seq_id = seq_gen.send(1)

                    # we store the seq id ranges (min and max)
                    if self.min_seq is None:
                        self.min_seq = seq_id
                    self.max_seq = seq_id

                    af_ip_pkt = af_ip_object(src=src_ip, dst=self.destination, **ip_kwargs)

                    if self.is_subnet:
                        # packet creations using the port range for each address in range
                        for ip_pkt in af_ip_pkt:
                            pkt = (
                                ip_pkt
                                / TCP(flags="S", seq=seq_id, dport=self.dst_port, sport=src_port)
                                / tcp_payload
                            )

                            packets_rst = ip_pkt / TCP(
                                flags="R", seq=seq_id, dport=self.dst_port, sport=src_port
                            )

                            # store the packets
                            self.packets.append(pkt)
                            self.packets_rst.append(packets_rst)
                    else:
                        pkt = (
                            af_ip_pkt
                            / TCP(flags="S", seq=seq_id, dport=self.dst_port, sport=src_port)
                            / tcp_payload
                        )

                        packets_rst = af_ip_pkt / TCP(
                            flags="R", seq=seq_id, dport=self.dst_port, sport=src_port
                        )

                        # store the packets
                        self.packets.append(pkt)
                        self.packets_rst.append(packets_rst)

                    # we jump seq in range [seq, seq + TCP payload]
                    # for the next packet of this target, or or the next target
                    seq_id = seq_gen.send(self.proto_payload_size)

        log_tcpsyn.debug("%s: packets generated", self.name)

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
        match_fail = 0
        port_mismatch = 0

        for grp in all_groups:
            if grp.name in self.groups:
                for src_port in range(grp.src_port_a, grp.src_port_z + 1):
                    points[src_port] = {}
                    points[src_port]["sent"] = 0
                    points[src_port]["loss"] = 0
                    points[src_port]["timestamp_ooo"] = 0
                    points[src_port]["latency"] = []

        # set logging level
        log_tcpsyn.setLevel(logging_level)

        # Force PF_INET usage for compatibility issues
        if force_raw_socket:
            conf.L3socket = L3RawSocket

        # Non promiscuous mode
        conf.promisc = 0
        conf.sniff_promisc = 0

        # set scapy buffers
        conf.bufsize = 2**30

        # sending packets, and waiting for responses
        log_tcpsyn.debug("%s: sending %i TCP SYN packets", self.name, len(self.packets))

        # we get our local IP addresses without duplicate
        try:
            self_ips = " or ".join(list_self_ips(self.address_family, conf))
        except ValueError as error:
            log_tcpsyn.error("could not get self IPs for bpf: %s", error)

        """FIXME: simplify when libpcap supports filtering on specific fields for
           IPV6 upper-layer packets (remove condition and apply ipv4 filter)
        """
        if self.address_family == "ipv6":
            bpf_filter = "tcp and src net {} and not src net ({})".format(
                self.destination, self_ips
            )
        else:
            # the ack is (seq+1) + ip_payload - header
            max_ack = self.max_seq + self.proto_payload_size + 1
            bpf_filter = "tcp[8:4] >= {0} and tcp[8:4] <= {1} and \
                src net {2} and not src net ({3})".format(
                self.min_seq, max_ack, self.destination, self_ips
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

        # send reset packets
        log_tcpsyn.debug("%s: sending %i TCP RST packets", self.name, len(self.packets_rst))
        send(self.packets_rst, iface=if_egress, inter=self.interval, verbose=0)

        log_tcpsyn.debug("%s: packets sent", self.name)

        # matching responses with sent packets using seq/ack
        # necessary because of scapy bug
        packets = {}

        # we record "unanswered" packets
        for pkt in unans:
            seq = pkt[0].seq
            if seq not in packets:
                packets[seq] = {}

            packets[seq][0] = pkt[0]

        # we record sent packets
        for pkt in ans:
            # sequence of sent packet
            seq = pkt[0].seq

            # we store packets
            if seq not in packets:
                packets[seq] = {}
            packets[seq][0] = pkt[0]

        # we record received packets
        for pkt in ans:
            tcp_flags = pkt[1][TCP].flags
            # if RstAck
            if tcp_flags == 0x14:
                # calculate the sequence of sent packet acknowledged by the response
                # if SynAck: ack = seq + 1
                # if RstAck: ack = seq + payload + 1
                #            OR ack = seq + 1 (depending of TCP implementation on remote side)
                seq_acked = pkt[1].ack - self.proto_payload_size - 1
                if seq_acked not in packets:
                    seq_acked = pkt[1].ack - 1
            else:
                seq_acked = pkt[1].ack - 1

            # we match seq with ack
            if seq_acked not in packets:
                log_tcpsyn.error(
                    "No sent packet for response with ack={0}, "
                    "destination={1}:{2}".format(pkt[1].ack, self.config_destination, self.dst_port)
                )
                match_fail += 1
            else:
                packets[seq_acked][1] = pkt[1]

        # results analysis
        for pkt_id in packets:
            sent_pkt = packets[pkt_id][0]

            # for each responses
            if packets[pkt_id].get(1):
                # we get both sent and received packets
                received_pkt = packets[pkt_id][1]

                # if the port is not the good one, we ignore the packet
                if received_pkt.dport not in points:
                    log_tcpsyn.warning("%s: error port not right", self.name)
                    continue

                # logs of mismatch sent / received packets and ignore packet
                if received_pkt.dport != sent_pkt.sport:
                    log_tcpsyn.error(
                        "%s: mismatch ports between sent packet and received", self.name
                    )
                    port_mismatch += 1
                    continue

                # latency calculation
                latency = received_pkt.time - sent_pkt.sent_time

                # we increment the sent counter
                points[received_pkt.dport]["sent"] += 1

                # we make sure the calculation is good (timestamping issue)
                if latency >= 0:
                    points[received_pkt.dport]["latency"].append(latency)
                else:
                    points[received_pkt.dport]["timestamp_ooo"] += 1

            # for each unanswered request
            else:
                # if the port is not the good one, we ignore the packet
                if sent_pkt.sport not in points:
                    log_tcpsyn.warning(
                        "%s: ignoring packet as TCP response destination port "
                        "doesn't match with sent packets",
                        self.name,
                    )
                    continue

                # we increment the sent counter and the loss counter
                points[sent_pkt.sport]["sent"] += 1
                points[sent_pkt.sport]["loss"] += 1

        # we store the information
        points["name"] = self.name
        points["probing_type"] = "TCPsyn"
        points["groups"] = self.groups
        points["state"] = self.state
        points["alert_level"] = self.alert_level
        points["destination"] = self.destination
        points["address_family"] = self.address_family
        points["ip_payload_size"] = self.ip_payload_size
        points["match_fail"] = match_fail
        points["port_mismatch"] = port_mismatch
        res.append(points)

        log_tcpsyn.debug("%s: metrics sent to main code", self.name)
