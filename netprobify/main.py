#!/usr/bin/env python
"""Main module."""

import importlib
import itertools
import logging
import os
import pkgutil
import signal
import sys
import time
from datetime import datetime, timedelta
from ipaddress import ip_address
from multiprocessing import Manager, Process

import pkg_resources
import scapy
import yaml
from prometheus_client import start_http_server
from pykwalify.core import Core, SchemaError
from scapy.all import conf as scapyconf

from netprobify import common, dynamic_inventories
from netprobify.external import percentile
from netprobify.metrics import (
    APP_HOST_RESOLUTION,
    APP_HOST_RESOLUTION_CHANGE,
    APP_PROCESS_TIMED_OUT,
    APP_RELOAD_CONF_FAILED,
    APP_ROUND_TIME,
    APP_TARGET_NAME_DUP,
    APP_TIME_OOO,
    ICMP_LOSS,
    ICMP_LOSS_RATIO,
    ICMP_ROUND_TRIP,
    ICMP_SENT,
    IPERF_BANDWIDTH,
    IPERF_LOSS,
    IPERF_LOSS_RATIO,
    IPERF_OUT_OF_ORDER,
    IPERF_SENT,
    LIST_TARGET_MEASUREMENT_METRICS,
    LIST_TARGET_METRICS,
    NETPROBIFY_INFO,
    TCP_LOSS,
    TCP_LOSS_RATIO,
    TCP_MATCH_ACK_FAIL,
    TCP_PORT_MISTMATCH,
    TCP_ROUND_TRIP,
    TCP_SENT,
    THRESHOLD,
    UDP_UNREACHABLE_LOSS,
    UDP_UNREACHABLE_LOSS_RATIO,
    UDP_UNREACHABLE_PORT_MISTMATCH,
    UDP_UNREACHABLE_ROUND_TRIP,
    UDP_UNREACHABLE_SENT,
)
from netprobify.protocol.common.protocols import list_self_ips
from netprobify.protocol.icmp_ping import ICMPping
from netprobify.protocol.iperf import Iperf
from netprobify.protocol.target import Group
from netprobify.protocol.tcpsyn import TCPsyn
from netprobify.protocol.udp_unreachable import UDPunreachable
from netprobify.settings import DEFAULT_ADDRESS_FAMILY, LOGGING_CONFIG

# we configure the logging before loading scapy to avoid warning when on non-ipv6 server
logging.config.dictConfig(LOGGING_CONFIG)


log = logging.getLogger(__name__)


class NetProbify:
    """Main class for NetProbify app."""

    def __init__(self, f="config.yaml"):
        """Netprobify initialization.

        Keyword arguments:
        config_file -- path of config file
        """
        self.config_file = f
        self.list_targets = []
        self.list_target_name = []
        self.list_special_targets = []
        self.list_dynamic_targets = []
        self.list_dynamic_special_targets = []
        self.shared_dynamic_targets = {}
        self.shared_dynamic_targets_backup = {}
        self.list_groups = []
        self.global_vars = {}
        self.reload_conf_needed = False
        self.first_iter = True
        self.seq_gen = None

    def get_uniq_id(self, max_value):
        """Generate ID."""
        number = 0
        while True:
            if number > max_value:
                number = 0
                # if max reached, we regenerate all targets to avoid overlap
                self.reload_conf_needed = True

                # if max reached before sending any packets, we have too much targets
                if self.first_iter:
                    raise Exception(
                        "Too much targets configured: " "not enough ID available in generator"
                    )

            offset = yield number
            number += offset

    def instantiate_generator(self):
        """Instantiate a new generator."""
        self.seq_gen = self.get_uniq_id(2 ** 31)
        self.id_gen = self.get_uniq_id(2 ** 16 - 1)
        next(self.seq_gen)
        next(self.id_gen)

    def getter(self, name):
        """Get global variable (useful for unit tests only)."""
        return globals()[name]

    def load_target_conf(self, target, target_name, target_groups):
        """Load target from a dict.

        Keyword arguments:
        target -- dict containing description of the target
        """
        if target["type"] == "TCPsyn":
            # create target
            target = TCPsyn(
                name=target_name,
                active=True,
                description=target.get("description", target_name),
                destination=None,
                config_destination=target["destination"],
                address_family=target.get("address_family", DEFAULT_ADDRESS_FAMILY),
                dont_fragment=target.get("dont_fragment", True),
                is_subnet=target.get("is_subnet", False),
                nb_packets=target.get("nb_packets", 1),
                interval=self.global_vars.get("interval_packets", 0),
                timeout=target.get("timeout", 1),
                dst_port=target["dst_port"],
                ip_payload_size=target.get("ip_payload_size"),
                threshold=target.get("threshold"),
                state=target.get("state"),
                alert_level=target.get("alert_level", "no_alert"),
                is_dynamic=target.get("is_dynamic", False),
                # dns_update interval is global if not specified
                dns_update_interval=target.get(
                    "dns_update_interval", self.global_vars.get("dns_update_interval", 0)
                ),
                groups=target_groups,
                creation_date=target.get("creation_date"),
                lifetime=target.get("lifetime"),
            )
        elif target["type"] == "ICMPping":
            # create target
            target = ICMPping(
                name=target_name,
                active=True,
                description=target.get("description", target_name),
                destination=None,
                config_destination=target["destination"],
                address_family=target.get("address_family", DEFAULT_ADDRESS_FAMILY),
                dont_fragment=target.get("dont_fragment", True),
                is_subnet=target.get("is_subnet", False),
                nb_packets=target.get("nb_packets", 1),
                interval=self.global_vars.get("interval_packets", 0),
                timeout=target.get("timeout", 1),
                ip_payload_size=target.get("ip_payload_size"),
                threshold=target.get("threshold"),
                state=target.get("state"),
                alert_level=target.get("alert_level", "no_alert"),
                is_dynamic=target.get("is_dynamic", False),
                # dns_update interval is global if not specified
                dns_update_interval=target.get(
                    "dns_update_interval", self.global_vars.get("dns_update_interval", 0)
                ),
                groups=target_groups,
                creation_date=target.get("creation_date"),
                lifetime=target.get("lifetime"),
            )
        elif target["type"] == "UDPunreachable":
            # create target
            target = UDPunreachable(
                name=target_name,
                active=True,
                description=target.get("description", target_name),
                destination=None,
                config_destination=target["destination"],
                address_family=target.get("address_family", DEFAULT_ADDRESS_FAMILY),
                dont_fragment=target.get("dont_fragment", True),
                is_subnet=target.get("is_subnet", False),
                nb_packets=target.get("nb_packets", 1),
                interval=self.global_vars.get("interval_packets", 0),
                timeout=target.get("timeout", 1),
                dst_port=target["dst_port"],
                ip_payload_size=target.get("ip_payload_size"),
                threshold=target.get("threshold"),
                state=target.get("state"),
                alert_level=target.get("alert_level", "no_alert"),
                is_dynamic=target.get("is_dynamic", False),
                # dns_update interval is global if not specified
                dns_update_interval=target.get(
                    "dns_update_interval", self.global_vars.get("dns_update_interval", 0)
                ),
                groups=target_groups,
                creation_date=target.get("creation_date"),
                lifetime=target.get("lifetime"),
            )
        elif target["type"] == "iperf":
            target = Iperf(
                name=target_name,
                active=True,
                description=target.get("description", target_name),
                destination=None,
                config_destination=target["destination"],
                address_family=target.get("address_family", DEFAULT_ADDRESS_FAMILY),
                dst_port=target["dst_port"],
                threshold=target.get("threshold"),
                state=target.get("state"),
                alert_level=target.get("alert_level", "no_alert"),
                is_dynamic=target.get("is_dynamic", False),
                # dns_update interval is global if not specified
                dns_update_interval=target.get(
                    "dns_update_interval", self.global_vars.get("dns_update_interval", 0)
                ),
                groups=target_groups,
                duration=target.get("iperf_parameters", {}).get("duration", 5),
                bandwidth=target.get("iperf_parameters", {}).get("bandwidth_per_stream", "1M"),
                protocol=target.get("iperf_parameters", {}).get("protocol", "udp"),
                num_streams=target.get("iperf_parameters", {}).get("nb_parallel_streams", 1),
                creation_date=target.get("creation_date"),
                lifetime=target.get("lifetime"),
            )
        else:
            return

        # we put the target in the right list
        if target.is_dynamic:
            if target.is_special:
                self.list_dynamic_special_targets.append(target)
            else:
                self.list_dynamic_targets.append(target)
        else:
            if target.is_special:
                self.list_special_targets.append(target)
            else:
                self.list_targets.append(target)

    def load_conf(self, schema_file="schema_config.yaml"):
        """Load the configuration from a config file.

        Keyword arguments:
        schema_file -- relative/absolute path and filename for yaml schema
        """
        log.debug("Loading configuration")

        # cleaning targets list
        self.list_groups = []
        self.list_targets = []
        self.list_special_targets = []
        self.list_target_name = []
        self.global_vars = {}
        self.first_iter = True

        # instantiate a new generator
        self.instantiate_generator()

        # validate yaml config with the schema
        schema = pkg_resources.resource_filename(__name__, schema_file)
        yaml_validator = Core(source_file=self.config_file, schema_files=[schema])
        yaml_validator.validate(raise_exception=True)

        # we load the configuration from the file
        with open(self.config_file, "r") as conf_file:
            # load as a yaml
            conf = yaml.safe_load(conf_file)

        # get global variables
        self.global_vars = conf["global"]

        # setting logging level
        log.setLevel(self.global_vars["logging_level"])

        # setting default percentile values if needed
        if self.global_vars.get("percentile") is None:
            self.global_vars["percentile"] = [95, 50]

        # get groups
        for group_name in conf["groups"]:
            group = conf["groups"][group_name]
            self.list_groups.append(
                Group(
                    name=group_name,
                    src_ipv4=group.get("src_ipv4", group.get("src_ip")),
                    src_ipv6=group.get("src_ipv6"),
                    src_subnet_ipv4=group.get("src_subnet_ipv4"),
                    src_subnet_ipv6=group.get("src_subnet_ipv6"),
                    src_port_a=group.get("src_port_a", 65000),
                    src_port_z=group.get("src_port_z", 65001),
                    ip_payload_size=group.get("ip_payload_size"),
                    dscp=group.get("dscp", 0),
                    permit_target_auto_register=group.get("permit_target_auto_register", True),
                )
            )

        # check targets are set
        if not conf.get("targets"):
            return

        # get target list
        for target_name in conf["targets"]:
            target = conf["targets"][target_name]

            if not target.get("address_family"):
                try:
                    ip = ip_address(target.get("destination"))
                    target["address_family"] = "ipv{}".format(ip.version)
                except ValueError:
                    log.debug(
                        "was not able to detect address-family from destination"
                        ", setting to default (%s)",
                        DEFAULT_ADDRESS_FAMILY,
                    )
                    target["address_family"] = DEFAULT_ADDRESS_FAMILY

            if target_name in self.list_target_name:
                log.warning("Duplicate target name %s", target_name)
                APP_TARGET_NAME_DUP.labels(target_name=target_name).inc(1)
            else:
                self.list_target_name.append(target_name)

            # manage group association
            target_groups = set()

            # we register to all group if allowed
            if target.get("auto_register_to_groups", True):
                for grp in self.list_groups:
                    if grp.permit_target_auto_register:
                        target_groups.add(grp.name)

            # we explicitly register to a group
            for grp in target.get("explicit_groups", {}).get("register_to", []):
                if grp in conf["groups"]:
                    target_groups.add(grp)
                else:
                    log.warning(
                        "Trying to associate '%s' to an inexistant group: %s", target_name, grp
                    )

            # we remove the target from a group
            for grp in target.get("explicit_groups", {}).get("exclude_from", []):
                try:
                    target_groups.remove(grp)
                except Exception:
                    log.info("Failed to remove target %s from %s", target_name, grp)

            # create target objects
            self.load_target_conf(target, target_name, target_groups)

            log.debug("Target %s created", target_name)

            if len(target_groups) == 0 and target["type"] != "iperf":
                log.warning("Target %s disabled: not associated to any group", target_name)

    def update_hosts(self, force=False):
        """Update targets with host resolution.

        force -- force all target to update (after a reload conf for example)
        """
        # we get  our local IP addresses
        self_ips = {af: list_self_ips(af, scapyconf) for af in ("ipv4", "ipv6")}
        for target in itertools.chain(
            self.list_targets,
            self.list_special_targets,
            self.list_dynamic_targets,
            self.list_dynamic_special_targets,
        ):
            if len(target.groups):
                changed = False

                if not target.is_dynamic:
                    # we update all target if needed
                    if (
                        not force
                        and target.dns_update_interval > 0
                        and target.time_to_refresh > time.time()
                    ):
                        continue

                log.debug("%s: updating", target.name)

                # we try to resolve the hostname if not a subnet
                if not target.is_subnet:
                    new_ip = common.resolve_hostname(
                        target.config_destination, target.address_family
                    )
                else:
                    new_ip = target.config_destination

                # if the resolution failed
                if new_ip is None:
                    # we disable the target and register the failure
                    target.active = False
                    APP_HOST_RESOLUTION.labels(
                        probe_name=self.global_vars["probe_name"],
                        destination=target.name,
                        address_family=target.address_family,
                    ).set(0)
                    log.warning("Hostname resolution failed for %s", target.name)
                elif new_ip != target.destination:
                    # we enable the target and register the change and success
                    target.active = True
                    changed = True
                    APP_HOST_RESOLUTION.labels(
                        probe_name=self.global_vars["probe_name"],
                        destination=target.name,
                        address_family=target.address_family,
                    ).set(1)

                # we update the destination of the target
                target.destination = new_ip

                # we prevent the probe to ping itself to avoid issues (known bug)
                if new_ip in self_ips[target.address_family]:
                    target.active = False
                    log.info("Disabling %s because destination is the local machine", target.name)

                # we generate the packets for the target if active
                if target.active and changed:
                    log.debug("%s: changed. New IP address is %s", target.name, new_ip)
                    if isinstance(target, TCPsyn):
                        target.generate_packets(
                            self.list_groups, self.seq_gen, self.global_vars["logging_level"]
                        )
                    elif isinstance(target, UDPunreachable):
                        target.generate_packets(
                            self.list_groups, self.id_gen, self.global_vars["logging_level"]
                        )
                    elif isinstance(target, ICMPping):
                        target.generate_packets(self.list_groups, self.global_vars["logging_level"])

                    APP_HOST_RESOLUTION_CHANGE.labels(
                        probe_name=self.global_vars["probe_name"],
                        destination=target.name,
                        address_family=target.address_family,
                    ).inc()

                # we expose threshold if target is active
                if target.active and target.threshold:
                    # we clear the previous THRESHOLD metrics in case of changes
                    self.clear_metrics([THRESHOLD], "destination", [target.name])

                    for threshold_name in target.threshold:
                        threshold = target.threshold[threshold_name]
                        THRESHOLD.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=target.name,
                            address_family=target.address_family,
                            state=target.state,
                            type=threshold_name,
                            alert_level=target.alert_level,
                        ).set(threshold)

                target.time_to_refresh = time.time() + target.dns_update_interval
            else:
                # if there is no group associated the target is disabled (nothing to target)
                target.active = False
                log.warning("%s: disabled because no group associated", target.name)

            if not target.active:
                self.clear_metrics(LIST_TARGET_MEASUREMENT_METRICS, "destination", [target.name])

    def clear_metrics(self, list_prom_obj, label_to_clear, list_value_to_clear):
        """Clear metrics when target has been deleted.

        It will clear every metrics contained in list_value_to_clear for the given label_to_clear.

        Keyword arguments:
        list_prom_obj -- list of prometheus object which has to be cleaned
        label_to_clear -- list of label of the value to clear (example: "destination")
        list_value_to_clear -- list of value to clear (example: "google")
        """
        log.debug("Cleaning metrics")
        # we clean the metrics from each Prometheus objects
        for prom in list_prom_obj:
            # if the metric contains the label to clear
            if label_to_clear in prom.__dict__["_labelnames"]:
                # we record the position of the label value in the tuple
                index_to_clear = prom.__dict__["_labelnames"].index(label_to_clear)

                metrics_to_clear = []
                for metrics in prom.__dict__["_metrics"]:
                    # we store the tuple of the metric if the label value matches
                    if metrics[index_to_clear] in list_value_to_clear:
                        metrics_to_clear.append(metrics)

                # clearing selected metrics
                for metrics in metrics_to_clear:
                    prom.remove(*metrics)

    def reload_conf(self):
        """Reload configuration on the fly."""
        log.warning("Reloading configuration...")
        self.reload_conf_needed = False

        # we backup the target list
        list_target_before = set()
        for target in itertools.chain(self.list_targets, self.list_dynamic_targets):
            list_target_before.add(target.name)

        list_group_before = set()
        for group in self.list_groups:
            list_group_before.add(group.name)

        # backup config before reload
        backup_list_groups = self.list_groups
        backup_list_targets = self.list_targets
        backup_list_target_name = self.list_target_name
        backup_global_vars = self.global_vars
        try:
            # reloading configuration, it also reset the list of probes/groups
            self.load_conf()
        except Exception:
            # we rollback
            self.list_groups = backup_list_groups
            self.list_targets = backup_list_targets
            self.list_target_name = backup_list_target_name
            self.global_vars = backup_global_vars
            log.exception("Error: configuration reload failed. Rollback.")
            APP_RELOAD_CONF_FAILED.labels(probe_name=self.global_vars["probe_name"]).set(1)
        else:
            # if config load succeeded:
            # updating static targets
            self.update_hosts(True)

            # we get the new targets list
            list_target_after = set()
            for target in itertools.chain(self.list_targets, self.list_dynamic_targets):
                list_target_after.add(target.name)

            list_group_after = set()
            for group in self.list_groups:
                list_group_after.add(group.name)

            # we clean metrics for removed objects
            target_to_clean = list_target_before - list_target_after
            groups_to_clean = list_group_before - list_group_after

            percentile_to_clean = set(backup_global_vars["percentile"]) - set(
                self.global_vars["percentile"]
            )

            percentile_to_clean_str = set()
            for per in percentile_to_clean:
                percentile_to_clean_str.add(str(per))

            # get reference list of Prometheus objects
            self.clear_metrics(LIST_TARGET_METRICS, "destination", target_to_clean)
            self.clear_metrics(LIST_TARGET_METRICS, "group", groups_to_clean)
            self.clear_metrics(LIST_TARGET_METRICS, "percentile", percentile_to_clean_str)

            # if probe_name changed, we clean all target metrics
            if backup_global_vars["probe_name"] != self.global_vars["probe_name"]:
                self.clear_metrics(
                    LIST_TARGET_METRICS, "probe_name", backup_global_vars["probe_name"]
                )

            log.warning("Configuration reloaded")
            APP_RELOAD_CONF_FAILED.labels(probe_name=self.global_vars["probe_name"]).set(0)

    def get_metrics(self):
        """Get metrics, calculate and expose."""
        log.debug("Updating metrics")
        # we get the values and add it to prometheus metrics
        for res in self.result:
            log.debug("%s: updating metrics", res["name"])

            for grp in self.list_groups:
                if grp.name in res["groups"]:
                    sent = 0
                    loss = 0
                    timestamp_ooo = 0
                    latency = []

                    if res["probing_type"] in ("TCPsyn", "UDPunreachable"):
                        # get some metrics
                        if res["probing_type"] == "TCPsyn":
                            match_fail = res["match_fail"]

                        port_mismatch = res["port_mismatch"]

                        # we get all metrics for the group port range
                        for port in range(grp.src_port_a, grp.src_port_z + 1):
                            sent += res[port]["sent"]
                            loss += res[port]["loss"]
                            latency += res[port]["latency"]
                            timestamp_ooo += res[port]["timestamp_ooo"]
                    elif res["probing_type"] == "ICMPping":
                        sent = res[grp.dscp]["sent"]
                        loss = res[grp.dscp]["loss"]
                        latency = res[grp.dscp]["latency"]
                        timestamp_ooo = res[grp.dscp]["timestamp_ooo"]

                    name = res["name"]
                    address_family = res["address_family"]

                    # we calculate the percentile values requested in config file
                    latency.sort()

                    results_percentile = {}
                    for percent in self.global_vars["percentile"]:
                        results_percentile[percent] = percentile(latency, percent=percent / 100)
                        if results_percentile[percent] is None:
                            results_percentile[percent] = 0

                    APP_TIME_OOO.labels(
                        probe_name=self.global_vars["probe_name"],
                        destination=name,
                        address_family=address_family,
                        group=grp.name,
                    ).inc(timestamp_ooo)

                    if res["probing_type"] == "TCPsyn":
                        TCP_SENT.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(sent)

                        TCP_LOSS.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(loss)

                        TCP_LOSS_RATIO.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(loss / sent)

                        for percent, result in results_percentile.items():
                            TCP_ROUND_TRIP.labels(
                                probe_name=self.global_vars["probe_name"],
                                destination=name,
                                address_family=address_family,
                                state=res["state"],
                                group=grp.name,
                                percentile=percent,
                            ).set(result)

                        TCP_MATCH_ACK_FAIL.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                        ).inc(match_fail)

                        TCP_PORT_MISTMATCH.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                        ).inc(port_mismatch)

                    elif res["probing_type"] == "ICMPping":
                        ICMP_SENT.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(sent)

                        ICMP_LOSS.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(loss)

                        ICMP_LOSS_RATIO.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(loss / sent)

                        for percent, result in results_percentile.items():
                            ICMP_ROUND_TRIP.labels(
                                probe_name=self.global_vars["probe_name"],
                                destination=name,
                                address_family=address_family,
                                state=res["state"],
                                group=grp.name,
                                percentile=percent,
                            ).set(result)

                    elif res["probing_type"] == "UDPunreachable":
                        UDP_UNREACHABLE_SENT.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(sent)

                        UDP_UNREACHABLE_LOSS.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).inc(loss)

                        UDP_UNREACHABLE_LOSS_RATIO.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(loss / sent)

                        for percent, result in results_percentile.items():
                            UDP_UNREACHABLE_ROUND_TRIP.labels(
                                probe_name=self.global_vars["probe_name"],
                                destination=name,
                                address_family=address_family,
                                state=res["state"],
                                group=grp.name,
                                percentile=percent,
                            ).set(result)

                        UDP_UNREACHABLE_PORT_MISTMATCH.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                        ).inc(port_mismatch)
                    elif res["probing_type"] == "iperf":
                        loss_ratio = res["loss"] / res["sent"] if res["sent"] != 0 else 0
                        IPERF_SENT.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(res["sent"])

                        IPERF_LOSS.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(res["loss"])

                        IPERF_LOSS_RATIO.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(loss_ratio)

                        IPERF_BANDWIDTH.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(res["bandwidth"])

                        IPERF_OUT_OF_ORDER.labels(
                            probe_name=self.global_vars["probe_name"],
                            destination=name,
                            address_family=address_family,
                            state=res["state"],
                            group=grp.name,
                        ).set(res["out_of_order"])

    def reload_request(self, signum, frame):
        """Reload handler for SIGHUP. Will reload the configuration.

        Keyword arguments:
        signum -- signal number
        frame -- None or a frame object. Represents execution frames
        """
        log.warning("Reload requested...")
        self.reload_conf_needed = True

    def stop_request(self, signum, frame):
        """Stop handler for SIGTERM and SIGINT.

        Keyword arguments:
        signum -- signal number
        frame -- None or a frame object. Represents execution frames
        """
        log.warning("Process %i exiting...", os.getpid())
        os._exit(0)

    def check_expiration(self, target):
        """Check if the target is expired.

        Keyword arguments:
        target -- target to check
        """
        # if there is no value set we consider it is not expired
        if (
            not target.get("lifetime")
            or not target.get("creation_date")
            or target.get("lifetime") == timedelta(0)
        ):
            return False

        expiration_date = target["creation_date"] + target.get("lifetime")
        return datetime.now() > expiration_date

    def get_dynamic_targets(self):
        """Get targets from dynamic inventories."""
        log.debug("Getting dynamic targets")

        # cleaning outdated targets
        for inventory in self.shared_dynamic_targets.keys():
            dynamic_targets = self.shared_dynamic_targets[inventory]
            for target in dynamic_targets:
                if self.check_expiration(target):
                    log.info("{}: {} is expired".format(inventory, target["hostname"]))
                    dynamic_targets.remove(target)
                    continue
            self.shared_dynamic_targets[inventory] = dynamic_targets

        # we check if the targets changed
        if self.shared_dynamic_targets_backup.__eq__(self.shared_dynamic_targets.copy()):
            # we do not need to load the targets
            log.debug("No dynamic targets changes")
            return

        log.debug("Loading new dynamic targets")

        # we reset the targets
        self.list_dynamic_targets = []
        self.list_dynamic_special_targets = []

        # get targets by inventory
        for inventory in self.shared_dynamic_targets.keys():
            for target in self.shared_dynamic_targets[inventory]:
                # specific parameters for dynamic targets
                target_name = "{0}_{1}".format(inventory, target["hostname"])
                target["description"] = "from_{0}".format(inventory)
                target["is_dynamic"] = True

                # create target objects
                self.load_target_conf(target, target_name, target.get("groups"))

        # we clean the targets removed or changed
        for inventory in self.shared_dynamic_targets_backup.keys():
            # we browse all targets in the previous target list
            for target in self.shared_dynamic_targets_backup.get(inventory, []):
                # we check if target is still here and not changed
                if target not in self.shared_dynamic_targets.get(inventory, []):
                    # we clear Prometheus metrics
                    target_name = "{0}_{1}".format(inventory, target["hostname"])
                    log.debug("%s: cleaning metrics (dynamic target)", target_name)
                    self.clear_metrics(LIST_TARGET_METRICS, "destination", target_name)

        # we backup the targets list
        self.shared_dynamic_targets_backup = self.shared_dynamic_targets.copy()
        log.debug("Dynamic targets loaded and backup done")

    def get_dynamic_inventories(self, path, import_path):
        """Get module path and name of dynamic inventories."""
        list_module = []
        for _, module_name, is_pkg in pkgutil.iter_modules(path):
            if module_name in self.global_vars.get("disable_dynamic_inventories", []):
                log.warning("Dynamic inventory '%s' disabled", module_name)
                continue

            if is_pkg:
                pkg_path = ["{}/{}".format(path[0], module_name)]
                pkg_import_path = "{}.{}".format(import_path, module_name)
                list_rec = self.get_dynamic_inventories(pkg_path, pkg_import_path)
                list_module.extend(list_rec)
            else:
                module_path = "{}.{}".format(import_path, module_name)
                list_module.append((module_name, module_path))

        return list_module

    def load_dynamic_inventories(self):
        """Load dynamically all inventories in different processes."""
        log.debug("Loading dynamic inventories")
        # creating the manager to share a dictionary
        manager = Manager()
        self.shared_dynamic_targets = manager.dict()

        list_module = self.get_dynamic_inventories(dynamic_inventories.__path__, "")

        # we run each dynamic inventory modules in different processes
        for module_name, module_path in list_module:
            if module_name in self.global_vars.get("disable_dynamic_inventories", []):
                log.warning("Dynamic inventory '%s' disabled", module_name)
                continue

            log.warning("Dynamic inventory '%s' enabled", module_name)

            # we import the module manually
            module = importlib.import_module("netprobify.dynamic_inventories{}".format(module_path))

            log.info("Loading %s module", module_name)

            # we start the process using "module".start()
            process = Process(
                target=module.start,
                args=(
                    self.shared_dynamic_targets,
                    module_name,
                    self.global_vars["logging_level"],
                    "{0}.yaml".format(module_name),
                ),
            )
            process.start()

    def start_processes(self, target_list, timeout):
        """Orchestrate probing among processes.

        Keyword arguments:
        target_list: list of target objects to run in processes
        """
        jobs = []
        manager = Manager()
        self.result = manager.list()

        # start the probing in processes
        for target in target_list:
            if target.active:
                # create, reference and start processes
                process = Process(
                    target=target.send_packets,
                    args=(
                        self.result,
                        self.global_vars["logging_level"],
                        self.list_groups,
                        self.global_vars.get("verbose", 0),
                        self.global_vars.get("l3_raw_socket", False),
                    ),
                )
                jobs.append(process)
                process.start()
                # wait for available process
                while len(jobs) > self.global_vars["nb_proc"] - 1:
                    # check if processes are finished
                    for i in reversed(range(len(jobs))):
                        if not jobs[i].is_alive():
                            jobs.pop(i)

        log.debug("No targets in the queue anymore")
        # wait for all process to finish
        for j in jobs:
            j.join(timeout=timeout)

            # if the timeout is reached and the process is still alive
            if j.is_alive():
                APP_PROCESS_TIMED_OUT.labels(probe_name=self.global_vars["probe_name"]).inc()
                log.warning("A probing process has timed out")
                j.terminate()
                j.join()
        log.info("All targets have been processed")

        # get and expose metrics
        self.get_metrics()

    def _expose_version(self):
        try:
            version = pkg_resources.require("netprobify")[0].version
        except pkg_resources.DistributionNotFound:
            with open("VERSION") as ver_file:
                version = ver_file.read().splitlines()[0]

        log.info("running netprobify %s, using scapy %s", version, scapy.VERSION)
        NETPROBIFY_INFO.labels(version=version, scapy_version=scapy.VERSION).set(1)

    def main(self):
        """Entry point."""
        # handling signal
        signal.signal(signal.SIGTERM, self.stop_request)
        signal.signal(signal.SIGINT, self.stop_request)
        signal.signal(signal.SIGHUP, self.reload_request)

        # load configuration
        try:
            self.load_conf()
        except SchemaError:
            log.exception("Config file: YAML validation error")
            os._exit(os.EX_DATAERR)
        except Exception:
            log.exception("Error: configuration load failed")
            os._exit(os.EX_DATAERR)

        # start dynamic inventories
        self.load_dynamic_inventories()

        # DNS resolution, enable healthy targets
        self.update_hosts(True)

        # we calculate when we will have to reload the configuration
        time_to_reload = time.time() + self.global_vars.get("reload_conf_interval", 0)

        # start prometheus http server
        start_http_server(
            self.global_vars["prometheus_port"],
            addr=self.global_vars.get("prometheus_address", "0.0.0.0"),
        )
        self._expose_version()
        log.info(
            "HTTP server started and listening on port %i", self.global_vars["prometheus_port"]
        )

        # initialize the metric
        APP_RELOAD_CONF_FAILED.labels(probe_name=self.global_vars["probe_name"]).set(0)

        # starting the loop
        while True:
            log.info("Starting new probing iteration")
            round_start = time.time()

            # start probing only for standard targets
            self.start_processes(
                itertools.chain(self.list_targets, self.list_dynamic_targets),
                self.global_vars.get("timeout", 3600),
            )

            # start probing only for special targets which are not a priority
            remaining_time = self.global_vars["interval"] - (time.time() - round_start)
            self.start_processes(self.list_special_targets, remaining_time)

            # the first iteration is done
            self.first_iter = False

            # get targets from dynamic inventories
            self.get_dynamic_targets()
            self.update_hosts()

            # Reload configuration if interval reached
            if time.time() > time_to_reload and self.global_vars.get("reload_conf_interval", 0) > 0:
                self.reload_conf_needed = True

            # reload configuration if necessary
            if self.reload_conf_needed:
                self.reload_conf()

                time_to_reload = time.time() + self.global_vars.get("reload_conf_interval", 0)

            # calculate the round time
            round_duration = time.time() - round_start
            APP_ROUND_TIME.labels(probe_name=self.global_vars["probe_name"]).set(round_duration)
            log.info("Probing iteration finished in %i seconds", round_duration)

            # wait the appropriate time to respect interval set in config
            time_to_wait = self.global_vars["interval"] - round_duration
            if time_to_wait > 0:
                log.info("Waiting %i seconds", time_to_wait)
                time.sleep(time_to_wait)


def entrypoint():
    """Entrypoint of the program."""
    start = None

    # load the script with a custom config file if any
    if len(sys.argv) > 1:
        f = sys.argv[1]
        if os.path.isfile(f):
            start = NetProbify(f)
    else:
        start = NetProbify()

    start.main()
