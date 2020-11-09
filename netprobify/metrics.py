"""Prometheus metrics."""

from prometheus_client import Counter, Gauge

# version
NETPROBIFY_INFO = Gauge(
    "netprobify_info",
    "some info regarding netprobify",
    ["version", "scapy_version"]
)

# prometheus metrics - TCP probe
TCP_SENT = Counter(
    "tcpsyn_sent_total",
    "number of sent packets using tcp syn stealth probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
TCP_LOSS = Counter(
    "tcpsyn_loss_total",
    "number of lost packets using tcp syn stealth probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
TCP_LOSS_RATIO = Gauge(
    "tcpsyn_loss_ratio",
    "loss ratio using tcp syn stealth probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
TCP_ROUND_TRIP = Gauge(
    "tcpsyn_round_trip_seconds",
    "percentile latency in seconds using tcp syn stealth probing.",
    ["probe_name", "destination", "address_family", "state", "group", "percentile"],
)
TCP_MATCH_ACK_FAIL = Gauge(
    "tcpsyn_match_ack_fail_count",
    "fail to match response packet with sent packet using ack.",
    ["probe_name", "destination", "address_family"],
)
TCP_PORT_MISTMATCH = Gauge(
    "tcpsyn_port_mismatch_count",
    "port source/destination mismatch.",
    ["probe_name", "destination", "address_family"],
)

# prometheus metrics - ICMP probe
ICMP_SENT = Counter(
    "icmp_sent_total",
    "number of sent packets using ICMP ping probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
ICMP_LOSS = Counter(
    "icmp_loss_total",
    "number of lost packets using ICMP ping probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
ICMP_LOSS_RATIO = Gauge(
    "icmp_loss_ratio",
    "loss ratio using ICMP ping probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
ICMP_ROUND_TRIP = Gauge(
    "icmp_round_trip_seconds",
    "percentile latency in seconds using ICMP ping probing.",
    ["probe_name", "destination", "address_family", "state", "group", "percentile"],
)

# prometheus metrics - UDP probe
UDP_UNREACHABLE_SENT = Counter(
    "udp_unreachable_sent_total",
    "number of sent packets using udp unreachable probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
UDP_UNREACHABLE_LOSS = Counter(
    "udp_unreachable_loss_total",
    "number of lost packets using udp unreachable probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
UDP_UNREACHABLE_LOSS_RATIO = Gauge(
    "udp_unreachable_loss_ratio",
    "loss ratio using udp unreachable probing.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
UDP_UNREACHABLE_ROUND_TRIP = Gauge(
    "udp_unreachable_round_trip_seconds",
    "percentile latency in seconds using udp unreachable probing.",
    ["probe_name", "destination", "address_family", "state", "group", "percentile"],
)
UDP_UNREACHABLE_PORT_MISTMATCH = Gauge(
    "udp_unreachable_port_mismatch_count",
    "port source/destination mismatch.",
    ["probe_name", "destination", "address_family"],
)

# prometheus metrics - iperf probe
IPERF_SENT = Gauge(
    "iperf_sent_total",
    "number of sent packets reported by iperf.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
IPERF_LOSS = Gauge(
    "iperf_loss_total",
    "number of lost packets reported by iperf.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
IPERF_LOSS_RATIO = Gauge(
    "iperf_loss_ratio",
    "loss ratio reported by iperf.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
IPERF_BANDWIDTH = Gauge(
    "iperf_bandwidth_bps",
    "bandwidth reported by iperf.",
    ["probe_name", "destination", "address_family", "state", "group"],
)
IPERF_OUT_OF_ORDER = Gauge(
    "iperf_out_of_order_count",
    "port source/destination mismatch.",
    ["probe_name", "destination", "address_family", "state", "group"],
)

# prometheus metrics - common
THRESHOLD = Gauge(
    "threshold",
    "threshold for alerting systems.",
    ["probe_name", "destination", "address_family", "type", "state", "alert_level"],
)

# prometheus metrics - app health
APP_HOST_RESOLUTION = Gauge(
    "app_host_resolution_status",
    "hostname resolution status.",
    ["probe_name", "destination", "address_family"],
)
APP_HOST_RESOLUTION_CHANGE = Counter(
    "app_host_resolution_change_total",
    "number of hostname resolution change.",
    ["probe_name", "destination", "address_family"],
)
APP_TIME_OOO = Counter(
    "app_time_ooo_total",
    "number of out of order - timestamp issue.",
    ["probe_name", "destination", "address_family", "group"],
)
APP_ROUND_TIME = Gauge(
    "app_iteration_time_seconds", "time to finish one round of probing.", ["probe_name"]
)
APP_TARGET_NAME_DUP = Counter(
    "app_target_name_dup_total", "number of target name duplicated.", ["target_name"]
)
APP_PROCESS_TIMED_OUT = Counter(
    "app_process_timed_out_total",
    "a process was taking too long and had timed out.",
    ["probe_name"],
)
APP_RELOAD_CONF_FAILED = Gauge(
    "app_reload_conf_failed_status", "failed to load the configuration file.", ["probe_name"]
)

# list of Prometheus objects

LIST_TARGET_HEALTH_METRICS = [
    APP_TIME_OOO,
    APP_HOST_RESOLUTION,
    APP_HOST_RESOLUTION_CHANGE,
    THRESHOLD,
]

LIST_TARGET_MEASUREMENT_METRICS = [
    TCP_ROUND_TRIP,
    TCP_SENT,
    TCP_LOSS,
    TCP_LOSS_RATIO,
    UDP_UNREACHABLE_ROUND_TRIP,
    UDP_UNREACHABLE_SENT,
    UDP_UNREACHABLE_LOSS,
    UDP_UNREACHABLE_LOSS_RATIO,
    ICMP_SENT,
    ICMP_LOSS,
    ICMP_ROUND_TRIP,
    ICMP_LOSS_RATIO,
    IPERF_SENT,
    IPERF_LOSS,
    IPERF_LOSS_RATIO,
    IPERF_BANDWIDTH,
    IPERF_OUT_OF_ORDER,
]

LIST_TARGET_METRICS = LIST_TARGET_HEALTH_METRICS + LIST_TARGET_MEASUREMENT_METRICS
