"""
ZeroWatch - shared feature contract.

One place that defines the 20 input features, their allowed ranges/values and
how a raw network flow becomes the numeric vector the models see. train.py
(training) and app.py (serving) both import from here, so the two can never
drift apart ("training/serving skew").

Team: Bhavishyata Yadav (24CSU036), Bhavya Jain (24CSU037), Rudra Kumar Sharma (24CSU175)
"""
from __future__ import annotations

import math

PROTOCOLS = ["tcp", "udp", "icmp"]
FLAGS = ["SF", "S0", "REJ", "RSTR", "RSTO", "S1", "S2", "S3", "SH", "RSTOS0", "OTH"]
SERVICES = [
    "IRC", "X11", "Z39_50", "aol", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
    "discard", "domain", "domain_u", "echo", "eco_i", "ecr_i", "efs", "exec", "finger", "ftp",
    "ftp_data", "gopher", "harvest", "hostnames", "http", "http_2784", "http_443", "http_8001",
    "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login", "mtp", "name",
    "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp", "ntp_u", "other",
    "pm_dump", "pop_2", "pop_3", "printer", "private", "red_i", "remote_job", "rje", "shell",
    "smtp", "sql_net", "ssh", "sunrpc", "supdup", "systat", "telnet", "tftp_u", "tim_i", "time",
    "urh_i", "urp_i", "uucp", "uucp_path", "vmnet", "whois",
]

# name, kind, (low, high) or allowed values, why it matters.  This table IS the
# data contract: README, Pydantic schema and UI form are all generated from it.
CONTRACT = [
    ("duration", "int", (0, 86400), "Connection length in seconds; very long or zero-length flows are unusual"),
    ("protocol_type", "cat", PROTOCOLS, "Transport protocol; ICMP/UDP floods look different from TCP abuse"),
    ("service", "cat", SERVICES, "Destination service (http, ftp, private...); attacks cluster on a few services"),
    ("flag", "cat", FLAGS, "TCP connection status; S0/REJ (no reply / rejected) signal floods and scans"),
    ("src_bytes", "int", (0, 2_000_000_000), "Bytes sent by the source; near-zero for scans, huge for exfiltration"),
    ("dst_bytes", "int", (0, 2_000_000_000), "Bytes returned by the destination"),
    ("logged_in", "int", (0, 1), "1 if a login succeeded; most attacks never authenticate"),
    ("wrong_fragment", "int", (0, 3), "Malformed IP fragments (teardrop / pod style DoS)"),
    ("hot", "int", (0, 101), "Count of 'hot' indicators such as entering system directories"),
    ("num_failed_logins", "int", (0, 5), "Failed login attempts; password guessing signal"),
    ("root_shell", "int", (0, 1), "1 if a root shell was obtained; privilege-escalation signal"),
    ("count", "int", (0, 511), "Connections to the same host in the last 2 seconds; flood volume"),
    ("srv_count", "int", (0, 511), "Connections to the same service in the last 2 seconds"),
    ("serror_rate", "float", (0.0, 1.0), "Share of those connections with SYN errors; SYN-flood signature"),
    ("rerror_rate", "float", (0.0, 1.0), "Share with REJ errors; closed-port probing signature"),
    ("same_srv_rate", "float", (0.0, 1.0), "Share going to the same service; low values mean service sweeping"),
    ("diff_srv_rate", "float", (0.0, 1.0), "Share going to different services; port-scan signal"),
    ("dst_host_count", "int", (0, 255), "Connections seen by the destination host (last 100)"),
    ("dst_host_srv_count", "int", (0, 255), "Of those, how many used the same service"),
    ("dst_host_serror_rate", "float", (0.0, 1.0), "SYN-error share at the destination host level"),
]
FEATURES = [c[0] for c in CONTRACT]
CATEGORICAL = {"protocol_type": PROTOCOLS, "service": SERVICES, "flag": FLAGS}
CAT_INDEX = [i for i, n in enumerate(FEATURES) if n in CATEGORICAL]
NUM_INDEX = [i for i, n in enumerate(FEATURES) if n not in CATEGORICAL]
LOG_FEATURES = {"duration", "src_bytes", "dst_bytes"}  # heavy-tailed -> log1p
TARGET = "is_attack"

FAMILIES = ["DoS", "Probe", "R2L", "U2R"]


def encode(flow: dict) -> list[float]:
    """Raw flow dict -> numeric row. Categories become their index in the
    contract list (tree models use it directly, the logistic pipeline one-hot
    encodes it); byte/duration counts are log-scaled."""
    row = []
    for name in FEATURES:
        v = flow[name]
        if name in CATEGORICAL:
            row.append(float(CATEGORICAL[name].index(v)))
        elif name in LOG_FEATURES:
            row.append(math.log1p(float(v)))
        else:
            row.append(float(v))
    return row


def decode_value(name: str, x: float):
    """Inverse of encode() for one feature (used to show baselines in the UI)."""
    if name in CATEGORICAL:
        return CATEGORICAL[name][int(round(x))]
    if name in LOG_FEATURES:
        return int(round(math.expm1(x)))
    kind = next(c[1] for c in CONTRACT if c[0] == name)
    return round(float(x), 2) if kind == "float" else int(round(x))
