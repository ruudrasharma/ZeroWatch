"""
ZeroWatch ML — dataset loading (NSL-KDD).

Direct .py port of notebook cells 5, 7 (ZeroWatch_Model_Training.ipynb §2-3).
NSL-KDD downloads from a public GitHub mirror, no auth required — see
ml/README.md for the documented CICIDS2017/2018 swap-in notes.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import io

import httpx
import pandas as pd

TRAIN_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
TEST_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"

COL_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

# NSL-KDD's 39+ specific attack names, grouped into the 5 standard research
# categories. This is the granularity leave-one-attack-out holds categories
# out at (notebook cell 7).
ATTACK_MAP = {
    "normal": "Normal",
    # DoS
    "neptune": "DoS", "back": "DoS", "land": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    "apache2": "DoS", "worm": "DoS",
    # Probe
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R", "perl": "U2R",
    "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
}

HELD_OUT_CATEGORIES = ["DoS", "Probe", "R2L", "U2R"]


def _fetch_csv(url: str) -> pd.DataFrame:
    """
    Fetches via httpx (which uses certifi's CA bundle) rather than letting
    pandas.read_csv() open the URL directly through stdlib urllib — a stock
    python.org macOS build doesn't link the system trust store, so a raw
    urllib fetch fails with CERTIFICATE_VERIFY_FAILED there.
    """
    resp = httpx.get(url, timeout=30.0, follow_redirects=True)
    resp.raise_for_status()
    return pd.read_csv(io.StringIO(resp.text), names=COL_NAMES)


def load_nsl_kdd() -> pd.DataFrame:
    """Downloads and concatenates KDDTrain+/KDDTest+, maps labels into the 5
    attack categories. We build our own leave-one-out splits downstream, so
    the original train/test split is discarded here (concatenated first)."""
    df_train_raw = _fetch_csv(TRAIN_URL)
    df_test_raw = _fetch_csv(TEST_URL)
    df = pd.concat([df_train_raw, df_test_raw], ignore_index=True)
    df = df.drop(columns=["difficulty"])

    df["label"] = df["label"].str.strip()
    df["attack_category"] = df["label"].map(ATTACK_MAP)
    df["attack_category"] = df["attack_category"].fillna("Other")
    return df
