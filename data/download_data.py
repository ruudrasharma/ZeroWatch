"""
Download NSL-KDD and build data/nsl_kdd.csv (the file train.py reads).

Source: NSL-KDD (Canadian Institute for Cybersecurity, University of New
Brunswick) - https://www.unb.ca/cic/datasets/nsl.html
Mirror used: https://github.com/jmnwong/NSL-KDD-Dataset

Keeps only the 20 contract features plus:
  label          original attack name (normal, neptune, ...)
  attack_family  Normal / DoS / Probe / R2L / U2R
  is_attack      target, 0 = normal, 1 = attack
  split          train (KDDTrain+) or test (KDDTest+, contains attack types absent from train)

Usage:  python data/download_data.py
"""
from __future__ import annotations

import io
import sys
import urllib.request
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from features import FEATURES  # noqa: E402

BASE = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/"
FILES = {"train": "KDDTrain%2B.txt", "test": "KDDTest%2B.txt"}
COLS = [
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
FAMILY = {"normal": "Normal"}
FAMILY |= dict.fromkeys(["neptune", "back", "land", "pod", "smurf", "teardrop", "mailbomb",
                         "processtable", "udpstorm", "apache2", "worm"], "DoS")
FAMILY |= dict.fromkeys(["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"], "Probe")
FAMILY |= dict.fromkeys(["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
                         "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
                         "httptunnel", "sendmail", "named"], "R2L")
FAMILY |= dict.fromkeys(["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
                         "xterm", "ps"], "U2R")


def build(out: Path = ROOT / "nsl_kdd.csv") -> Path:
    parts = []
    for split, name in FILES.items():
        local = ROOT / name.replace("%2B", "+")
        if local.exists():
            raw = local.read_text()
        else:
            print(f"downloading {name} ...")
            raw = urllib.request.urlopen(BASE + name, timeout=60).read().decode()
        df = pd.read_csv(io.StringIO(raw), names=COLS)
        df["split"] = split
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    df["label"] = df["label"].str.strip()
    df["attack_family"] = df["label"].map(FAMILY)
    df = df.dropna(subset=["attack_family"])
    df["is_attack"] = (df["label"] != "normal").astype(int)
    df = df[FEATURES + ["label", "attack_family", "is_attack", "split"]]
    # exact duplicate flows inside a split add no information
    df = df.drop_duplicates().reset_index(drop=True)
    df.to_csv(out, index=False)
    print(f"wrote {out}  rows={len(df)}  attacks={int(df.is_attack.sum())}")
    return out


if __name__ == "__main__":
    build()
