"""
ZeroWatch - cross-dataset generalisation test (NSL-KDD <-> UNSW-NB15).

A detector that scores 0.99 on its own dataset can still be useless on another network.
The two datasets record different columns, so both are first mapped onto the six
measurements they share:

    duration, protocol, service, connection state, bytes sent, bytes received

The same algorithm is then trained on one dataset and tested on the other, in both
directions, plus once on both together. Results go to MLflow (experiment
"zerowatch-cross-dataset") and to model/cross_dataset.json for the UI.

UNSW-NB15: Moustafa & Slay, UNSW Canberra, https://research.unsw.edu.au/projects/unsw-nb15-dataset
(the 32 MB CSV is downloaded on first run and is not committed).

Usage:  python cross_dataset.py
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import mlflow
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent
UNSW = ROOT / "data" / "UNSW_NB15_training-set.csv"
UNSW_URL = ("https://raw.githubusercontent.com/Nir-J/ML-Projects/master/"
            "UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv")
PROTO = ["tcp", "udp", "icmp", "other"]
SERVICE = ["http", "ftp", "smtp", "ssh", "dns", "pop3", "other"]
STATE = ["closed", "open", "no_reply", "reset", "other"]  # how the connection ended
COLS = ["duration", "protocol", "service", "state", "src_bytes", "dst_bytes"]


def nsl() -> tuple[pd.DataFrame, pd.DataFrame]:
    d = pd.read_csv(ROOT / "data" / "nsl_kdd.csv")
    svc = {"http": "http", "http_443": "http", "http_8001": "http", "http_2784": "http", "ftp": "ftp",
           "ftp_data": "ftp", "smtp": "smtp", "ssh": "ssh", "domain": "dns", "domain_u": "dns", "pop_3": "pop3"}
    st = {"SF": "closed", "S1": "open", "S2": "open", "S3": "open", "S0": "no_reply", "SH": "no_reply",
          "REJ": "reset", "RSTO": "reset", "RSTR": "reset", "RSTOS0": "reset", "OTH": "other"}
    out = pd.DataFrame({"duration": d.duration.astype(float), "protocol": d.protocol_type,
                        "service": d.service.map(svc).fillna("other"), "state": d.flag.map(st),
                        "src_bytes": d.src_bytes, "dst_bytes": d.dst_bytes, "y": d.is_attack})
    return out[d.split == "train"], out[d.split == "test"]


def unsw() -> tuple[pd.DataFrame, pd.DataFrame]:
    if not UNSW.exists():
        print("downloading UNSW-NB15 (32 MB) ...")
        urllib.request.urlretrieve(UNSW_URL, UNSW)
    d = pd.read_csv(UNSW, encoding="utf-8-sig")
    svc = {"http": "http", "ftp": "ftp", "ftp-data": "ftp", "smtp": "smtp", "ssh": "ssh", "dns": "dns", "pop3": "pop3"}
    st = {"FIN": "closed", "CON": "open", "INT": "no_reply", "REQ": "no_reply", "RST": "reset"}
    out = pd.DataFrame({"duration": d.dur, "protocol": d.proto.where(d.proto.isin(PROTO[:3]), "other"),
                        "service": d.service.map(svc).fillna("other"), "state": d.state.map(st).fillna("other"),
                        "src_bytes": d.sbytes, "dst_bytes": d.dbytes, "y": d.label}).drop_duplicates()
    return train_test_split(out, test_size=0.25, stratify=out.y, random_state=42)


def matrix(df: pd.DataFrame) -> np.ndarray:
    return np.column_stack([np.log1p(df.duration), df.protocol.map(PROTO.index), df.service.map(SERVICE.index),
                            df.state.map(STATE.index), np.log1p(df.src_bytes), np.log1p(df.dst_bytes)]).astype(float)


def fit(df: pd.DataFrame):
    return HistGradientBoostingClassifier(max_iter=200, max_depth=6, learning_rate=0.1, categorical_features=[1, 2, 3],
                                          random_state=42).fit(matrix(df), df.y)


def score(model, df: pd.DataFrame) -> dict:
    p = model.predict_proba(matrix(df))[:, 1]
    return {"accuracy": round(float(accuracy_score(df.y, p >= 0.5)), 4), "f1": round(float(f1_score(df.y, p >= 0.5)), 4),
            "roc_auc": round(float(roc_auc_score(df.y, p)), 4)}


def main() -> list[dict]:
    n_tr, n_te = nsl()
    u_tr, u_te = unsw()
    n = min(len(n_tr), len(u_tr))  # equal weight to each dataset in the combined run
    both = pd.concat([n_tr.sample(n, random_state=42), u_tr.sample(n, random_state=42)])
    rows = []
    mlflow.set_tracking_uri("sqlite:///mlflow.db")
    mlflow.set_experiment("zerowatch-cross-dataset")
    for name, train in [("NSL-KDD", n_tr), ("UNSW-NB15", u_tr), ("Both", both)]:
        model = fit(train)
        for test_name, test in [("NSL-KDD", n_te), ("UNSW-NB15", u_te)]:
            m = score(model, test)
            rows.append({"trained_on": name, "tested_on": test_name, "train_rows": len(train), "test_rows": len(test), **m})
            with mlflow.start_run(run_name=f"{name} -> {test_name}"):
                mlflow.log_params({"trained_on": name, "tested_on": test_name, "features": ",".join(COLS),
                                   "algorithm": "hgb", "max_iter": 200, "max_depth": 6})
                mlflow.log_metrics(m)
            print(f"{name:10} -> {test_name:10} accuracy={m['accuracy']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")
    (ROOT / "model" / "cross_dataset.json").write_text(json.dumps({"features": COLS, "results": rows}, indent=2))
    return rows


if __name__ == "__main__":
    main()
