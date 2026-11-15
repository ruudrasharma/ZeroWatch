"""Build data/sample_flows.json: 330 held-out KDDTest+ flows for the UI's live
replay, plus the named example flows ("presets") shown in the Analyze form.
Run after training:  python data/make_samples.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import app  # noqa: E402  (loads model/model.joblib)
from features import FEATURES  # noqa: E402

PRESETS = [
    ("Normal web request", "normal", {"service": "http"}, "benign", "Ordinary HTTP request from a logged-in session"),
    ("SYN flood", "neptune", {"flag": "S0"}, "attack", "Hundreds of half-open connections to one host"),
    ("Port scan", "portsweep", {}, "attack", "One source probing many closed ports"),
    ("Password guessing", "guess_passwd", {}, "attack", "Repeated failed logins against a remote service"),
    ("Root shell exploit", "buffer_overflow", {}, "attack", "Buffer overflow that ends in a root shell"),
    ("Unseen: apache2 flood", "apache2", {}, "zero_day_suspect", "Attack type absent from the training data"),
    ("Unseen: mscan sweep", "mscan", {}, "zero_day_suspect", "Attack type absent from the training data"),
]


def flow_of(r) -> dict:
    return {k: (r[k].item() if hasattr(r[k], "item") else r[k]) for k in FEATURES}


d = pd.read_csv(ROOT / "nsl_kdd.csv")
seen = set(d[d.split == "train"].label)
te = d[d.split == "test"]
parts = [te[te.attack_family == "Normal"].sample(150, random_state=1)]
for fam, n in [("DoS", 60), ("Probe", 50), ("R2L", 50), ("U2R", 20)]:
    g = te[te.attack_family == fam]
    parts.append(g.sample(min(n, len(g)), random_state=1))
s = pd.concat(parts).sample(frac=1, random_state=2)
flows = [{"flow": flow_of(r), "label": r.label, "family": r.attack_family,
          "seen_in_training": r.label in seen} for _, r in s.iterrows()]

presets = []
for name, label, filt, expect, desc in PRESETS:
    g = te[te.label == label]
    for k, v in filt.items():
        g = g[g[k] == v]
    for _, r in g.iterrows():  # first flow of that type the model gives the expected verdict
        if app.analyse(flow_of(r), False)["verdict"] == expect:
            presets.append({"name": name, "description": desc, "label": label, "flow": flow_of(r)})
            break

(ROOT / "sample_flows.json").write_text(json.dumps({"flows": flows, "presets": presets}))
print(f"{len(flows)} flows, {len(presets)} presets")
