"""Rebuilds the test-data pack in this folder and records what the deployed model answers.
Run from the repository root:  python test_data/build.py
Expected verdicts in the pack come from the model in model/model.joblib; rerun after retraining."""
import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import os

os.environ["LOG_DIR"] = tempfile.mkdtemp()
from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402
from features import CONTRACT  # noqa: E402

client = TestClient(service.app)
NAMES = [c[0] for c in CONTRACT]
sample = json.loads((ROOT / "data" / "sample_flows.json").read_text())
presets = sample["presets"]
preset = {p["name"]: p["flow"] for p in presets} if isinstance(presets, list) else presets

base = dict(preset["Normal web request"])


def flow(**kw):
    f = dict(base)
    f.update(kw)
    return f


# ---- 1. named single flows: what each should demonstrate --------------------------------------
single = [
    ("TC01 Normal web request", "Ordinary page load", preset["Normal web request"], "benign"),
    ("TC02 Normal DNS lookup", "Short UDP query", flow(protocol_type="udp", service="domain_u", flag="SF", src_bytes=44, dst_bytes=120, duration=0, count=3, srv_count=3, logged_in=0, dst_host_count=40, dst_host_srv_count=35), "benign"),
    ("TC03 SYN flood", "Hundreds of unanswered SYNs", preset["SYN flood"], "attack"),
    ("TC04 Port scan", "Many rejected connections to different services", preset["Port scan"], "attack"),
    ("TC05 Password guessing", "Failed logins on one service (R2L; known weak spot)", preset["Password guessing"], "attack or weak spot"),
    ("TC06 Root shell exploit", "Privilege escalation (U2R)", preset["Root shell exploit"], "attack"),
    ("TC07 Unseen apache2 flood", "Attack type absent from training", preset["Unseen: apache2 flood"], "attack or zero_day_suspect"),
    ("TC08 Unseen mscan sweep", "Attack type absent from training", preset["Unseen: mscan sweep"], "attack or zero_day_suspect"),
    ("TC09 ICMP flood", "Large ICMP burst", flow(protocol_type="icmp", service="ecr_i", flag="SF", src_bytes=1032, dst_bytes=0, duration=0, logged_in=0, count=511, srv_count=511, serror_rate=0.0, same_srv_rate=1.0, dst_host_count=255, dst_host_srv_count=255), "attack"),
    ("TC10 Teardrop-style fragments", "Malformed IP fragments", flow(protocol_type="udp", service="private", flag="SF", src_bytes=28, dst_bytes=0, wrong_fragment=3, duration=0, logged_in=0, count=2, srv_count=2, dst_host_count=1, dst_host_srv_count=1), "attack"),
    ("TC11 Large upload", "Big benign transfer, to check size alone is not enough", flow(src_bytes=5_000_000, dst_bytes=300, duration=120, service="ftp_data", logged_in=1, count=1, srv_count=1), "benign or review"),
    ("TC12 Quiet login-heavy session", "Logged in, many sensitive-directory hits", flow(service="ftp", logged_in=1, hot=12, count=1, srv_count=1, src_bytes=300, dst_bytes=900, duration=200), "may be missed (flow-level limit)"),
]
rows, single_out = [], []
for name, why, f, expect in single:
    r = client.post("/predict", json=f).json()
    single_out.append({"id": name.split()[0], "name": name, "why": why, "expected": expect, "flow": f})
    rows.append([name.split()[0], name[5:], why, expect, r["verdict"], r["risk_score"], r["severity"], r.get("attack_family") or ""])
(OUT / "single_flows.json").write_text(json.dumps(single_out, indent=2))

# ---- 2. batch CSVs ----------------------------------------------------------------------------
flows = sample["flows"]
normal = [f for f in flows if f["family"] == "Normal"][:20]
known = [f for f in flows if f["family"] != "Normal" and f["seen_in_training"]][:20]
unseen = [f for f in flows if not f["seen_in_training"]][:20]


def write_csv(path, items, truth=False):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(NAMES + (["truth_label", "truth_family", "seen_in_training"] if truth else []))
        for it in items:
            w.writerow([it["flow"][n] for n in NAMES] + ([it["label"], it["family"], it["seen_in_training"]] if truth else []))


write_csv(OUT / "batch_60_flows.csv", normal + known + unseen)                      # paste or upload in Batch
write_csv(OUT / "batch_60_flows_with_truth.csv", normal + known + unseen, truth=True)   # for your own checking only
write_csv(OUT / "batch_unseen_attacks_20.csv", unseen)                              # feeds the Hunt demo
write_csv(OUT / "batch_normal_20.csv", normal)

# Hunt demo: unseen attack types from KDDTest+ (never in training), enough of them to form campaigns
import random

allrows = list(csv.DictReader(open(ROOT / "data" / "nsl_kdd.csv")))
train_labels = {r["label"] for r in allrows if r["split"] == "train"}
unseen_rows = [r for r in allrows if r["split"] == "test" and r["is_attack"] == "1" and r["label"] not in train_labels]
normal_rows = [r for r in allrows if r["split"] == "test" and r["is_attack"] == "0"]
rnd = random.Random(7)
for name, pool, n in [("hunt_unseen_attacks_400.csv", unseen_rows, 400), ("hunt_normal_100.csv", normal_rows, 100)]:
    with open(OUT / name, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(NAMES)
        for r in rnd.sample(pool, n):
            w.writerow([r[k] for k in NAMES])

summary = {}
for label, items in [("normal_20", normal), ("known_attacks_20", known), ("unseen_attacks_20", unseen)]:
    d = client.post("/predict/batch", json={"flows": [i["flow"] for i in items]}).json()
    summary[label] = d["verdicts"]

# ---- 3. invalid inputs: every one must be rejected with HTTP 422 -------------------------------
bad = []


def add(name, f):
    code = client.post("/predict", json=f).status_code
    bad.append({"name": name, "expect_status": 422, "got_status": code, "flow": f})


ok = preset["Normal web request"]
add("BAD01 missing field", {k: v for k, v in ok.items() if k != "root_shell"})
add("BAD02 extra field", ok | {"is_attack": 1})
add("BAD03 string instead of int", ok | {"src_bytes": "200"})
add("BAD04 boolean instead of int", ok | {"logged_in": True})
add("BAD05 float for int field", ok | {"count": 5.5})
add("BAD06 negative bytes", ok | {"src_bytes": -1})
add("BAD07 rate above 1", ok | {"serror_rate": 1.5})
add("BAD08 unknown protocol", ok | {"protocol_type": "sctp"})
add("BAD09 unknown service", ok | {"service": "not_a_service"})
add("BAD10 unknown flag", ok | {"flag": "XX"})
add("BAD11 count too large", ok | {"count": 100000})
add("BAD12 null value", ok | {"duration": None})
(OUT / "invalid_inputs.json").write_text(json.dumps(bad, indent=2))
for b in bad:
    assert b["got_status"] == 422, b["name"]

# ---- 4. capture files -----------------------------------------------------------------------
shutil.copy(ROOT / "data" / "sample_capture.pcap", OUT / "sample_capture.pcap")
head = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
lines, t = [], 1700000000.0
for i in range(25):                                                       # normal web and DNS from 4 clients
    c = f"10.1.0.{10 + i % 4}"
    lines.append(f"{t + i:.3f}\tC{i}\t{c}\t{40000 + i}\t10.1.0.80\t80\ttcp\thttp\t0.4\t320\t5400\tSF")
    lines.append(f"{t + i + .2:.3f}\tD{i}\t{c}\t{50000 + i}\t10.1.0.53\t53\tudp\tdns\t0.02\t44\t120\tSF")
for i in range(40):                                                       # one scanner, rejected connections
    lines.append(f"{t + 30 + i * .05:.3f}\tS{i}\t10.1.0.66\t{41000 + i}\t10.1.0.25\t{1 + i}\ttcp\t-\t0.0\t0\t0\tREJ")
for i in range(120):                                                      # one flooder, unanswered SYNs
    lines.append(f"{t + 40 + i * .01:.3f}\tF{i}\t10.1.0.99\t{42000 + i}\t10.1.0.10\t80\ttcp\t-\t0.0\t0\t0\tS0")
(OUT / "zeek_conn_sample.log").write_text(head + "\n".join(lines) + "\n")
cap = client.get("/capture/sample").json()
z = client.post("/capture", content=(OUT / "zeek_conn_sample.log").read_bytes(), headers={"content-type": "application/octet-stream"})
zeek_summary = z.json().get("verdicts") if z.status_code == 200 else {"error": z.text[:100]}
zeek_sources = [(s["ip"], s["behaviour"]) for s in z.json()["graph"]["sources"][:3]] if z.status_code == 200 else []

# ---- 5. expected results ------------------------------------------------------------------------
with open(OUT / "expected_results.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["id", "scenario", "what it shows", "expected", "model_verdict", "risk", "severity", "family"])
    w.writerows(rows)
(OUT / "expected_summary.json").write_text(json.dumps({
    "model_version": client.get("/health").json()["model_version"],
    "batch": summary,
    "sample_pcap": cap["verdicts"],
    "sample_pcap_top_sources": [(s["ip"], s["behaviour"]) for s in cap["graph"]["sources"][:2]],
    "zeek_sample": zeek_summary, "zeek_sample_top_sources": zeek_sources,
}, indent=2))
print(json.dumps(json.loads((OUT / "expected_summary.json").read_text()), indent=1))
for r in rows:
    print(r)
