"""
ZeroWatch - drift check.

Compares the inputs the live service has logged (logs/predictions.jsonl)
against the training data statistics stored inside model/model.joblib.

  numeric feature      shift = |live mean - train mean| / train std   (+ std ratio)
  categorical feature  shift = total variation distance between category shares

A feature is "warn" above 0.25 and "drift" above 0.5. If any feature drifts
the script exits with code 1, so it can run from cron or CI as a retraining alarm.

Usage:  python drift_check.py [--log logs/predictions.jsonl] [--last 2000]
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

WARN, DRIFT, MIN_ROWS = 0.25, 0.5, 30


def read_inputs(path: Path, last: int = 2000) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines()[-last:]:
        try:
            rows.append(json.loads(line)["input"])
        except (ValueError, KeyError):
            continue
    return rows


def drift_report(rows: list[dict], stats: dict) -> dict:
    """stats = meta['feature_stats'] from the model bundle."""
    out = {"rows": len(rows), "enough_data": len(rows) >= MIN_ROWS, "features": [], "status": "ok"}
    if not out["enough_data"]:
        out["status"] = "waiting"
        return out
    for name, ref in stats.items():
        vals = [r[name] for r in rows if name in r]
        if not vals:
            continue
        if ref["kind"] == "num":
            mean = sum(vals) / len(vals)
            std = math.sqrt(sum((v - mean) ** 2 for v in vals) / max(len(vals) - 1, 1))
            ref_std = ref["std"] or 1e-9
            shift = abs(mean - ref["mean"]) / ref_std
            item = {"feature": name, "kind": "num", "train_mean": round(ref["mean"], 3),
                    "live_mean": round(mean, 3), "train_std": round(ref["std"], 3),
                    "live_std": round(std, 3), "shift": round(shift, 3)}
        else:
            live = {}
            for v in vals:
                live[v] = live.get(v, 0) + 1 / len(vals)
            keys = set(live) | set(ref["freq"])
            shift = 0.5 * sum(abs(live.get(k, 0) - ref["freq"].get(k, 0)) for k in keys)
            top = max(live, key=live.get)
            item = {"feature": name, "kind": "cat", "live_top": top, "live_top_share": round(live[top], 3),
                    "train_top_share": round(ref["freq"].get(top, 0), 3), "shift": round(shift, 3)}
        item["status"] = "drift" if shift > DRIFT else "warn" if shift > WARN else "ok"
        out["features"].append(item)
    out["features"].sort(key=lambda f: -f["shift"])
    statuses = {f["status"] for f in out["features"]}
    out["status"] = "drift" if "drift" in statuses else "warn" if "warn" in statuses else "ok"
    return out


def main() -> int:
    import joblib
    p = argparse.ArgumentParser()
    p.add_argument("--log", default="logs/predictions.jsonl")
    p.add_argument("--model", default="model/model.joblib")
    p.add_argument("--last", type=int, default=2000)
    a = p.parse_args()
    stats = joblib.load(a.model)["meta"]["feature_stats"]
    rep = drift_report(read_inputs(Path(a.log), a.last), stats)
    print(f"rows analysed: {rep['rows']}   overall: {rep['status'].upper()}")
    if not rep["enough_data"]:
        print(f"need at least {MIN_ROWS} logged predictions")
        return 0
    print(f"{'feature':24}{'train':>12}{'live':>12}{'shift':>8}  status")
    for f in rep["features"]:
        tr, lv = ((f["train_mean"], f["live_mean"]) if f["kind"] == "num"
                  else (f["train_top_share"], f"{f['live_top']}={f['live_top_share']}"))
        print(f"{f['feature']:24}{tr!s:>12}{lv!s:>12}{f['shift']:>8}  {f['status']}")
    return 1 if rep["status"] == "drift" else 0


if __name__ == "__main__":
    sys.exit(main())
