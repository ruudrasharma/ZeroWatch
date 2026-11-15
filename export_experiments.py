"""Export the MLflow runs to model/experiments.json (shown in the UI's Model tab)
and print the Markdown results table used in the README.

Usage:  python export_experiments.py
"""
import json
from pathlib import Path

import mlflow

from train import EXPERIMENT

mlflow.set_tracking_uri("sqlite:///mlflow.db")
runs = mlflow.search_runs(experiment_names=[EXPERIMENT], order_by=["start_time ASC"])
SKIP = {"algorithm", "seed", "train_rows", "threshold", "contamination"}
rows = []
for _, r in runs.iterrows():
    hp = {k[7:]: r[k] for k in runs.columns if k.startswith("params.") and k[7:] not in SKIP and r[k] is not None and r[k] == r[k]}
    rows.append({
        "run": r["tags.mlflow.runName"], "algorithm": r["params.algorithm"],
        "hyperparameters": ", ".join(f"{k}={v}" for k, v in sorted(hp.items())),
        "promoted": False,
        **{m: round(float(r[f"metrics.{m}"]), 4) for m in
           ("val_f1", "test_accuracy", "test_f1", "ensemble_test_f1", "ensemble_test_fpr",
            "zero_day_recall_detector", "zero_day_recall_ensemble")},
    })
if rows:
    max(rows, key=lambda x: x["val_f1"])["promoted"] = True  # same rule train.py uses
Path("model/experiments.json").write_text(json.dumps(rows, indent=2))

print("| Run | Algorithm | Hyperparameters | Val F1 | Test accuracy | Test F1 | Ensemble F1 | Ensemble FPR "
      "| Zero-day recall (detector -> ensemble) |")
print("|---|---|---|---|---|---|---|---|---|")
for x in rows:
    star = " **(deployed)**" if x["promoted"] else ""
    print(f"| {x['run']}{star} | {x['algorithm']} | {x['hyperparameters']} | {x['val_f1']:.4f} | {x['test_accuracy']:.4f} | "
          f"{x['test_f1']:.4f} | {x['ensemble_test_f1']:.4f} | {x['ensemble_test_fpr']:.4f} | "
          f"{x['zero_day_recall_detector']:.1%} -> {x['zero_day_recall_ensemble']:.1%} |")
