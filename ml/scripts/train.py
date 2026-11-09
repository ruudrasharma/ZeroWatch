"""
ZeroWatch ML — CLI training entrypoint.

.py conversion of the full ZeroWatch_Model_Training.ipynb pipeline (docs/
TODO.md Phase 1), rebuilt on the leakage-free preprocessing in preprocess.py.
Produces the checkpoint set backend/services/model_loader.py loads.

Production models: the shipped Autoencoder / Isolation Forest / Random Forest
are the ones from ONE leave-one-out run (`--production-rf-category`, default
Probe), together with the preprocessor fitted on that run's training rows.
Shipping a single run keeps every checkpoint consistent with its preprocessor
(a model trained on one scaler's output must be fed by that same scaler). The
Random Forest has never seen that category's label — the explicit contrast
case against a signature-based system.

Usage:
    python -m ml.scripts.train --output-dir backend/models/checkpoints

    # faster smoke-test run against a data subsample:
    python -m ml.scripts.train --output-dir /tmp/ml_smoke --quick --no-replay

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from .data import HELD_OUT_CATEGORIES, load_nsl_kdd
from .evaluate import run_leave_one_out_evaluation
from .preprocess import RAW_FEATURE_COLS

REPLAY_NORMAL_ROWS = 3000
REPLAY_ATTACK_ROWS = 2000


def export_replay_csv(artifact: dict, path: Path, seed: int) -> int:
    """
    Writes raw (un-preprocessed) NSL-KDD rows for the live dashboard replay:
    normal rows the production Autoencoder never trained on, plus a stratified
    sample of every attack category, shuffled so the first N rows (the backend
    reads the first 5000) are representative.
    """
    rng = np.random.RandomState(seed)
    normal = artifact["normal_test_df"]
    attacks = pd.concat([artifact["held_out_df"], artifact["seen_attacks_df"]])
    normal = normal.sample(n=min(REPLAY_NORMAL_ROWS, len(normal)), random_state=rng)
    per_cat = max(1, REPLAY_ATTACK_ROWS // attacks["attack_category"].nunique())
    attacks = (
        attacks.groupby("attack_category", group_keys=False)
        .apply(lambda g: g.sample(n=min(per_cat, len(g)), random_state=rng))
    )
    out = pd.concat([normal, attacks]).sample(frac=1.0, random_state=rng).reset_index(drop=True)
    out = out[RAW_FEATURE_COLS + ["label", "attack_category"]]
    path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(path, index=False)
    return len(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("ml/output"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=25, help="Autoencoder training epochs")
    parser.add_argument("--rf-estimators", type=int, default=200)
    parser.add_argument(
        "--production-rf-category", default="Probe",
        help="Which held-out run's models + preprocessor to ship as production.",
    )
    parser.add_argument(
        "--replay-output", type=Path, default=Path("backend/data/processed/nsl_kdd_test.csv"),
        help="Where to write the raw-row replay file for the live anomaly dashboard.",
    )
    parser.add_argument("--no-replay", action="store_true", help="Skip writing the replay CSV.")
    parser.add_argument(
        "--mlflow", action="store_true",
        help="Log the run to MLflow and register/promote the model (needs `pip install mlflow`).",
    )
    parser.add_argument("--mlflow-tracking-uri", default=None,
                        help="MLflow tracking server URI (default: local ./mlruns).")
    parser.add_argument(
        "--quick", action="store_true",
        help="Subsample the dataset + reduce epochs/estimators for a fast local smoke test.",
    )
    args = parser.parse_args()

    seed = args.seed
    np.random.seed(seed)
    torch.manual_seed(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Using device:", device)

    epochs = 3 if args.quick else args.epochs
    rf_estimators = 20 if args.quick else args.rf_estimators

    t0 = time.time()
    print("Loading NSL-KDD...")
    df = load_nsl_kdd()
    if args.quick:
        df = df.sample(frac=0.15, random_state=seed).reset_index(drop=True)
    print(f"  {len(df)} records ({time.time() - t0:.1f}s)")

    print("\nRunning leave-one-attack-out evaluation (preprocessor fitted per run, train rows only)...")
    results_df, auc_df, artifacts = run_leave_one_out_evaluation(
        df, HELD_OUT_CATEGORIES, device,
        seed=seed, ae_epochs=epochs, rf_n_estimators=rf_estimators,
    )
    print("\nThresholded results (95th-percentile threshold):")
    print(results_df.round(4).to_string(index=False))
    print("\nThreshold-free ranking quality:")
    print(auc_df.round(4).to_string(index=False))

    prod = artifacts[args.production_rf_category]
    print(f"\nShipping production models from the '{args.production_rf_category}'-held-out run "
          f"({len(prod['feature_names'])} features).")

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    torch.save(prod["autoencoder"].state_dict(), out / "autoencoder.pt")
    joblib.dump(prod["ae_threshold"], out / "autoencoder_threshold.pkl")
    joblib.dump(prod["preprocessor"], out / "preprocessor.pkl")
    joblib.dump(list(RAW_FEATURE_COLS), out / "raw_feature_cols.pkl")
    joblib.dump(prod["feature_names"], out / "feature_cols.pkl")
    joblib.dump(prod["random_forest"], out / "random_forest_baseline.pkl")
    joblib.dump(prod["isolation_forest"], out / "isolation_forest.pkl")
    joblib.dump(prod["if_threshold"], out / "isolation_forest_threshold.pkl")
    results_df.to_csv(out / "leave_one_out_results.csv", index=False)
    auc_df.to_csv(out / "leave_one_out_auc.csv", index=False)
    (out / "preprocessing_report.json").write_text(
        json.dumps(prod["preprocessing_report"], indent=2)
    )

    import datetime
    import subprocess
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:  # noqa: BLE001 — not a git checkout
        git_sha = "unknown"
    params = {
        "seed": seed, "epochs": epochs, "rf_estimators": rf_estimators, "quick": args.quick,
        "production_category": args.production_rf_category, "n_records": len(df),
        "n_features": len(prod["feature_names"]), "git_sha": git_sha,
    }
    metadata = {**params, "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "mlflow_run_id": None}
    if args.mlflow:
        from .tracking import log_training_run, register_production
        (out / "model_metadata.json").write_text(json.dumps(metadata, indent=2))
        run_id = log_training_run(out, params, results_df, auc_df, args.mlflow_tracking_uri)
        metadata["mlflow_run_id"] = run_id
        register_production(run_id, args.mlflow_tracking_uri)
    (out / "model_metadata.json").write_text(json.dumps(metadata, indent=2))

    if not args.no_replay:
        n = export_replay_csv(prod, args.replay_output, seed)
        print(f"Wrote {n} replay rows → {args.replay_output}")

    print(f"\nSaved checkpoints to {out}/ ({time.time() - t0:.1f}s total):")
    for f in sorted(out.iterdir()):
        print(" -", f.name)


if __name__ == "__main__":
    main()
