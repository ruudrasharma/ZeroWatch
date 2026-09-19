"""
ZeroWatch ML — CLI training entrypoint.

.py conversion of the full ZeroWatch_Model_Training.ipynb pipeline (docs/
TODO.md Phase 1: "Convert the notebook's training logic into ml/scripts/*.py
for automated/reproducible re-runs outside Colab"). Produces the exact same
checkpoint set backend/services/model_loader.py loads, plus a production
Isolation Forest checkpoint the notebook never produced (see "Known
limitation" in CHANGELOG.md [0.2.1] — score_isolation_forest() was a proxy
that delegated to the Autoencoder because no isolation_forest.pkl existed).

Usage:
    python -m ml.scripts.train --output-dir backend/models/checkpoints

    # faster smoke-test run against a data subsample:
    python -m ml.scripts.train --output-dir /tmp/ml_smoke --quick

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.ensemble import IsolationForest

from .data import HELD_OUT_CATEGORIES, load_nsl_kdd
from .evaluate import run_leave_one_out_evaluation
from .models import autoencoder_anomaly_scores, train_autoencoder
from .preprocess import encode_and_scale


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("ml/output"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=25, help="Autoencoder training epochs")
    parser.add_argument("--rf-estimators", type=int, default=200)
    parser.add_argument(
        "--production-rf-category", default="Probe",
        help="Which held-out run's RF model to ship as the production baseline "
             "(matches the notebook's own choice — that RF has never seen this "
             "category's label, which is the point: it's the explicit contrast case).",
    )
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

    print("Encoding + scaling...")
    df, encoders, scaler, feature_cols = encode_and_scale(df)
    print(f"  {len(feature_cols)} feature columns")

    print("\nRunning leave-one-attack-out evaluation...")
    results_df, trained_autoencoders, trained_rf_models = run_leave_one_out_evaluation(
        df, feature_cols, HELD_OUT_CATEGORIES, device,
        seed=seed, ae_epochs=epochs, rf_n_estimators=rf_estimators,
    )
    print("\nResults:")
    print(results_df.round(4).to_string(index=False))

    # ── Production Autoencoder — trained on ALL normal traffic (no held-out
    #    category), the same convention the notebook uses for the shipped model.
    print("\nTraining production Autoencoder (all normal traffic, no held-out category)...")
    full_normal_only = df[df["attack_category"] == "Normal"][feature_cols].values
    production_ae, _ = train_autoencoder(
        full_normal_only, input_dim=len(feature_cols), device=device, epochs=epochs
    )
    production_threshold = float(
        np.percentile(autoencoder_anomaly_scores(production_ae, full_normal_only, device), 95)
    )

    # ── Production Isolation Forest — same "all normal traffic" convention,
    #    filling the gap noted in CHANGELOG.md [0.2.1]'s known limitation.
    print("Training production Isolation Forest (all normal traffic)...")
    production_iso = IsolationForest(contamination=0.05, random_state=seed)
    production_iso.fit(full_normal_only)
    # score_samples: "the lower, the more abnormal" — negate so higher means
    # more anomalous, then take the 95th percentile of the *training* normal
    # traffic as the threshold, exactly mirroring how production_threshold is
    # derived for the Autoencoder above (backend/services/model_loader.py
    # normalizes both the same way: score = min(raw / (threshold * 2), 1.0)).
    iso_train_scores = -production_iso.score_samples(full_normal_only)
    iso_threshold = float(np.percentile(iso_train_scores, 95))

    production_rf = trained_rf_models[args.production_rf_category]

    # ── Save ──────────────────────────────────────────────────────────────
    args.output_dir.mkdir(parents=True, exist_ok=True)
    torch.save(production_ae.state_dict(), args.output_dir / "autoencoder.pt")
    joblib.dump(production_threshold, args.output_dir / "autoencoder_threshold.pkl")
    joblib.dump(scaler, args.output_dir / "scaler.pkl")
    joblib.dump(encoders, args.output_dir / "label_encoders.pkl")
    joblib.dump(feature_cols, args.output_dir / "feature_cols.pkl")
    joblib.dump(production_rf, args.output_dir / "random_forest_baseline.pkl")
    joblib.dump(production_iso, args.output_dir / "isolation_forest.pkl")
    joblib.dump(iso_threshold, args.output_dir / "isolation_forest_threshold.pkl")
    results_df.to_csv(args.output_dir / "leave_one_out_results.csv", index=False)

    print(f"\nSaved checkpoints to {args.output_dir}/ ({time.time() - t0:.1f}s total):")
    for f in sorted(args.output_dir.iterdir()):
        print(" -", f.name)


if __name__ == "__main__":
    main()
