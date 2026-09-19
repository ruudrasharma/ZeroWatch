"""
ZeroWatch ML — leave-one-attack-out evaluation harness.

Direct .py port of notebook cell 15 (§7). For each held-out category: trains
fresh Autoencoder/IsolationForest/RandomForest, thresholds the Autoencoder at
the 95th percentile of its own training-normal reconstruction error (no
attack labels used to pick the threshold — standard unsupervised-anomaly
convention), and reports Precision/Recall/F1/FPR treating the held-out
category as the positive ("attack") class.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import torch
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from .models import Autoencoder, autoencoder_anomaly_scores, train_autoencoder
from .preprocess import leave_one_attack_out_split


def evaluate_run(
    y_test: np.ndarray, y_pred_binary: np.ndarray, held_out_category: str
) -> dict[str, Any]:
    y_true_binary = (y_test == held_out_category).astype(int)
    precision = precision_score(y_true_binary, y_pred_binary, zero_division=0)
    recall = recall_score(y_true_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true_binary, y_pred_binary).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "precision": precision, "recall": recall, "f1_score": f1,
        "false_positive_rate": fpr,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def run_leave_one_out_evaluation(
    df: pd.DataFrame,
    feature_cols: list[str],
    held_out_categories: list[str],
    device: torch.device,
    seed: int = 42,
    ae_epochs: int = 25,
    rf_n_estimators: int = 200,
    verbose: bool = True,
) -> tuple[pd.DataFrame, dict[str, tuple[Autoencoder, float]], dict[str, RandomForestClassifier]]:
    """
    Runs the full leave-one-attack-out evaluation across all held_out_categories.
    Returns (results_df, trained_autoencoders, trained_rf_models) — the latter
    two keyed by held_out_category, matching the notebook's globals so
    downstream cells (SHAP demo, production checkpoint save) can reuse them.
    """
    results: list[dict[str, Any]] = []
    trained_autoencoders: dict[str, tuple[Autoencoder, float]] = {}
    trained_rf_models: dict[str, RandomForestClassifier] = {}

    for held_out in held_out_categories:
        if verbose:
            print(f"\n=== Holding out: {held_out} (simulated zero-day) ===")
        split = leave_one_attack_out_split(df, held_out, feature_cols, seed=seed)

        # --- Autoencoder (unsupervised, true zero-day detector) ---
        ae_model, _ = train_autoencoder(
            split["X_train_normal_only"], input_dim=len(feature_cols),
            device=device, epochs=ae_epochs, verbose=verbose,
        )
        train_scores = autoencoder_anomaly_scores(ae_model, split["X_train_normal_only"], device)
        threshold = float(np.percentile(train_scores, 95))
        test_scores = autoencoder_anomaly_scores(ae_model, split["X_test"], device)
        ae_pred = (test_scores > threshold).astype(int)
        ae_metrics = evaluate_run(split["y_test"], ae_pred, held_out)
        ae_metrics.update({"model": "Autoencoder", "held_out_category": held_out})
        results.append(ae_metrics)
        trained_autoencoders[held_out] = (ae_model, threshold)

        # --- Isolation Forest (unsupervised baseline) ---
        iso = IsolationForest(contamination=0.05, random_state=seed)
        iso.fit(split["X_train_normal_only"])
        iso_pred = (iso.predict(split["X_test"]) == -1).astype(int)
        iso_metrics = evaluate_run(split["y_test"], iso_pred, held_out)
        iso_metrics.update({"model": "IsolationForest", "held_out_category": held_out})
        results.append(iso_metrics)

        # --- Random Forest (supervised baseline — the contrast case) ---
        x_bal, y_bal = SMOTE(random_state=seed).fit_resample(
            split["X_train_supervised"], split["y_train_supervised"]
        )
        rf = RandomForestClassifier(n_estimators=rf_n_estimators, random_state=seed, n_jobs=-1)
        rf.fit(x_bal, y_bal)
        rf_pred_labels = rf.predict(split["X_test"])
        rf_pred = (rf_pred_labels != "Normal").astype(int)
        rf_metrics = evaluate_run(split["y_test"], rf_pred, held_out)
        rf_metrics.update({"model": "RandomForest", "held_out_category": held_out})
        results.append(rf_metrics)
        trained_rf_models[held_out] = rf

    results_df = pd.DataFrame(results)[
        ["model", "held_out_category", "precision", "recall", "f1_score",
         "false_positive_rate", "tp", "fp", "tn", "fn"]
    ]
    return results_df, trained_autoencoders, trained_rf_models
