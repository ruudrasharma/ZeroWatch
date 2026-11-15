"""
ZeroWatch ML — leave-one-attack-out evaluation harness.

For each held-out category: fits a fresh preprocessor on that run's TRAINING
rows only, trains fresh Autoencoder/IsolationForest/RandomForest, thresholds
the unsupervised models at the 95th percentile of their own training-normal
scores (no attack labels used to pick the threshold — standard unsupervised
convention), and reports Precision/Recall/F1/FPR treating the held-out category
as the positive ("attack") class.

Alongside the thresholded metrics it records ROC-AUC and PR-AUC. Those are
threshold-free, so they show how well a model *ranks* the unseen attack above
normal traffic independent of the fixed 5%-FPR operating point — important for
rare categories (U2R has ~100 positives against ~20k normal rows, so precision
at any fixed FPR is structurally low).

The supervised baseline uses class_weight="balanced_subsample" instead of
SMOTE: SMOTE interpolates between rows, which on one-hot columns produces
fractional "categories" that don't exist in real traffic.

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
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .models import autoencoder_anomaly_scores, train_autoencoder
from .preprocess import leave_one_attack_out_split

RESULT_COLUMNS = [
    "model", "held_out_category", "precision", "recall", "f1_score",
    "false_positive_rate", "tp", "fp", "tn", "fn",
]
AUC_COLUMNS = ["model", "held_out_category", "roc_auc", "pr_auc"]


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


def _auc_row(model: str, held_out: str, y_test: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    y_true = (y_test == held_out).astype(int)
    return {
        "model": model,
        "held_out_category": held_out,
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
    }


def run_leave_one_out_evaluation(
    df: pd.DataFrame,
    held_out_categories: list[str],
    device: torch.device,
    seed: int = 42,
    ae_epochs: int = 25,
    rf_n_estimators: int = 200,
    verbose: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, dict[str, Any]]]:
    """
    Runs the full leave-one-attack-out evaluation across all held_out_categories.

    Returns (results_df, auc_df, artifacts). `artifacts[held_out]` holds every
    fitted object of that run (preprocessor, models, thresholds, raw frames) so
    train.py can ship one run's models as the production checkpoints with a
    preprocessor that is guaranteed to match them.
    """
    results: list[dict[str, Any]] = []
    auc_rows: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, Any]] = {}

    for held_out in held_out_categories:
        if verbose:
            print(f"\n=== Holding out: {held_out} (simulated zero-day) ===")
        split = leave_one_attack_out_split(df, held_out, seed=seed)
        n_features = len(split["feature_names"])
        if verbose:
            rep = split["preprocessing_report"]
            print(f"  preprocessor fit on {rep['n_train_rows']} training rows → "
                  f"{n_features} features (log1p on {len(rep['log1p_cols'])} columns)")

        # --- Autoencoder (unsupervised, true zero-day detector) ---
        ae_model, _ = train_autoencoder(
            split["X_train_normal_only"], input_dim=n_features,
            device=device, epochs=ae_epochs, verbose=verbose,
        )
        train_scores = autoencoder_anomaly_scores(ae_model, split["X_train_normal_only"], device)
        ae_threshold = float(np.percentile(train_scores, 95))
        test_scores = autoencoder_anomaly_scores(ae_model, split["X_test"], device)
        ae_metrics = evaluate_run(split["y_test"], (test_scores > ae_threshold).astype(int), held_out)
        ae_metrics.update({"model": "Autoencoder", "held_out_category": held_out})
        results.append(ae_metrics)
        auc_rows.append(_auc_row("Autoencoder", held_out, split["y_test"], test_scores))

        # --- Isolation Forest (unsupervised baseline) ---
        iso = IsolationForest(contamination=0.05, random_state=seed)
        iso.fit(split["X_train_normal_only"])
        iso_pred = (iso.predict(split["X_test"]) == -1).astype(int)
        iso_metrics = evaluate_run(split["y_test"], iso_pred, held_out)
        iso_metrics.update({"model": "IsolationForest", "held_out_category": held_out})
        results.append(iso_metrics)
        # score_samples: lower = more abnormal → negate so higher = more anomalous
        iso_train_scores = -iso.score_samples(split["X_train_normal_only"])
        iso_threshold = float(np.percentile(iso_train_scores, 95))
        auc_rows.append(
            _auc_row("IsolationForest", held_out, split["y_test"], -iso.score_samples(split["X_test"]))
        )

        # --- Random Forest (supervised baseline — the contrast case) ---
        rf = RandomForestClassifier(
            n_estimators=rf_n_estimators, random_state=seed, n_jobs=-1,
            class_weight="balanced_subsample",
        )
        rf.fit(split["X_train_supervised"], split["y_train_supervised"])
        rf_pred = (rf.predict(split["X_test"]) != "Normal").astype(int)
        rf_metrics = evaluate_run(split["y_test"], rf_pred, held_out)
        rf_metrics.update({"model": "RandomForest", "held_out_category": held_out})
        results.append(rf_metrics)
        normal_idx = list(rf.classes_).index("Normal")
        rf_attack_prob = 1.0 - rf.predict_proba(split["X_test"])[:, normal_idx]
        auc_rows.append(_auc_row("RandomForest", held_out, split["y_test"], rf_attack_prob))

        artifacts[held_out] = {
            "autoencoder": ae_model,
            "ae_threshold": ae_threshold,
            "isolation_forest": iso,
            "if_threshold": iso_threshold,
            "random_forest": rf,
            "preprocessor": split["preprocessor"],
            "preprocessing_report": split["preprocessing_report"],
            "feature_names": split["feature_names"],
            "normal_test_df": split["normal_test_df"],
            "held_out_df": split["held_out_df"],
            "seen_attacks_df": split["seen_attacks_df"],
        }

    results_df = pd.DataFrame(results)[RESULT_COLUMNS]
    auc_df = pd.DataFrame(auc_rows)[AUC_COLUMNS]
    return results_df, auc_df, artifacts
