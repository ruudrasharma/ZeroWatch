"""
ZeroWatch - training script with MLflow experiment tracking.

Trains three things and bundles them into model/model.joblib:
  1. detector  - supervised binary classifier (normal vs attack) on labelled flows
  2. novelty   - Isolation Forest fitted on NORMAL traffic only; flags flows that
                 look unlike anything normal, which is how unseen ("zero-day")
                 attacks get caught when the detector does not recognise them
  3. family    - multi-class classifier naming the attack family (DoS/Probe/R2L/U2R)

Every run logs its hyperparameters and metrics to MLflow (SQLite backend).
The bundle on disk is only replaced when the new run beats the stored one on
validation F1, so model/model.joblib is always the best run so far.

Examples:
  python train.py --n_estimators 100 --max_depth 6
  python train.py --algorithm hgb --learning_rate 0.1 --max_iter 200
  python train.py --algorithm logreg --C 1.0
  mlflow ui --backend-store-uri sqlite:///mlflow.db
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import mlflow
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from features import CATEGORICAL, FAMILIES, FEATURES, TARGET, encode
from learning import build_classifier

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "nsl_kdd.csv"
MODEL = ROOT / "model" / "model.joblib"
METRICS = ROOT / "model" / "metrics.json"
SHA = ROOT / "model" / "model.sha256"
CACHE = ROOT / "model" / "train_cache.npz"
EXPERIMENT = "zerowatch-intrusion-detection"
REGISTERED_NAME = "zerowatch-detector"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--algorithm", choices=["rf", "extratrees", "hgb", "logreg"], default="rf")
    p.add_argument("--n_estimators", type=int, default=100, help="trees (rf, extratrees)")
    p.add_argument("--max_depth", type=int, default=12, help="tree depth (rf, extratrees, hgb)")
    p.add_argument("--learning_rate", type=float, default=0.1, help="hgb only")
    p.add_argument("--max_iter", type=int, default=200, help="boosting rounds (hgb) / solver iterations (logreg)")
    p.add_argument("--C", type=float, default=1.0, help="inverse regularisation strength (logreg)")
    p.add_argument("--threshold", type=float, default=0.5, help="attack probability cut-off")
    p.add_argument("--contamination", type=float, default=0.05,
                   help="share of normal training traffic the novelty model may flag (its false-positive budget)")
    p.add_argument("--novelty_estimators", type=int, default=150)
    p.add_argument("--sample", type=int, default=0, help="train on a random subset of N rows (quick CI runs)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--run_name", default=None)
    p.add_argument("--force", action="store_true", help="save the model even if it is not the best so far")
    p.add_argument("--register", action="store_true", help="also log the model to the MLflow Model Registry")
    p.add_argument("--tracking_uri", default="sqlite:///mlflow.db")
    return p.parse_args(argv)


def load_data() -> pd.DataFrame:
    if not DATA.exists():
        from data.download_data import build
        build(DATA)
    return pd.read_csv(DATA)


def to_matrix(df: pd.DataFrame) -> np.ndarray:
    return np.array([encode(r) for r in df[FEATURES].to_dict("records")], dtype=float)


def hyperparams(a) -> dict:
    used = {"rf": ["n_estimators", "max_depth"], "extratrees": ["n_estimators", "max_depth"],
            "hgb": ["learning_rate", "max_iter", "max_depth"], "logreg": ["C", "max_iter"]}[a.algorithm]
    return {k: getattr(a, k) for k in used}


def binary_metrics(y, pred, proba=None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    m = {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
         "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
         "fpr": fp / max(fp + tn, 1)}
    if proba is not None:
        m["roc_auc"] = roc_auc_score(y, proba)
    return {k: round(float(v), 4) for k, v in m.items()}


def novelty_scores(model: IsolationForest, X: np.ndarray, cut: float, spread: float) -> np.ndarray:
    """Map raw Isolation Forest scores onto 0..1 where 0.5 is the alert
    threshold (the `contamination` quantile of normal training traffic)."""
    raw = -model.score_samples(X)  # higher = more anomalous
    return 1.0 / (1.0 + np.exp(-(raw - cut) / spread))


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def main(argv=None) -> dict:
    a = parse_args(argv)
    t0 = time.time()
    df = load_data()
    train = df[df.split == "train"]
    test = df[df.split == "test"]
    if a.sample:
        train = train.sample(min(a.sample, len(train)), random_state=a.seed)
    fit_df, val_df = train_test_split(train, test_size=0.2, stratify=train[TARGET], random_state=a.seed)

    X_fit, y_fit = to_matrix(fit_df), fit_df[TARGET].to_numpy()
    X_val, y_val = to_matrix(val_df), val_df[TARGET].to_numpy()
    X_test, y_test = to_matrix(test), test[TARGET].to_numpy()

    # 1. supervised detector
    detector = build_classifier(a.algorithm, hyperparams(a), a.seed).fit(X_fit, y_fit)
    p_val = detector.predict_proba(X_val)[:, 1]
    p_test = detector.predict_proba(X_test)[:, 1]
    val = binary_metrics(y_val, p_val >= a.threshold, p_val)
    tst = binary_metrics(y_test, p_test >= a.threshold, p_test)

    # 1b. split-conformal calibration on validation data ("not sure" verdict).
    #     score = 1 - probability of the true class. qhat is the level 95% of validation flows
    #     stay under, so a flow whose attack probability lies strictly between qhat and 1 - qhat
    #     fits neither class at that confidence and is sent to a human instead of being passed.
    alpha = 0.05
    nonconf = np.where(y_val == 1, 1 - p_val, p_val)
    level = min(1.0, np.ceil((len(nonconf) + 1) * (1 - alpha)) / len(nonconf))
    qhat = float(max(np.quantile(nonconf, level, method="higher"), 0.02))  # floor: never trust below 2%
    unsure = (p_test > qhat) & (p_test < 1 - qhat)
    missed = (y_test == 1) & (p_test < a.threshold)
    conformal = {"alpha": alpha, "qhat": round(qhat, 4), "abstain_rate_test": round(float(unsure.mean()), 4),
                 "accuracy_when_sure_test": round(float(((p_test >= a.threshold) == y_test)[~unsure].mean()), 4),
                 "missed_attacks_sent_to_review": round(float(unsure[missed].mean()), 4)}

    # 2. novelty model: NORMAL rows only, never sees an attack
    normal_fit = X_fit[y_fit == 0]
    novelty = IsolationForest(n_estimators=a.novelty_estimators, random_state=a.seed, n_jobs=-1).fit(normal_fit)
    raw_normal = -novelty.score_samples(normal_fit)
    cut = float(np.quantile(raw_normal, 1 - a.contamination))
    spread = float(max(raw_normal.std(), 1e-6) / 2)
    n_test = novelty_scores(novelty, X_test, cut, spread)

    # 3. ensemble = detector OR novelty. "Zero-day recall" = share of attacks whose
    #    type never appears in training (17 such types in KDDTest+) that get flagged.
    seen = set(train.label)
    unseen = (~test.label.isin(seen)).to_numpy() & (y_test == 1)
    det_flag = p_test >= a.threshold
    ens_flag = det_flag | (n_test >= 0.5)
    ens = binary_metrics(y_test, ens_flag)
    zero_day = {"detector_only": round(float(det_flag[unseen].mean()), 4),
                "ensemble": round(float(ens_flag[unseen].mean()), 4),
                "unseen_attack_flows": int(unseen.sum())}

    # 4. attack family classifier (attack rows only)
    atk = fit_df[fit_df[TARGET] == 1]
    family = RandomForestClassifier(n_estimators=60, max_depth=12, class_weight="balanced",
                                    n_jobs=-1, random_state=a.seed).fit(to_matrix(atk), atk.attack_family)
    atk_test = test[test[TARGET] == 1]
    family_acc = round(float(accuracy_score(atk_test.attack_family, family.predict(to_matrix(atk_test)))), 4)

    # reference statistics for drift checks + baseline flow for explanations
    normal_df = fit_df[fit_df[TARGET] == 0]
    stats = {}
    for n in FEATURES:
        if n in CATEGORICAL:
            stats[n] = {"kind": "cat", "freq": fit_df[n].value_counts(normalize=True).round(4).to_dict()}
        else:
            s = fit_df[n]
            stats[n] = {"kind": "num", "mean": float(s.mean()), "std": float(s.std()),
                        "p50": float(s.median()), "p99": float(s.quantile(0.99))}
    baseline = {n: (normal_df[n].mode()[0] if n in CATEGORICAL else float(normal_df[n].median()))
                for n in FEATURES}
    kinds = {n: ("float" if fit_df[n].dtype.kind == "f" else "int") for n in FEATURES if n not in CATEGORICAL}
    baseline = {n: (v if n in CATEGORICAL else (round(v, 2) if kinds[n] == "float" else int(v)))
                for n, v in baseline.items()}

    # permutation importance on validation data: works for every algorithm
    idx = np.random.default_rng(a.seed).choice(len(X_val), min(4000, len(X_val)), replace=False)
    perm = permutation_importance(detector, X_val[idx], y_val[idx], scoring="f1", n_repeats=3,
                                  random_state=a.seed, n_jobs=-1)
    importance = {n: round(float(v), 4) for n, v in zip(FEATURES, perm.importances_mean, strict=True)}

    params = {"algorithm": a.algorithm, **hyperparams(a), "threshold": a.threshold,
              "contamination": a.contamination, "seed": a.seed, "train_rows": len(fit_df)}
    meta = {
        "algorithm": a.algorithm, "params": params, "threshold": a.threshold,
        "novelty": {"cut": cut, "spread": spread, "contamination": a.contamination},
        "conformal": {"alpha": alpha, "qhat": qhat},
        "metrics": {"validation": val, "test": tst, "ensemble_test": ens, "zero_day_recall": zero_day,
                    "family_accuracy": family_acc, "conformal": conformal},
        "feature_stats": stats, "baseline": baseline, "feature_importance": importance,
        "features": FEATURES, "families": FAMILIES,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_sha": git_sha(), "sklearn": sklearn.__version__,
        "data_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest()[:16],
        "rows": {"fit": len(fit_df), "validation": len(val_df), "test": len(test)},
    }

    mlflow.set_tracking_uri(a.tracking_uri)
    mlflow.set_experiment(EXPERIMENT)
    run_name = a.run_name or f"{a.algorithm}-" + "-".join(f"{k}{v}" for k, v in hyperparams(a).items())
    with mlflow.start_run(run_name=run_name) as run:
        mlflow.log_params(params)
        mlflow.log_metrics({f"val_{k}": v for k, v in val.items()})
        mlflow.log_metrics({f"test_{k}": v for k, v in tst.items()})
        mlflow.log_metrics({f"ensemble_test_{k}": v for k, v in ens.items()})
        mlflow.log_metrics({"zero_day_recall_detector": zero_day["detector_only"],
                            "zero_day_recall_ensemble": zero_day["ensemble"],
                            "conformal_abstain_rate": conformal["abstain_rate_test"],
                            "conformal_accuracy_when_sure": conformal["accuracy_when_sure_test"],
                            "family_accuracy": family_acc, "train_seconds": round(time.time() - t0, 1)})
        mlflow.set_tags({"git_sha": meta["git_sha"], "data_sha256": meta["data_sha256"]})
        mlflow.log_dict(meta["metrics"], "metrics.json")
        meta["mlflow_run_id"] = run.info.run_id

        # keep model/model.joblib = best run so far (by validation F1, never by test)
        best = json.loads(METRICS.read_text())["metrics"]["validation"]["f1"] if METRICS.exists() else -1
        is_best = a.force or not MODEL.exists() or val["f1"] > best
        mlflow.set_tag("promoted", str(is_best).lower())
        if is_best:
            MODEL.parent.mkdir(exist_ok=True)
            joblib.dump({"detector": detector, "novelty": novelty, "family": family, "meta": meta},
                        MODEL, compress=3)
            # integrity: app.py refuses to load a model whose hash does not match this file
            SHA.write_text(hashlib.sha256(MODEL.read_bytes()).hexdigest() + "\n")
            # compact copy of the training data so the serving container can retrain a challenger
            np.savez_compressed(CACHE, X_fit=X_fit.astype(np.float32), y_fit=y_fit.astype(np.int8),
                                X_val=X_val.astype(np.float32), y_val=y_val.astype(np.int8))
            METRICS.write_text(json.dumps({k: meta[k] for k in
                               ("algorithm", "params", "metrics", "trained_at", "git_sha", "rows")}, indent=2))
            if a.register:  # MLflow Model Registry: new version + "production" alias
                # cloudpickle: we trained this object ourselves seconds ago, so it is trusted
                info = mlflow.sklearn.log_model(detector, name="detector", serialization_format="cloudpickle",
                                                registered_model_name=REGISTERED_NAME)
                mlflow.MlflowClient().set_registered_model_alias(
                    REGISTERED_NAME, "production", info.registered_model_version)

    size = MODEL.stat().st_size / 1e6 if MODEL.exists() else 0
    print(f"[{run_name}] val_f1={val['f1']} test_f1={tst['f1']} test_acc={tst['accuracy']} "
          f"ensemble_f1={ens['f1']} zero_day_recall={zero_day['detector_only']}->{zero_day['ensemble']} "
          f"family_acc={family_acc}  {'SAVED as best' if is_best else 'kept previous best'} "
          f"({size:.1f} MB, {time.time() - t0:.0f}s)")
    return meta


if __name__ == "__main__":
    main()
