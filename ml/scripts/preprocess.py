"""
ZeroWatch ML — leakage-free preprocessing + leave-one-attack-out split.

Everything that *learns* from data (category lists, skew decisions, correlation
filter, means/variances) is fitted on the TRAINING rows of a split only, then
applied unchanged to the test rows and, at inference time, by the backend.
The held-out attack category and the test rows never influence any fitted
statistic — fitting a scaler on the full dataset before splitting would leak
exactly the zero-day traffic the evaluation is supposed to be blind to.

Pipeline (one sklearn ColumnTransformer, saved as `preprocessor.pkl`):
  nominal   protocol_type, service, flag     → one-hot (unknown → all zeros)
  binary    land, logged_in, ...             → passthrough (already 0/1)
  skewed    byte/count columns (skew > 1)    → log1p → StandardScaler
  other     rates / small counts             → StandardScaler
  dropped   constant columns, and one column of every pair with |r| > 0.95
            (decided on the training rows only)

Only sklearn/numpy objects are pickled (np.log1p is a plain ufunc) so the
backend can `joblib.load` the preprocessor without importing the `ml` package.

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
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from .data import COL_NAMES

# The 41 raw NSL-KDD input columns, in file order. This is the contract between
# training and the backend: the backend builds a frame with exactly these columns.
RAW_FEATURE_COLS: list[str] = [c for c in COL_NAMES if c not in ("label", "difficulty")]

# Nominal: no natural order, so one-hot (label-encoding would invent an order).
NOMINAL_COLS = ["protocol_type", "service", "flag"]
# Binary: already 0/1 flags, no encoding needed.
BINARY_COLS = ["land", "logged_in", "root_shell", "is_host_login", "is_guest_login"]
# Everything else is a count, byte total, duration or a 0-1 rate.
CONTINUOUS_COLS = [c for c in RAW_FEATURE_COLS if c not in NOMINAL_COLS + BINARY_COLS]

SKEW_THRESHOLD = 1.0
CORR_THRESHOLD = 0.95


def fit_preprocessor(train_df: pd.DataFrame) -> tuple[ColumnTransformer, dict[str, Any]]:
    """Fit the preprocessing pipeline on `train_df` ONLY. Returns (pipeline, report)."""
    train = train_df[RAW_FEATURE_COLS]

    # 1. Constant columns carry no information (e.g. num_outbound_cmds is always 0).
    constant = [c for c in CONTINUOUS_COLS + BINARY_COLS if train[c].nunique() <= 1]
    cont = [c for c in CONTINUOUS_COLS if c not in constant]
    binary = [c for c in BINARY_COLS if c not in constant]

    # 2. Heavy right skew (bytes, durations, counts) → log1p. Rates already in
    #    [0, 1] are left alone.
    skew = train[cont].skew()
    log_cols = [
        c for c in cont
        if train[c].min() >= 0 and train[c].max() > 1 and skew[c] > SKEW_THRESHOLD
    ]

    # 3. Correlation filter, measured on the log-transformed view: keep the first
    #    column of every highly correlated group (file order → deterministic).
    view = train[cont].copy()
    view[log_cols] = np.log1p(view[log_cols])
    corr = view.corr().abs()
    kept: list[str] = []
    dropped_correlated: dict[str, dict[str, Any]] = {}
    for col in cont:
        partner = next((k for k in kept if corr.loc[col, k] > CORR_THRESHOLD), None)
        if partner is None:
            kept.append(col)
        else:
            dropped_correlated[col] = {
                "correlated_with": partner,
                "abs_corr": round(float(corr.loc[col, partner]), 4),
            }

    log_kept = [c for c in log_cols if c in kept]
    scale_only = [c for c in kept if c not in log_kept]

    transformers: list[tuple[str, Any, list[str]]] = [
        ("nominal", OneHotEncoder(handle_unknown="ignore", sparse_output=False), NOMINAL_COLS),
    ]
    if binary:
        transformers.append(("binary", "passthrough", binary))
    if log_kept:
        transformers.append((
            "log_scaled",
            Pipeline([
                ("log1p", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
                ("scale", StandardScaler()),
            ]),
            log_kept,
        ))
    if scale_only:
        transformers.append(("scaled", StandardScaler(), scale_only))

    pre = ColumnTransformer(
        transformers, remainder="drop", sparse_threshold=0.0, verbose_feature_names_out=False
    )
    pre.fit(train)

    names = list(pre.get_feature_names_out())
    n_onehot = int(sum(len(c) for c in pre.named_transformers_["nominal"].categories_))
    report = {
        "n_raw_columns": len(RAW_FEATURE_COLS),
        "n_after_encoding_before_selection": len(CONTINUOUS_COLS) + len(BINARY_COLS) + n_onehot,
        "n_final_features": len(names),
        "nominal_cols": NOMINAL_COLS,
        "binary_cols": binary,
        "log1p_cols": log_kept,
        "scaled_only_cols": scale_only,
        "dropped_constant": constant,
        "dropped_correlated": dropped_correlated,
        "skew_threshold": SKEW_THRESHOLD,
        "corr_threshold": CORR_THRESHOLD,
        "n_train_rows": int(len(train)),
    }
    return pre, report


def transform(pre: ColumnTransformer, df: pd.DataFrame) -> np.ndarray:
    """Apply an already-fitted preprocessor. float32 everywhere (torch + sklearn)."""
    return pre.transform(df[RAW_FEATURE_COLS]).astype(np.float32)


def feature_names(pre: ColumnTransformer) -> list[str]:
    return list(pre.get_feature_names_out())


def leave_one_attack_out_split(
    df: pd.DataFrame,
    held_out_category: str,
    test_size_normal: float = 0.3,
    seed: int = 42,
) -> dict[str, Any]:
    """
    For `held_out_category`:
      - Training rows: Normal (70%) + every attack category EXCEPT the held-out one
      - Test rows: the other 30% of Normal + ONLY the held-out category

    The preprocessor is fitted on the training rows only. The Autoencoder and
    Isolation Forest train on normal-only rows (true unsupervised zero-day
    detection); the supervised baseline trains on normal + seen attacks to show
    the contrast: it has no class for the held-out label and can only miss it,
    mirroring what a signature-based system would miss.
    """
    normal_df = df[df["attack_category"] == "Normal"]
    seen_attacks_df = df[~df["attack_category"].isin(["Normal", "Other", held_out_category])]
    held_out_df = df[df["attack_category"] == held_out_category]

    normal_test_df = normal_df.sample(frac=test_size_normal, random_state=seed)
    normal_train_df = normal_df.drop(normal_test_df.index)
    supervised_train_df = pd.concat([normal_train_df, seen_attacks_df])
    test_df = pd.concat([normal_test_df, held_out_df])

    pre, report = fit_preprocessor(supervised_train_df)  # ← training rows only

    return {
        "X_train_normal_only": transform(pre, normal_train_df),
        "X_train_supervised": transform(pre, supervised_train_df),
        "y_train_supervised": supervised_train_df["attack_category"].values,
        "X_test": transform(pre, test_df),
        "y_test": test_df["attack_category"].values,
        "preprocessor": pre,
        "preprocessing_report": report,
        "feature_names": feature_names(pre),
        # raw frames, kept so train.py can export a replay file of unseen rows
        "normal_test_df": normal_test_df,
        "held_out_df": held_out_df,
        "seen_attacks_df": seen_attacks_df,
    }
