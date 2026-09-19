"""
ZeroWatch ML — feature encoding/scaling + leave-one-attack-out split.

Direct .py port of notebook cells 9, 11 (§4-5).

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
from sklearn.preprocessing import LabelEncoder, StandardScaler

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def encode_and_scale(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, LabelEncoder], StandardScaler, list[str]]:
    """
    Label-encodes categorical columns in place, fits a StandardScaler over all
    feature columns (everything except label/attack_category), and scales
    them in place. Returns the mutated df plus the fitted encoders/scaler/
    feature_cols — all three must travel together and be reused unchanged at
    inference time (this is exactly what backend/services/model_loader.py
    loads from the checkpoint .pkl files).
    """
    df = df.copy()
    encoders: dict[str, LabelEncoder] = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le

    feature_cols = [c for c in df.columns if c not in ("label", "attack_category")]

    scaler = StandardScaler()
    df[feature_cols] = scaler.fit_transform(df[feature_cols])

    return df, encoders, scaler, feature_cols


def leave_one_attack_out_split(
    df: pd.DataFrame,
    held_out_category: str,
    feature_cols: list[str],
    test_size_normal: float = 0.3,
    seed: int = 42,
) -> dict[str, Any]:
    """
    For `held_out_category`:
      - Training set: Normal traffic + every attack category EXCEPT the held-out one
      - Test set: a mix of Normal traffic + ONLY the held-out category

    The Autoencoder trains on Normal-only (true unsupervised zero-day
    detection). The supervised baseline trains on Normal + seen-attack labels
    specifically to show the contrast: it has no class for the held-out
    label and can only ever miss it, mirroring what a signature/rule-based
    system would miss.
    """
    normal_df = df[df["attack_category"] == "Normal"]
    seen_attacks_df = df[
        (df["attack_category"] != "Normal")
        & (df["attack_category"] != held_out_category)
        & (df["attack_category"] != "Other")
    ]
    held_out_df = df[df["attack_category"] == held_out_category]

    normal_test_idx = normal_df.sample(frac=test_size_normal, random_state=seed).index
    normal_train_df = normal_df.drop(normal_test_idx)
    normal_test_df = normal_df.loc[normal_test_idx]

    x_train_normal_only = normal_train_df[feature_cols].values
    supervised_train_df = pd.concat([normal_train_df, seen_attacks_df])
    x_train_supervised = supervised_train_df[feature_cols].values
    y_train_supervised = supervised_train_df["attack_category"].values

    x_test = pd.concat([normal_test_df, held_out_df])[feature_cols].values
    y_test = np.array(
        ["Normal"] * len(normal_test_df) + [held_out_category] * len(held_out_df)
    )

    return {
        "X_train_normal_only": x_train_normal_only,
        "X_train_supervised": x_train_supervised,
        "y_train_supervised": y_train_supervised,
        "X_test": x_test,
        "y_test": y_test,
    }
