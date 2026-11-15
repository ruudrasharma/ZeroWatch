"""
Leakage regression tests for ml/scripts/preprocess.py.

These use a small synthetic frame with the real NSL-KDD column layout, so they
need no network and no torch. Run from the repo root:  python -m pytest ml/tests
"""

import numpy as np
import pandas as pd

from ml.scripts.preprocess import (
    BINARY_COLS,
    NOMINAL_COLS,
    RAW_FEATURE_COLS,
    fit_preprocessor,
    leave_one_attack_out_split,
    transform,
)


def _make_df(n_per_cat: int = 120, seed: int = 0) -> pd.DataFrame:
    rng = np.random.RandomState(seed)
    cats = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    rows = []
    for cat in cats:
        for _ in range(n_per_cat):
            row = {c: float(rng.poisson(3)) for c in RAW_FEATURE_COLS}
            row.update({c: int(rng.randint(0, 2)) for c in BINARY_COLS})
            row["src_bytes"] = float(rng.lognormal(6, 2))  # heavy right skew
            row["serror_rate"] = float(rng.rand())
            row["num_outbound_cmds"] = 0.0                  # constant column
            row["protocol_type"] = rng.choice(["tcp", "udp"])
            row["flag"] = rng.choice(["SF", "REJ"])
            row["service"] = rng.choice(["http", "ftp"])
            row["attack_category"] = cat
            row["label"] = cat.lower()
            rows.append(row)
    return pd.DataFrame(rows)


def test_scaler_statistics_come_from_training_rows_only():
    df = _make_df()
    train, test = df.iloc[:400].copy(), df.iloc[400:].copy()
    test["src_bytes"] = 1e9  # extreme test values must not move the fitted stats

    pre_train_only, _ = fit_preprocessor(train)
    pre_leaky, _ = fit_preprocessor(pd.concat([train, test]))

    names = list(pre_train_only.get_feature_names_out())
    j = names.index("src_bytes")
    x_train = transform(pre_train_only, train)
    # standardised on its own training rows → mean ≈ 0, std ≈ 1
    assert abs(x_train[:, j].mean()) < 1e-3
    assert abs(x_train[:, j].std() - 1) < 1e-2
    # the "leaky" fit would have produced visibly different statistics
    leaky = transform(pre_leaky, train)
    assert abs(leaky[:, list(pre_leaky.get_feature_names_out()).index("src_bytes")].mean()) > 0.05


def test_nominal_columns_are_one_hot_not_label_encoded():
    df = _make_df()
    pre, report = fit_preprocessor(df)
    names = set(pre.get_feature_names_out())
    assert {"protocol_type_tcp", "protocol_type_udp"} <= names
    assert "protocol_type" not in names
    assert report["nominal_cols"] == NOMINAL_COLS


def test_constant_and_skewed_columns_are_handled():
    df = _make_df()
    pre, report = fit_preprocessor(df)
    assert "num_outbound_cmds" in report["dropped_constant"]
    assert "src_bytes" in report["log1p_cols"]
    assert report["n_final_features"] < report["n_after_encoding_before_selection"]


def test_unseen_category_at_inference_does_not_crash():
    df = _make_df()
    pre, _ = fit_preprocessor(df)
    row = df.iloc[[0]].copy()
    row["service"] = "never_seen_service"
    x = transform(pre, row)
    names = list(pre.get_feature_names_out())
    service_cols = [i for i, n in enumerate(names) if n.startswith("service_")]
    assert np.allclose(x[0, service_cols], 0.0)


def test_held_out_category_never_influences_the_fit():
    df = _make_df()
    # a service that appears ONLY in the held-out category
    mask = df["attack_category"] == "R2L"
    df.loc[mask, "service"] = "only_in_r2l"
    split = leave_one_attack_out_split(df, "R2L", seed=1)
    names = split["feature_names"]
    assert "service_only_in_r2l" not in names
    # held-out rows are test-only: every test attack row is R2L, no R2L in train
    assert set(split["y_test"]) == {"Normal", "R2L"}
    assert "R2L" not in set(split["y_train_supervised"])
    assert split["X_test"].shape[1] == split["X_train_supervised"].shape[1] == len(names)
