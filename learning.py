"""
ZeroWatch - the self-learning loop (scikit-learn only, so it runs inside the lean serving image).

  find_campaigns()  group the "possible zero-day" flows into campaigns (KMeans) and write a
                    human-readable detection rule for each one (shallow decision tree)
  retrain()         add analyst-labelled flows to the training cache, fit a challenger with the
                    champion's hyperparameters, and promote it only if it is better
  red_team()        search for the fewest attacker-controllable changes that slip past detection

train.py imports build_classifier() from here so offline training and online retraining
build exactly the same model.
"""
from __future__ import annotations

import hashlib
import math
import random

import numpy as np
from sklearn.cluster import KMeans
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, silhouette_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import CAT_INDEX, CATEGORICAL, FEATURES, LOG_FEATURES, NUM_INDEX, encode

MIN_CAMPAIGN = 8          # flows needed before a cluster is called a campaign
MIN_LABELLED = 10         # labelled flows needed before a retrain is allowed
LABEL_WEIGHT = 25         # a labelled flow counts as much as 25 ordinary training rows
# features an attacker controls directly from their own machine; destination-host history,
# TCP flags and login state are observed by the defender and cannot simply be set
ATTACKER_CONTROLLED = ["duration", "src_bytes", "count", "srv_count", "same_srv_rate", "diff_srv_rate", "hot"]


def build_classifier(algorithm: str, p: dict, seed: int = 42) -> Pipeline:
    """Every algorithm is wrapped in a Pipeline so callers always use .predict_proba()."""
    if algorithm == "rf":
        clf = RandomForestClassifier(n_estimators=p["n_estimators"], max_depth=p["max_depth"],
                                     min_samples_leaf=2, n_jobs=-1, random_state=seed)
    elif algorithm == "extratrees":
        clf = ExtraTreesClassifier(n_estimators=p["n_estimators"], max_depth=p["max_depth"],
                                   min_samples_leaf=2, n_jobs=-1, random_state=seed)
    elif algorithm == "hgb":
        clf = HistGradientBoostingClassifier(learning_rate=p["learning_rate"], max_iter=p["max_iter"],
                                             max_depth=p["max_depth"], categorical_features=CAT_INDEX,
                                             random_state=seed)
    else:  # logreg needs one-hot categories and scaled numerics; trees do not
        pre = ColumnTransformer([("cat", OneHotEncoder(handle_unknown="ignore"), CAT_INDEX),
                                 ("num", StandardScaler(), NUM_INDEX)])
        return Pipeline([("pre", pre), ("clf", LogisticRegression(C=p["C"], max_iter=p["max_iter"]))])
    return Pipeline([("clf", clf)])


# ---------------------------------------------------------------- campaigns + signatures
def _readable(X: np.ndarray):
    """Encoded rows -> matrix a human can read rules from: raw numeric values and one
    0/1 column per category value (so a rule says `flag == RSTR`, not `flag <= 3.5`)."""
    cols, names = [], []
    for i, name in enumerate(FEATURES):
        if name in CATEGORICAL:
            for j, v in enumerate(CATEGORICAL[name]):
                cols.append((X[:, i].round() == j).astype(float))
                names.append((name, v))
        else:
            cols.append(np.expm1(X[:, i]) if name in LOG_FEATURES else X[:, i])
            names.append((name, None))
    return np.column_stack(cols), names


def _signature(cluster: np.ndarray, normal: np.ndarray) -> dict:
    """Depth-3 decision tree separating one campaign from normal traffic; the path to the
    leaf holding most of the campaign becomes the rule."""
    Xc, names = _readable(cluster)
    Xn, _ = _readable(normal)
    X = np.vstack([Xc, Xn])
    y = np.r_[np.ones(len(Xc)), np.zeros(len(Xn))]
    tree = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0).fit(X, y)
    leaves = tree.apply(Xc)
    leaf = np.bincount(leaves).argmax()
    t = tree.tree_
    path = tree.decision_path(Xc[leaves == leaf][:1]).indices
    bounds: dict = {}
    for node, child in zip(path[:-1], path[1:], strict=True):
        name, value = names[t.feature[node]]
        went_left = child == t.children_left[node]
        if value is not None:
            bounds[(name, value)] = "!=" if went_left else "=="
        else:
            lo, hi = bounds.get((name, None), (None, None))
            thr = float(t.threshold[node])
            bounds[(name, None)] = (lo, thr) if went_left else (thr, hi)
    conds = []
    for (name, value), b in bounds.items():
        if value is not None:
            conds.append(f"{name} {b} {value}")
        else:
            lo, hi = b
            fmt = (lambda v: f"{v:.2f}".rstrip("0").rstrip(".")) if name.endswith("_rate") else (lambda v: str(int(math.ceil(v))))
            if lo is not None:
                conds.append(f"{name} > {fmt(lo)}" if name.endswith("_rate") else f"{name} >= {fmt(lo)}")
            if hi is not None:
                conds.append(f"{name} <= {fmt(hi)}" if name.endswith("_rate") else f"{name} < {fmt(hi)}")
    hit = tree.apply(X) == leaf
    return {"rule": " AND ".join(conds) or "no separating rule found",
            "coverage": round(float(hit[: len(Xc)].mean()), 3),          # share of the campaign the rule matches
            "false_match_rate": round(float(hit[len(Xc):].mean()), 4)}  # share of normal traffic it would also match


def find_campaigns(entries: list[dict], normal: np.ndarray) -> list[dict]:
    """entries: log entries of flows currently judged 'possible zero-day'."""
    seen, rows = set(), []
    for e in entries:  # identical flows repeated in the log count once
        key = tuple(e["input"].values())
        if key not in seen:
            seen.add(key)
            rows.append(e)
    if len(rows) < MIN_CAMPAIGN:
        return []
    X = np.array([encode(e["input"]) for e in rows])
    Z = np.hstack([StandardScaler().fit(normal[:, NUM_INDEX]).transform(X[:, NUM_INDEX]).clip(-6, 6),
                   OneHotEncoder(categories=[list(range(len(CATEGORICAL[FEATURES[i]]))) for i in CAT_INDEX],
                                 sparse_output=False).fit_transform(X[:, CAT_INDEX].round())])
    labels, best = np.zeros(len(rows), dtype=int), 0.25  # stay with one group unless a split is clearly better
    for k in range(2, min(6, len(rows) // MIN_CAMPAIGN) + 1):
        cand = KMeans(n_clusters=k, n_init=5, random_state=0).fit_predict(Z)
        score = silhouette_score(Z, cand)
        if score > best:
            labels, best = cand, score
    out = []
    for c in sorted(set(labels), key=lambda c: -(labels == c).sum()):
        idx = np.where(labels == c)[0]
        if len(idx) < MIN_CAMPAIGN:
            continue
        members = [rows[i] for i in idx]
        sig = _signature(X[idx], normal)
        truth: dict = {}
        for m in members:
            if m.get("truth"):
                truth[m["truth"]] = truth.get(m["truth"], 0) + 1
        common = {}
        for name in CATEGORICAL:
            vals = [m["input"][name] for m in members]
            top = max(set(vals), key=vals.count)
            common[name] = {"value": top, "share": round(vals.count(top) / len(vals), 2)}
        out.append({"id": hashlib.sha1(sig["rule"].encode()).hexdigest()[:10], "size": len(members),
                    "mean_risk": round(sum(m["output"]["risk_score"] for m in members) / len(members)),
                    "signature": sig, "common": common,
                    "true_labels": dict(sorted(truth.items(), key=lambda kv: -kv[1])[:4]),
                    "flows": [m["input"] for m in members]})
    return out


# ---------------------------------------------------------------- retraining
def retrain(detector: Pipeline, meta: dict, cache: dict, labelled: list[dict]) -> dict:
    """Champion/challenger. `labelled` rows are {"input": flow, "label": "attack"|"benign"}.
    30% of the labelled flows are held back so the improvement is measured on flows the
    challenger did not train on."""
    report: dict = {"labelled": len(labelled), "promoted": False}
    if len(labelled) < MIN_LABELLED:
        return report | {"reason": f"Need at least {MIN_LABELLED} labelled flows, have {len(labelled)}."}
    X = np.array([encode(r["input"]) for r in labelled])
    y = np.array([1 if r["label"] == "attack" else 0 for r in labelled])

    # poisoning guard: a "benign" label on a flow the champion is almost certain is an attack is
    # more likely a mistake or sabotage than new knowledge, so it is quarantined
    p_champ = detector.predict_proba(X)[:, 1]
    suspicious = (y == 0) & (p_champ > 0.99)
    report["quarantined_labels"] = int(suspicious.sum())
    X, y = X[~suspicious], y[~suspicious]
    if len(y) < MIN_LABELLED:
        return report | {"reason": "Too few labels left after quarantining suspicious ones."}

    order = np.random.default_rng(0).permutation(len(y))
    cut = max(3, int(len(y) * 0.3))
    hold, fit = order[:cut], order[cut:]
    Xf = np.vstack([cache["X_fit"], X[fit]])
    yf = np.r_[cache["y_fit"], y[fit]]
    weight = np.r_[np.ones(len(cache["y_fit"])), np.full(len(fit), LABEL_WEIGHT)]
    params = {k: v for k, v in meta["params"].items() if k not in ("algorithm", "threshold", "contamination",
                                                                    "seed", "train_rows")}
    challenger = build_classifier(meta["algorithm"], params, meta["params"]["seed"])
    challenger.fit(Xf, yf, clf__sample_weight=weight)

    thr = meta["threshold"]
    def scores(model):
        return {"validation_f1": round(float(f1_score(cache["y_val"], model.predict_proba(cache["X_val"])[:, 1] >= thr)), 4),
                "labelled_holdout_accuracy": round(float(((model.predict_proba(X[hold])[:, 1] >= thr) == y[hold]).mean()), 4)}
    champ, chall = scores(detector), scores(challenger)
    better = chall["labelled_holdout_accuracy"] > champ["labelled_holdout_accuracy"]
    safe = chall["validation_f1"] >= champ["validation_f1"] - 0.002  # must not forget what it already knew
    report |= {"champion": champ, "challenger": chall, "holdout_flows": int(len(hold)), "promoted": bool(better and safe),
               "reason": ("Challenger is better on held-back labelled flows and no worse on validation." if better and safe
                          else "Challenger does not beat the champion on held-back labelled flows." if not better
                          else "Challenger lost more than 0.002 validation F1, so it was rejected.")}
    if report["promoted"]:
        report["detector"] = challenger
    return report


# ---------------------------------------------------------------- evasion search
def red_team(flow: dict, stats: dict, baseline: dict, judge, max_changes: int = 4) -> dict:
    """Greedy evasion search. `judge(flows) -> list[(verdict, risk)]`. At each step try moving
    one attacker-controlled feature to a normal-looking value and keep the change that lowers
    the risk most. Fewer changes needed = more fragile detection."""
    cur = dict(flow)
    verdict, risk = judge([cur])[0]
    start, changes = risk, []
    rng = random.Random(0)
    for _ in range(max_changes):
        if verdict == "benign":
            break
        trials = []
        for name in ATTACKER_CONTROLLED:
            s = stats[name]
            kind_float = name.endswith("_rate")
            cands = {baseline[name], round(s["p50"], 2) if kind_float else int(s["p50"]),
                     round(min(1.0, s["mean"]), 2) if kind_float else int(s["mean"])}
            for v in cands - {cur[name]}:
                trials.append((name, v))
        rng.shuffle(trials)
        results = judge([cur | {n: v} for n, v in trials])
        best = min(range(len(trials)), key=lambda i: results[i][1])
        if results[best][1] >= risk:
            break
        name, v = trials[best]
        changes.append({"feature": name, "from": cur[name], "to": v, "risk_after": results[best][1]})
        cur[name] = v
        verdict, risk = results[best]
    evaded = verdict == "benign"
    return {"evaded": evaded, "changes": changes, "start_risk": start, "final_risk": risk, "final_verdict": verdict,
            "robustness": "fragile" if evaded and len(changes) <= 1 else "moderate" if evaded else "robust",
            "attacker_controlled": ATTACKER_CONTROLLED}
