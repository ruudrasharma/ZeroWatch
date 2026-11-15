"""
ZeroWatch - FastAPI serving app.

Routes
  GET  /                    analyst console (static/index.html)
  GET  /health              liveness + model status
  POST /predict             score one network flow (422 on any contract violation)
  POST /predict/batch       score up to 500 flows
  POST /counterfactual      smallest set of changes that would make a flagged flow benign
  POST /redteam             can an attacker slip this flow past detection? (evasion search)
  GET  /campaigns           possible zero-days grouped into campaigns, each with a generated rule
  POST /campaigns/{id}/label   analyst labels a whole campaign
  POST /learning/retrain    train a challenger on the labelled flows; promote it only if better
  GET  /audit/verify        check the hash chain of the prediction log
  GET  /brief               shift report: what happened and what to do
  POST /capture             upload a .pcap: packets -> flows -> verdicts + host graph
  GET  /capture/sample      the same for the bundled sample capture
  POST /assets, GET /assets register an asset; one passive exposure scan; alerts on it get a priority
  POST /copilot             ask a question about what the service has seen (LLM or built-in rules)
  GET  /overview            one-screen summary for the dashboard
  GET  /alerts, PATCH /alerts/{id}   triage queue; closing an alert labels the flow
  GET  /campaigns/{id}/rule | /rule/test | /report   Sigma rule, its hits on the log, incident report
  POST /learning/rollback, GET /learning/status      saved model versions
  POST /settings/threshold, POST /monitoring/alarm/test, GET /audit/actions
  GET  /simulate/stream     the replay as Server-Sent Events
  POST /learning/retrain {"mode": "shadow"}, GET|DELETE /learning/shadow, POST /learning/shadow/promote
  GET  /campaigns/{id}/stix STIX 2.1 bundle

Roles: set ANALYST_TOKEN and ADMIN_TOKEN to require an X-API-Key on every route that changes state.
  GET  /simulate            replay labelled held-out flows through the model
  GET  /contract            the data contract (drives the UI form)
  GET  /model/info          model card: algorithm, hyperparameters, metrics
  GET  /monitoring/drift    live inputs vs training statistics
  GET  /monitoring/recent   last predictions
  POST /feedback            analyst says a verdict was right/wrong (retraining signal)
  GET  /metrics             Prometheus metrics
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

import pcap_flows
import recon
from drift_check import drift_report, read_inputs
from features import CONTRACT, FEATURES, FLAGS, PROTOCOLS, SERVICES, encode
from learning import retrain
from ops import Registry, blocklist, match_rule, send_webhook
from store import ChainLog

ROOT = Path(__file__).resolve().parent
MODEL_PATH = Path(os.getenv("MODEL_PATH", ROOT / "model" / "model.joblib"))
LOG_DIR = Path(os.getenv("LOG_DIR", ROOT / "logs"))
LOG_FILE = LOG_DIR / "predictions.jsonl"
FEEDBACK_FILE = LOG_DIR / "feedback.jsonl"
LABEL_FILE = LOG_DIR / "labelled.jsonl"
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "600"))
# Access control. With neither token set the service runs in open mode (local development).
# On a public deployment set both: analysts can label and triage, admins can also retrain,
# roll back, change the threshold and manage assets.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
ANALYST_TOKEN = os.getenv("ANALYST_TOKEN", "")
# Named accounts so the action log says who acted: USERS="asha:analyst:<key>,ravi:admin:<key>"
USERS = {tok: (name, role) for name, role, tok in
         (u.split(":", 2) for u in os.getenv("USERS", "").split(",") if u.count(":") >= 2) if role in ("analyst", "admin")}
DOCS_ENABLED = os.getenv("DOCS_ENABLED", "1") == "1"
ON_RENDER = bool(os.getenv("RENDER"))               # Render sets this itself; a public host must never run open
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"  # only then is X-Forwarded-For believed
REAL_SOURCES = {"api", "batch", "capture"}          # replay and the bundled sample are demo traffic
PRED_LOG = ChainLog(LOG_FILE, int(os.getenv("LOG_MAX_BYTES", "5000000")))
AUDIT_LOG = ChainLog(LOG_DIR / "audit.jsonl")       # who labelled, retrained, rolled back, changed settings
ALERT_FILE = LOG_DIR / "alerts.json"
SETTINGS_FILE = LOG_DIR / "settings.json"
REGISTRY = Registry(LOG_DIR / "models")
STARTED = time.time()

# ---- Stage 3: the model is loaded ONCE here, at import/startup, never per request ----
# Integrity check first: a .joblib file is a pickle, and unpickling a tampered file runs
# whatever code is inside it. train.py writes the SHA-256 next to the model.
_sha_file = MODEL_PATH.with_suffix(".sha256")
MODEL_SHA = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
# MODEL_SHA256 (environment) outranks the file: someone who can replace the model on disk can
# replace the .sha256 beside it too, but not the deployment's environment.
_expected = os.getenv("MODEL_SHA256") or (_sha_file.read_text().strip() if _sha_file.exists() else MODEL_SHA)
if _expected != MODEL_SHA and os.getenv("ALLOW_UNVERIFIED_MODEL") != "1":
    raise RuntimeError(f"{MODEL_PATH} does not match its expected SHA-256; refusing to load an unverified model")
BUNDLE = joblib.load(MODEL_PATH)
DETECTOR, NOVELTY, FAMILY, META = BUNDLE["detector"], BUNDLE["novelty"], BUNDLE["family"], BUNDLE["meta"]
BASE_DETECTOR = DETECTOR  # generation 0, what model.joblib shipped with
THRESHOLD = float(os.getenv("THRESHOLD", META["threshold"]))
MODEL_VERSION = f"{META['algorithm']}-{META['trained_at'][:10]}-{META.get('mlflow_run_id', 'local')[:8]}"
BASELINE = META["baseline"]  # typical normal flow, used for explanations
SAMPLES = json.loads((ROOT / "data" / "sample_flows.json").read_text())
QHAT = META.get("conformal", {}).get("qhat", 0.02)  # "not sure" band: QHAT < attack probability < 0.5
_cache_file = MODEL_PATH.with_name("train_cache.npz")
CACHE = dict(np.load(_cache_file)) if _cache_file.exists() else None  # training data for online retraining
NORMAL_REF = CACHE["X_fit"][CACHE["y_fit"] == 0][:2000].astype(float) if CACHE else None
LEARNING = {"generation": 0, "last_report": None}
_retrain_lock = threading.Lock()
ALARM = {"last_check": None, "drift": "waiting", "chain_valid": True, "last_sent": None, "webhook": bool(os.getenv("ALERT_WEBHOOK_URL"))}
ASSET_FILE = LOG_DIR / "assets.json"
ASSETS: dict[str, dict] = json.loads(ASSET_FILE.read_text()) if ASSET_FILE.exists() else {}
MAX_CAPTURE_BYTES = 5_000_000
CAMPAIGNS: dict[str, dict] = {}

RECENT: deque = deque(maxlen=300)
_log_lock = threading.Lock()
_hits: dict[str, deque] = {}

# ---- Prometheus metrics ----
PREDICTIONS = Counter("zerowatch_predictions_total", "Predictions served", ["verdict"])
REJECTED = Counter("zerowatch_rejected_requests_total", "Requests rejected by validation (422)")
LATENCY = Histogram("zerowatch_inference_seconds", "Model inference time",
                    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2))
RISK = Histogram("zerowatch_risk_score", "Risk score distribution (drift signal)",
                 buckets=(10, 20, 30, 40, 50, 60, 70, 80, 90, 100))
MODEL_UP = Gauge("zerowatch_model_loaded", "1 when the model bundle is in memory")
MODEL_UP.set(1)
LOG_ENTRIES = Gauge("zerowatch_log_entries", "Entries in the current prediction log (falls if the log is truncated)")
GENERATION = Gauge("zerowatch_model_generation", "0 = shipped model, n = nth promoted challenger")
DRIFT_STATE = Gauge("zerowatch_drift_state", "0 ok / waiting, 1 warn, 2 drift")


# ---- Data contract: every row of the README table is enforced here ----
class Flow(BaseModel):
    # strict: "5" is not an int, true is not a count, 1000.0 is not a byte count -> all 422
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False, json_schema_extra={"example": {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 232,
        "dst_bytes": 8153, "logged_in": 1, "wrong_fragment": 0, "hot": 0, "num_failed_logins": 0,
        "root_shell": 0, "count": 5, "srv_count": 5, "serror_rate": 0.0, "rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "dst_host_count": 30, "dst_host_srv_count": 255,
        "dst_host_serror_rate": 0.0}})

    duration: int = Field(ge=0, le=86400)
    protocol_type: Literal[tuple(PROTOCOLS)]
    service: Literal[tuple(SERVICES)]
    flag: Literal[tuple(FLAGS)]
    src_bytes: int = Field(ge=0, le=2_000_000_000)
    dst_bytes: int = Field(ge=0, le=2_000_000_000)
    logged_in: int = Field(ge=0, le=1)
    wrong_fragment: int = Field(ge=0, le=3)
    hot: int = Field(ge=0, le=101)
    num_failed_logins: int = Field(ge=0, le=5)
    root_shell: int = Field(ge=0, le=1)
    count: int = Field(ge=0, le=511)
    srv_count: int = Field(ge=0, le=511)
    serror_rate: float = Field(ge=0, le=1)
    rerror_rate: float = Field(ge=0, le=1)
    same_srv_rate: float = Field(ge=0, le=1)
    diff_srv_rate: float = Field(ge=0, le=1)
    dst_host_count: int = Field(ge=0, le=255)
    dst_host_srv_count: int = Field(ge=0, le=255)
    dst_host_serror_rate: float = Field(ge=0, le=1)


class Batch(BaseModel):
    flows: list[Flow] = Field(min_length=1, max_length=500)


class Feedback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=8, max_length=64)
    correct: bool
    true_label: Literal["benign", "attack"] | None = None
    note: str = Field(default="", max_length=500)


# ---- Scoring ----
MITRE = {
    "DoS": [("T1498", "Network Denial of Service"), ("T1499", "Endpoint Denial of Service")],
    "Probe": [("T1046", "Network Service Discovery"), ("T1595", "Active Scanning")],
    "R2L": [("T1110", "Brute Force"), ("T1078", "Valid Accounts")],
    "U2R": [("T1068", "Exploitation for Privilege Escalation"), ("T1548", "Abuse Elevation Control Mechanism")],
}


def score_matrix(X: np.ndarray):
    """Returns attack probability and novelty score (0.5 = alert threshold) per row."""
    p = DETECTOR.predict_proba(X)[:, 1]
    raw = -NOVELTY.score_samples(X)
    nov = 1.0 / (1.0 + np.exp(-(raw - META["novelty"]["cut"]) / META["novelty"]["spread"]))
    return p, nov


def fuse(p: float, nov: float):
    """Known pattern -> attack. Not recognised but unlike normal traffic -> zero-day suspect.
    Looks normal but the classifier is not confident enough to say so -> uncertain (human review)."""
    if p >= THRESHOLD:
        verdict, risk = "attack", p
    elif nov >= 0.5:
        verdict, risk = "zero_day_suspect", max(p, 0.5 + 0.45 * (nov - 0.5) / 0.5)
    elif p > QHAT:
        verdict, risk = "uncertain", max(p, 0.25)
    else:
        verdict, risk = "benign", p
    risk = int(round(100 * risk))
    severity = "critical" if risk >= 85 else "high" if risk >= 65 else "medium" if risk >= 40 else "low"
    return verdict, risk, severity


def explain(flow: dict, x: list[float], verdict: str, p: float, nov: float) -> list[dict]:
    """Sampled Shapley values against a typical normal flow (BASELINE).

    Start from the normal flow and switch this flow's values in one at a time,
    in a random order; a feature's contribution is how much the score moves at
    the moment it is switched in. Averaged over 24 random orders. The
    contributions add up to (this flow's score - the normal flow's score), and
    because only predictions are used it works for whichever algorithm won.
    Single-feature occlusion is not enough here: in a flood, several features
    are each sufficient on their own, so removing any one changes nothing."""
    base = encode(BASELINE)
    differs = [i for i in range(len(x)) if x[i] != base[i]]
    if not differs:
        return []
    rng = random.Random(0)  # fixed seed: same flow -> same explanation
    rows, steps = [base], []
    for _ in range(24):
        order = differs[:]
        rng.shuffle(order)
        cur = base[:]
        for i in order:
            cur = cur[:]
            cur[i] = x[i]
            rows.append(cur)
            steps.append(i)
    X = np.array(rows)
    if verdict == "zero_day_suspect":  # explain the score that drove the verdict
        raw = -NOVELTY.score_samples(X)
        s = 1.0 / (1.0 + np.exp(-(raw - META["novelty"]["cut"]) / META["novelty"]["spread"]))
    else:
        s = DETECTOR.predict_proba(X)[:, 1]
    impact = dict.fromkeys(differs, 0.0)
    k = len(differs)
    for j, i in enumerate(steps):
        prev = s[0] if j % k == 0 else s[j]  # each walk restarts from the baseline row
        impact[i] += (s[j + 1] - prev) / 24
    out = [{"feature": FEATURES[i], "value": flow[FEATURES[i]], "typical": BASELINE[FEATURES[i]],
            "impact": round(float(d), 4)} for i, d in impact.items() if abs(d) >= 0.005]
    return sorted(out, key=lambda f: -abs(f["impact"]))[:6]


def tips(flow: dict, verdict: str, family: str | None) -> list[str]:
    """Rule-based analyst guidance (2-3 items) from the flow's own values."""
    t = []
    if flow["serror_rate"] >= 0.5 or flow["flag"] in ("S0", "SH"):
        lead = (f"{flow['serror_rate']:.0%} of recent connections never completed the TCP handshake."
                if flow["serror_rate"] >= 0.5 else f"This connection's SYN was never answered (flag {flow['flag']}).")
        t.append(lead + " Turn on SYN cookies and rate-limit new connections per source IP.")
    if flow["rerror_rate"] >= 0.5 or flow["diff_srv_rate"] >= 0.3 or flow["flag"] in ("REJ", "RSTR", "RSTOS0"):
        t.append("The source is touching many closed ports or services, which is how a port scan looks. "
                 "Block the source at the perimeter and review which services are exposed.")
    if flow["num_failed_logins"] >= 1:
        t.append(f"{flow['num_failed_logins']} failed login(s) on {flow['service']}. "
                 "Enforce account lockout and MFA, and check the account for a later successful login.")
    if flow["root_shell"] == 1 or flow["hot"] >= 5:
        t.append("Privileged activity on the host (root shell or sensitive directory access). "
                 "Isolate the machine and review running processes and recent sudo/su history.")
    if flow["wrong_fragment"] >= 1:
        t.append("Malformed IP fragments were seen. Drop fragmented packets at the firewall and patch the target's network stack.")
    if flow["count"] >= 200 and not t:
        t.append(f"{flow['count']} connections to one host in two seconds. Apply per-source rate limiting upstream.")
    if verdict == "zero_day_suspect":
        t.insert(0, "No known attack pattern matched, but this flow is unlike normal traffic. "
                    "Capture packets for this source, quarantine if the asset is sensitive, and escalate to tier 2.")
        t.append("Label this flow after triage so it can join the next retraining set.")
    elif verdict == "uncertain":
        t.insert(0, "The model cannot rule this flow in or out at 95% confidence. Queue it for manual review "
                    "rather than auto-closing it.")
    elif verdict == "attack" and len(t) < 2:
        t.append(f"Matches the {family} family. Add the source to the watchlist and correlate with firewall and auth logs for the same time window.")
    if verdict == "benign":
        t = t[:1]
        t.append("No action needed. The flow matches normal traffic for this service.")
        if flow["logged_in"] == 0 and flow["service"] in ("telnet", "ftp", "login", "shell"):
            t.append(f"{flow['service']} is a clear-text protocol. Prefer SSH/SFTP even for benign use.")
        else:
            t.append("Keep sampling flows from this service so the drift monitor has a current baseline.")
    if len(t) < 2:
        t.append("Record the verdict with the feedback buttons so wrong calls feed the next retraining run.")
    return t[:3]


def summarise(flow: dict, verdict: str, risk: int, family: str | None, factors: list[dict]) -> str:
    why = ", ".join(f"{f['feature']}={f['value']}" for f in factors[:3]) or "no single dominant feature"
    conn = f"{flow['protocol_type'].upper()}/{flow['service']} flow with flag {flow['flag']}"
    if verdict == "attack":
        return f"{conn} scored {risk}/100 and matches known {family} behaviour. Main drivers: {why}."
    if verdict == "zero_day_suspect":
        return (f"{conn} scored {risk}/100. The classifier does not recognise it as a known attack, "
                f"but the novelty model places it outside normal traffic. Most unusual: {why}.")
    if verdict == "uncertain":
        return (f"{conn} scored {risk}/100. It resembles normal traffic, but the attack probability is above the "
                f"level the model was calibrated to trust, so it is held for review. Closest signals: {why}.")
    return f"{conn} scored {risk}/100 and is consistent with normal traffic."


SHADOW = {"detector": None, "since": None, "report": None, "stats": None}


def _shadow_observe(X: np.ndarray, p_live: np.ndarray, truths: list) -> None:
    """Shadow mode: the challenger scores the same traffic as the live model, but its answers
    are only counted, never returned. Disagreements show what promoting it would change."""
    det = SHADOW["detector"]
    if det is None:
        return
    live, shadow = p_live >= THRESHOLD, det.predict_proba(X)[:, 1] >= THRESHOLD
    st = SHADOW["stats"]
    st["flows"] += len(X)
    st["agree"] += int((live == shadow).sum())
    for lv, sh, truth in zip(live, shadow, truths, strict=True):
        if lv == sh:
            continue
        side = "only_shadow_flags" if sh else "only_live_flags"
        st[side] += 1
        if truth is not None:
            st[side + ("_true_normal" if truth == "normal" else "_true_attack")] += 1


def _build(flow: dict, p: float, nov: float, fam_row, factors: list, t0: float) -> dict:
    verdict, risk, severity = fuse(p, nov)
    family, fam_probs = None, {}
    if fam_row is not None:
        fam_probs = {c: round(float(v), 3) for c, v in zip(FAMILY.classes_, fam_row, strict=False)}
        if verdict == "attack":
            family = max(fam_probs, key=fam_probs.get)
    result = {
        "request_id": uuid.uuid4().hex[:12],
        "verdict": verdict, "risk_score": risk, "severity": severity,
        "attack_probability": round(p, 4), "novelty_score": round(nov, 4),
        "attack_family": family, "family_probabilities": fam_probs,
        "mitre_attack": [{"id": i, "name": n} for i, n in MITRE.get(family or "", [])],
        "top_factors": factors,
        "tips": tips(flow, verdict, family),
        "summary": summarise(flow, verdict, risk, family, factors),
        "model_version": model_version(),
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
    asset = next((a for a in ASSETS.values() if flow["service"] in a["services"]), None)
    if asset:  # recon fusion: the same risk matters more on an exposed asset
        result["asset_context"] = {"asset": asset["name"], "exposure": asset["exposure"], "grade": asset["grade"],
                                   "priority": recon.priority(risk, asset["exposure"]),
                                   "top_finding": asset["findings"][0]["text"] if asset["findings"] else None}
    return result


def analyse(flow: dict, with_explanation: bool = True, log: bool = True, truth: str | None = None,
            source: str = "api") -> dict:
    """Score one flow, with its explanation."""
    t0 = time.perf_counter()
    x = encode(flow)
    X = np.array([x])
    ps, novs = score_matrix(X)
    p, nov = float(ps[0]), float(novs[0])
    verdict = fuse(p, nov)[0]
    fam_row = FAMILY.predict_proba(X)[0] if verdict != "benign" else None
    factors = explain(flow, x, verdict, p, nov) if with_explanation else []
    result = _build(flow, p, nov, fam_row, factors, t0)
    if log:  # what-if and red-team probes are not real traffic: keep them out of the log and metrics
        LATENCY.observe(time.perf_counter() - t0)
        PREDICTIONS.labels(verdict).inc()
        RISK.observe(result["risk_score"])
        _shadow_observe(X, ps, [truth])
        log_prediction(flow, result, truth, source)
    return result


def analyse_many(flows: list[dict], source: str, truths: list | None = None, log: bool = True) -> list[dict]:
    """Score many flows with ONE call to each model. Scoring them one by one made a 500-flow
    batch take 10 s and a 3,000-connection capture 40 s; this is about 100 times faster."""
    if not flows:
        return []
    t0 = time.perf_counter()
    truths = truths or [None] * len(flows)
    X = np.array([encode(f) for f in flows])
    ps, novs = score_matrix(X)
    flagged = [i for i in range(len(flows)) if fuse(float(ps[i]), float(novs[i]))[0] != "benign"]
    fam = dict(zip(flagged, FAMILY.predict_proba(X[flagged]), strict=True)) if flagged else {}
    results = [_build(f, float(ps[i]), float(novs[i]), fam.get(i), [], t0) for i, f in enumerate(flows)]
    if log:
        LATENCY.observe((time.perf_counter() - t0) / len(flows))
        now = datetime.now(UTC).isoformat(timespec="seconds")
        entries = []
        for f, r, truth in zip(flows, results, truths, strict=True):
            PREDICTIONS.labels(r["verdict"]).inc()
            RISK.observe(r["risk_score"])
            entries.append(_log_entry(f, r, truth, source, now))
        _shadow_observe(X, ps, truths)
        PRED_LOG.append_many(entries)
        RECENT.extendleft(entries)
    return results


def _log_entry(flow: dict, result: dict, truth: str | None, source: str, ts: str) -> dict:
    entry = {"ts": ts, "request_id": result["request_id"], "source": source, "input": flow,
             "output": {k: result[k] for k in ("verdict", "risk_score", "attack_probability",
                                               "novelty_score", "attack_family")},
             "model_version": result["model_version"]}
    if truth:
        entry["truth"] = truth  # only the labelled replay knows the real answer
    return entry


def log_prediction(flow: dict, result: dict, truth: str | None = None, source: str = "api") -> None:
    """Stage 8: every prediction input is appended to a JSON-lines file for drift checks.
    The file is hash-chained and rotated by store.ChainLog. `source` separates real traffic
    (api, batch, capture) from demo traffic (replay, capture-sample) so demos cannot fake drift."""
    entry = _log_entry(flow, result, truth, source, datetime.now(UTC).isoformat(timespec="seconds"))
    PRED_LOG.append(entry)
    RECENT.appendleft(entry)


def read_log(last: int = 3000) -> list[dict]:
    return PRED_LOG.read(last)


# ---- access control ----
def client_ip(request: Request) -> str:
    """The proxy appends the address it saw, so only the LAST X-Forwarded-For hop is trustworthy,
    and only when we know a proxy is in front (TRUST_PROXY=1). Anything else is attacker-controlled."""
    if TRUST_PROXY and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[-1].strip()
    return request.client.host if request.client else "?"


def identity(request: Request) -> tuple[str, str]:
    """(role, user) for this request. Keys are compared in constant time."""
    if open_mode():
        return "admin", "open-mode"
    key = request.headers.get("x-api-key", "")
    for tok, (name, role) in USERS.items():
        if hmac.compare_digest(key, tok):
            return role, name
    if ADMIN_TOKEN and hmac.compare_digest(key, ADMIN_TOKEN):
        return "admin", "admin"
    if ANALYST_TOKEN and hmac.compare_digest(key, ANALYST_TOKEN):
        return "analyst", "analyst"
    return "viewer", "anonymous"


def role_of(request: Request) -> str:
    return identity(request)[0]


def open_mode() -> bool:
    """Open mode is for local development only. On a public host without tokens, everything that
    changes state stays locked (viewer role) instead of being open to every visitor."""
    return not ADMIN_TOKEN and not ANALYST_TOKEN and not USERS and not ON_RENDER


def require(minimum: str):
    def check(request: Request) -> str:
        role, user = identity(request)
        if role == "viewer":
            raise HTTPException(401, "This needs an API key. Send it in the X-API-Key header.")
        if minimum == "admin" and role != "admin":
            raise HTTPException(403, "This action needs an admin key; an analyst key is not enough.")
        return f"{role}/{user}"
    return check


analyst = Depends(require("analyst"))
admin = Depends(require("admin"))


def audit(actor: str, action: str, **detail) -> None:
    role, _, user = actor.partition("/")
    AUDIT_LOG.append({"ts": datetime.now(UTC).isoformat(timespec="seconds"), "role": role, "user": user or role,
                      "action": action, "detail": detail})


def judge(flows: list[dict]) -> list[tuple[str, int]]:
    """Verdict and risk for many flows at once, without logging (used by the search tools)."""
    p, nov = score_matrix(np.array([encode(f) for f in flows]))
    return [fuse(float(a), float(b))[:2] for a, b in zip(p, nov, strict=True)]


def model_version() -> str:
    return MODEL_VERSION + (f"+learned{LEARNING['generation']}" if LEARNING["generation"] else "")


# ---- App ----
ALARM_INTERVAL = int(os.getenv("ALARM_INTERVAL_SECONDS", "300"))


def _restore_state() -> None:
    """After a restart: bring back the promoted model and the tuned threshold."""
    global THRESHOLD
    active = REGISTRY.state()["active"]
    if active and REGISTRY.load(active) is not None:
        _activate(active)
    try:
        THRESHOLD = float(json.loads(SETTINGS_FILE.read_text())["threshold"])
    except (OSError, ValueError, KeyError):
        pass


def _alarm_loop(stop: threading.Event) -> None:
    while not stop.wait(ALARM_INTERVAL):
        try:
            check_alarm()
            auto_retrain()
        except Exception:  # noqa: BLE001 - the watchdog must never die
            pass


@asynccontextmanager
async def lifespan(_: FastAPI):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _restore_state()
    stop = threading.Event()
    if ALARM_INTERVAL > 0:
        threading.Thread(target=_alarm_loop, args=(stop,), daemon=True).start()
    yield
    stop.set()


app = FastAPI(title="ZeroWatch", version="3.0.0", lifespan=lifespan, docs_url="/docs" if DOCS_ENABLED else None,
              redoc_url=None, openapi_url="/openapi.json" if DOCS_ENABLED else None,
              description="AI-based zero-day attack detection: supervised detector + novelty model, "
                          "with explanations, drift monitoring and a validated data contract.")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.exception_handler(RequestValidationError)
async def contract_violation(_: Request, exc: RequestValidationError):
    """422 with only loc/msg/type. FastAPI's default echoes the offending input
    back, and a NaN input cannot be serialised to JSON, which turned a bad
    request into a 500."""
    detail = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse({"detail": detail}, status_code=422)


@app.middleware("http")
async def guard(request: Request, call_next):
    """Per-IP rate limit on scoring routes + basic security headers."""
    if request.url.path.startswith(("/predict", "/counterfactual", "/redteam", "/learning", "/capture", "/copilot",
                                    "/campaigns", "/alerts", "/feedback", "/settings")):
        ip = client_ip(request)
        if len(_hits) > 5000:  # do not let the table grow without bound
            _hits.clear()
        q = _hits.setdefault(ip, deque())
        now = time.time()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return JSONResponse({"detail": "Rate limit exceeded. Try again in a minute."}, status_code=429)
        q.append(now)
    response = await call_next(request)
    if response.status_code == 422:
        REJECTED.inc()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith(("/docs", "/openapi")):  # Swagger UI loads its script from a CDN
        # scripts only from this origin: an injected <script> or inline handler cannot run and steal the API key
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if TRUST_PROXY or ON_RENDER:  # served over HTTPS behind the platform's proxy
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if "json" in response.headers.get("content-type", ""):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def ui():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(ROOT / "static" / "favicon.svg", media_type="image/svg+xml")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": True, "model_version": model_version(), "model_sha256": MODEL_SHA[:16],
            "log_head": PRED_LOG.head[:16],
            "algorithm": META["algorithm"], "uptime_seconds": int(time.time() - STARTED)}


@app.post("/predict")
def predict(flow: Flow):
    return analyse(flow.model_dump())


@app.post("/predict/batch")
def predict_batch(batch: Batch):
    results = analyse_many([f.model_dump() for f in batch.flows], "batch")
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"count": len(results), "verdicts": counts, "results": results}


def _replay(n: int, log: bool) -> list[dict]:
    picked = random.sample(SAMPLES["flows"], n)
    results = analyse_many([s["flow"] for s in picked], "replay", [s["label"] for s in picked], log=log)
    return [{"flow": s["flow"], "truth": {k: s[k] for k in ("label", "family", "seen_in_training")},
             "result": {k: r[k] for k in ("request_id", "verdict", "risk_score", "severity",
                                          "attack_family", "attack_probability", "novelty_score")}}
            for s, r in zip(picked, results, strict=True)]


def _may_log_demo(request: Request) -> bool:
    """With keys configured, replayed and sample traffic from a visitor WITHOUT a key is scored
    but not written to the log, so an anonymous visitor cannot fill the disk or seed the hunt."""
    return role_of(request) != "viewer"


@app.get("/contract")
def contract():
    return {"features": [{"name": n, "type": k, "why": why,
                          **({"values": spec} if k == "cat" else {"min": spec[0], "max": spec[1]})}
                         for n, k, spec, why in CONTRACT],
            "presets": SAMPLES["presets"], "baseline": BASELINE}


@app.get("/model/info")
def model_info():
    return {"model_version": model_version(), "threshold": THRESHOLD, "model_sha256": MODEL_SHA,
            "learning": {k: v for k, v in LEARNING.items() if k != "detector"},
            **{k: META[k] for k in ("algorithm", "params", "metrics", "trained_at", "git_sha", "sklearn",
                                    "rows", "feature_importance", "data_sha256")},
            "threshold_curve": META.get("threshold_curve", []), "qhat": QHAT, "evaluation": META.get("evaluation"),
            "cross_dataset": json.loads((ROOT / "model" / "cross_dataset.json").read_text())
            if (ROOT / "model" / "cross_dataset.json").exists() else None,
            "experiments": json.loads((ROOT / "model" / "experiments.json").read_text())
            if (ROOT / "model" / "experiments.json").exists() else []}


def current_suspects() -> list[dict]:
    """Logged flows that the CURRENT model still calls a possible zero-day (after a retrain,
    flows the new model recognises drop out of the hunt on their own)."""
    uniq = {}
    for e in read_log():
        if e["output"]["verdict"] == "zero_day_suspect":
            uniq.setdefault(json.dumps(e["input"], sort_keys=True), e)  # the same flow replayed counts once
    seen = list(uniq.values())
    if not seen:
        return []
    done = {json.dumps(r["input"], sort_keys=True) for r in _read_labelled()}  # already triaged
    seen = [e for e in seen if json.dumps(e["input"], sort_keys=True) not in done]
    if not seen:
        return []
    verdicts = judge([e["input"] for e in seen])
    return [e for e, (v, _risk) in zip(seen, verdicts, strict=True) if v == "zero_day_suspect"]


def _campaign(campaign_id: str) -> dict:
    c = CAMPAIGNS.get(campaign_id)
    if not c:
        raise HTTPException(404, "Unknown campaign. Reload the campaign list and try again.")
    return c


def _read_labelled() -> list[dict]:
    if not LABEL_FILE.exists():
        return []
    return [json.loads(line) for line in LABEL_FILE.read_text().splitlines() if line.strip()]


def _labelled_counts() -> dict:
    rows = _read_labelled()
    return {"attack": sum(r["label"] == "attack" for r in rows), "benign": sum(r["label"] == "benign" for r in rows)}


def _write_labels(rows: list[dict]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LABEL_FILE.write_text("".join(json.dumps(r) + "\n" for r in rows))


def _add_labels(rows: list[dict]) -> None:
    """One label per flow, the newest wins. Otherwise a flow marked benign twice and then confirmed
    as an attack would enter training three times with contradictory answers."""
    with _log_lock:
        current = {json.dumps(r["input"], sort_keys=True): r for r in _read_labelled()}
        for r in rows:
            key = json.dumps(r["input"], sort_keys=True)
            current.pop(key, None)  # re-insert at the end: newest last
            current[key] = r
        _write_labels(list(current.values()))


def _remove_labels(match) -> int:
    with _log_lock:
        rows = _read_labelled()
        keep = [r for r in rows if not match(r)]
        if len(keep) != len(rows):
            _write_labels(keep)
        return len(rows) - len(keep)


def _rule_test(conditions: list[dict]) -> dict:
    """Run a rule over the distinct flows in the prediction log."""
    uniq = {json.dumps(e["input"], sort_keys=True): e for e in read_log()}
    hits = [e for e in uniq.values() if match_rule(conditions, e["input"])]
    by: dict = {}
    for e in hits:
        by[e["output"]["verdict"]] = by.get(e["output"]["verdict"], 0) + 1
    return {"flows": len(uniq), "matched": len(hits), "matched_by_verdict": by, "matched_benign": by.get("benign", 0),
            "matched_true_normal": sum(e.get("truth") == "normal" for e in hits),
            "matched_true_attack": sum(e.get("truth") not in (None, "normal") for e in hits)}


def _activate(generation: int) -> None:
    global DETECTOR
    DETECTOR = BASE_DETECTOR if generation == 0 else REGISTRY.load(generation)
    LEARNING["generation"] = generation
    GENERATION.set(generation)


def _new_shadow(detector, report: dict) -> None:
    SHADOW.update(detector=detector, since=int(time.time()), report=report,
                  stats=dict.fromkeys(("flows", "agree", "only_shadow_flags", "only_live_flags",
                                       "only_shadow_flags_true_attack", "only_shadow_flags_true_normal",
                                       "only_live_flags_true_attack", "only_live_flags_true_normal"), 0))


def verify_logs() -> dict:
    """Recompute both hash chains: the prediction log and the log of analyst/admin actions."""
    pred, acts = PRED_LOG.verify(), AUDIT_LOG.verify()
    LOG_ENTRIES.set(pred["entries"])
    return pred | {"valid": pred["valid"] and acts["valid"], "actions": acts}


def make_brief(last: int = 500) -> dict:
    """Shift report built from the log: what was seen and what to do first."""
    entries = read_log(max(10, min(last, 3000)))
    if not entries:
        return {"flows": 0, "headline": "No traffic has been scored yet.", "points": [], "actions": []}
    by: dict = {}
    for e in entries:
        by.setdefault(e["output"]["verdict"], []).append(e)
    n = len(entries)
    atk, zd, unsure = by.get("attack", []), by.get("zero_day_suspect", []), by.get("uncertain", [])
    points, actions = [], []
    if atk:
        fam: dict = {}
        svc: dict = {}
        for e in atk:
            fam[e["output"]["attack_family"]] = fam.get(e["output"]["attack_family"], 0) + 1
            svc[e["input"]["service"]] = svc.get(e["input"]["service"], 0) + 1
        top_f, top_s = max(fam, key=fam.get), max(svc, key=svc.get)
        points.append(f"{len(atk)} known attacks ({len(atk) / n:.0%} of traffic). Most common family: {top_f} "
                      f"({fam[top_f]}). Most targeted service: {top_s} ({svc[top_s]}).")
        actions.append({"DoS": f"Rate-limit and enable SYN cookies in front of {top_s}.",
                        "Probe": "Block the scanning sources and review which ports are exposed.",
                        "R2L": f"Enforce lockout and MFA on {top_s}; audit recent logins.",
                        "U2R": "Isolate affected hosts and review privileged processes."}[top_f])
    if zd:
        points.append(f"{len(zd)} possible zero-days: flows the classifier did not recognise but the novelty model flagged.")
        actions.append("Open Hunt, review the campaigns, label them and retrain so they become known attacks.")
    if unsure:
        points.append(f"{len(unsure)} flows held for review because the model was not confident enough to pass them.")
        actions.append("Triage the review queue; label what you find with the feedback buttons.")
    if not points:
        points.append("All scored traffic matched normal behaviour.")
    chain = verify_logs()
    points.append("Prediction log integrity: " + ("hash chain intact." if chain["valid"]
                                                  else f"CHAIN BROKEN at line {chain['broken_at_line']}."))
    if not chain["valid"]:
        actions.insert(0, "Treat the prediction log as tampered: preserve it and investigate who had write access.")
    flagged = len(atk) + len(zd)
    return {"flows": n, "window": {"from": entries[0]["ts"], "to": entries[-1]["ts"]},
            "headline": f"{flagged} of {n} flows flagged, {len(unsure)} held for review.",
            "points": points, "actions": actions}


# ---- real traffic ----
def _capture_report(data: bytes, name: str, source: str, log: bool = True) -> dict:
    try:
        conns = pcap_flows.parse_zeek(data) if pcap_flows.is_zeek(data) else pcap_flows.connections(pcap_flows.parse_pcap(data))
        items = pcap_flows.to_flows(conns)[:20000]
        flows = [Flow(**it["flow"]).model_dump() for it in items]
    except pcap_flows.PcapError as e:
        raise HTTPException(422, str(e)) from None
    results = analyse_many(flows, source, log=log)
    counts: dict = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    rows = [{"src": it["src"], "dst": it["dst"], "dport": it["dport"], "service": it["flow"]["service"],
             "flag": it["flow"]["flag"], "verdict": r["verdict"], "risk": r["risk_score"], "family": r["attack_family"],
             "priority": r.get("asset_context", {}).get("priority"), "flow": it["flow"]}
            for it, r in zip(items, results, strict=True)]
    rows.sort(key=lambda r: -r["risk"])
    graph = pcap_flows.host_graph(items, results)
    return {"name": name, "flows": len(rows), "verdicts": counts, "graph": graph, "rows": rows[:300], "logged": log,
            "blocklist": blocklist(graph["sources"]), "timeline": pcap_flows.timeline(items, results, graph["sources"]),
            "span_seconds": round(max(i["start"] for i in items) - min(i["start"] for i in items), 1)}


_scans: dict[str, deque] = {}


def _entry(request_id: str) -> dict | None:
    return next((e for e in reversed(read_log()) if e["request_id"] == request_id), None)


def _label_from_verdict(entry: dict, correct: bool, true_label: str | None) -> str:
    said_attack = entry["output"]["verdict"] in ("attack", "zero_day_suspect")
    return true_label or ("attack" if said_attack == correct else "benign")


# ---- alert queue ----
ALERT_STATES = ("new", "investigating", "confirmed", "false_positive")


def _alert_states() -> dict:
    try:
        return json.loads(ALERT_FILE.read_text())
    except (OSError, ValueError):
        return {}


def list_alerts(state: str = "open", limit: int = 200) -> dict:
    """Everything that is not benign, newest first, with its triage state. state=open means new + investigating."""
    states = _alert_states()
    items, counts = [], dict.fromkeys(ALERT_STATES, 0)
    for e in reversed(read_log()):
        if e["output"]["verdict"] == "benign":
            continue
        st = states.get(e["request_id"], {"state": "new", "assignee": ""})
        counts[st["state"]] += 1
        if state == "all" or st["state"] == state or (state == "open" and st["state"] in ("new", "investigating")):
            asset = next((a for a in ASSETS.values() if e["input"]["service"] in a["services"]), None)
            items.append({"request_id": e["request_id"], "ts": e["ts"], "source": e.get("source", "api"),
                          "connection": f"{e['input']['protocol_type']}/{e['input']['service']} {e['input']['flag']}",
                          **e["output"], **st,
                          "priority": recon.priority(e["output"]["risk_score"], asset["exposure"]) if asset
                          else e["output"]["risk_score"]})
    items.sort(key=lambda a: -a["priority"])
    return {"counts": counts, "items": items[:max(1, min(limit, 500))]}


# ---- drift / integrity alarm ----
def check_alarm(force: bool = False) -> dict:
    """Runs on a timer. Sends one webhook message when drift appears or the log chain breaks
    (on the change, not on every check, so a channel is not flooded)."""
    drift = drift_report(read_inputs(LOG_FILE, 2000), META["feature_stats"])["status"]
    chain = verify_logs()["valid"]
    DRIFT_STATE.set({"warn": 1, "drift": 2}.get(drift, 0))
    worse = (drift == "drift" and ALARM["drift"] != "drift") or (not chain and ALARM["chain_valid"])
    ALARM.update(last_check=int(time.time()), drift=drift, chain_valid=chain)
    url = os.getenv("ALERT_WEBHOOK_URL", "")
    sent = False
    if url and (worse or force):
        problems = [p for p in ("input drift detected: retrain the model" if drift == "drift" else "",
                                "prediction log hash chain is BROKEN" if not chain else "") if p]
        sent = send_webhook(url, "ZeroWatch " + ("alarm: " + "; ".join(problems) if problems
                                                  else "test: drift and log integrity are both fine") + f" (model {model_version()})")
        if sent:
            ALARM["last_sent"] = int(time.time())
    return ALARM | {"sent": sent, "webhook": bool(url)}


AUTO_RETRAIN = os.getenv("AUTO_RETRAIN", "0") == "1"
AUTO_RETRAIN_MIN_LABELS = int(os.getenv("AUTO_RETRAIN_MIN_LABELS", "50"))
_auto = {"labels_at_last_run": 0}


def auto_retrain() -> dict | None:
    """Continuous training, run by the timer. Starts a retrain when enough new labels have
    arrived, or when drift is detected and there are labels to learn from. The challenger
    always goes to SHADOW: an unattended job must never replace the live model by itself."""
    if not AUTO_RETRAIN or CACHE is None or SHADOW["detector"] is not None:
        return None
    n = sum(_labelled_counts().values())
    fresh = n - _auto["labels_at_last_run"]
    if not (fresh >= AUTO_RETRAIN_MIN_LABELS or (ALARM["drift"] == "drift" and fresh >= 10)):
        return None
    if not _retrain_lock.acquire(blocking=False):
        return None
    try:
        report = retrain(DETECTOR, META | {"threshold": THRESHOLD}, CACHE, _read_labelled())
        new = report.pop("detector", None)
        _auto["labels_at_last_run"] = n
        if new is not None:
            report |= {"promoted": False, "mode": "shadow", "reason": "Scheduled retrain: challenger is running in shadow."}
            _new_shadow(new, dict(report))
        LEARNING["last_report"] = report | {"model_version": model_version()}
        audit("system/scheduler", "auto_retrain", labelled=n, shadow=new is not None)
        return report
    finally:
        _retrain_lock.release()


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/audit/verify")
def audit_verify():
    return verify_logs()


@app.get("/brief")
def brief(last: int = 500):
    return make_brief(last)


# The remaining routes live in three modules. They are imported last because each one does
# `import app as core` and needs everything above to exist already.
import routes_hunt  # noqa: E402
import routes_ops  # noqa: E402
import routes_traffic  # noqa: E402

for _module in (routes_hunt, routes_ops, routes_traffic):
    app.include_router(_module.router)
