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
import json
import os
import random
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from drift_check import drift_report, read_inputs
from features import CONTRACT, FEATURES, FLAGS, PROTOCOLS, SERVICES, encode
from learning import find_campaigns, red_team, retrain

ROOT = Path(__file__).resolve().parent
MODEL_PATH = Path(os.getenv("MODEL_PATH", ROOT / "model" / "model.joblib"))
LOG_DIR = Path(os.getenv("LOG_DIR", ROOT / "logs"))
LOG_FILE = LOG_DIR / "predictions.jsonl"
FEEDBACK_FILE = LOG_DIR / "feedback.jsonl"
LABEL_FILE = LOG_DIR / "labelled.jsonl"
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "600"))
STARTED = time.time()

# ---- Stage 3: the model is loaded ONCE here, at import/startup, never per request ----
# Integrity check first: a .joblib file is a pickle, and unpickling a tampered file runs
# whatever code is inside it. train.py writes the SHA-256 next to the model.
_sha_file = MODEL_PATH.with_suffix(".sha256")
MODEL_SHA = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
if _sha_file.exists() and _sha_file.read_text().strip() != MODEL_SHA and os.getenv("ALLOW_UNVERIFIED_MODEL") != "1":
    raise RuntimeError(f"{MODEL_PATH} does not match {_sha_file.name}; refusing to load an unverified model")
BUNDLE = joblib.load(MODEL_PATH)
DETECTOR, NOVELTY, FAMILY, META = BUNDLE["detector"], BUNDLE["novelty"], BUNDLE["family"], BUNDLE["meta"]
THRESHOLD = float(os.getenv("THRESHOLD", META["threshold"]))
MODEL_VERSION = f"{META['algorithm']}-{META['trained_at'][:10]}-{META.get('mlflow_run_id', 'local')[:8]}"
BASELINE = META["baseline"]  # typical normal flow, used for explanations
SAMPLES = json.loads((ROOT / "data" / "sample_flows.json").read_text())
QHAT = META.get("conformal", {}).get("qhat", 0.02)  # "not sure" band: QHAT < attack probability < 0.5
_cache_file = MODEL_PATH.with_name("train_cache.npz")
CACHE = dict(np.load(_cache_file)) if _cache_file.exists() else None  # training data for online retraining
NORMAL_REF = CACHE["X_fit"][CACHE["y_fit"] == 0][:2000].astype(float) if CACHE else None
LEARNING = {"generation": 0, "last_report": None}
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


# ---- Data contract: every row of the README table is enforced here ----
class Flow(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, json_schema_extra={"example": {
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
        t.append(f"{flow['serror_rate']:.0%} of recent connections never completed the TCP handshake. "
                 "Turn on SYN cookies and rate-limit new connections per source IP.")
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


def analyse(flow: dict, with_explanation: bool = True, log: bool = True, truth: str | None = None) -> dict:
    t0 = time.perf_counter()
    x = encode(flow)
    p, nov = (float(v[0]) for v in score_matrix(np.array([x])))
    verdict, risk, severity = fuse(p, nov)
    family, fam_probs = None, {}
    if verdict != "benign":
        probs = FAMILY.predict_proba(np.array([x]))[0]
        fam_probs = {c: round(float(v), 3) for c, v in zip(FAMILY.classes_, probs, strict=False)}
        if verdict == "attack":
            family = max(fam_probs, key=fam_probs.get)
    factors = explain(flow, x, verdict, p, nov) if with_explanation else []
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
    if log:  # what-if and red-team probes are not real traffic: keep them out of the log and metrics
        LATENCY.observe(time.perf_counter() - t0)
        PREDICTIONS.labels(verdict).inc()
        RISK.observe(risk)
        log_prediction(flow, result, truth)
    return result


def _chain_head() -> str:
    """Hash of the last log line (or zeros for an empty log)."""
    try:
        last = LOG_FILE.read_text().splitlines()[-1]
        return json.loads(last)["hash"]
    except (OSError, IndexError, ValueError, KeyError):
        return "0" * 64


def _entry_hash(prev: str, entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k not in ("hash", "prev")}
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()


_head = {"hash": None}


def log_prediction(flow: dict, result: dict, truth: str | None = None) -> None:
    """Stage 8: every prediction input is appended to a JSON-lines file for drift checks.
    Each line carries the hash of the previous line, so editing or deleting any past verdict
    breaks the chain and /audit/verify reports where."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "request_id": result["request_id"], "input": flow,
             "output": {k: result[k] for k in ("verdict", "risk_score", "attack_probability",
                                               "novelty_score", "attack_family")},
             "model_version": result["model_version"]}
    if truth:
        entry["truth"] = truth  # only the labelled replay knows the real answer
    try:
        with _log_lock:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            if _head["hash"] is None:
                _head["hash"] = _chain_head()
            entry["prev"] = _head["hash"]
            entry["hash"] = _head["hash"] = _entry_hash(entry["prev"], entry)
            with LOG_FILE.open("a") as f:
                f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # a read-only disk must not take the API down
    RECENT.appendleft(entry)


def read_log(last: int = 3000) -> list[dict]:
    if not LOG_FILE.exists():
        return []
    out = []
    for line in LOG_FILE.read_text().splitlines()[-last:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def judge(flows: list[dict]) -> list[tuple[str, int]]:
    """Verdict and risk for many flows at once, without logging (used by the search tools)."""
    p, nov = score_matrix(np.array([encode(f) for f in flows]))
    return [fuse(float(a), float(b))[:2] for a, b in zip(p, nov, strict=True)]


def model_version() -> str:
    return MODEL_VERSION + (f"+learned{LEARNING['generation']}" if LEARNING["generation"] else "")


# ---- App ----
@asynccontextmanager
async def lifespan(_: FastAPI):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="ZeroWatch", version="2.0.0", lifespan=lifespan,
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
    if request.url.path.startswith(("/predict", "/counterfactual", "/redteam", "/learning")):
        # behind Render's proxy every client shares one socket address, so use the forwarded one
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "?")
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
    return response


@app.get("/", include_in_schema=False)
def ui():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": True, "model_version": model_version(), "model_sha256": MODEL_SHA[:16],
            "algorithm": META["algorithm"], "uptime_seconds": int(time.time() - STARTED)}


@app.post("/predict")
def predict(flow: Flow):
    return analyse(flow.model_dump())


@app.post("/predict/batch")
def predict_batch(batch: Batch):
    results = [analyse(f.model_dump(), with_explanation=False) for f in batch.flows]
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"count": len(results), "verdicts": counts, "results": results}


@app.post("/counterfactual")
def counterfactual(flow: Flow):
    """Greedy what-if: keep resetting the most incriminating feature to its
    normal value until the flow would pass. Shows the analyst what actually
    separates this flow from benign traffic."""
    cur = flow.model_dump()
    first = analyse(cur, with_explanation=False, log=False)
    if first["verdict"] == "benign":
        return {"already_benign": True, "changes": [], "final_risk": first["risk_score"]}
    changes, risk, verdict = [], first["risk_score"], first["verdict"]
    for _ in range(8):
        x = encode(cur)
        p, nov = (float(v[0]) for v in score_matrix(np.array([x])))
        verdict, risk, _sev = fuse(p, nov)
        if verdict == "benign":
            break
        factors = [f for f in explain(cur, x, verdict, p, nov) if f["impact"] > 0]
        if not factors:
            break
        f = factors[0]
        changes.append({"feature": f["feature"], "from": f["value"], "to": f["typical"]})
        cur[f["feature"]] = f["typical"]
    else:
        x = encode(cur)
        p, nov = (float(v[0]) for v in score_matrix(np.array([x])))
        verdict, risk, _sev = fuse(p, nov)
    return {"already_benign": False, "changes": changes, "flips_to_benign": verdict == "benign",
            "start_risk": first["risk_score"], "final_risk": risk}


@app.get("/simulate")
def simulate(n: int = 12):
    """Replays held-out KDDTest+ flows (true labels attached) through the live model."""
    if not 1 <= n <= 60:
        raise HTTPException(422, "n must be between 1 and 60")
    out = []
    for s in random.sample(SAMPLES["flows"], n):
        r = analyse(s["flow"], with_explanation=False, truth=s["label"])
        out.append({"flow": s["flow"], "truth": {k: s[k] for k in ("label", "family", "seen_in_training")},
                    "result": {k: r[k] for k in ("request_id", "verdict", "risk_score", "severity",
                                                 "attack_family", "attack_probability", "novelty_score")}})
    return {"events": out}


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
            "experiments": json.loads((ROOT / "model" / "experiments.json").read_text())
            if (ROOT / "model" / "experiments.json").exists() else []}


@app.get("/monitoring/drift")
def monitoring_drift(last: int = 2000):
    return drift_report(read_inputs(LOG_FILE, max(30, min(last, 10000))), META["feature_stats"])


@app.get("/monitoring/recent")
def monitoring_recent(limit: int = 50):
    items = list(RECENT)[:max(1, min(limit, 300))]
    counts = {}
    for e in RECENT:
        v = e["output"]["verdict"]
        counts[v] = counts.get(v, 0) + 1
    return {"total_in_memory": len(RECENT), "verdicts": counts, "items": items}


@app.post("/redteam")
def redteam(flow: Flow):
    """Adversarial robustness: fewest attacker-controllable changes that make the flow pass."""
    return red_team(flow.model_dump(), META["feature_stats"], BASELINE, judge)


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


@app.get("/campaigns")
def campaigns():
    if NORMAL_REF is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    suspects = current_suspects()
    found = find_campaigns(suspects, NORMAL_REF)
    CAMPAIGNS.clear()
    CAMPAIGNS.update({c["id"]: c for c in found})
    return {"suspects": len(suspects), "campaigns": [{k: v for k, v in c.items() if k != "flows"} | {
        "example": c["flows"][0]} for c in found], "labelled": _labelled_counts()}


class CampaignLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Literal["attack", "benign"]


def _read_labelled() -> list[dict]:
    if not LABEL_FILE.exists():
        return []
    return [json.loads(line) for line in LABEL_FILE.read_text().splitlines() if line.strip()]


def _labelled_counts() -> dict:
    rows = _read_labelled()
    return {"attack": sum(r["label"] == "attack" for r in rows), "benign": sum(r["label"] == "benign" for r in rows)}


@app.post("/campaigns/{campaign_id}/label")
def label_campaign(campaign_id: str, body: CampaignLabel):
    c = CAMPAIGNS.get(campaign_id)
    if not c:
        raise HTTPException(404, "Unknown campaign. Reload the campaign list and try again.")
    with _log_lock, LABEL_FILE.open("a") as f:
        for flow in c["flows"]:
            f.write(json.dumps({"input": flow, "label": body.label, "campaign": campaign_id,
                                "rule": c["signature"]["rule"]}) + "\n")
    return {"labelled": len(c["flows"]), "label": body.label, "totals": _labelled_counts()}


@app.post("/learning/retrain")
def learning_retrain():
    """Champion/challenger retraining on the analyst-labelled flows. Takes about 10-20 s."""
    global DETECTOR
    if CACHE is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    report = retrain(DETECTOR, META, CACHE, _read_labelled())
    new = report.pop("detector", None)
    if new is not None:
        DETECTOR = new
        LEARNING["generation"] += 1
    report["model_version"] = model_version()
    LEARNING["last_report"] = report
    return report


@app.get("/audit/verify")
def audit_verify():
    """Recompute the hash chain of the prediction log."""
    prev, n = "0" * 64, 0
    if LOG_FILE.exists():
        for n, line in enumerate(LOG_FILE.read_text().splitlines(), 1):  # noqa: B007
            try:
                e = json.loads(line)
                ok = e["prev"] == prev and e["hash"] == _entry_hash(prev, e)
            except (ValueError, KeyError):
                ok = False
            if not ok:
                return {"valid": False, "entries": n, "broken_at_line": n,
                        "detail": "This entry was edited, or an earlier entry was removed."}
            prev = e["hash"]
    return {"valid": True, "entries": n, "head": prev[:16]}


@app.get("/brief")
def brief(last: int = 500):
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
    chain = audit_verify()
    points.append("Prediction log integrity: " + ("hash chain intact." if chain["valid"]
                                                  else f"CHAIN BROKEN at line {chain['broken_at_line']}."))
    if not chain["valid"]:
        actions.insert(0, "Treat the prediction log as tampered: preserve it and investigate who had write access.")
    flagged = len(atk) + len(zd)
    return {"flows": n, "window": {"from": entries[0]["ts"], "to": entries[-1]["ts"]},
            "headline": f"{flagged} of {n} flows flagged, {len(unsure)} held for review.",
            "points": points, "actions": actions}


@app.post("/feedback")
def feedback(fb: Feedback):
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **fb.model_dump()}
    try:
        with _log_lock, FEEDBACK_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        raise HTTPException(503, "Feedback log is not writable") from None
    return {"stored": True}


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
