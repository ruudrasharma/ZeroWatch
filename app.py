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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

import pcap_flows
import recon
from copilot import answer as copilot_answer
from drift_check import drift_report, read_inputs
from features import CONTRACT, FEATURES, FLAGS, PROTOCOLS, SERVICES, encode
from learning import find_campaigns, red_team, retrain
from ops import Registry, incident_markdown, match_rule, send_webhook, sigma_rule
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


def analyse(flow: dict, with_explanation: bool = True, log: bool = True, truth: str | None = None,
            source: str = "api") -> dict:
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
    asset = next((a for a in ASSETS.values() if flow["service"] in a["services"]), None)
    if asset:  # recon fusion: the same risk matters more on an exposed asset
        result["asset_context"] = {"asset": asset["name"], "exposure": asset["exposure"], "grade": asset["grade"],
                                   "priority": recon.priority(risk, asset["exposure"]),
                                   "top_finding": asset["findings"][0]["text"] if asset["findings"] else None}
    if log:  # what-if and red-team probes are not real traffic: keep them out of the log and metrics
        LATENCY.observe(time.perf_counter() - t0)
        PREDICTIONS.labels(verdict).inc()
        RISK.observe(risk)
        log_prediction(flow, result, truth, source)
    return result


def log_prediction(flow: dict, result: dict, truth: str | None = None, source: str = "api") -> None:
    """Stage 8: every prediction input is appended to a JSON-lines file for drift checks.
    The file is hash-chained and rotated by store.ChainLog. `source` separates real traffic
    (api, batch, capture) from demo traffic (replay, capture-sample) so demos cannot fake drift."""
    entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"),
             "request_id": result["request_id"], "source": source, "input": flow,
             "output": {k: result[k] for k in ("verdict", "risk_score", "attack_probability",
                                               "novelty_score", "attack_family")},
             "model_version": result["model_version"]}
    if truth:
        entry["truth"] = truth  # only the labelled replay knows the real answer
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


def role_of(request: Request) -> str:
    if not ADMIN_TOKEN and not ANALYST_TOKEN:
        return "admin"  # open mode
    key = request.headers.get("x-api-key", "")
    if ADMIN_TOKEN and hmac.compare_digest(key, ADMIN_TOKEN):
        return "admin"
    if ANALYST_TOKEN and hmac.compare_digest(key, ANALYST_TOKEN):
        return "analyst"
    return "viewer"


def require(minimum: str):
    def check(request: Request) -> str:
        role = role_of(request)
        if role == "viewer":
            raise HTTPException(401, "This action needs an API key. Send it in the X-API-Key header.")
        if minimum == "admin" and role != "admin":
            raise HTTPException(403, "This action needs the admin key; the analyst key is not enough.")
        return role
    return check


analyst = Depends(require("analyst"))
admin = Depends(require("admin"))


def audit(role: str, action: str, **detail) -> None:
    AUDIT_LOG.append({"ts": datetime.now(UTC).isoformat(timespec="seconds"), "role": role,
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
    return response


@app.get("/", include_in_schema=False)
def ui():
    return FileResponse(ROOT / "static" / "index.html")


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
    results = [analyse(f.model_dump(), with_explanation=False, source="batch") for f in batch.flows]
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
        r = analyse(s["flow"], with_explanation=False, truth=s["label"], source="replay")
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
            "threshold_curve": META.get("threshold_curve", []), "qhat": QHAT,
            "cross_dataset": json.loads((ROOT / "model" / "cross_dataset.json").read_text())
            if (ROOT / "model" / "cross_dataset.json").exists() else None,
            "experiments": json.loads((ROOT / "model" / "experiments.json").read_text())
            if (ROOT / "model" / "experiments.json").exists() else []}


@app.get("/monitoring/drift")
def monitoring_drift(last: int = 2000):
    """Only real traffic counts (api, batch, uploaded captures); the replay and the sample capture are excluded."""
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


def _add_labels(rows: list[dict]) -> None:
    with _log_lock:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with LABEL_FILE.open("a") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")


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


@app.get("/campaigns")
def campaigns():
    if NORMAL_REF is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    suspects = current_suspects()
    found = find_campaigns(suspects, NORMAL_REF)
    CAMPAIGNS.clear()
    CAMPAIGNS.update({c["id"]: c for c in found})
    done: dict = {}
    for r in _read_labelled():
        if r.get("campaign"):
            d = done.setdefault(r["campaign"], {"id": r["campaign"], "label": r["label"], "flows": 0, "rule": r.get("rule")})
            d["flows"] += 1
    return {"suspects": len(suspects), "campaigns": [{k: v for k, v in c.items() if k != "flows"} | {
        "example": c["flows"][0]} for c in found], "labelled": _labelled_counts(), "labelled_campaigns": list(done.values())}


class CampaignLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Literal["attack", "benign"]


@app.post("/campaigns/{campaign_id}/label")
def label_campaign(campaign_id: str, body: CampaignLabel, role: str = analyst):
    c = _campaign(campaign_id)
    _add_labels([{"input": flow, "label": body.label, "campaign": campaign_id, "rule": c["signature"]["rule"]}
                 for flow in c["flows"]])
    audit(role, "label_campaign", campaign=campaign_id, label=body.label, flows=len(c["flows"]))
    return {"labelled": len(c["flows"]), "label": body.label, "totals": _labelled_counts()}


@app.delete("/campaigns/{campaign_id}/label")
def unlabel_campaign(campaign_id: str, role: str = analyst):
    """Undo: drop this campaign's labels so its flows return to the hunt."""
    rows = _read_labelled()
    keep = [r for r in rows if r.get("campaign") != campaign_id]
    if len(keep) == len(rows):
        raise HTTPException(404, "No labels are stored for that campaign.")
    with _log_lock:
        LABEL_FILE.write_text("".join(json.dumps(r) + "\n" for r in keep))
    audit(role, "unlabel_campaign", campaign=campaign_id, flows=len(rows) - len(keep))
    return {"removed": len(rows) - len(keep), "totals": _labelled_counts()}


@app.get("/campaigns/{campaign_id}/rule", response_class=PlainTextResponse)
def campaign_rule(campaign_id: str):
    """The generated rule in Sigma format (text/yaml)."""
    c = _campaign(campaign_id)
    sig = c["signature"]
    return PlainTextResponse(sigma_rule(campaign_id, sig["conditions"], c["size"], sig["false_match_rate"]),
                             media_type="text/yaml",
                             headers={"content-disposition": f'attachment; filename="zerowatch-{campaign_id}.yml"'})


@app.get("/campaigns/{campaign_id}/rule/test")
def campaign_rule_test(campaign_id: str):
    return _rule_test(_campaign(campaign_id)["signature"]["conditions"])


@app.get("/campaigns/{campaign_id}/report", response_class=PlainTextResponse)
def campaign_report(campaign_id: str):
    """Incident report for one campaign, as Markdown."""
    c = _campaign(campaign_id)
    X = np.array([encode(f) for f in c["flows"]])
    fam = max(set(FAMILY.predict(X)), key=list(FAMILY.predict(X)).count)
    text = incident_markdown(c, MITRE.get(fam, []), _rule_test(c["signature"]["conditions"]), model_version(),
                             PRED_LOG.head[:16])
    return PlainTextResponse(text, media_type="text/markdown",
                             headers={"content-disposition": f'attachment; filename="incident-{campaign_id}.md"'})


def _activate(generation: int) -> None:
    global DETECTOR
    DETECTOR = BASE_DETECTOR if generation == 0 else REGISTRY.load(generation)
    LEARNING["generation"] = generation
    GENERATION.set(generation)


@app.post("/learning/retrain")
def learning_retrain(role: str = admin):
    """Champion/challenger retraining on the analyst-labelled flows. Takes about 10-20 s.
    A promoted challenger is saved to disk, so it survives a restart and can be rolled back."""
    if CACHE is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    if not _retrain_lock.acquire(blocking=False):
        raise HTTPException(409, "A retrain is already running. Wait for it to finish.")
    try:
        report = retrain(DETECTOR, META | {"threshold": THRESHOLD}, CACHE, _read_labelled())
        new = report.pop("detector", None)
        if new is not None:
            _activate(REGISTRY.save(new, report))
        report["model_version"] = model_version()
        LEARNING["last_report"] = report
        audit(role, "retrain", promoted=report["promoted"], labelled=report["labelled"], model_version=report["model_version"])
        return report
    finally:
        _retrain_lock.release()


class Rollback(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    generation: int = Field(ge=0)


@app.post("/learning/rollback")
def learning_rollback(body: Rollback, role: str = admin):
    """Make an earlier model live again. Generation 0 is the model the image shipped with."""
    if body.generation and REGISTRY.load(body.generation) is None:
        raise HTTPException(404, "That model version does not exist or failed its integrity check.")
    REGISTRY.activate(body.generation)
    _activate(body.generation)
    audit(role, "rollback", generation=body.generation)
    return {"active": body.generation, "model_version": model_version()}


@app.get("/learning/status")
def learning_status():
    st = REGISTRY.state()
    return {"active": LEARNING["generation"], "busy": _retrain_lock.locked(), "labelled": _labelled_counts(),
            "model_version": model_version(),
            "versions": [{k: v for k, v in ver.items() if k != "file"} for ver in st["versions"]]}


@app.get("/audit/verify")
def audit_verify():
    """Recompute both hash chains: the prediction log and the log of analyst/admin actions."""
    pred, acts = PRED_LOG.verify(), AUDIT_LOG.verify()
    LOG_ENTRIES.set(pred["entries"])
    return pred | {"valid": pred["valid"] and acts["valid"], "actions": acts}


@app.get("/audit/actions")
def audit_actions(limit: int = 50):
    return {"items": AUDIT_LOG.read(max(1, min(limit, 500)))[::-1]}


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


# ---- real traffic ----
def _capture_report(data: bytes, name: str, source: str) -> dict:
    try:
        items = pcap_flows.to_flows(pcap_flows.connections(pcap_flows.parse_pcap(data)))
    except pcap_flows.PcapError as e:
        raise HTTPException(422, str(e)) from None
    results = [analyse(Flow(**it["flow"]).model_dump(), with_explanation=False, source=source) for it in items[:3000]]
    items = items[:len(results)]
    counts: dict = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    rows = [{"src": it["src"], "dst": it["dst"], "dport": it["dport"], "service": it["flow"]["service"],
             "flag": it["flow"]["flag"], "verdict": r["verdict"], "risk": r["risk_score"], "family": r["attack_family"],
             "priority": r.get("asset_context", {}).get("priority"), "flow": it["flow"]}
            for it, r in zip(items, results, strict=True)]
    rows.sort(key=lambda r: -r["risk"])
    return {"name": name, "flows": len(rows), "verdicts": counts, "graph": pcap_flows.host_graph(items, results),
            "rows": rows[:200],
            "span_seconds": round(max(i["start"] for i in items) - min(i["start"] for i in items), 1)}


@app.post("/capture")
async def capture(request: Request):
    """Body: the raw bytes of a classic .pcap file (Content-Type: application/octet-stream), up to 5 MB."""
    data = await request.body()
    if len(data) > MAX_CAPTURE_BYTES:
        raise HTTPException(413, "Capture is larger than 5 MB. Trim it first, e.g. editcap -c 20000 in.pcap out.pcap")
    return _capture_report(data, "uploaded capture", "capture")


@app.get("/capture/sample")
def capture_sample():
    return _capture_report((ROOT / "data" / "sample_capture.pcap").read_bytes(), "sample_capture.pcap (synthetic)",
                           "capture-sample")


# ---- assets: recon fused into alert priority ----
class AssetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=40, pattern=r"^[\w .-]+$")
    url: str = Field(min_length=8, max_length=200)
    services: list[Literal[tuple(SERVICES)]] = Field(min_length=1, max_length=8)


_scans: dict[str, deque] = {}


@app.post("/assets")
def add_asset(body: AssetIn, request: Request, role: str = admin):
    if os.getenv("RECON_ENABLED", "1") != "1":
        raise HTTPException(503, "Asset scanning is switched off on this deployment (RECON_ENABLED=0).")
    q = _scans.setdefault(client_ip(request), deque())
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 6:  # each scan makes an outbound request, so this limit is much tighter than scoring
        raise HTTPException(429, "Scan limit reached: 6 per minute.")
    q.append(now)
    if len(ASSETS) >= 20 and body.name not in ASSETS:
        raise HTTPException(409, "Asset list is full (20). Remove one first.")
    try:
        result = recon.scan(body.url)
    except recon.ReconError as e:
        raise HTTPException(422, str(e)) from None
    ASSETS[body.name] = {"name": body.name, "services": body.services, **result}
    audit(role, "add_asset", name=body.name, url=body.url, exposure=result["exposure"])
    try:
        ASSET_FILE.write_text(json.dumps(ASSETS))
    except OSError:
        pass
    return ASSETS[body.name]


@app.get("/assets")
def list_assets():
    return {"assets": list(ASSETS.values()), "enabled": os.getenv("RECON_ENABLED", "1") == "1"}


@app.delete("/assets/{name}")
def delete_asset(name: str, role: str = admin):
    if ASSETS.pop(name, None) is None:
        raise HTTPException(404, "No asset with that name.")
    audit(role, "delete_asset", name=name)
    try:
        ASSET_FILE.write_text(json.dumps(ASSETS))
    except OSError:
        pass
    return {"removed": name}


# ---- copilot ----
class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=300)


@app.post("/copilot")
def copilot(q: Question):
    entries = read_log(500)
    verdicts: dict = {}
    fam: dict = {}
    svc: dict = {}
    for e in entries:
        o = e["output"]
        verdicts[o["verdict"]] = verdicts.get(o["verdict"], 0) + 1
        if o["verdict"] == "attack":
            fam[o["attack_family"]] = fam.get(o["attack_family"], 0) + 1
            svc[e["input"]["service"]] = svc.get(e["input"]["service"], 0) + 1
    b = brief()
    context = {"flows": len(entries), "verdicts": verdicts,
               "attack_families": sorted(fam.items(), key=lambda kv: -kv[1])[:4],
               "top_services_attacked": sorted(svc.items(), key=lambda kv: -kv[1])[:4],
               "actions": b["actions"], "log_chain_valid": audit_verify()["valid"],
               "drift_status": drift_report(read_inputs(LOG_FILE, 2000), META["feature_stats"])["status"],
               "campaigns": len(find_campaigns(current_suspects(), NORMAL_REF)) if NORMAL_REF is not None else 0,
               "assets": [{"name": a["name"], "exposure": a["exposure"], "services": a["services"]} for a in ASSETS.values()],
               "model_version": model_version()}
    return copilot_answer(q.question, context)


def _entry(request_id: str) -> dict | None:
    return next((e for e in reversed(read_log()) if e["request_id"] == request_id), None)


def _label_from_verdict(entry: dict, correct: bool, true_label: str | None) -> str:
    said_attack = entry["output"]["verdict"] in ("attack", "zero_day_suspect")
    return true_label or ("attack" if said_attack == correct else "benign")


@app.post("/feedback")
def feedback(fb: Feedback, role: str = analyst):
    """A verdict marked wrong becomes a labelled flow, so it reaches the next retrain."""
    entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), **fb.model_dump()}
    try:
        with _log_lock, FEEDBACK_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        raise HTTPException(503, "Feedback log is not writable") from None
    queued = False
    logged = _entry(fb.request_id)
    if logged and (not fb.correct or fb.true_label):
        _add_labels([{"input": logged["input"], "label": _label_from_verdict(logged, fb.correct, fb.true_label),
                      "source": "feedback", "request_id": fb.request_id}])
        queued = True
    audit(role, "feedback", request_id=fb.request_id, correct=fb.correct, queued=queued)
    return {"stored": True, "queued_for_retraining": queued}


# ---- alert queue ----
ALERT_STATES = ("new", "investigating", "confirmed", "false_positive")


def _alert_states() -> dict:
    try:
        return json.loads(ALERT_FILE.read_text())
    except (OSError, ValueError):
        return {}


@app.get("/alerts")
def alerts(state: str = "open", limit: int = 200):
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
                          **e["output"], **st, "input": e["input"],
                          "priority": recon.priority(e["output"]["risk_score"], asset["exposure"]) if asset
                          else e["output"]["risk_score"]})
    items.sort(key=lambda a: -a["priority"])
    return {"counts": counts, "items": items[:max(1, min(limit, 500))]}


class AlertUpdate(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    state: Literal[ALERT_STATES]
    assignee: str = Field(default="", max_length=40, pattern=r"^[\w .@-]*$")


@app.patch("/alerts/{request_id}")
def update_alert(request_id: str, body: AlertUpdate, role: str = analyst):
    """Closing an alert is also a label: confirmed -> attack, false_positive -> benign."""
    logged = _entry(request_id)
    if not logged:
        raise HTTPException(404, "No logged prediction with that request id.")
    states = _alert_states()
    states[request_id] = {"state": body.state, "assignee": body.assignee}
    with _log_lock:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        ALERT_FILE.write_text(json.dumps(states))
    if body.state in ("confirmed", "false_positive"):
        _add_labels([{"input": logged["input"], "label": "attack" if body.state == "confirmed" else "benign",
                      "source": "triage", "request_id": request_id}])
    audit(role, "triage", request_id=request_id, state=body.state, assignee=body.assignee)
    return states[request_id] | {"request_id": request_id}


# ---- settings: decision threshold ----
class ThresholdIn(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    threshold: float = Field(ge=0.05, le=0.95)


@app.post("/settings/threshold")
def set_threshold(body: ThresholdIn, role: str = admin):
    """Move the attack-probability cut-off. Lower catches more and raises more false alarms."""
    global THRESHOLD
    if body.threshold <= QHAT:
        raise HTTPException(422, f"Threshold must stay above the review band ({QHAT:.2f}).")
    old, THRESHOLD = THRESHOLD, round(body.threshold, 2)
    try:
        SETTINGS_FILE.write_text(json.dumps({"threshold": THRESHOLD}))
    except OSError:
        pass
    audit(role, "set_threshold", old=old, new=THRESHOLD)
    return {"threshold": THRESHOLD}


# ---- drift / integrity alarm ----
def check_alarm(force: bool = False) -> dict:
    """Runs on a timer. Sends one webhook message when drift appears or the log chain breaks
    (on the change, not on every check, so a channel is not flooded)."""
    drift = drift_report(read_inputs(LOG_FILE, 2000), META["feature_stats"])["status"]
    chain = audit_verify()["valid"]
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


@app.get("/monitoring/alarm")
def alarm_state():
    return ALARM | {"webhook": bool(os.getenv("ALERT_WEBHOOK_URL")), "interval_seconds": ALARM_INTERVAL}


@app.post("/monitoring/alarm/test")
def alarm_test(role: str = admin):
    audit(role, "alarm_test")
    return check_alarm(force=True)


# ---- overview ----
@app.get("/auth/whoami")
def whoami(request: Request):
    return {"role": role_of(request), "open_mode": not ADMIN_TOKEN and not ANALYST_TOKEN}


@app.get("/overview")
def overview():
    entries = read_log()
    verdicts: dict = {}
    sources: dict = {}
    for e in entries:
        verdicts[e["output"]["verdict"]] = verdicts.get(e["output"]["verdict"], 0) + 1
        sources[e.get("source", "api")] = sources.get(e.get("source", "api"), 0) + 1
    queue = alerts("open", 500)
    distinct: dict = {}
    for a in queue["items"]:  # a flood is one finding, not 200 identical rows
        distinct.setdefault((a["connection"], a["verdict"]), a)
    queue["items"] = list(distinct.values())[:6]
    chain = audit_verify()
    return {"flows": len(entries), "verdicts": verdicts, "sources": sources,
            "open_alerts": queue["counts"]["new"] + queue["counts"]["investigating"], "alert_counts": queue["counts"],
            "top_alerts": [{k: a[k] for k in ("request_id", "connection", "verdict", "risk_score", "priority", "state", "input")}
                           for a in queue["items"]],
            "campaigns": len(find_campaigns(current_suspects(), NORMAL_REF)) if NORMAL_REF is not None else 0,
            "labelled": _labelled_counts(),
            "drift": drift_report(read_inputs(LOG_FILE, 2000), META["feature_stats"])["status"],
            "chain": {"valid": chain["valid"], "entries": chain["entries"]},
            "model": {"version": model_version(), "generation": LEARNING["generation"], "threshold": THRESHOLD},
            "assets": sorted(({"name": a["name"], "exposure": a["exposure"], "grade": a["grade"]} for a in ASSETS.values()),
                             key=lambda a: -a["exposure"])[:4],
            "open_mode": not ADMIN_TOKEN and not ANALYST_TOKEN}


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
