"""ZeroWatch API tests. Run:  pytest -v --tb=short"""
import json
import os
import tempfile

os.environ["LOG_DIR"] = tempfile.mkdtemp(prefix="zerowatch-logs-")  # keep test traffic out of logs/

from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402
from drift_check import drift_report  # noqa: E402

client = TestClient(service.app)

NORMAL = {
    "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 232,
    "dst_bytes": 8153, "logged_in": 1, "wrong_fragment": 0, "hot": 0, "num_failed_logins": 0,
    "root_shell": 0, "count": 5, "srv_count": 5, "serror_rate": 0.0, "rerror_rate": 0.0,
    "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "dst_host_count": 30, "dst_host_srv_count": 255,
    "dst_host_serror_rate": 0.0,
}
# SYN flood: hundreds of half-open connections (flag S0, 100% SYN errors, no bytes)
SYN_FLOOD = NORMAL | {"service": "private", "flag": "S0", "src_bytes": 0, "dst_bytes": 0, "logged_in": 0,
                      "count": 280, "srv_count": 12, "serror_rate": 1.0, "same_srv_rate": 0.05,
                      "diff_srv_rate": 0.07, "dst_host_count": 255, "dst_host_srv_count": 12,
                      "dst_host_serror_rate": 1.0}


# 1. health check
def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["model_loaded"] is True


# 2. UI loads
def test_ui_loads():
    r = client.get("/")
    assert r.status_code == 200
    assert "ZeroWatch" in r.text and "text/html" in r.headers["content-type"]
    assert client.get("/static/app.js").status_code == 200


# 3. domain logic: a SYN flood must look far riskier than an ordinary web request
def test_syn_flood_scores_higher_than_normal_traffic():
    normal = client.post("/predict", json=NORMAL).json()
    flood = client.post("/predict", json=SYN_FLOOD).json()
    assert flood["risk_score"] > normal["risk_score"]
    assert flood["attack_probability"] > normal["attack_probability"]
    assert normal["verdict"] == "benign"
    assert flood["verdict"] in ("attack", "zero_day_suspect")


# 4. boundary tests: anything outside the data contract is a 422, never a 500
def test_rate_above_one_is_rejected():
    assert client.post("/predict", json=NORMAL | {"serror_rate": 1.01}).status_code == 422


def test_boundary_values_are_accepted():
    assert client.post("/predict", json=NORMAL | {"serror_rate": 1.0, "count": 511, "duration": 0}).status_code == 200
    assert client.post("/predict", json=NORMAL | {"count": 512}).status_code == 422
    assert client.post("/predict", json=NORMAL | {"duration": -1}).status_code == 422


def test_wrong_types_and_unknown_categories_are_rejected():
    for bad in ({"src_bytes": "lots"}, {"count": 3.5}, {"protocol_type": "sctp"}, {"service": "gopher2"},
                {"flag": "XX"}, {"logged_in": 2}, {"serror_rate": None}, {"unexpected": 1}):
        assert client.post("/predict", json=NORMAL | bad).status_code == 422, bad


def test_missing_field_and_nan_are_rejected():
    assert client.post("/predict", json={k: v for k, v in NORMAL.items() if k != "flag"}).status_code == 422
    raw = json.dumps(NORMAL).replace('"serror_rate": 0.0', '"serror_rate": NaN')
    assert client.post("/predict", content=raw, headers={"content-type": "application/json"}).status_code == 422


# response contract
def test_prediction_response_shape():
    r = client.post("/predict", json=SYN_FLOOD).json()
    assert 0 <= r["risk_score"] <= 100
    assert 0 <= r["attack_probability"] <= 1 and 0 <= r["novelty_score"] <= 1
    assert 2 <= len(r["tips"]) <= 3
    assert r["top_factors"], "an attack verdict must come with an explanation"
    assert {"feature", "value", "typical", "impact"} <= set(r["top_factors"][0])


def test_tips_follow_the_input():
    r = client.post("/predict", json=SYN_FLOOD).json()
    assert any("SYN" in t for t in r["tips"])
    r = client.post("/predict", json=NORMAL | {"num_failed_logins": 4, "service": "ftp"}).json()
    assert any("failed login" in t for t in r["tips"])


def test_batch_and_limits():
    r = client.post("/predict/batch", json={"flows": [NORMAL, SYN_FLOOD]})
    assert r.status_code == 200 and r.json()["count"] == 2
    assert client.post("/predict/batch", json={"flows": []}).status_code == 422
    assert client.post("/predict/batch", json={"flows": [NORMAL] * 501}).status_code == 422


def test_counterfactual_lowers_risk():
    r = client.post("/counterfactual", json=SYN_FLOOD).json()
    assert r["changes"] and r["final_risk"] < r["start_risk"]
    assert client.post("/counterfactual", json=NORMAL).json()["already_benign"] is True


# monitoring
def test_every_prediction_is_logged():
    before = len(service.LOG_FILE.read_text().splitlines()) if service.LOG_FILE.exists() else 0
    rid = client.post("/predict", json=NORMAL).json()["request_id"]
    lines = service.LOG_FILE.read_text().splitlines()
    assert len(lines) == before + 1
    last = json.loads(lines[-1])
    assert last["request_id"] == rid and last["input"] == NORMAL


def test_drift_report_flags_shifted_inputs():
    stats = service.META["feature_stats"]
    calm = drift_report([s["flow"] for s in service.SAMPLES["flows"][:200]], stats)
    flood = drift_report([SYN_FLOOD] * 60, stats)
    assert flood["status"] == "drift"
    assert max(f["shift"] for f in flood["features"]) > max(f["shift"] for f in calm["features"])
    assert drift_report([NORMAL] * 5, stats)["status"] == "waiting"


def test_simulate_metrics_and_model_info():
    assert len(client.get("/simulate?n=5").json()["events"]) == 5
    assert client.get("/simulate?n=500").status_code == 422
    assert "zerowatch_predictions_total" in client.get("/metrics").text
    info = client.get("/model/info").json()
    assert info["metrics"]["validation"]["f1"] > 0.9
    assert len(client.get("/contract").json()["features"]) == 20


def test_feedback_is_stored_and_validated():
    assert client.post("/feedback", json={"request_id": "abcdef123456", "correct": False}).json()["stored"]
    assert client.post("/feedback", json={"request_id": "x", "correct": True}).status_code == 422


# ---- zero-day loop, robustness and integrity ----
def test_uncertain_verdict_sits_between_benign_and_attack():
    assert service.fuse(0.001, 0.1)[0] == "benign"
    assert service.fuse(service.QHAT + 0.05, 0.1)[0] == "uncertain"
    assert service.fuse(0.9, 0.1)[0] == "attack"
    assert service.fuse(0.1, 0.9)[0] == "zero_day_suspect"


def test_redteam_reports_robustness_without_logging():
    before = len(service.read_log())
    r = client.post("/redteam", json=SYN_FLOOD).json()
    assert r["robustness"] in ("robust", "moderate", "fragile")
    assert r["final_risk"] <= r["start_risk"]
    assert set(c["feature"] for c in r["changes"]) <= set(r["attacker_controlled"])
    assert len(service.read_log()) == before, "search probes must not pollute the prediction log"


def test_zero_day_loop_campaign_label_retrain():
    """Unseen attacks are flagged, grouped into a campaign with a rule, labelled, and learned."""
    import random
    random.seed(7)
    for _ in range(10):
        client.get("/simulate?n=60")
    found = client.get("/campaigns").json()
    assert found["campaigns"], "the replay contains unseen attack types, so campaigns must appear"
    c = found["campaigns"][0]
    assert c["size"] >= 8 and c["signature"]["rule"] and 0 <= c["signature"]["false_match_rate"] < 0.2
    example = c["example"]
    assert client.post("/predict", json=example).json()["verdict"] == "zero_day_suspect"
    assert client.post("/campaigns/nope/label", json={"label": "attack"}).status_code == 404
    for camp in found["campaigns"]:
        assert client.post(f"/campaigns/{camp['id']}/label", json={"label": "attack"}).status_code == 200
    p_before = client.post("/predict", json=example).json()["attack_probability"]
    report = client.post("/learning/retrain").json()
    assert report["labelled"] >= 10 and "champion" in report
    if report["promoted"]:  # promotion is earned, not guaranteed
        assert report["challenger"]["labelled_holdout_accuracy"] > report["champion"]["labelled_holdout_accuracy"]
        assert report["challenger"]["validation_f1"] >= report["champion"]["validation_f1"] - 0.002
        after = client.post("/predict", json=example).json()
        assert after["attack_probability"] > p_before and "learned" in after["model_version"]
    # the model must still pass ordinary traffic after learning
    assert client.post("/predict", json=NORMAL).json()["verdict"] in ("benign", "uncertain")


def test_poisoned_labels_are_quarantined():
    from learning import retrain
    rows = [{"input": SYN_FLOOD, "label": "benign"}] * 12
    report = retrain(service.DETECTOR, service.META, service.CACHE, rows)
    assert report["quarantined_labels"] == 12 and report["promoted"] is False


def test_audit_chain_detects_tampering():
    client.post("/predict", json=NORMAL)
    client.post("/predict", json=SYN_FLOOD)
    assert client.get("/audit/verify").json()["valid"] is True
    original = service.LOG_FILE.read_text()
    lines = original.splitlines()
    lines[-2] = lines[-2].replace('"verdict": "benign"', '"verdict": "attack"').replace(
        '"risk_score": 0', '"risk_score": 99')
    try:
        service.LOG_FILE.write_text("\n".join(lines) + "\n")
        if lines != original.splitlines():
            bad = client.get("/audit/verify").json()
            assert bad["valid"] is False and bad["broken_at_line"] == len(lines) - 1
    finally:
        service.LOG_FILE.write_text(original)


def test_brief_and_model_integrity():
    b = client.get("/brief").json()
    assert b["flows"] > 0 and b["points"]
    assert service.MODEL_PATH.with_suffix(".sha256").read_text().strip() == service.MODEL_SHA


# ---- real traffic, host graph, recon fusion, copilot ----
def _capture():
    from pcap_flows import write_pcap
    S, SA, A, PA, FA, R = 0x02, 0x12, 0x10, 0x18, 0x11, 0x14
    pk = []
    for i in range(6):  # six complete web sessions
        t, sp = i * 1.0, 40000 + i
        pk += [(t, "10.0.0.101", "10.0.0.10", "tcp", sp, 80, S, 0), (t + .01, "10.0.0.10", "10.0.0.101", "tcp", 80, sp, SA, 0),
               (t + .02, "10.0.0.101", "10.0.0.10", "tcp", sp, 80, A, 0), (t + .03, "10.0.0.101", "10.0.0.10", "tcp", sp, 80, PA, 300),
               (t + .05, "10.0.0.10", "10.0.0.101", "tcp", 80, sp, PA, 2000), (t + .06, "10.0.0.101", "10.0.0.10", "tcp", sp, 80, FA, 0),
               (t + .07, "10.0.0.10", "10.0.0.101", "tcp", 80, sp, FA, 0)]
    for port in range(100, 140):  # port scan answered with RST
        pk += [(8 + port / 1000, "10.0.0.66", "10.0.0.10", "tcp", 50000, port, S, 0),
               (8.001 + port / 1000, "10.0.0.10", "10.0.0.66", "tcp", port, 50000, R, 0)]
    for i in range(80):  # SYN flood, never answered
        pk.append((10 + i * .01, "10.0.0.99", "10.0.0.10", "tcp", 1024 + i, 80, S, 0))
    return write_pcap(sorted(pk))


def test_pcap_becomes_contract_flows():
    import pcap_flows
    items = pcap_flows.to_flows(pcap_flows.connections(pcap_flows.parse_pcap(_capture())))
    assert len(items) == 6 + 40 + 80
    flags = {(i["src"], i["flow"]["flag"]) for i in items}
    assert flags == {("10.0.0.101", "SF"), ("10.0.0.66", "REJ"), ("10.0.0.99", "S0")}
    web = next(i["flow"] for i in items if i["src"] == "10.0.0.101")
    assert web["service"] == "http" and web["src_bytes"] == 300 and web["dst_bytes"] == 2000
    flood = [i["flow"] for i in items if i["src"] == "10.0.0.99"][-1]
    assert flood["serror_rate"] == 1.0 and flood["count"] >= 70
    for i in items:  # every derived flow must satisfy the data contract
        service.Flow(**i["flow"])


def test_capture_endpoint_finds_scanner_and_flooder():
    r = client.post("/capture", content=_capture(), headers={"content-type": "application/octet-stream"})
    assert r.status_code == 200
    body = r.json()
    roles = {s["ip"]: s["behaviour"] for s in body["graph"]["sources"]}
    assert roles["10.0.0.66"] == "scanner" and roles["10.0.0.99"] == "flooder" and roles["10.0.0.101"] == "normal"
    assert body["verdicts"].get("attack", 0) + body["verdicts"].get("zero_day_suspect", 0) >= 100
    assert client.get("/capture/sample").json()["flows"] > 200


def test_capture_rejects_garbage_and_oversize():
    h = {"content-type": "application/octet-stream"}
    assert client.post("/capture", content=b"this is not a pcap file at all", headers=h).status_code == 422
    assert client.post("/capture", content=b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, headers=h).status_code == 422  # empty pcapng
    assert client.post("/capture", content=b"\x00" * 5_000_001, headers=h).status_code == 413


def test_recon_blocks_internal_targets():
    import recon
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "https://10.0.0.5/",
                "https://192.168.1.1/", "ftp://example.com/", "http://[::1]/", "https://8.8.8.8:22/"):
        try:
            recon.safe_target(url)
            raise AssertionError(f"{url} should have been refused")
        except recon.ReconError:
            pass
    assert client.post("/assets", json={"name": "meta", "url": "http://169.254.169.254/", "services": ["http"]}).status_code == 422


def test_exposure_scoring_and_priority_fusion():
    import recon
    hardened = recon.score_findings("https", {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "x",
                                              "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                              "Referrer-Policy": "no-referrer", "Server": "nginx"},
                                    {"version": "TLSv1.3", "days_left": 200})
    weak = recon.score_findings("http", {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/5.6"}, None)
    assert hardened["exposure"] == 0 and hardened["grade"] == "A"
    assert weak["exposure"] > 60 and weak["grade"] == "D"
    assert recon.priority(80, 100) > 80 > recon.priority(80, 0) and recon.priority(80, 50) == 80
    # fusion: register an exposed asset running "private" and score a flood against it
    service.ASSETS["db"] = {"name": "db", "services": ["private"], "url": "https://db.example", **weak}
    try:
        r = client.post("/predict", json=SYN_FLOOD).json()
        assert r["asset_context"]["asset"] == "db" and r["asset_context"]["priority"] >= r["risk_score"]
        assert "asset_context" not in client.post("/predict", json=NORMAL).json()
    finally:
        service.ASSETS.pop("db")


def test_copilot_uses_llm_when_configured_and_rules_otherwise(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    client.post("/predict", json=SYN_FLOOD)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    r = client.post("/copilot", json={"question": "What happened in the last hour?"}).json()
    assert r["engine"] == "rules" and "known attacks" in r["answer"]
    assert "intact" in client.post("/copilot", json={"question": "Can I trust the log, was it tampered?"}).json()["answer"]

    seen = {}

    class FakeLLM(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["body"] = json.loads(self.rfile.read(int(self.headers["content-length"])))
            out = json.dumps({"choices": [{"message": {"content": "Two floods hit http."}}]}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{srv.server_port}/v1")
        r = client.post("/copilot", json={"question": "Summarise the attacks"}).json()
        assert r == {"answer": "Two floods hit http.", "engine": "llm", "model": "llama3.1:8b"}
        assert "verdicts" in seen["body"]["messages"][1]["content"]  # grounded in the log summary
        monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9/v1")  # nothing listening: must fall back
        assert client.post("/copilot", json={"question": "Summarise the attacks"}).json()["engine"] == "rules"
    finally:
        srv.shutdown()
    assert client.post("/copilot", json={"question": "x"}).status_code == 422


# ---- hardening: strict contract, access control, log integrity, operations ----
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_state():
    """Each test starts with the shipped model and an empty rate-limit table."""
    yield
    service._hits.clear()
    service._activate(0)


def test_contract_is_strict_about_types():
    for bad in ({"duration": "5"}, {"serror_rate": "0.5"}, {"count": True}, {"src_bytes": 1000.0},
                {"logged_in": "1"}, {"protocol_type": 6}):
        assert client.post("/predict", json=NORMAL | bad).status_code == 422, bad
    assert client.post("/predict", json=NORMAL | {"serror_rate": 1}).status_code == 200  # an int is a valid rate


def test_roles_gate_every_state_changing_route(monkeypatch):
    monkeypatch.setattr(service, "ADMIN_TOKEN", "admin-secret")
    monkeypatch.setattr(service, "ANALYST_TOKEN", "analyst-secret")
    a, adm = {"x-api-key": "analyst-secret"}, {"x-api-key": "admin-secret"}
    assert client.post("/predict", json=NORMAL).status_code == 200  # scoring stays open
    assert client.get("/auth/whoami").json() == {"role": "viewer", "user": "anonymous", "open_mode": False}
    for method, path, body in [("post", "/learning/retrain", None), ("post", "/learning/rollback", {"generation": 0}),
                               ("post", "/settings/threshold", {"threshold": 0.5}), ("post", "/monitoring/alarm/test", None),
                               ("post", "/assets", {"name": "x", "url": "https://example.org", "services": ["http"]}),
                               ("delete", "/assets/x", None)]:
        assert client.request(method, path, json=body).status_code == 401, path
        assert client.request(method, path, json=body, headers={"x-api-key": "wrong"}).status_code == 401, path
        assert client.request(method, path, json=body, headers=a).status_code == 403, path
    fb = {"request_id": "abcdef123456", "correct": True}
    assert client.post("/feedback", json=fb).status_code == 401
    assert client.post("/feedback", json=fb, headers=a).status_code == 200
    assert client.post("/learning/rollback", json={"generation": 0}, headers=adm).status_code == 200
    assert client.get("/audit/actions").status_code == 401  # the action log itself is not public
    actions = [e["action"] for e in client.get("/audit/actions", headers=a).json()["items"]]
    assert "rollback" in actions and "feedback" in actions


def test_rate_limit_cannot_be_bypassed_with_forwarded_header(monkeypatch):
    monkeypatch.setattr(service, "RATE_LIMIT", 5)
    service._hits.clear()
    codes = [client.post("/predict", json=NORMAL, headers={"x-forwarded-for": f"1.2.3.{i}"}).status_code for i in range(9)]
    assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}
    monkeypatch.setattr(service, "TRUST_PROXY", True)  # behind a proxy: the LAST hop is the client
    service._hits.clear()
    codes = [client.post("/predict", json=NORMAL, headers={"x-forwarded-for": f"9.9.9.{i}, 7.7.7.7"}).status_code
             for i in range(7)]
    assert codes.count(429) == 2


def test_truncating_the_log_is_detected():
    for _ in range(3):
        client.post("/predict", json=NORMAL)
    assert client.get("/audit/verify").json()["valid"] is True
    original = service.LOG_FILE.read_text()
    try:
        service.LOG_FILE.write_text("\n".join(original.splitlines()[:-2]) + "\n")
        bad = client.get("/audit/verify").json()
        assert bad["valid"] is False and "removed from the end" in bad["detail"]
    finally:
        service.LOG_FILE.write_text(original)
    assert client.get("/audit/verify").json()["valid"] is True


def test_log_rotation_keeps_the_chain(tmp_path):
    from store import ChainLog
    log = ChainLog(tmp_path / "p.jsonl", max_bytes=300)
    for i in range(12):
        log.append({"n": i})
    assert len(list(tmp_path.glob("p-*.jsonl"))) >= 1, "the log must have rotated"
    assert log.verify()["valid"] is True
    assert ChainLog(tmp_path / "p.jsonl", max_bytes=300).verify()["valid"] is True  # survives a restart


def test_demo_traffic_is_tagged_and_kept_out_of_drift():
    from drift_check import read_inputs
    before = len(read_inputs(service.LOG_FILE, 10**6))
    client.get("/simulate?n=20")
    client.get("/capture/sample")
    assert len(read_inputs(service.LOG_FILE, 10**6)) == before
    client.post("/predict", json=NORMAL)
    assert len(read_inputs(service.LOG_FILE, 10**6)) == before + 1
    assert {e["source"] for e in service.read_log(400)} >= {"replay", "capture-sample", "api"}


def test_only_one_retrain_at_a_time():
    assert service._retrain_lock.acquire(blocking=False)
    try:
        assert client.post("/learning/retrain").status_code == 409
    finally:
        service._retrain_lock.release()


def test_promoted_model_is_saved_and_can_be_rolled_back():
    rows = [{"input": s["flow"], "label": "attack"} for s in service.SAMPLES["flows"]
            if s["label"] != "normal" and not s["seen_in_training"]][:40]
    service.LABEL_FILE.write_text("".join(json.dumps(r) + "\n" for r in rows))
    try:
        report = client.post("/learning/retrain").json()
        status = client.get("/learning/status").json()
        if report["promoted"]:
            gen = status["active"]
            assert gen >= 1 and (service.REGISTRY.dir / f"detector-gen{gen}.joblib").exists()
            service._activate(0)
            service._restore_state()  # what happens on a restart
            assert service.LEARNING["generation"] == gen
            assert client.post("/learning/rollback", json={"generation": 0}).json()["active"] == 0
            assert "learned" not in client.get("/health").json()["model_version"]
            assert client.post("/learning/rollback", json={"generation": gen}).json()["active"] == gen
        assert client.post("/learning/rollback", json={"generation": 999}).status_code == 404
    finally:
        service.LABEL_FILE.write_text("")
        service.REGISTRY.activate(0)


def test_wrong_verdict_feedback_and_triage_become_labels():
    service.LABEL_FILE.write_text("")
    rid = client.post("/predict", json=SYN_FLOOD).json()["request_id"]
    r = client.post("/feedback", json={"request_id": rid, "correct": False}).json()
    assert r["queued_for_retraining"] is True
    assert service._read_labelled()[-1] == {"input": SYN_FLOOD, "label": "benign", "source": "feedback", "request_id": rid}
    rid2 = client.post("/predict", json=SYN_FLOOD | {"count": 300}).json()["request_id"]
    queue = client.get("/alerts").json()
    assert any(a["request_id"] == rid2 and a["state"] == "new" for a in queue["items"])
    assert client.patch(f"/alerts/{rid2}", json={"state": "confirmed", "assignee": "rudra"}).json()["state"] == "confirmed"
    assert service._read_labelled()[-1]["label"] == "attack"
    assert all(a["request_id"] != rid2 for a in client.get("/alerts").json()["items"])  # closed alerts leave the open queue
    assert client.patch("/alerts/nope", json={"state": "confirmed"}).status_code == 404
    assert client.patch(f"/alerts/{rid2}", json={"state": "deleted"}).status_code == 422
    service.LABEL_FILE.write_text("")


def test_rule_export_test_report_and_undo():
    import random
    random.seed(7)
    service.LABEL_FILE.write_text("")
    for _ in range(10):
        client.get("/simulate?n=60")
    found = client.get("/campaigns").json()["campaigns"]
    assert found
    cid = found[0]["id"]
    rule = client.get(f"/campaigns/{cid}/rule")
    assert rule.status_code == 200 and "detection:" in rule.text and "condition: selection" in rule.text
    hits = client.get(f"/campaigns/{cid}/rule/test").json()
    assert 0 < hits["matched"] <= hits["flows"]
    report = client.get(f"/campaigns/{cid}/report").text
    assert report.startswith("# Incident report") and found[0]["signature"]["rule"] in report
    assert client.post(f"/campaigns/{cid}/label", json={"label": "attack"}).status_code == 200
    after = client.get("/campaigns").json()
    assert any(c["id"] == cid for c in after["labelled_campaigns"])
    assert client.delete(f"/campaigns/{cid}/label").json()["removed"] == found[0]["size"]
    assert client.delete(f"/campaigns/{cid}/label").status_code == 404
    assert client.get("/campaigns/unknown/rule").status_code == 404


def test_threshold_can_be_tuned_within_limits():
    old = service.THRESHOLD
    try:
        p = client.post("/predict", json=SYN_FLOOD).json()["attack_probability"]
        assert client.post("/settings/threshold", json={"threshold": 0.9}).json() == {"threshold": 0.9}
        assert client.get("/model/info").json()["threshold"] == 0.9
        assert (client.post("/predict", json=SYN_FLOOD).json()["verdict"] == "attack") == (p >= 0.9)
        assert client.post("/settings/threshold", json={"threshold": 0.99}).status_code == 422
        assert client.post("/settings/threshold", json={"threshold": "0.5"}).status_code == 422
        assert len(client.get("/model/info").json()["threshold_curve"]) == 19
    finally:
        service.THRESHOLD = old


def test_alarm_posts_to_the_webhook(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    got = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["content-length"])))["text"])
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("ALERT_WEBHOOK_URL", f"http://127.0.0.1:{srv.server_port}/hook")
        assert client.post("/monitoring/alarm/test").json()["sent"] is True
        assert got and got[0].startswith("ZeroWatch")
        monkeypatch.setitem(service.ALARM, "chain_valid", True)
        original = service.LOG_FILE.read_text()
        try:  # break the chain: the timer check must raise the alarm once, not on every check
            service.LOG_FILE.write_text("\n".join(original.splitlines()[:-1]) + "\n")
            assert service.check_alarm()["sent"] is True and "BROKEN" in got[-1]
            assert service.check_alarm()["sent"] is False
        finally:
            service.LOG_FILE.write_text(original)
    finally:
        srv.shutdown()


def test_overview_summarises_the_service():
    o = client.get("/overview").json()
    assert o["flows"] > 0 and o["chain"]["valid"] is True and o["open_mode"] is True
    assert set(o["model"]) == {"version", "generation", "threshold"} and "replay" in o["sources"]


def test_pcapng_and_ipv6_are_parsed():
    import socket
    import struct

    import pcap_flows

    def tcp6(src, dst, sport, dport, flags):
        seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0)
        ip = struct.pack("!IHBB", 6 << 28, len(seg), 6, 64) + socket.inet_pton(socket.AF_INET6, src) + \
            socket.inet_pton(socket.AF_INET6, dst) + seg
        return b"\x00" * 12 + b"\x86\xdd" + ip

    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    frames = [tcp6("2001:db8::1", "2001:db8::2", 40000, 443, 0x02), tcp6("2001:db8::2", "2001:db8::1", 443, 40000, 0x12)]
    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, f in enumerate(frames):
        data += block(6, struct.pack("<IIIII", 0, 0, 1_000_000 + i * 1000, len(f), len(f)) + f)
    pkts = pcap_flows.parse_pcap(data)
    assert [(p["src"], p["dport"], p["flags"]) for p in pkts] == [("2001:db8::1", 443, 0x02), ("2001:db8::2", 40000, 0x12)]
    flows = pcap_flows.to_flows(pcap_flows.connections(pkts))
    assert len(flows) == 1 and flows[0]["flow"]["service"] == "http_443" and flows[0]["flow"]["flag"] == "S1"


# ---- round 3: speed, label hygiene, read access, shadow mode, imports and exports ----
def _unseen_labels(n=40):
    return [{"input": s["flow"], "label": "attack"} for s in service.SAMPLES["flows"]
            if s["label"] != "normal" and not s["seen_in_training"]][:n]


def test_bulk_scoring_is_vectorised():
    import time

    from pcap_flows import write_pcap
    t = time.time()
    assert client.post("/predict/batch", json={"flows": [NORMAL] * 500}).json()["count"] == 500
    assert time.time() - t < 3, "500 flows used to take 10 s"
    flood = write_pcap([(i * 0.001, "10.0.0.99", "10.0.0.10", "tcp", 1024 + i, 80, 0x02, 0) for i in range(3000)])
    t = time.time()
    r = client.post("/capture", content=flood, headers={"content-type": "application/octet-stream"}).json()
    assert r["flows"] == 3000 and time.time() - t < 10, "3,000 connections used to take 40 s"


def test_one_label_per_flow_and_reopening_withdraws_it():
    service.LABEL_FILE.write_text("")
    rid = client.post("/predict", json=SYN_FLOOD | {"count": 333}).json()["request_id"]
    client.post("/feedback", json={"request_id": rid, "correct": False})
    client.post("/feedback", json={"request_id": rid, "correct": False})
    client.patch(f"/alerts/{rid}", json={"state": "confirmed"})
    mine = [r for r in service._read_labelled() if r["input"]["count"] == 333]
    assert [r["label"] for r in mine] == ["attack"], "the newest decision wins and there is exactly one label"
    client.patch(f"/alerts/{rid}", json={"state": "investigating"})
    assert not [r for r in service._read_labelled() if r["input"]["count"] == 333]
    service.LABEL_FILE.write_text("")


def test_keyless_visitor_cannot_read_or_fill_the_logs(monkeypatch):
    monkeypatch.setattr(service, "ADMIN_TOKEN", "admin-secret")
    monkeypatch.setattr(service, "ANALYST_TOKEN", "analyst-secret")
    a = {"x-api-key": "analyst-secret"}
    for path in ("/audit/actions", "/alerts", "/campaigns", "/alerts/abc"):
        assert client.get(path).status_code == 401, path
    assert client.post("/copilot", json={"question": "what happened?"}).status_code == 401
    assert client.post("/capture", content=b"x" * 64, headers={"content-type": "application/octet-stream"}).status_code == 401
    before = len(service.read_log(10**6))
    r = client.get("/simulate?n=30").json()
    assert len(r["events"]) == 30 and r["logged"] is False
    assert client.get("/capture/sample").json()["logged"] is False
    assert len(service.read_log(10**6)) == before, "an anonymous visitor must not be able to grow the log"
    assert client.get("/simulate?n=5", headers=a).json()["logged"] is True
    assert client.get("/alerts", headers=a).status_code == 200


def test_security_headers_and_no_inline_script():
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-eval" not in csp
    assert "<script>" not in r.text, "inline scripts would be blocked by the policy"
    assert "content-security-policy" not in client.get("/docs").headers  # Swagger UI needs its CDN
    assert client.get("/health").headers["cache-control"] == "no-store"
    assert client.get("/favicon.ico").status_code == 200 and client.get("/static/theme.js").status_code == 200


def test_alert_list_is_compact_and_detail_carries_the_flow():
    rid = client.post("/predict", json=SYN_FLOOD | {"count": 444}).json()["request_id"]
    items = client.get("/alerts?state=all&limit=500").json()["items"]
    assert items and all("input" not in a for a in items)
    assert client.get(f"/alerts/{rid}").json()["input"]["count"] == 444
    assert client.get("/alerts/missing").status_code == 404


def test_sigma_rule_groups_repeated_exclusions():
    from ops import sigma_rule
    y = sigma_rule("abc", [{"field": "rerror_rate", "op": ">", "value": 0.38}, {"field": "service", "op": "!=", "value": "smtp"},
                           {"field": "service", "op": "!=", "value": "ftp_data"}], 20, 0.01)
    block = y.split("    filter:\n")[1].split("    condition")[0]
    keys = [ln.strip().split(":")[0] for ln in block.splitlines() if ln.startswith("        ") and not ln.strip().startswith("-")]
    assert keys == ["service"] and "- smtp" in block and "- ftp_data" in block
    assert "rerror_rate|gt: 0.38" in y and "condition: selection and not filter" in y


def test_shadow_mode_counts_disagreements_before_promotion():
    service.LABEL_FILE.write_text("".join(json.dumps(r) + "\n" for r in _unseen_labels()))
    try:
        report = client.post("/learning/retrain", json={"mode": "shadow"}).json()
        assert report["promoted"] is False and report["mode"] == "shadow"
        st = client.get("/learning/shadow").json()
        if st["active"]:
            assert "learned" not in client.get("/health").json()["model_version"], "shadow must not change the live model"
            client.get("/simulate?n=60")
            stats = client.get("/learning/shadow").json()["stats"]
            assert stats["flows"] == 60 and stats["agree"] + stats["only_shadow_flags"] + stats["only_live_flags"] == 60
            assert stats["only_shadow_flags_true_attack"] + stats["only_shadow_flags_true_normal"] == stats["only_shadow_flags"]
            promoted = client.post("/learning/shadow/promote").json()
            assert promoted["active"] >= 1 and "learned" in promoted["model_version"]
            assert client.get("/learning/shadow").json() == {"active": False}
        assert client.delete("/learning/shadow").status_code == 404
    finally:
        service.LABEL_FILE.write_text("")
        service.SHADOW.update(detector=None, since=None, report=None, stats=None)
        service.REGISTRY.activate(0)


def test_rollback_is_refused_while_retraining():
    assert service._retrain_lock.acquire(blocking=False)
    try:
        assert client.post("/learning/rollback", json={"generation": 0}).status_code == 409
    finally:
        service._retrain_lock.release()


def test_capture_gives_a_block_list_and_a_timeline():
    from ops import blocklist
    body = client.post("/capture", content=_capture(), headers={"content-type": "application/octet-stream"}).json()
    bl = body["blocklist"]
    assert {s["ip"] for s in bl["sources"]} == {"10.0.0.66", "10.0.0.99"}
    assert "iptables -I INPUT -s 10.0.0.66 -j DROP" in bl["iptables"] and "10.0.0.101" not in bl["iptables"]
    assert "ip saddr { 10.0.0.66, 10.0.0.99 }" in bl["nftables"] or "ip saddr { 10.0.0.99, 10.0.0.66 }" in bl["nftables"]
    tl = body["timeline"]
    assert tl["sources"] and all(len(s["buckets"]) == 40 for s in tl["sources"])
    assert sum(b[0] for s in tl["sources"] for b in s["buckets"]) == body["flows"]
    evil = blocklist([{"ip": "1.2.3.4; rm -rf /", "behaviour": "scanner", "flows": 9}])
    assert evil["sources"] == [] and evil["iptables"] == "", "a hostile address must never reach a shell command"


def test_zeek_conn_log_import():
    cols = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state"
    head = "#separator \\x09\n#fields\t" + "\t".join(cols.split()) + "\n"
    rows = [f"{1000 + i}.0\tC{i}\t10.0.0.101\t{40000 + i}\t10.0.0.10\t80\ttcp\thttp\t0.5\t300\t2000\tSF" for i in range(5)]
    rows += [f"{1010 + i * 0.01}\tS{i}\t10.0.0.99\t{1024 + i}\t10.0.0.10\t80\ttcp\t-\t-\t0\t0\tS0" for i in range(80)]
    r = client.post("/capture", content=(head + "\n".join(rows) + "\n").encode(), headers={"content-type": "application/octet-stream"})
    assert r.status_code == 200
    body = r.json()
    assert body["flows"] == 85
    assert {s["ip"]: s["behaviour"] for s in body["graph"]["sources"]}["10.0.0.99"] == "flooder"
    web = next(x for x in body["rows"] if x["src"] == "10.0.0.101")
    assert web["flag"] == "SF" and web["flow"]["src_bytes"] == 300 and web["flow"]["dst_bytes"] == 2000
    assert client.post("/capture", content=b"#fields\tfoo\tbar\n1\t2\n", headers={"content-type": "application/octet-stream"}).status_code == 422


def test_named_users_appear_in_the_action_log(monkeypatch):
    monkeypatch.setattr(service, "USERS", {"asha-key": ("asha", "analyst"), "ravi-key": ("ravi", "admin")})
    assert client.get("/auth/whoami", headers={"x-api-key": "asha-key"}).json() == {"role": "analyst", "user": "asha", "open_mode": False}
    assert client.post("/learning/rollback", json={"generation": 0}, headers={"x-api-key": "asha-key"}).status_code == 403
    assert client.post("/learning/rollback", json={"generation": 0}, headers={"x-api-key": "ravi-key"}).status_code == 200
    last = client.get("/audit/actions?limit=1", headers={"x-api-key": "asha-key"}).json()["items"][0]
    assert (last["user"], last["role"], last["action"]) == ("ravi", "admin", "rollback")


def test_scheduled_retrain_only_ever_goes_to_shadow(monkeypatch):
    monkeypatch.setattr(service, "AUTO_RETRAIN", True)
    monkeypatch.setattr(service, "AUTO_RETRAIN_MIN_LABELS", 10)
    monkeypatch.setitem(service._auto, "labels_at_last_run", 0)
    service.LABEL_FILE.write_text("")
    assert service.auto_retrain() is None, "nothing to learn from"
    service.LABEL_FILE.write_text("".join(json.dumps(r) + "\n" for r in _unseen_labels()))
    try:
        report = service.auto_retrain()
        assert report is not None and report["promoted"] is False
        assert service.LEARNING["generation"] == 0, "an unattended job must not replace the live model"
        assert service.auto_retrain() is None, "no new labels since the last run"
        assert service.AUDIT_LOG.read(1)[0]["user"] == "scheduler"
    finally:
        service.LABEL_FILE.write_text("")
        service.SHADOW.update(detector=None, since=None, report=None, stats=None)


def test_stix_bundle_for_a_campaign():
    import random
    random.seed(7)
    service.LABEL_FILE.write_text("")
    for _ in range(10):
        client.get("/simulate?n=60")
    found = client.get("/campaigns").json()["campaigns"]
    assert found
    b = client.get(f"/campaigns/{found[0]['id']}/stix").json()
    kinds = [o["type"] for o in b["objects"]]
    ind = b["objects"][0]
    assert b["type"] == "bundle" and kinds[0] == "indicator" and ind["pattern_type"] == "sigma" and "detection:" in ind["pattern"]
    assert all(o["spec_version"] == "2.1" and o["id"].startswith(o["type"] + "--") for o in b["objects"])
    assert kinds.count("relationship") == kinds.count("attack-pattern")


def test_replay_stream_sends_events():
    with client.stream("GET", "/simulate/stream?n=3&ticks=2&interval=0") as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        chunks = [ln for ln in r.iter_lines() if ln.startswith("data: ")]
    assert len(chunks) == 2 and len(json.loads(chunks[0][6:])["events"]) == 3
    assert client.get("/simulate/stream?ticks=9999").status_code == 422


def test_log_reads_span_a_rotation(tmp_path):
    from store import ChainLog
    log = ChainLog(tmp_path / "p.jsonl", max_bytes=400)
    for i in range(30):
        log.append({"n": i})
    log.append_many([{"n": 30 + i} for i in range(5)])
    assert len(list(tmp_path.glob("p-*.jsonl"))) >= 2
    assert [e["n"] for e in log.read(20)] == list(range(15, 35)), "newest 20, oldest first, across files"
    assert log.verify()["valid"] is True


def test_model_tab_data_is_present():
    ev = client.get("/model/info").json()["evaluation"]
    c = ev["confusion"]
    assert c["tp"] + c["fp"] + c["fn"] + c["tn"] == 21494
    assert set(ev["family_recall"]) == {"DoS", "Probe", "R2L", "U2R"} and len(ev["roc"]) >= 10


def test_public_host_without_tokens_is_not_open(monkeypatch):
    """On Render with no keys configured, state-changing routes must stay locked, not open to everyone."""
    monkeypatch.setattr(service, "ON_RENDER", True)
    assert service.open_mode() is False
    r = client.post("/learning/rollback", json={})
    assert r.status_code in (401, 403, 422) and r.status_code != 200
    assert client.get("/auth/whoami").json()["role"] == "viewer"
    assert "strict-transport-security" in client.get("/health").headers


def test_alert_limit_is_clamped():
    assert len(client.get("/alerts?limit=100000").content) < 200_000
