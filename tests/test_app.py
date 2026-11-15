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
    assert client.post("/capture", content=b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, headers=h).status_code == 422  # pcapng
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
