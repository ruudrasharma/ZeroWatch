"""
ZeroWatch - operations helpers used by app.py: rule export and testing, incident reports,
the model version registry (persist + roll back promoted challengers) and webhook alarms.
Standard library + joblib only.
"""
from __future__ import annotations

import hashlib
import json
import operator
import time
import urllib.request
import uuid
from pathlib import Path

import joblib

OPS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}
SIGMA_MOD = {">": "|gt", ">=": "|gte", "<": "|lt", "<=": "|lte"}


def match_rule(conditions: list[dict], flow: dict) -> bool:
    return bool(conditions) and all(OPS[c["op"]](flow[c["field"]], c["value"]) for c in conditions)


def sigma_rule(campaign_id: str, conditions: list[dict], size: int, false_match_rate: float) -> str:
    """Sigma-format detection rule (https://sigmahq.io). Equality goes in `selection`, exclusions in
    `filter`, numeric comparisons use Sigma's |gt/|gte/|lt/|lte modifiers."""
    sel = [f"        {c['field']}{SIGMA_MOD.get(c['op'], '')}: {c['value']}" for c in conditions if c["op"] != "!="]
    flt = [f"        {c['field']}: {c['value']}" for c in conditions if c["op"] == "!="]
    lines = [
        f"title: ZeroWatch campaign {campaign_id}",
        f"id: {uuid.uuid5(uuid.NAMESPACE_URL, 'zerowatch/' + campaign_id)}",
        "status: experimental",
        f"description: Generated from {size} flows the novelty model flagged as a possible zero-day. "
        f"Matches {false_match_rate:.2%} of normal training traffic. Review before deploying.",
        "author: ZeroWatch (generated)",
        f"date: {time.strftime('%Y-%m-%d')}",
        "logsource:", "    category: network_connection", "    product: zerowatch",
        "detection:", "    selection:", *(sel or ["        protocol_type: '*'"]),
        *(["    filter:", *flt] if flt else []),
        f"    condition: selection{' and not filter' if flt else ''}",
        "falsepositives:", "    - Normal traffic that shares these connection statistics",
        "level: high", "",
    ]
    return "\n".join(lines)


def incident_markdown(c: dict, techniques: list[tuple[str, str]], rule_test: dict, model_version: str, chain_head: str) -> str:
    """One-page incident report for a campaign, as Markdown."""
    common = ", ".join(f"{k} = {v['value']} ({v['share']:.0%})" for k, v in c["common"].items())
    truth = ", ".join(f"{k} ({n})" for k, n in c.get("true_labels", {}).items()) or "not available (live traffic)"
    sample = "\n".join("| " + " | ".join(str(f[k]) for k in ("protocol_type", "service", "flag", "src_bytes", "dst_bytes",
                                                                 "count", "serror_rate", "rerror_rate")) + " |"
                       for f in c["flows"][:8])
    return f"""# Incident report: campaign {c['id']}

Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by ZeroWatch, model `{model_version}`.

## Summary

{c['size']} distinct flows were flagged as a possible zero-day: the classifier did not recognise them as a known
attack, and the novelty model placed them outside normal traffic. They cluster into one campaign with a mean
risk of {c['mean_risk']}/100.

- Shared traits: {common}
- True labels (replay data only): {truth}

## Detection rule

```
{c['signature']['rule']}
```

The rule matches {c['signature']['coverage']:.0%} of this campaign and {c['signature']['false_match_rate']:.2%} of
normal training traffic. Against the current prediction log it matches {rule_test['matched']} of
{rule_test['flows']} distinct flows ({rule_test['matched_benign']} of them judged benign by the model).

## Closest known techniques (MITRE ATT&CK)

{chr(10).join(f'- {i} {n}' for i, n in techniques) or '- none mapped'}

## Recommended actions

1. Capture packets for the sources involved and preserve them.
2. Deploy the rule above in monitor-only mode and watch its false-match rate for a day.
3. Label the campaign in Hunt and retrain, so these flows are detected as a known attack.
4. If the targeted asset is exposed (see Assets), restrict access until the review is complete.

## Sample flows

| protocol | service | flag | src_bytes | dst_bytes | count | serror_rate | rerror_rate |
|---|---|---|---|---|---|---|---|
{sample}

## Evidence integrity

Prediction log hash-chain head when this report was generated: `{chain_head}`.
"""


def send_webhook(url: str, text: str) -> bool:
    """POST {"text": ...} (the format Slack, Discord-compatible and Teams webhooks accept)."""
    try:
        req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return 200 <= r.status < 300
    except Exception:  # noqa: BLE001 - an unreachable webhook must never break the service
        return False


class Registry:
    """Promoted detectors on disk, so learning survives a restart and can be rolled back.
    registry.json = {"active": generation, "versions": [{generation, file, sha256, promoted_at, report}]}"""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.index = self.dir / "registry.json"

    def state(self) -> dict:
        try:
            return json.loads(self.index.read_text())
        except (OSError, ValueError):
            return {"active": 0, "versions": []}

    def _write(self, st: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index.write_text(json.dumps(st, indent=2))

    def save(self, detector, report: dict) -> int:
        st = self.state()
        gen = max([v["generation"] for v in st["versions"]], default=0) + 1
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"detector-gen{gen}.joblib"
        joblib.dump(detector, path, compress=3)
        st["versions"].append({"generation": gen, "file": path.name, "promoted_at": int(time.time()),
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "report": report})
        st["active"] = gen
        self._write(st)
        return gen

    def load(self, generation: int):
        """Returns the detector, or None if the file is missing or does not match its recorded hash."""
        v = next((v for v in self.state()["versions"] if v["generation"] == generation), None)
        if not v:
            return None
        path = self.dir / v["file"]
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != v["sha256"]:
            return None
        return joblib.load(path)

    def activate(self, generation: int) -> None:
        st = self.state()
        st["active"] = generation
        self._write(st)
