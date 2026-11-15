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
    # several exclusions on one field must be ONE key with a list (a list means "any of"),
    # because repeating a key is not valid YAML
    excluded: dict = {}
    for c in conditions:
        if c["op"] == "!=":
            excluded.setdefault(c["field"], []).append(c["value"])
    flt = []
    for field, values in excluded.items():
        flt += [f"        {field}: {values[0]}"] if len(values) == 1 else [f"        {field}:", *(f"            - {v}" for v in values)]
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


def stix_bundle(campaign_id: str, rule_text: str, sigma: str, techniques: list[tuple[str, str]], size: int) -> dict:
    """STIX 2.1 bundle: one indicator carrying the Sigma rule (pattern_type "sigma" is part of
    the standard), the ATT&CK techniques it relates to, and the relationships between them."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    def sid(kind: str, name: str) -> str:
        return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'zerowatch/' + kind + '/' + name)}"

    indicator = {"type": "indicator", "spec_version": "2.1", "id": sid("indicator", campaign_id), "created": now,
                 "modified": now, "name": f"ZeroWatch campaign {campaign_id}", "indicator_types": ["anomalous-activity"],
                 "description": f"Generated from {size} flows flagged as a possible zero-day. Rule: {rule_text}",
                 "pattern": sigma, "pattern_type": "sigma", "valid_from": now}
    objects = [indicator]
    for tid, name in techniques:
        ap = {"type": "attack-pattern", "spec_version": "2.1", "id": sid("attack-pattern", tid), "created": now,
              "modified": now, "name": name,
              "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                       "url": f"https://attack.mitre.org/techniques/{tid}/"}]}
        objects += [ap, {"type": "relationship", "spec_version": "2.1", "id": sid("relationship", campaign_id + tid),
                         "created": now, "modified": now, "relationship_type": "indicates",
                         "source_ref": indicator["id"], "target_ref": ap["id"]}]
    return {"type": "bundle", "id": sid("bundle", campaign_id), "objects": objects}


def blocklist(sources: list[dict]) -> dict:
    """Firewall rules for the sources a capture showed scanning or flooding. Addresses come from
    an uploaded file, so each is parsed as an IP address before it is put into a command."""
    import ipaddress
    bad = []
    for s in sources:
        if s["behaviour"] == "normal":
            continue
        try:
            bad.append((str(ipaddress.ip_address(s["ip"])), s["behaviour"], s["flows"]))
        except ValueError:
            continue
    if not bad:
        return {"sources": [], "iptables": "", "nftables": ""}
    ipt = ["# ZeroWatch block list. Review before applying; these rules drop ALL traffic from each source."]
    ipt += [f"{'ip6tables' if ':' in ip else 'iptables'} -I INPUT -s {ip} -j DROP   # {role}, {n} flows" for ip, role, n in bad]
    v4, v6 = [ip for ip, _, _ in bad if ":" not in ip], [ip for ip, _, _ in bad if ":" in ip]
    nft = ["# ZeroWatch block list for nftables (table inet filter, chain input must exist)"]
    if v4:
        nft.append(f"nft add rule inet filter input ip saddr {{ {', '.join(v4)} }} drop")
    if v6:
        nft.append(f"nft add rule inet filter input ip6 saddr {{ {', '.join(v6)} }} drop")
    return {"sources": [{"ip": ip, "behaviour": role, "flows": n} for ip, role, n in bad],
            "iptables": "\n".join(ipt) + "\n", "nftables": "\n".join(nft) + "\n"}


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
        # keep the five newest versions: older model files would otherwise pile up forever
        for old in st["versions"][:-5]:
            (self.dir / old["file"]).unlink(missing_ok=True)
        st["versions"] = st["versions"][-5:]
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
