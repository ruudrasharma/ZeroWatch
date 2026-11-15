"""
ZeroWatch - asset exposure scan, fused into alert priority.

A flood against a hardened server and the same flood against a server with weak TLS and no
security headers are not the same incident. This module takes ONE passive look at an asset
(one HTTPS request for its headers, one TLS handshake for its certificate), scores how exposed
it is, and app.py uses that score to raise or lower the priority of alerts aimed at it.

Safe to run on a public deployment:
  - only http/https URLs, and the host must resolve to public addresses (no loopback, private,
    link-local or cloud-metadata ranges), which blocks server-side request forgery
  - the request goes to the address that was checked, redirects are not followed, 6 s timeout
  - one request per scan; app.py rate-limits scans per client
Standard library only.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

TIMEOUT = 6
HEADER_CHECKS = [  # header, severity, points, what is missing
    ("strict-transport-security", "high", 15, "No HSTS header: browsers may be downgraded to plain HTTP."),
    ("content-security-policy", "medium", 10, "No Content-Security-Policy: injected scripts are not restricted."),
    ("x-content-type-options", "low", 5, "No X-Content-Type-Options: browsers may MIME-sniff responses."),
    ("x-frame-options", "low", 5, "No X-Frame-Options: the site can be framed for clickjacking."),
    ("referrer-policy", "low", 3, "No Referrer-Policy: full URLs leak to other sites."),
]


class ReconError(ValueError):
    pass


def safe_target(url: str) -> tuple[str, str, int, str]:
    """Validate the URL and return (scheme, host, port, ip). Raises ReconError if unsafe."""
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ReconError("Enter a full http:// or https:// URL.")
    port = u.port or (443 if u.scheme == "https" else 80)
    if port not in (80, 443, 8080, 8443):
        raise ReconError("Only ports 80, 443, 8080 and 8443 can be scanned.")
    try:
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        raise ReconError(f"Could not resolve {u.hostname}.") from None
    ips = {i[4][0] for i in infos}
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if not a.is_global or a.is_multicast:
            raise ReconError("That host resolves to a private or reserved address, which is not scanned.")
    return u.scheme, u.hostname, port, sorted(ips)[0]


def score_findings(scheme: str, headers: dict, tls: dict | None) -> dict:
    """Pure scoring: 0 = hardened, 100 = wide open. Kept separate so it can be unit-tested offline."""
    h = {k.lower(): v for k, v in headers.items()}
    findings = []
    if scheme == "http":
        findings.append({"severity": "high", "points": 30, "text": "Served over plain HTTP: traffic can be read and altered in transit."})
    for name, sev, pts, text in HEADER_CHECKS:
        if name == "strict-transport-security" and scheme == "http":
            continue
        if name not in h:
            findings.append({"severity": sev, "points": pts, "text": text})
    server = h.get("server", "")
    if any(ch.isdigit() for ch in server):
        findings.append({"severity": "medium", "points": 10,
                         "text": f"Server header reveals a version ({server}): attackers can match it to known CVEs."})
    if "x-powered-by" in h:
        findings.append({"severity": "low", "points": 5, "text": f"X-Powered-By reveals the stack ({h['x-powered-by']})."})
    if tls:
        if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({"severity": "high", "points": 25, "text": f"Outdated protocol {tls['version']} is accepted."})
        days = tls.get("days_left")
        if days is not None and days < 0:
            findings.append({"severity": "high", "points": 25, "text": "The TLS certificate has expired."})
        elif days is not None and days < 21:
            findings.append({"severity": "medium", "points": 10, "text": f"The TLS certificate expires in {days} days."})
    exposure = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    return {"exposure": exposure, "grade": "A" if exposure < 15 else "B" if exposure < 35 else "C" if exposure < 60 else "D",
            "findings": findings}


def scan(url: str) -> dict:
    scheme, host, port, ip = safe_target(url)
    tls = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            raw = socket.create_connection((ip, port), timeout=TIMEOUT)  # connect to the address we validated
            sock = ctx.wrap_socket(raw, server_hostname=host)
            cert = sock.getpeercert()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            tls = {"version": sock.version(), "expires": expires.date().isoformat(),
                   "days_left": (expires - datetime.now(timezone.utc)).days}
            conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ctx)
            conn.sock = sock
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
        conn.request("GET", "/", headers={"Host": host, "User-Agent": "ZeroWatch-exposure-check/1.0"})
        resp = conn.getresponse()  # redirects are reported, never followed
        headers = dict(resp.getheaders())
        status = resp.status
        conn.close()
    except ssl.SSLCertVerificationError as e:
        return {"url": url, "host": host, "scanned_at": int(time.time()), "status": None, "tls": None, "exposure": 80,
                "grade": "D", "findings": [{"severity": "high", "points": 80,
                                            "text": f"TLS certificate is not trusted: {e.verify_message}."}]}
    except (OSError, http.client.HTTPException) as e:
        raise ReconError(f"Could not reach {host}: {e.__class__.__name__}.") from None
    return {"url": url, "host": host, "scanned_at": int(time.time()), "status": status, "tls": tls,
            **score_findings(scheme, headers, tls)}


def priority(risk: int, exposure: int) -> int:
    """Alert priority = model risk scaled by how exposed the targeted asset is.
    exposure 50 leaves the risk unchanged; a hardened asset (0) scales it by 0.7, a wide-open one (100) by 1.3."""
    return min(100, round(risk * (0.7 + 0.6 * exposure / 100)))
