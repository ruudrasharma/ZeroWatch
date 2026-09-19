"""
ZeroWatch — Recon Engine: SSL/TLS analyzer.

Checks per FEATURES.md:
  - Certificate validity dates (expired → critical, not-yet-valid → critical)
  - Self-signed certificate → critical
  - Weak/old protocol supported (TLS 1.0/1.1 → medium)
  - Cipher suite strength (placeholder: connection-level info)
  - All clear → informational pass

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse


def _get_cert_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Establish a TLS connection and extract certificate details."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw_info: Dict[str, Any] = {}
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                raw_info["cert"] = cert
                raw_info["protocol"] = ssock.version()
                raw_info["cipher"] = ssock.cipher()
                raw_info["self_signed"] = False
    except ssl.SSLCertVerificationError as exc:
        raw_info["error"] = str(exc)
        raw_info["self_signed"] = "self-signed" in str(exc).lower() or "unable to verify" in str(exc).lower()
        raw_info["cert"] = None
        raw_info["protocol"] = None
        raw_info["cipher"] = None
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        raw_info["connection_error"] = str(exc)
        raw_info["cert"] = None
        raw_info["protocol"] = None
        raw_info["cipher"] = None
        raw_info["self_signed"] = False

    return raw_info


def _parse_ssl_date(date_str: str) -> datetime:
    """Parse SSL certificate date string (format: 'Jan  1 12:00:00 2026 GMT')."""
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def check_ssl(url: str) -> List[Dict[str, Any]]:
    """
    Run SSL/TLS checks against the target URL.

    Returns a list of finding dicts:
      {category, severity, title, description, raw_data}
    An empty list means the target is HTTP-only (no TLS to check).
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [
            {
                "category": "ssl",
                "severity": "medium",
                "title": "Site does not use HTTPS",
                "description": (
                    "The target URL uses plain HTTP rather than HTTPS. "
                    "All traffic is transmitted unencrypted."
                ),
                "raw_data": {"url": url, "scheme": parsed.scheme},
            }
        ]

    hostname = parsed.hostname or ""
    port = parsed.port or 443
    findings: List[Dict[str, Any]] = []

    info = _get_cert_info(hostname, port)

    # ── Connection error ──────────────────────────────────────────────────────
    if "connection_error" in info:
        findings.append(
            {
                "category": "ssl",
                "severity": "high",
                "title": "Could not establish TLS connection",
                "description": f"TLS handshake failed: {info['connection_error']}",
                "raw_data": info,
            }
        )
        return findings

    # ── Self-signed / unverifiable certificate ────────────────────────────────
    if info.get("self_signed"):
        findings.append(
            {
                "category": "ssl",
                "severity": "critical",
                "title": "Self-signed or unverifiable certificate",
                "description": (
                    "The server's TLS certificate could not be verified against a trusted CA. "
                    "This allows man-in-the-middle attacks."
                ),
                "raw_data": {"error": info.get("error")},
            }
        )
        return findings  # can't inspect further without a valid cert

    cert = info.get("cert") or {}

    # ── Expiry check ──────────────────────────────────────────────────────────
    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")
    now = datetime.now(tz=timezone.utc)

    if not_after_str:
        try:
            not_after = _parse_ssl_date(not_after_str)
            if now > not_after:
                findings.append(
                    {
                        "category": "ssl",
                        "severity": "critical",
                        "title": "TLS certificate has expired",
                        "description": (
                            f"Certificate expired on {not_after.date()}. "
                            "Browsers will reject this site with a security warning."
                        ),
                        "raw_data": {"notAfter": not_after_str},
                    }
                )
            elif (not_after - now).days < 30:
                findings.append(
                    {
                        "category": "ssl",
                        "severity": "medium",
                        "title": f"TLS certificate expires soon ({(not_after - now).days} days)",
                        "description": "Certificate nearing expiry — renew to avoid downtime.",
                        "raw_data": {"notAfter": not_after_str},
                    }
                )
        except ValueError:
            pass

    if not_before_str:
        try:
            not_before = _parse_ssl_date(not_before_str)
            if now < not_before:
                findings.append(
                    {
                        "category": "ssl",
                        "severity": "critical",
                        "title": "TLS certificate not yet valid",
                        "description": f"Certificate valid from {not_before.date()} — clock skew or misconfiguration.",
                        "raw_data": {"notBefore": not_before_str},
                    }
                )
        except ValueError:
            pass

    # ── Protocol version ──────────────────────────────────────────────────────
    protocol = info.get("protocol") or ""
    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append(
            {
                "category": "ssl",
                "severity": "medium",
                "title": f"Weak TLS protocol in use: {protocol}",
                "description": (
                    f"{protocol} is deprecated and vulnerable to known attacks "
                    "(BEAST, POODLE, DROWN). Upgrade to TLS 1.2 or TLS 1.3."
                ),
                "raw_data": {"protocol": protocol},
            }
        )

    # ── Cipher suite ─────────────────────────────────────────────────────────
    cipher = info.get("cipher")
    if cipher:
        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        weak_keywords = ("RC4", "DES", "EXPORT", "NULL", "MD5", "ANON")
        if any(k in cipher_name.upper() for k in weak_keywords):
            findings.append(
                {
                    "category": "ssl",
                    "severity": "medium",
                    "title": f"Weak cipher suite in use: {cipher_name}",
                    "description": "Weak cipher suites can be exploited to decrypt TLS traffic.",
                    "raw_data": {"cipher": list(cipher) if cipher else None},
                }
            )

    # ── All clear (no findings → add informational pass) ─────────────────────
    if not findings:
        findings.append(
            {
                "category": "ssl",
                "severity": "low",
                "title": "SSL/TLS configuration looks healthy",
                "description": (
                    f"Certificate is valid, protocol is {protocol or 'TLS 1.2+'}, "
                    "no weak ciphers detected."
                ),
                "raw_data": {
                    "protocol": protocol,
                    "cipher": list(cipher) if cipher else None,
                    "notAfter": not_after_str,
                },
            }
        )

    return findings
