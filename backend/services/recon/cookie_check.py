"""
ZeroWatch — Recon Engine: Cookie security flag checker.

Checks per FEATURES.md:
  - Missing Secure flag on HTTPS cookie → high
  - Missing HttpOnly on session-looking cookie → high
  - Missing SameSite flag → medium

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

# Heuristic: cookie names suggesting session tokens
SESSION_PATTERNS = re.compile(
    r"(sess|session|token|auth|login|jwt|bearer|sid|uid|user|account|csrf)",
    re.IGNORECASE,
)


def _parse_set_cookie(header_value: str) -> dict[str, Any]:
    """Parse a single Set-Cookie header into a dict of flags/attributes."""
    parts = [p.strip() for p in header_value.split(";")]
    cookie: dict[str, Any] = {"raw": header_value}

    # First part is name=value
    if parts:
        nv = parts[0].split("=", 1)
        cookie["name"] = nv[0].strip()
        cookie["value"] = nv[1].strip() if len(nv) > 1 else ""

    flags = {p.lower() for p in parts[1:]}
    cookie["secure"] = any(f.startswith("secure") for f in flags)
    cookie["httponly"] = any(f.startswith("httponly") for f in flags)
    cookie["samesite"] = next(
        (p for p in parts[1:] if p.lower().startswith("samesite")), None
    )
    return cookie


async def check_cookies(url: str) -> list[dict[str, Any]]:
    """
    Fetch the target URL and audit Set-Cookie headers.

    Returns a list of finding dicts.
    """
    findings: list[dict[str, Any]] = []
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ZeroWatch-SecurityScanner/0.1"},
        ) as client:
            resp = await client.get(url)
    except httpx.RequestError as exc:
        return [
            {
                "category": "cookies",
                "severity": "medium",
                "title": "Could not fetch cookies (request failed)",
                "description": str(exc),
                "raw_data": {"error": str(exc)},
            }
        ]

    # httpx exposes cookies; we parse raw Set-Cookie headers for flag analysis
    set_cookie_headers = [
        v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
    ]

    if not set_cookie_headers:
        findings.append(
            {
                "category": "cookies",
                "severity": "low",
                "title": "No cookies set on the home page",
                "description": "No Set-Cookie headers found in the response. "
                "This is informational — cookies may be set after login.",
                "raw_data": {"set_cookie_count": 0},
            }
        )
        return findings

    found_any_issue = False
    for raw in set_cookie_headers:
        cookie = _parse_set_cookie(raw)
        name = cookie.get("name", "<unknown>")
        looks_like_session = bool(SESSION_PATTERNS.search(name))

        if is_https and not cookie["secure"]:
            found_any_issue = True
            findings.append(
                {
                    "category": "cookies",
                    "severity": "high",
                    "title": f"Cookie '{name}' missing Secure flag",
                    "description": (
                        "Without the Secure flag, this cookie can be transmitted over "
                        "plain HTTP, exposing it to eavesdroppers."
                    ),
                    "raw_data": {"cookie_name": name, "raw_header": raw},
                }
            )

        if looks_like_session and not cookie["httponly"]:
            found_any_issue = True
            findings.append(
                {
                    "category": "cookies",
                    "severity": "high",
                    "title": f"Session-looking cookie '{name}' missing HttpOnly flag",
                    "description": (
                        "Without HttpOnly, this cookie is accessible to JavaScript and "
                        "can be stolen via XSS attacks."
                    ),
                    "raw_data": {"cookie_name": name, "raw_header": raw},
                }
            )

        if not cookie["samesite"]:
            found_any_issue = True
            findings.append(
                {
                    "category": "cookies",
                    "severity": "medium",
                    "title": f"Cookie '{name}' missing SameSite attribute",
                    "description": (
                        "Without SameSite, this cookie is sent on cross-site requests, "
                        "increasing CSRF risk."
                    ),
                    "raw_data": {"cookie_name": name, "raw_header": raw},
                }
            )

    if not found_any_issue:
        findings.append(
            {
                "category": "cookies",
                "severity": "low",
                "title": "All cookies have proper security flags",
                "description": "Secure, HttpOnly, and SameSite flags are present on detected cookies.",
                "raw_data": {"cookie_count": len(set_cookie_headers)},
            }
        )

    return findings
