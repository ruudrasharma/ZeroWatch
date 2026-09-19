"""
ZeroWatch — Recon Engine: Security header audit.

Checks per FEATURES.md: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy.

Severity assignments match FEATURES.md:
  Missing CSP → high
  Missing HSTS → high
  Missing X-Frame-Options → medium
  Missing X-Content-Type-Options → medium
  Missing Referrer-Policy → low
  Missing Permissions-Policy → low

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from typing import Any

import httpx

# (header_name, severity_if_missing, description_if_missing)
REQUIRED_HEADERS: list[tuple[str, str, str]] = [
    (
        "Content-Security-Policy",
        "high",
        "CSP prevents cross-site scripting (XSS) by restricting which content sources "
        "the browser will load. Missing CSP leaves the site open to XSS injection attacks.",
    ),
    (
        "Strict-Transport-Security",
        "high",
        "HSTS forces browsers to use HTTPS for all future requests, preventing "
        "SSL-stripping attacks. Missing HSTS means HTTP downgrade attacks are possible.",
    ),
    (
        "X-Frame-Options",
        "medium",
        "Prevents the page from being embedded in iframes on other origins, "
        "protecting against clickjacking attacks.",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "Prevents browsers from MIME-sniffing the content type, which can lead to "
        "execution of malicious scripts disguised as benign files.",
    ),
    (
        "Referrer-Policy",
        "low",
        "Controls how much referrer information is included in requests. "
        "Missing this header may leak sensitive URL parameters to third parties.",
    ),
    (
        "Permissions-Policy",
        "low",
        "Restricts access to browser features (camera, microphone, geolocation, etc.). "
        "Missing this header leaves feature permissions unrestricted.",
    ),
]


async def check_headers(url: str) -> list[dict[str, Any]]:
    """
    Fetch the target URL (HEAD first, fall back to GET) and audit response headers.

    Returns a list of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=False,  # some targets may have cert issues already caught by ssl_check
            headers={"User-Agent": "ZeroWatch-SecurityScanner/0.1"},
        ) as client:
            try:
                resp = await client.head(url)
            except Exception:
                resp = await client.get(url)

            response_headers = {k.lower(): v for k, v in resp.headers.items()}

    except httpx.RequestError as exc:
        return [
            {
                "category": "headers",
                "severity": "high",
                "title": "Could not fetch response headers",
                "description": f"HTTP request failed: {exc}",
                "raw_data": {"url": url, "error": str(exc)},
            }
        ]

    found_any_issue = False
    for header_name, severity, description in REQUIRED_HEADERS:
        if header_name.lower() not in response_headers:
            found_any_issue = True
            findings.append(
                {
                    "category": "headers",
                    "severity": severity,
                    "title": f"Missing security header: {header_name}",
                    "description": description,
                    "raw_data": {
                        "header": header_name,
                        "present": False,
                        "response_status": resp.status_code,
                    },
                }
            )

    if not found_any_issue:
        findings.append(
            {
                "category": "headers",
                "severity": "low",
                "title": "All recommended security headers are present",
                "description": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
                "Referrer-Policy, and Permissions-Policy are all set.",
                "raw_data": {
                    "checked_headers": [h[0] for h in REQUIRED_HEADERS],
                    "response_status": resp.status_code,
                },
            }
        )

    return findings
