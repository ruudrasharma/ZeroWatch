"""
ZeroWatch — Ollama LLM integration service.

Calls the local Ollama HTTP API (http://localhost:11434) to generate:
  1. Per-finding remediation text for the Recon report.
  2. Plain-English explanations of SHAP values for anomaly alerts.

All generated text is labeled AI-generated per SECURITY.md §4.
Raw page HTML is never passed to Ollama — only structured JSON findings.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_TIMEOUT: float = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60"))

# Prompt templates (structured JSON → LLM → human-readable explanation)

_RECON_FINDING_PROMPT = """\
You are a security analyst writing a plain-English report for a developer.
Given the following security finding from an automated web scan, write a concise explanation:
1. What this finding is (1-2 sentences).
2. Why it matters — what attack is enabled by this weakness (1-2 sentences).
3. A concrete remediation step the developer can take today (1-3 sentences).

Keep the total response under 150 words. Do not repeat the finding title verbatim.
Be specific and actionable.

Finding:
{finding_json}

[AI-GENERATED — verify before acting]
"""

_SHAP_EXPLANATION_PROMPT = """\
You are a network security analyst explaining an anomaly detection alert to a developer.
An AI model flagged a network flow as anomalous. The following SHAP feature contributions
explain which features most influenced this decision (positive = pushes toward anomaly).

Flow context: {flow_context}
Top contributing features: {shap_json}
Anomaly score: {score:.3f} (threshold: {threshold:.3f})

Write a plain-English explanation in 3-5 sentences:
- What pattern the AI noticed
- Which features are most suspicious and why
- What real-world attack this might correspond to (if applicable)

End with: "[AI-GENERATED — verify before acting]"
"""


async def generate_finding_remediation(finding: Dict[str, Any]) -> str:
    """
    Generate AI remediation text for a single Recon finding.
    Returns the generated text, or a fallback string if Ollama is unavailable.

    Text is cached in finding.remediation at the DB level — not regenerated on every view.
    """
    prompt = _RECON_FINDING_PROMPT.format(
        finding_json=json.dumps(
            {
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "description": finding.get("description"),
            },
            indent=2,
        )
    )

    return await _call_ollama(prompt, context="recon_finding")


async def generate_shap_explanation(
    shap_values: Dict[str, float],
    anomaly_score: float,
    threshold: float,
    flow_context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a plain-English explanation of SHAP values for an anomaly alert.
    """
    # Sort by contribution magnitude, top 5
    top_features = dict(
        sorted(shap_values.items(), key=lambda kv: abs(kv[1]), reverse=True)[:5]
    )
    context_str = json.dumps(flow_context or {}, indent=2)

    prompt = _SHAP_EXPLANATION_PROMPT.format(
        flow_context=context_str,
        shap_json=json.dumps(top_features, indent=2),
        score=anomaly_score,
        threshold=threshold,
    )

    return await _call_ollama(prompt, context="shap_explanation")


async def _call_ollama(prompt: str, context: str = "") -> str:
    """
    POST to the Ollama /api/generate endpoint.
    Returns the generated text, or a labeled fallback if unavailable.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 300,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            if not text:
                raise ValueError("Empty response from Ollama")
            return text

    except httpx.ConnectError:
        logger.warning("Ollama not running at %s — using fallback text", OLLAMA_BASE_URL)
        return (
            "[AI-GENERATED — Ollama not available. Start with: ollama serve] "
            "Refer to the finding description for remediation guidance."
        )
    except httpx.TimeoutException:
        logger.warning("Ollama timed out after %ss (context: %s)", OLLAMA_TIMEOUT, context)
        return (
            "[AI-GENERATED — Ollama timed out. Consider a smaller model or increase "
            "OLLAMA_TIMEOUT_SECONDS in .env.] Refer to the finding description."
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Ollama call failed (%s): %s", context, exc)
        return f"[AI-GENERATED — generation failed: {exc}] Refer to finding description."
