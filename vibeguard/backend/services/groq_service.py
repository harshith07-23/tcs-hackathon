"""
Groq reasoning/explanation layer.

Groq is used ONLY to explain, correlate, and describe remediation for
findings already produced by the deterministic scanners — it never decides
whether something is a vulnerability, and it never determines the numeric
security score.

If GROQ_API_KEY is missing, the API errors, or the response fails
validation, this module degrades gracefully: callers receive an
`unavailable` result and the rest of the report is still produced.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

from dotenv import load_dotenv
from groq import Groq

from backend.services.finding_types import RawFinding

load_dotenv()

logger = logging.getLogger("vibeguard.groq_service")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "mixtral-8x7b-32768")

_SYSTEM_PROMPT = """You are a senior application security engineer helping a developer \
understand a security finding that was already detected by a deterministic scanner. \
You do not decide whether the finding is valid — that has already been determined. \
Your job is to explain it clearly, describe a plausible (not verified) attack path, \
estimate potential business impact using cautious language ("could", "may", "potentially"), \
and provide a concrete, minimal secure-code fix that preserves behavior. \
Respond with ONLY a JSON object and nothing else — no markdown fences, no preamble. \
The JSON object must have exactly these keys: \
explanation (string), impact (string), attack_path (array of short strings), \
recommendation (string), example_fix (string), reasoning_summary (string), \
confidence (integer 0-100)."""


@dataclass
class GroqExplanation:
    available: bool
    explanation: Optional[str] = None
    impact: Optional[str] = None
    attack_path: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    example_fix: Optional[str] = None
    reasoning_summary: Optional[str] = None
    confidence: Optional[int] = None
    error: Optional[str] = None


def is_configured() -> bool:
    return bool(GROQ_API_KEY)


def _get_client():
    return Groq(api_key=GROQ_API_KEY)


def _validate_payload(data: dict) -> bool:
    required_keys = {
        "explanation", "impact", "attack_path", "recommendation",
        "example_fix", "reasoning_summary", "confidence",
    }
    if not required_keys.issubset(data.keys()):
        return False
    if not isinstance(data["attack_path"], list):
        return False
    if not isinstance(data["confidence"], (int, float)):
        return False
    return True


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()


def explain_finding(finding: RawFinding, code_context: Optional[str] = None) -> GroqExplanation:
    if not is_configured():
        return GroqExplanation(available=False, error="GROQ_API_KEY is not configured.")

    prompt = {
        "finding": {
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "description": finding.description,
            "code_snippet": finding.code_snippet,
        },
        "additional_code_context": code_context or "",
    }

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": _SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt),
                },
            ],
            temperature=0.2,
        )
        raw_text = _strip_code_fences(response.choices[0].message.content)
        data = json.loads(raw_text)

        if not _validate_payload(data):
            logger.warning("Groq response failed schema validation for finding '%s'.", finding.title)
            return GroqExplanation(available=False, error="Groq response failed validation.")

        return GroqExplanation(
            available=True,
            explanation=str(data["explanation"]),
            impact=str(data["impact"]),
            attack_path=[str(x) for x in data["attack_path"]],
            recommendation=str(data["recommendation"]),
            example_fix=str(data["example_fix"]),
            reasoning_summary=str(data["reasoning_summary"]),
            confidence=int(data["confidence"]),
        )
    except json.JSONDecodeError as exc:
        logger.warning("Groq returned malformed JSON: %s", type(exc).__name__)
        return GroqExplanation(available=False, error="Groq returned a malformed response.")
    except Exception as exc:
        # Broad catch is intentional: any Groq/network failure must be
        # non-fatal to the overall scan (spec section 36).
        logger.warning("Groq call failed: %s", type(exc).__name__)
        return GroqExplanation(available=False, error="Groq explanation is temporarily unavailable.")


def summarize_posture(score: int, critical: int, high: int, medium: int, low: int) -> Optional[str]:
    """Optional one-paragraph executive summary of overall posture. Returns None on failure."""
    if not is_configured():
        return None
    try:
        client = _get_client()
        prompt = (
            f"In 2-3 sentences, summarize the security posture of a codebase for a developer. "
            f"Score: {score}/100. Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}. "
            f"Be direct and avoid alarmism; use cautious language for potential impact."
        )
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        logger.warning("Groq posture summary failed: %s", type(exc).__name__)
        return None
