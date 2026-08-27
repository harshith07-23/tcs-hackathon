"""
Gemini reasoning/explanation layer.

Gemini is used ONLY to explain, correlate, and describe remediation for
findings already produced by the deterministic scanners — it never decides
whether something is a vulnerability, and it never determines the numeric
security score.

If GEMINI_API_KEY is missing, the API errors, or the response fails
validation, this module degrades gracefully: callers receive an
`unavailable` result and the rest of the report is still produced.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

from dotenv import load_dotenv

from backend.services.finding_types import RawFinding

load_dotenv()

logger = logging.getLogger("vibeguard.gemini_service")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

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
class GeminiExplanation:
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
    return bool(GEMINI_API_KEY)


def _get_model():
    import google.generativeai as genai

    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=_SYSTEM_PROMPT,
    )


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


def explain_finding(finding: RawFinding, code_context: Optional[str] = None) -> GeminiExplanation:
    if not is_configured():
        return GeminiExplanation(available=False, error="GEMINI_API_KEY is not configured.")

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
        model = _get_model()
        response = model.generate_content(
            json.dumps(prompt),
            generation_config={"temperature": 0.2, "response_mime_type": "application/json"},
        )
        raw_text = _strip_code_fences(response.text)
        data = json.loads(raw_text)

        if not _validate_payload(data):
            logger.warning("Gemini response failed schema validation for finding '%s'.", finding.title)
            return GeminiExplanation(available=False, error="Gemini response failed validation.")

        return GeminiExplanation(
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
        logger.warning("Gemini returned malformed JSON: %s", type(exc).__name__)
        return GeminiExplanation(available=False, error="Gemini returned a malformed response.")
    except Exception as exc:
        # Broad catch is intentional: any Gemini/network failure must be
        # non-fatal to the overall scan (spec section 36).
        logger.warning("Gemini call failed: %s", type(exc).__name__)
        return GeminiExplanation(available=False, error="Gemini explanation is temporarily unavailable.")


def summarize_posture(score: int, critical: int, high: int, medium: int, low: int) -> Optional[str]:
    """Optional one-paragraph executive summary of overall posture. Returns None on failure."""
    if not is_configured():
        return None
    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(model_name=GEMINI_MODEL)
        prompt = (
            f"In 2-3 sentences, summarize the security posture of a codebase for a developer. "
            f"Score: {score}/100. Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}. "
            f"Be direct and avoid alarmism; use cautious language for potential impact."
        )
        response = model.generate_content(prompt, generation_config={"temperature": 0.3})
        return response.text.strip()
    except Exception as exc:
        logger.warning("Gemini posture summary failed: %s", type(exc).__name__)
        return None
