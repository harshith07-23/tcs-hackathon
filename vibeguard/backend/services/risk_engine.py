"""
Deterministic security scoring engine.

The overall score (0-100) is a pure function of the finding list — it never
depends on Groq output, so it is fully reproducible given the same
deterministic scanner results.

Approach: start at 100 and subtract weighted penalties per finding, scaled
by confidence, then apply a small extra penalty for exposed secrets and
critical dependency vulnerabilities (since those tend to be the most
directly exploitable). Score is clamped to [0, 100].
"""

from dataclasses import dataclass
from typing import List

from backend.services.finding_types import RawFinding

SEVERITY_WEIGHT = {
    "CRITICAL": 12,
    "HIGH": 7,
    "MEDIUM": 3,
    "LOW": 1,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass
class ScoreBreakdown:
    overall_score: int
    posture: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int


def _posture_for_score(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Needs Attention"
    if score >= 25:
        return "High Risk"
    return "Critical Risk"


def calculate_score(findings: List[RawFinding]) -> ScoreBreakdown:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    penalty = 0.0

    for f in findings:
        severity = f.severity if f.severity in counts else "MEDIUM"
        counts[severity] += 1

        base_weight = SEVERITY_WEIGHT[severity]
        confidence_factor = max(0.3, min(1.0, f.confidence / 100))
        finding_penalty = base_weight * confidence_factor

        # Extra weight for the most directly exploitable categories.
        if f.category == "hardcoded-secrets":
            finding_penalty *= 1.15
        if f.category == "insecure-dependency" and severity == "CRITICAL":
            finding_penalty *= 1.1

        penalty += finding_penalty

    score = round(max(0.0, 100.0 - penalty))
    score = max(0, min(100, score))

    total = sum(counts.values())

    return ScoreBreakdown(
        overall_score=score,
        posture=_posture_for_score(score),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        total_findings=total,
    )
