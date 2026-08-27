"""
Orchestrates a full VibeGuard scan:

    1. Extract project safely
    2. Discover files / detect frameworks
    3. Run static analysis, secret scan, dependency scan
    4. Calculate deterministic risk score
    5. Ask Groq to explain each finding (best-effort, non-fatal)
    6. Persist report + findings + scan metadata to PostgreSQL
"""

import logging
import time
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from backend.database import models
from backend.services import (
    scanner,
    secret_scanner,
    dependency_scanner,
    risk_engine,
    groq_service,
)
from backend.services.finding_types import RawFinding
from backend.utils import file_safety
from backend.utils.framework_detector import detect_frameworks

logger = logging.getLogger("vibeguard.orchestrator")

MAX_GROQ_FINDINGS = 25  # cap explained findings to keep demo scans fast/affordable


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


def _read_snippet(finding: RawFinding) -> Optional[str]:
    if finding.code_snippet:
        return finding.code_snippet
    try:
        path = Path(finding.file_path)
        if finding.line_number and path.is_file():
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            idx = finding.line_number - 1
            if 0 <= idx < len(lines):
                return lines[idx].strip()
    except OSError:
        pass
    return None


def run_full_scan(
    db: Session,
    project_name: str,
    workspace_dir: str,
    use_groq: bool = True,
) -> models.Report:
    start_time = time.time()

    files = file_safety.list_source_files(workspace_dir)
    python_files = [f for f in files if f.endswith(".py")]
    js_files = [f for f in files if f.endswith((".js", ".jsx", ".ts", ".tsx"))]
    config_files = [
        f for f in files
        if Path(f).name in {
            "package.json", "requirements.txt", "pyproject.toml",
            "Dockerfile", "docker-compose.yml", ".env", ".env.example",
        } or Path(f).suffix in {".yml", ".yaml"}
    ]
    frameworks = detect_frameworks(workspace_dir)

    # --- deterministic scanners -------------------------------------------------
    sast_findings = scanner.run_static_analysis(workspace_dir, files)
    secret_findings = secret_scanner.run_secret_scan(workspace_dir, files)
    dependency_findings = dependency_scanner.run_dependency_scan(workspace_dir)

    all_findings: List[RawFinding] = sast_findings + secret_findings + dependency_findings
    all_findings.sort(key=lambda f: _severity_rank(f.severity))

    # --- deterministic risk score ------------------------------------------------
    breakdown = risk_engine.calculate_score(all_findings)

    # --- persist report shell first ----------------------------------------------
    report = models.Report(
        project_name=project_name,
        overall_score=breakdown.overall_score,
        security_posture=breakdown.posture,
        total_findings=breakdown.total_findings,
        critical_count=breakdown.critical_count,
        high_count=breakdown.high_count,
        medium_count=breakdown.medium_count,
        low_count=breakdown.low_count,
        groq_available="unknown",
    )
    db.add(report)
    db.flush()  # obtain report.id

    # --- Groq explanations (best-effort, non-fatal) -------------------------
    groq_used = False
    groq_attempted = False
    if use_groq and groq_service.is_configured():
        groq_attempted = True
        for finding in all_findings[:MAX_GROQ_FINDINGS]:
            explanation = groq_service.explain_finding(
                finding, code_context=_read_snippet(finding)
            )
            if explanation.available:
                groq_used = True
                finding.description = finding.description or explanation.explanation
                finding.impact = explanation.impact or finding.impact
                finding.recommendation = explanation.recommendation or finding.recommendation
                finding.example_fix = explanation.example_fix or finding.example_fix
                finding.attack_path = explanation.attack_path or finding.attack_path
                ai_explanation = explanation.explanation
                ai_summary = explanation.reasoning_summary
                ai_confidence = explanation.confidence
            else:
                ai_explanation = None
                ai_summary = None
                ai_confidence = None

            db.add(
                models.Finding(
                    report_id=report.id,
                    title=finding.title,
                    category=finding.category,
                    severity=models.Severity(finding.severity),
                    confidence=finding.confidence,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    description=finding.description,
                    impact=finding.impact,
                    recommendation=finding.recommendation,
                    example_fix=finding.example_fix,
                    attack_path=finding.attack_path,
                    ai_explanation=ai_explanation,
                    ai_reasoning_summary=ai_summary,
                    ai_confidence=ai_confidence,
                    source_tool=finding.source_tool,
                    code_snippet=finding.code_snippet,
                )
            )

        # Any remaining findings beyond the Groq cap are still stored, just
        # without AI explanation.
        for finding in all_findings[MAX_GROQ_FINDINGS:]:
            db.add(
                models.Finding(
                    report_id=report.id,
                    title=finding.title,
                    category=finding.category,
                    severity=models.Severity(finding.severity),
                    confidence=finding.confidence,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    description=finding.description,
                    impact=finding.impact,
                    recommendation=finding.recommendation,
                    example_fix=finding.example_fix,
                    attack_path=finding.attack_path,
                    source_tool=finding.source_tool,
                    code_snippet=finding.code_snippet,
                )
            )
    else:
        for finding in all_findings:
            db.add(
                models.Finding(
                    report_id=report.id,
                    title=finding.title,
                    category=finding.category,
                    severity=models.Severity(finding.severity),
                    confidence=finding.confidence,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    description=finding.description,
                    impact=finding.impact,
                    recommendation=finding.recommendation,
                    example_fix=finding.example_fix,
                    attack_path=finding.attack_path,
                    source_tool=finding.source_tool,
                    code_snippet=finding.code_snippet,
                )
            )

    report.groq_available = (
        "unavailable" if not groq_attempted else ("available" if groq_used else "unavailable")
    )

    duration = time.time() - start_time
    db.add(
        models.ScanMetadata(
            report_id=report.id,
            total_files=len(files),
            python_files=len(python_files),
            javascript_files=len(js_files),
            config_files=len(config_files),
            detected_frameworks=frameworks,
            scan_duration=round(duration, 2),
        )
    )

    db.flush()
    db.refresh(report)
    return report
