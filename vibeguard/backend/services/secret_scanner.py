"""
Secret detection service.

Uses `gitleaks` if available on PATH, and always additionally runs a set of
built-in regex patterns for common credential formats. Detected secret
values are ALWAYS masked before being stored or returned — the full value
is never persisted or sent to the frontend or to Groq.
"""

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import List

from backend.services.finding_types import RawFinding

logger = logging.getLogger("vibeguard.secret_scanner")

# (name, regex, severity)
_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "CRITICAL"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "CRITICAL"),
    ("Generic Private Key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "HIGH"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "CRITICAL"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "HIGH"),
    ("Generic API Key Assignment", re.compile(
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "HIGH"),
    ("Hardcoded Password", re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\n]{6,}['\"]"), "CRITICAL"),
    ("Database Connection String with Credentials", re.compile(
        r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s]+:[^@\s]+@"), "CRITICAL"),
    ("Generic Secret Assignment", re.compile(
        r"(?i)(secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"), "HIGH"),
]

_SKIP_FILENAMES = {".env.example", "example.env"}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def mask_secret(value: str) -> str:
    value = value.strip("'\" ")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * max(4, len(value) - 8)}{value[-4:]}"


def run_gitleaks(workspace_dir: str, timeout: int = 60) -> List[RawFinding]:
    if not _tool_available("gitleaks"):
        logger.info("gitleaks not found on PATH, skipping.")
        return []

    try:
        proc = subprocess.run(
            [
                "gitleaks", "detect", "--source", workspace_dir, "--no-git",
                "-f", "json", "-r", "/dev/stdout",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        results = json.loads(proc.stdout or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        logger.warning("gitleaks run failed: %s", type(exc).__name__)
        return []

    findings = []
    for r in results:
        secret = r.get("Secret", "")
        findings.append(
            RawFinding(
                title=f"Detected secret: {r.get('RuleID', 'unknown')}",
                category="hardcoded-secrets",
                severity="CRITICAL",
                confidence=90,
                file_path=r.get("File", "unknown"),
                line_number=r.get("StartLine"),
                description=f"gitleaks detected a potential secret matching rule '{r.get('RuleID')}'.",
                impact="Exposed credentials could allow an attacker to access connected services or data.",
                recommendation="Revoke and rotate this credential immediately, then move it to an environment variable.",
                source_tool="gitleaks",
                code_snippet=f"Value: {mask_secret(secret)}" if secret else None,
            )
        )
    return findings


def run_pattern_secret_scan(files: List[str]) -> List[RawFinding]:
    findings = []
    for path in files:
        if Path(path).name in _SKIP_FILENAMES:
            continue
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        for name, pattern, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                masked = mask_secret(match.group(0))
                findings.append(
                    RawFinding(
                        title=f"Detected secret: {name}",
                        category="hardcoded-secrets",
                        severity=severity,
                        confidence=75,
                        file_path=path,
                        line_number=line_no,
                        description=f"A value matching the pattern for '{name}' was found in source code.",
                        impact="Exposed credentials could allow an attacker to access connected services, "
                               "cloud resources, or data.",
                        recommendation="Revoke and rotate this credential immediately. Store secrets in "
                                       "environment variables (.env, git-ignored) rather than in source code.",
                        source_tool="vibeguard-secret-pattern",
                        code_snippet=f"Value: {masked}",
                    )
                )
    return findings


def _dedupe(findings: List[RawFinding]) -> List[RawFinding]:
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file_path, f.line_number)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def run_secret_scan(workspace_dir: str, files: List[str]) -> List[RawFinding]:
    findings: List[RawFinding] = []
    try:
        findings.extend(run_gitleaks(workspace_dir))
    except Exception:
        logger.exception("gitleaks integration failed unexpectedly, continuing without it.")

    try:
        findings.extend(run_pattern_secret_scan(files))
    except Exception:
        logger.exception("pattern-based secret scan failed unexpectedly.")

    return _dedupe(findings)
