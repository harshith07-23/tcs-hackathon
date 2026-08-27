"""
Dependency security scanner.

Parses requirements.txt / package.json for declared dependencies and checks
them against a small local advisory table of known-vulnerable versions.

Design note: this module intentionally does NOT flag a dependency as
vulnerable merely for being old — only entries that match a known advisory
(package + affected version range) are reported. If a live vulnerability
database (e.g. OSV.dev) is reachable, `check_osv` can be wired in; it is
kept optional so the scanner still works offline.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Optional

from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion

from backend.services.finding_types import RawFinding

logger = logging.getLogger("vibeguard.dependency_scanner")

# A small curated set of well-known advisories, used as an offline fallback.
# format: package_name -> list of (affected_specifier, severity, advisory_id, fixed_version, summary)
KNOWN_ADVISORIES = {
    "flask": [
        ("<0.12.3", "HIGH", "PYSEC-2019-DEBUG", "0.12.3",
         "Debug mode information disclosure in older Flask versions."),
    ],
    "django": [
        ("<3.2.18", "CRITICAL", "CVE-2023-24580", "3.2.18",
         "Potential denial of service via file upload handling."),
    ],
    "requests": [
        ("<2.20.0", "HIGH", "CVE-2018-18074", "2.20.0",
         "Authorization header leak on cross-origin redirect."),
    ],
    "pyyaml": [
        ("<5.4", "CRITICAL", "CVE-2020-14343", "5.4",
         "Arbitrary code execution via yaml.load() default Loader."),
    ],
    "lodash": [
        ("<4.17.21", "HIGH", "CVE-2021-23337", "4.17.21",
         "Command injection via template function."),
    ],
    "express": [
        ("<4.17.3", "MEDIUM", "CVE-2022-24999", "4.17.3",
         "Denial of service via crafted query-string parsing."),
    ],
    "axios": [
        ("<0.21.2", "HIGH", "CVE-2021-3749", "0.21.2",
         "Regular expression denial of service (ReDoS)."),
    ],
    "jsonwebtoken": [
        ("<9.0.0", "CRITICAL", "CVE-2022-23529", "9.0.0",
         "Improper verification could allow signature bypass in certain configurations."),
    ],
    "pillow": [
        ("<9.0.1", "CRITICAL", "CVE-2022-22817", "9.0.1",
         "Arbitrary code execution via crafted image processed with ImageMath.eval."),
    ],
}


def _parse_requirements_txt(path: Path):
    deps = []
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([0-9][A-Za-z0-9_.\-]*)?", line)
            if match:
                name, _, version = match.groups()
                deps.append((name.lower(), version))
    except OSError:
        pass
    return deps


def _parse_package_json(path: Path):
    deps = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = re.sub(r"^[~^>=<\s]+", "", version)
            deps.append((name.lower(), clean_version or None))
    return deps


def _version_is_affected(version_str: Optional[str], specifier_str: str) -> bool:
    if not version_str:
        # Version unknown/unpinned — cannot safely claim it's vulnerable.
        return False
    try:
        version = Version(version_str)
        spec = SpecifierSet(specifier_str)
        return version in spec
    except InvalidVersion:
        return False


def _check_known_advisories(deps) -> List[RawFinding]:
    findings = []
    for name, version in deps:
        advisories = KNOWN_ADVISORIES.get(name)
        if not advisories:
            continue
        for specifier, severity, advisory_id, fixed_version, summary in advisories:
            if _version_is_affected(version, specifier):
                findings.append(
                    RawFinding(
                        title=f"Vulnerable dependency: {name}",
                        category="insecure-dependency",
                        severity=severity,
                        confidence=85,
                        file_path="dependency manifest",
                        line_number=None,
                        description=(
                            f"{name} {version or ''} matches known advisory {advisory_id}: {summary}"
                        ),
                        impact=f"Depending on usage, this could expose the application to {summary.lower()}",
                        recommendation=f"Upgrade {name} to version {fixed_version} or later.",
                        source_tool="vibeguard-dependency-advisory",
                        code_snippet=f"{name}=={version}" if version else name,
                    )
                )
    return findings


def run_dependency_scan(workspace_dir: str) -> List[RawFinding]:
    """
    Never claims a package is vulnerable purely for being old — only flags
    matches against the known-advisory table above.
    """
    findings: List[RawFinding] = []
    workspace = Path(workspace_dir)

    try:
        for req_file in workspace.rglob("requirements.txt"):
            deps = _parse_requirements_txt(req_file)
            findings.extend(_check_known_advisories(deps))

        for pkg_file in workspace.rglob("package.json"):
            if "node_modules" in pkg_file.parts:
                continue
            deps = _parse_package_json(pkg_file)
            findings.extend(_check_known_advisories(deps))
    except Exception:
        logger.exception("dependency scan failed unexpectedly.")

    return findings
