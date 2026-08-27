"""
Static Application Security Testing (SAST) service.

Strategy:
    1. If `semgrep` is available on PATH, run it with a security-focused
       ruleset and normalize its JSON output.
    2. If `bandit` is available, run it against Python files and normalize
       its JSON output.
    3. Always additionally run VibeGuard's own lightweight pattern-based
       rules, which cover the OWASP-style categories in the spec and act as
       a dependable fallback when the external tools are not installed
       (e.g. no network access in the deployment environment).

Findings from all sources are merged and de-duplicated (same file + line +
category is kept once, preferring the more specific external-tool finding).

This module never executes the scanned code — only static text/AST
inspection is performed.
"""

import ast
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import List

from backend.services.finding_types import RawFinding

logger = logging.getLogger("vibeguard.scanner")

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx"}


# ---------------------------------------------------------------------------
# External tool wrappers
# ---------------------------------------------------------------------------

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_semgrep(workspace_dir: str, timeout: int = 90) -> List[RawFinding]:
    if not _tool_available("semgrep"):
        logger.info("semgrep not found on PATH, skipping.")
        return []

    try:
        proc = subprocess.run(
            [
                "semgrep", "--config", "auto", "--json", "--quiet",
                "--timeout", str(timeout), workspace_dir,
            ],
            capture_output=True, text=True, timeout=timeout + 15,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        logger.warning("semgrep run failed: %s", type(exc).__name__)
        return []

    findings = []
    for r in data.get("results", []):
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        severity = sev_map.get(r.get("extra", {}).get("severity", "WARNING"), "MEDIUM")
        findings.append(
            RawFinding(
                title=r.get("check_id", "Semgrep finding").split(".")[-1].replace("-", " ").title(),
                category=r.get("extra", {}).get("metadata", {}).get("category", "security-misconfiguration"),
                severity=severity,
                confidence=80,
                file_path=r.get("path", "unknown"),
                line_number=r.get("start", {}).get("line"),
                description=r.get("extra", {}).get("message", "Semgrep flagged this pattern as risky."),
                impact="See recommendation for details on why this pattern is potentially exploitable.",
                recommendation=r.get("extra", {}).get("message", "Review and remediate per Semgrep guidance."),
                source_tool="semgrep",
                code_snippet=r.get("extra", {}).get("lines"),
            )
        )
    return findings


def run_bandit(workspace_dir: str, timeout: int = 60) -> List[RawFinding]:
    if not _tool_available("bandit"):
        logger.info("bandit not found on PATH, skipping.")
        return []

    try:
        proc = subprocess.run(
            ["bandit", "-r", workspace_dir, "-f", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        logger.warning("bandit run failed: %s", type(exc).__name__)
        return []

    findings = []
    for r in data.get("results", []):
        findings.append(
            RawFinding(
                title=r.get("test_name", "Bandit finding"),
                category=r.get("test_id", "security-misconfiguration"),
                severity=r.get("issue_severity", "MEDIUM").upper(),
                confidence={"HIGH": 85, "MEDIUM": 65, "LOW": 40}.get(
                    r.get("issue_confidence", "MEDIUM").upper(), 50
                ),
                file_path=r.get("filename", "unknown"),
                line_number=r.get("line_number"),
                description=r.get("issue_text", ""),
                impact="Bandit identified a pattern commonly associated with security weaknesses in Python code.",
                recommendation=r.get("issue_text", "Review Bandit documentation for this check."),
                source_tool="bandit",
                code_snippet=r.get("code"),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# VibeGuard built-in pattern rules (dependable fallback, no external deps)
# ---------------------------------------------------------------------------

# Each rule: (compiled regex, title, category, severity, confidence, description, impact, recommendation, example_fix)
_PY_RULES = [
    (
        re.compile(r"\beval\s*\("),
        "Use of eval()", "unsafe-code-execution", "CRITICAL", 90,
        "The code calls eval() on data that may include untrusted input.",
        "An attacker able to influence the evaluated string could execute arbitrary Python code.",
        "Avoid eval(). Use ast.literal_eval() for data parsing, or a proper parser/dispatcher for logic.",
        "- eval(user_input)\n+ ast.literal_eval(user_input)  # only for literals",
    ),
    (
        re.compile(r"\bexec\s*\("),
        "Use of exec()", "unsafe-code-execution", "CRITICAL", 88,
        "The code calls exec() which runs arbitrary Python source.",
        "If any part of the executed string is influenced by user input, this allows arbitrary code execution.",
        "Remove exec() from the code path or strictly whitelist what can be executed.",
        None,
    ),
    (
        re.compile(r"subprocess\.(Popen|call|run|check_output)\([^)]*shell\s*=\s*True"),
        "Unsafe subprocess execution (shell=True)", "command-injection", "HIGH", 85,
        "subprocess is invoked with shell=True, which passes the command through a shell.",
        "If any part of the command is built from user input, an attacker could inject additional shell commands.",
        "Avoid shell=True. Pass the command as a list of arguments and avoid shell interpolation.",
        "- subprocess.run(cmd, shell=True)\n+ subprocess.run(cmd_list, shell=False)",
    ),
    (
        re.compile(r"os\.system\s*\("),
        "Use of os.system()", "command-injection", "HIGH", 80,
        "os.system() executes a command through the shell.",
        "If the command string includes untrusted input, an attacker may be able to inject arbitrary shell commands.",
        "Use subprocess.run() with a list of arguments and shell=False instead of os.system().",
        None,
    ),
    (
        re.compile(r'["\']SELECT .*["\']\s*(\+|%|\.format\()'),
        "Potential SQL Injection via string concatenation", "sql-injection", "CRITICAL", 75,
        "A SQL query string appears to be built via concatenation or formatting rather than parameter binding.",
        "An attacker may be able to manipulate the query and access or modify unauthorized data.",
        "Use parameterized queries (e.g. cursor.execute(query, params)) or an ORM instead of string concatenation.",
        '- query = "SELECT * FROM users WHERE username=\'" + username + "\'"\n+ cursor.execute("SELECT * FROM users WHERE username = %s", (username,))',
    ),
    (
        re.compile(r"pickle\.loads?\s*\("),
        "Insecure deserialization (pickle)", "insecure-deserialization", "HIGH", 80,
        "pickle.load/loads is used to deserialize data.",
        "Deserializing untrusted data with pickle can lead to arbitrary code execution.",
        "Avoid unpickling untrusted data. Use a safe format like JSON, or sign/verify the payload first.",
        None,
    ),
    (
        re.compile(r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
        "Unsafe YAML load", "insecure-deserialization", "HIGH", 70,
        "yaml.load() is called without a safe Loader.",
        "Untrusted YAML content can be crafted to execute arbitrary code during deserialization.",
        "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
        "- yaml.load(data)\n+ yaml.safe_load(data)",
    ),
    (
        re.compile(r"(md5|sha1)\s*\("),
        "Weak cryptographic hash", "weak-cryptography", "MEDIUM", 65,
        "A weak hash algorithm (MD5/SHA1) is used.",
        "MD5 and SHA1 are cryptographically broken and unsuitable for security-sensitive hashing, especially passwords.",
        "Use bcrypt, scrypt, or Argon2 for password hashing; use SHA-256 or better for general integrity hashing.",
        None,
    ),
    (
        re.compile(r"DEBUG\s*=\s*True"),
        "Debug mode enabled", "security-misconfiguration", "MEDIUM", 70,
        "Debug mode appears to be enabled.",
        "Debug mode can expose stack traces, source code, and internal configuration to attackers.",
        "Disable debug mode in production and drive it from an environment variable, defaulting to False.",
        None,
    ),
    (
        re.compile(r"verify\s*=\s*False"),
        "TLS certificate verification disabled", "sensitive-data-exposure", "HIGH", 78,
        "An HTTP client call disables TLS certificate verification.",
        "This allows man-in-the-middle attacks against the connection, exposing any transmitted data.",
        "Remove verify=False and ensure certificates are validated. Use a custom CA bundle if needed instead of disabling verification.",
        None,
    ),
    (
        re.compile(r"(password|passwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"\n]{4,}['\"]", re.IGNORECASE),
        "Hardcoded credential", "hardcoded-secrets", "CRITICAL", 70,
        "A credential-like value appears to be hardcoded directly in source code.",
        "Hardcoded secrets can be leaked via version control and are difficult to rotate.",
        "Move the value to an environment variable loaded via os.environ / python-dotenv, and add the file to .gitignore.",
        None,
    ),
    (
        re.compile(r"cursor\.execute\([^,)]*%\s*\("),
        "Potential SQL Injection via % formatting", "sql-injection", "HIGH", 70,
        "A SQL query is built using % string formatting instead of parameter binding.",
        "An attacker able to influence the formatted value could alter the query logic.",
        "Pass parameters as a tuple/list to cursor.execute() instead of formatting them into the query string.",
        None,
    ),
    (
        re.compile(r"open\([^)]*request\.(args|form|values|GET|POST)"),
        "Potential path traversal", "path-traversal", "HIGH", 65,
        "A file is opened using a path derived directly from request input.",
        "An attacker could supply a path like '../../etc/passwd' to read arbitrary files on the server.",
        "Validate and sanitize the filename, resolve it against a fixed base directory, and reject paths that escape it.",
        None,
    ),
]

_JS_RULES = [
    (
        re.compile(r"\beval\s*\("),
        "Use of eval()", "unsafe-code-execution", "CRITICAL", 88,
        "The code calls eval() on a dynamic string.",
        "If the evaluated string includes user-controlled input, an attacker could execute arbitrary JavaScript.",
        "Avoid eval(). Use JSON.parse() for data or refactor the logic to avoid dynamic code execution.",
        None,
    ),
    (
        re.compile(r"new Function\s*\("),
        "Dynamic code execution via Function constructor", "unsafe-code-execution", "HIGH", 75,
        "The Function constructor is used to build code dynamically.",
        "This behaves like eval() and can lead to arbitrary code execution if fed untrusted input.",
        "Avoid constructing functions from strings; use static function definitions instead.",
        None,
    ),
    (
        re.compile(r"child_process\.exec\s*\("),
        "Unsafe command execution", "command-injection", "HIGH", 80,
        "child_process.exec() runs a command through a shell.",
        "If the command string includes user input, an attacker may inject additional shell commands.",
        "Use child_process.execFile() or spawn() with an argument array instead of a shell-interpreted string.",
        None,
    ),
    (
        re.compile(r"dangerouslySetInnerHTML"),
        "Potential Cross-Site Scripting (dangerouslySetInnerHTML)", "xss", "HIGH", 65,
        "dangerouslySetInnerHTML is used to render raw HTML.",
        "If the HTML source includes unsanitized user input, this can lead to stored or reflected XSS.",
        "Sanitize the HTML with a library such as DOMPurify before rendering, or avoid raw HTML injection.",
        None,
    ),
    (
        re.compile(r"\.innerHTML\s*="),
        "Potential DOM-based XSS via innerHTML", "xss", "MEDIUM", 55,
        "innerHTML is assigned directly, which can execute injected markup.",
        "If the assigned value includes untrusted input, this can lead to DOM-based XSS.",
        "Use textContent for plain text, or sanitize HTML input before assignment.",
        None,
    ),
    (
        re.compile(r"cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]"),
        "Insecure CORS configuration (wildcard origin)", "insecure-cors", "MEDIUM", 75,
        "CORS is configured to allow any origin ('*').",
        "This allows any website to make authenticated cross-origin requests, potentially exposing sensitive data.",
        "Restrict the CORS origin to a known allowlist of trusted domains instead of using a wildcard.",
        None,
    ),
    (
        re.compile(r"jwt\.sign\([^)]*algorithm\s*:\s*['\"]none['\"]", re.IGNORECASE),
        "JWT signed with 'none' algorithm", "broken-authentication", "CRITICAL", 85,
        "A JWT is being signed/verified using the 'none' algorithm.",
        "This allows an attacker to forge tokens without knowing any secret key.",
        "Use a strong signing algorithm (e.g. HS256/RS256) and reject tokens with alg=none.",
        None,
    ),
    (
        re.compile(r"(password|passwd|secret|api_key|apikey|token)\s*[:=]\s*['\"][^'\"\n]{4,}['\"]", re.IGNORECASE),
        "Hardcoded credential", "hardcoded-secrets", "CRITICAL", 68,
        "A credential-like value appears to be hardcoded directly in source code.",
        "Hardcoded secrets can be leaked via version control and are difficult to rotate.",
        "Move the value to an environment variable (process.env) and load it via a .env file that is git-ignored.",
        None,
    ),
    (
        re.compile(r"document\.cookie"),
        "Direct cookie manipulation", "sensitive-data-exposure", "LOW", 40,
        "Code directly reads or writes document.cookie.",
        "Cookies handled without HttpOnly/Secure flags may be accessible to malicious scripts (session theft).",
        "Set sensitive cookies server-side with HttpOnly, Secure, and SameSite attributes rather than via client-side JS.",
        None,
    ),
]


def _iter_python_files(files: List[str]):
    return [f for f in files if Path(f).suffix.lower() in PY_EXT]


def _iter_js_files(files: List[str]):
    return [f for f in files if Path(f).suffix.lower() in JS_EXT]


def _apply_rules(files: List[str], rules) -> List[RawFinding]:
    findings = []
    for path in files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for (
            pattern, title, category, severity, confidence,
            description, impact, recommendation, example_fix,
        ) in rules:
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else None
                findings.append(
                    RawFinding(
                        title=title,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        file_path=path,
                        line_number=line_no,
                        description=description,
                        impact=impact,
                        recommendation=recommendation,
                        example_fix=example_fix,
                        source_tool="vibeguard-pattern",
                        code_snippet=snippet,
                    )
                )
    return findings


def _check_python_ast_issues(files: List[str]) -> List[RawFinding]:
    """
    A couple of checks that are meaningfully more reliable via AST than regex:
    bare `except: pass` (error suppression) and assert-based auth checks.
    """
    findings = []
    for path in _iter_python_files(files):
        try:
            source = Path(path).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue

        request_values = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
                continue
            source = value.func.value
            if (
                isinstance(source, ast.Attribute)
                and isinstance(source.value, ast.Name)
                and source.value.id == "request"
                and source.attr in {"args", "form", "values", "json"}
            ):
                request_values.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Return) or not isinstance(node.value, ast.JoinedStr):
                continue
            interpolated_names = {
                formatted.value.id
                for formatted in node.value.values
                if isinstance(formatted, ast.FormattedValue)
                and isinstance(formatted.value, ast.Name)
            }
            if request_values.intersection(interpolated_names):
                findings.append(
                    RawFinding(
                        title="Reflected XSS in HTML response",
                        category="xss",
                        severity="MEDIUM",
                        confidence=85,
                        file_path=path,
                        line_number=node.lineno,
                        description="Request data is interpolated into an HTML response without output encoding.",
                        impact="An attacker can inject JavaScript into the response and execute it in a victim's browser.",
                        recommendation="Render the value through a template engine with autoescaping, or HTML-escape it before returning the response.",
                        source_tool="vibeguard-ast",
                    )
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                body_is_pass_only = all(isinstance(n, ast.Pass) for n in node.body)
                if body_is_pass_only:
                    findings.append(
                        RawFinding(
                            title="Silent exception suppression",
                            category="security-misconfiguration",
                            severity="LOW",
                            confidence=55,
                            file_path=path,
                            line_number=node.lineno,
                            description="A bare 'except: pass' block silently swallows all errors.",
                            impact="Security-relevant failures (e.g. failed auth checks) could be silently ignored.",
                            recommendation="Catch specific exceptions and log or handle them explicitly instead of silently passing.",
                            source_tool="vibeguard-ast",
                        )
                    )
    return findings


def run_pattern_rules(workspace_dir: str, files: List[str]) -> List[RawFinding]:
    py_files = _iter_python_files(files)
    js_files = _iter_js_files(files)

    findings = []
    findings.extend(_apply_rules(py_files, _PY_RULES))
    findings.extend(_apply_rules(js_files, _JS_RULES))
    findings.extend(_check_python_ast_issues(files))
    return findings


def _dedupe(findings: List[RawFinding]) -> List[RawFinding]:
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file_path, f.line_number, f.category)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def run_static_analysis(workspace_dir: str, files: List[str]) -> List[RawFinding]:
    """
    Orchestrates all SAST sources and returns a de-duplicated finding list.
    Never raises: a failing external tool degrades to the pattern-based fallback.
    """
    findings: List[RawFinding] = []

    try:
        findings.extend(run_semgrep(workspace_dir))
    except Exception:
        logger.exception("semgrep integration failed unexpectedly, continuing without it.")

    try:
        findings.extend(run_bandit(workspace_dir))
    except Exception:
        logger.exception("bandit integration failed unexpectedly, continuing without it.")

    try:
        findings.extend(run_pattern_rules(workspace_dir, files))
    except Exception:
        logger.exception("pattern-rule engine failed unexpectedly.")

    return _dedupe(findings)
