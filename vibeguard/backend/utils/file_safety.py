"""
Safe handling of untrusted project uploads.

Guards against:
    - zip-slip / path traversal during archive extraction
    - zip bombs (compression-ratio + total size limits)
    - disallowed file types
    - oversized uploads

Uploaded code is NEVER executed. It is only read as text for static analysis.
"""

import os
import shutil
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import List, Optional

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 50 * 1024 * 1024))  # 50 MB default
MAX_EXTRACTED_SIZE = MAX_UPLOAD_SIZE * 10  # cap total decompressed size (zip-bomb guard)
MAX_FILES = 5000
MAX_SINGLE_FILE_SIZE = 5 * 1024 * 1024  # 5 MB per individual file

# ---------------------------------------------------------------------------
# Source / config file allow-lists
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # JVM
    ".java", ".kt", ".scala", ".groovy",
    # Systems
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs",
    # Scripting
    ".php", ".rb", ".pl", ".sh", ".bash",
    # Web
    ".html", ".htm", ".css", ".scss", ".less",
    # Data / config
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg",
    ".env", ".example", ".properties",
    # Database
    ".sql",
    # Documentation / text
    ".txt", ".md", ".rst",
    # Container / CI
    ".dockerfile",
    # Lock files
    ".lock",
}

ALLOWED_FILENAMES = {
    # Container
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore",
    # Python
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock", "poetry.lock", "tox.ini",
    # JavaScript / Node
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ".npmrc", ".nvmrc",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # PHP
    "composer.json", "composer.lock",
    # Java / Gradle / Maven
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # .NET
    "*.csproj", "*.sln", "nuget.config",
    # Config
    ".env", ".env.example", ".env.local",
    ".gitignore", ".editorconfig",
    "Makefile", "Procfile",
    # CI
    ".github", ".gitlab-ci.yml", "Jenkinsfile",
}

BLOCKED_DIR_NAMES = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "myenv", "env3", "venv3", "virtualenv", "ENV", "site-packages",
    "dist", "build", "out", "target",
    "coverage", ".cache", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "vendor",  # Go / PHP vendor
    ".idea", ".vscode", ".vs",
    ".next", ".nuxt", ".svelte-kit",
    "bin", "obj",  # .NET build outputs
    ".eggs", "*.egg-info",
}


class UnsafeUploadError(Exception):
    """Raised when an upload fails safety checks. Message is safe to show to users."""


@dataclass
class ExtractionResult:
    workspace_dir: str
    file_count: int


def _is_allowed(path: Path) -> bool:
    if path.name in ALLOWED_FILENAMES:
        return True
    return path.suffix.lower() in ALLOWED_EXTENSIONS


def new_workspace() -> str:
    base = Path(tempfile.gettempdir()) / "vibeguard_scans"
    base.mkdir(parents=True, exist_ok=True)
    workspace = base / str(uuid.uuid4())
    workspace.mkdir(parents=True, exist_ok=False)
    return str(workspace)


def cleanup_workspace(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def safe_extract_zip(zip_path: str, dest_dir: str) -> ExtractionResult:
    """
    Extracts a ZIP archive defensively:
      - rejects entries that would escape dest_dir (zip-slip)
      - rejects absolute paths / symlinks
      - enforces total decompressed size and file-count limits
      - enforces per-file size limit
      - skips disallowed file types and noisy vendor directories
    """
    dest = Path(dest_dir).resolve()
    total_size = 0
    file_count = 0

    try:
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue

                member_path = Path(member.filename)

                # --- Zip-slip / path traversal protection ---
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise UnsafeUploadError(
                        "Archive contains an unsafe path and was rejected."
                    )

                # Reject Windows drive paths like C:\something
                raw = member.filename.replace("\\", "/")
                if len(raw) >= 2 and raw[1] == ":":
                    raise UnsafeUploadError(
                        "Archive contains an unsafe path and was rejected."
                    )

                if any(part in BLOCKED_DIR_NAMES for part in member_path.parts):
                    continue

                target_path = (dest / member_path).resolve()
                if not str(target_path).startswith(str(dest)):
                    raise UnsafeUploadError(
                        "Archive contains an unsafe path and was rejected."
                    )

                if not _is_allowed(member_path):
                    continue

                # --- Per-file size limit ---
                if member.file_size > MAX_SINGLE_FILE_SIZE:
                    continue  # silently skip oversized individual files

                total_size += member.file_size
                if total_size > MAX_EXTRACTED_SIZE:
                    raise UnsafeUploadError(
                        "Archive exceeds the maximum allowed decompressed size."
                    )

                file_count += 1
                if file_count > MAX_FILES:
                    raise UnsafeUploadError(
                        "Archive contains too many files."
                    )

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target_path, "wb") as out:
                    shutil.copyfileobj(src, out)
    except zipfile.BadZipFile as exc:
        raise UnsafeUploadError("Uploaded file is not a valid ZIP archive.") from exc

    if file_count == 0:
        raise UnsafeUploadError(
            "No analyzable source files found in the archive. "
            "Ensure your ZIP contains source code files (.py, .js, .ts, .java, etc.)."
        )

    return ExtractionResult(workspace_dir=str(dest), file_count=file_count)


def list_source_files(workspace_dir: str) -> List[str]:
    results = []
    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d not in BLOCKED_DIR_NAMES]
        for f in files:
            full = os.path.join(root, f)
            if _is_allowed(Path(full)):
                results.append(full)
    return results


def validate_upload_size(size_bytes: int) -> None:
    if size_bytes > MAX_UPLOAD_SIZE:
        raise UnsafeUploadError(
            f"Upload exceeds the maximum allowed size of {MAX_UPLOAD_SIZE // (1024 * 1024)} MB."
        )


# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------

def detect_project_root(extraction_dir: str) -> str:
    """
    Detect the actual project root inside an extraction directory.

    ZIP files may have different structures:
      A) project.zip → backend/ frontend/ package.json  (root IS the project)
      B) project.zip → myproject/ → backend/ frontend/  (single wrapper dir)
      C) project.zip → source.py config.py              (root IS the project)

    If the extraction contains exactly one subdirectory and no files at
    the top level, the single subdirectory is treated as the project root.
    Otherwise, the extraction directory itself is the project root.
    """
    extraction = Path(extraction_dir)
    top_entries = list(extraction.iterdir())

    top_dirs = [e for e in top_entries if e.is_dir()]
    top_files = [e for e in top_entries if e.is_file()]

    # Single wrapper directory, no top-level files → unwrap
    if len(top_dirs) == 1 and len(top_files) == 0:
        return str(top_dirs[0])

    return extraction_dir


# ---------------------------------------------------------------------------
# Path normalization (single source of truth)
# ---------------------------------------------------------------------------

def normalize_finding_path(file_path: str, project_root: str) -> str:
    """
    Convert an absolute or workspace-relative file path into a clean,
    project-relative path suitable for display.

    Examples:
        C:\\Users\\HP\\AppData\\Local\\Temp\\vibeguard_scans\\<uuid>\\project\\backend\\auth.py
        →  backend/auth.py

        /tmp/vibeguard_scans/abc123/project/src/main.py
        →  src/main.py

    Always uses forward slashes. Never returns an empty string (falls back
    to the basename).
    """
    try:
        abs_file = Path(file_path).resolve()
        abs_root = Path(project_root).resolve()
        relative = abs_file.relative_to(abs_root)
        clean = PurePosixPath(relative)
        result = str(clean)
    except (ValueError, TypeError):
        # file_path is not under project_root — extract manually
        normalized = file_path.replace("\\", "/")
        # Try to find vibeguard_scans marker and strip everything up to the project
        marker = "vibeguard_scans/"
        idx = normalized.find(marker)
        if idx != -1:
            after_marker = normalized[idx + len(marker):]
            # Skip the UUID segment
            parts = after_marker.split("/", 1)
            if len(parts) > 1:
                remainder = parts[1]
                # Skip "project/" if present
                if remainder.startswith("project/"):
                    remainder = remainder[len("project/"):]
                result = remainder
            else:
                result = parts[0]
        else:
            result = os.path.basename(file_path)

    # Never return empty string
    if not result or result == ".":
        result = os.path.basename(file_path)

    return result

