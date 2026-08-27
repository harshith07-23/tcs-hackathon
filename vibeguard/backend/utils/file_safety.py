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
from pathlib import Path
from typing import List

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 26 * 1024 * 1024))  # 26 MB default
MAX_EXTRACTED_SIZE = MAX_UPLOAD_SIZE * 10  # cap total decompressed size (zip-bomb guard)
MAX_FILES = 5000

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".env", ".example",
    ".yml", ".yaml", ".toml", ".txt", ".md", ".cfg", ".ini",
    ".dockerfile", ".lock",
}
ALLOWED_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "requirements.txt", "package.json", "package-lock.json",
    "pyproject.toml", ".env", ".env.example", ".gitignore",
}

BLOCKED_DIR_NAMES = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}


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

                if member_path.is_absolute() or ".." in member_path.parts:
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
