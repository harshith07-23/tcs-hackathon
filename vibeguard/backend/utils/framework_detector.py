"""
Lightweight framework detection based on dependency manifests and file markers.
"""

import json
from pathlib import Path
from typing import List, Set

_PY_MARKERS = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "sqlalchemy": "SQLAlchemy",
    "pydantic": "Pydantic",
}

_JS_MARKERS = {
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "svelte": "Svelte",
}


def detect_frameworks(workspace_dir: str) -> List[str]:
    found: Set[str] = set()
    workspace = Path(workspace_dir)

    for req_file in workspace.rglob("requirements.txt"):
        try:
            content = req_file.read_text(encoding="utf-8", errors="ignore").lower()
            for key, label in _PY_MARKERS.items():
                if key in content:
                    found.add(label)
        except OSError:
            continue

    for pyproject in workspace.rglob("pyproject.toml"):
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
            for key, label in _PY_MARKERS.items():
                if key in content:
                    found.add(label)
        except OSError:
            continue

    for pkg_file in workspace.rglob("package.json"):
        if "node_modules" in pkg_file.parts:
            continue
        try:
            data = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for key, label in _JS_MARKERS.items():
            if key in deps:
                found.add(label)

    return sorted(found)
