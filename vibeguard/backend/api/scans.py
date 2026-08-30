import logging
import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import get_db, DatabaseConnectionError
from backend.schemas.reports import ReportDetailOut
from backend.services.scan_orchestrator import run_full_scan
from backend.utils import file_safety

logger = logging.getLogger("vibeguard.api.scans")

router = APIRouter(prefix="/api", tags=["scans"])


class SourceAnalysisRequest(BaseModel):
    project_name: str
    files: list[dict[str, str]]


@router.post("/analyze", response_model=ReportDetailOut)
def analyze_source(payload: SourceAnalysisRequest, db: Session = Depends(get_db)):
    """Analyze source submitted directly by a user without executing it."""
    project_name = payload.project_name.strip()

    if not project_name:
        raise HTTPException(status_code=400, detail="project_name is required.")
    if not payload.files:
        raise HTTPException(status_code=400, detail="At least one source file is required.")

    workspace_dir = file_safety.new_workspace()
    try:
        total_size = 0
        for source in payload.files:
            filename = source.get("filename", "").replace("\\", "/").lstrip("/")
            source_code = source.get("source_code", "")
            
            if not filename or any(part in {"", ".", ".."} for part in filename.split("/")):
                raise HTTPException(status_code=400, detail="Source filename contains an unsafe path.")
                
            path_obj = Path(filename)
            if any(part in file_safety.BLOCKED_DIR_NAMES for part in path_obj.parts):
                continue

            if not file_safety._is_allowed(path_obj):
                # Skip unallowed files instead of failing the whole request
                continue
                
            if not source_code.strip():
                # Skip empty files
                continue
                
            total_size += len(source_code.encode("utf-8"))
            source_path = os.path.join(workspace_dir, filename)
            os.makedirs(os.path.dirname(source_path), exist_ok=True)
            with open(source_path, "w", encoding="utf-8") as source_file:
                source_file.write(source_code)
        file_safety.validate_upload_size(total_size)

        project_root = file_safety.detect_project_root(workspace_dir)

        try:
            report = run_full_scan(
                db=db,
                project_name=project_name,
                workspace_dir=workspace_dir,
                project_root=project_root,
            )
        except DatabaseConnectionError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

        db.commit()
        db.refresh(report)
        return report
    except file_safety.UnsafeUploadError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Source analysis failed unexpectedly.")
        raise HTTPException(status_code=500, detail=f"The source could not be analyzed. Error: {str(exc)}")
    finally:
        file_safety.cleanup_workspace(workspace_dir)


@router.post("/scan", response_model=ReportDetailOut)
async def create_scan(
    project_name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not project_name.strip():
        raise HTTPException(status_code=400, detail="project_name is required.")

    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only ZIP archives are currently accepted. Please upload a .zip of your project.",
        )

    workspace_dir = file_safety.new_workspace()
    zip_path = os.path.join(workspace_dir, "_upload.zip")

    try:
        contents = await file.read()
        file_safety.validate_upload_size(len(contents))

        with open(zip_path, "wb") as f:
            f.write(contents)

        extraction_dir = os.path.join(workspace_dir, "project")
        os.makedirs(extraction_dir, exist_ok=True)
        file_safety.safe_extract_zip(zip_path, extraction_dir)

        # Detect the actual project root (handles wrapper directories)
        project_root = file_safety.detect_project_root(extraction_dir)

        try:
            report = run_full_scan(
                db=db,
                project_name=project_name.strip(),
                workspace_dir=extraction_dir,
                project_root=project_root,
            )
        except DatabaseConnectionError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

        db.commit()
        db.refresh(report)
        return report

    except file_safety.UnsafeUploadError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Scan failed unexpectedly.")
        raise HTTPException(
            status_code=500,
            detail="The scan could not be completed due to an internal error. "
                   "Please try again; if the problem persists, verify the project archive is valid.",
        )
    finally:
        file_safety.cleanup_workspace(workspace_dir)

