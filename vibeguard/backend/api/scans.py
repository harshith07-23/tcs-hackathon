import logging
import os

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Form
from sqlalchemy.orm import Session

from backend.database.connection import get_db, DatabaseConnectionError
from backend.schemas.reports import ReportDetailOut
from backend.services.scan_orchestrator import run_full_scan
from backend.utils import file_safety

logger = logging.getLogger("vibeguard.api.scans")

router = APIRouter(prefix="/api", tags=["scans"])


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

        try:
            report = run_full_scan(
                db=db,
                project_name=project_name.strip(),
                workspace_dir=extraction_dir,
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
