import logging
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from backend.database import models
from backend.database.connection import get_db, DatabaseConnectionError
from backend.schemas.findings import FindingOut, FindingStatusUpdate
from backend.schemas.reports import ReportDetailOut, ReportSummaryOut

logger = logging.getLogger("vibeguard.api.reports")

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports", response_model=List[ReportSummaryOut])
def list_reports(db: Session = Depends(get_db)):
    try:
        reports = db.query(models.Report).order_by(models.Report.scan_date.desc()).all()
        return reports
    except DatabaseConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/reports/{report_id}", response_model=ReportDetailOut)
def get_report(report_id: uuid.UUID, db: Session = Depends(get_db)):
    report = (
        db.query(models.Report)
        .options(joinedload(models.Report.findings), joinedload(models.Report.scan_metadata))
        .filter(models.Report.id == report_id)
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/reports/{report_id}/findings", response_model=List[FindingOut])
def get_report_findings(report_id: uuid.UUID, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    findings = (
        db.query(models.Finding)
        .filter(models.Finding.report_id == report_id)
        .order_by(models.Finding.severity)
        .all()
    )
    return findings


@router.patch("/findings/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: uuid.UUID, payload: FindingStatusUpdate, db: Session = Depends(get_db)
):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    # Status changes are persisted; findings themselves are never deleted,
    # preserving historical scan information.
    finding.status = models.FindingStatus(payload.status.value)
    db.commit()
    db.refresh(finding)
    return finding
