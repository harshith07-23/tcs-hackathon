from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel

from backend.schemas.findings import FindingOut


class ScanMetadataOut(BaseModel):
    total_files: int
    python_files: int
    javascript_files: int
    config_files: int
    detected_frameworks: List[str]
    scan_duration: float

    class Config:
        from_attributes = True


class ReportSummaryOut(BaseModel):
    id: UUID
    project_name: str
    scan_date: datetime
    overall_score: int
    security_posture: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    groq_available: str

    class Config:
        from_attributes = True


class ReportDetailOut(ReportSummaryOut):
    findings: List[FindingOut] = []
    scan_metadata: Optional[ScanMetadataOut] = None
