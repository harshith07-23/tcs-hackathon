"""
SQLAlchemy ORM models for VibeGuard.

Tables:
    reports        - one row per completed security scan
    findings       - individual vulnerabilities tied to a report
    scan_metadata  - file/framework/timing stats tied to a report
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Text,
    DateTime,
    ForeignKey,
    Enum,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.database.connection import Base


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    IGNORED = "IGNORED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_name = Column(String(255), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)

    overall_score = Column(Integer, nullable=False, default=0)
    security_posture = Column(String(32), nullable=False, default="Unknown")

    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)

    groq_available = Column(String(16), nullable=False, default="unknown")

    findings = relationship(
        "Finding", back_populates="report", cascade="all, delete-orphan"
    )
    scan_metadata = relationship(
        "ScanMetadata",
        back_populates="report",
        uselist=False,
        cascade="all, delete-orphan",
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(
        UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )

    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Integer, nullable=False, default=50)  # 0-100

    file_path = Column(String(1024), nullable=False)
    line_number = Column(Integer, nullable=True)

    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    example_fix = Column(Text, nullable=True)

    attack_path = Column(JSON, nullable=True)  # list[str]
    ai_explanation = Column(Text, nullable=True)
    ai_reasoning_summary = Column(Text, nullable=True)
    ai_confidence = Column(Integer, nullable=True)

    status = Column(Enum(FindingStatus), nullable=False, default=FindingStatus.OPEN)
    source_tool = Column(String(64), nullable=True)  # semgrep / bandit / vibeguard-pattern / secret-scanner
    code_snippet = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    report = relationship("Report", back_populates="findings")


class ScanMetadata(Base):
    __tablename__ = "scan_metadata"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(
        UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )

    total_files = Column(Integer, default=0)
    python_files = Column(Integer, default=0)
    javascript_files = Column(Integer, default=0)
    config_files = Column(Integer, default=0)
    detected_frameworks = Column(JSON, default=list)  # list[str]
    scan_duration = Column(Float, default=0.0)  # seconds

    report = relationship("Report", back_populates="scan_metadata")
