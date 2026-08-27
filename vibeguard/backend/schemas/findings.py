from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SeveritySchema(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatusSchema(str, Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    IGNORED = "IGNORED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingBase(BaseModel):
    title: str
    category: str
    severity: SeveritySchema
    confidence: int = Field(ge=0, le=100)
    file_path: str
    line_number: Optional[int] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    example_fix: Optional[str] = None
    attack_path: Optional[List[str]] = None
    ai_explanation: Optional[str] = None
    ai_reasoning_summary: Optional[str] = None
    ai_confidence: Optional[int] = Field(default=None, ge=0, le=100)
    status: FindingStatusSchema = FindingStatusSchema.OPEN
    source_tool: Optional[str] = None
    code_snippet: Optional[str] = None


class FindingOut(FindingBase):
    id: UUID
    report_id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class FindingStatusUpdate(BaseModel):
    status: FindingStatusSchema
