"""
IRVES — Finding Pydantic Models
Request/response schemas for security findings.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status types."""
    OPEN = "open"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class FindingCreate(BaseModel):
    """Request model for creating a finding."""
    scan_id: str = Field(..., min_length=1, max_length=8)
    title: str = Field(..., min_length=1, max_length=500)
    severity: FindingSeverity
    tool: str = Field(..., min_length=1, max_length=50)
    category: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = Field(None, max_length=500)
    code_snippet: Optional[str] = None
    description: Optional[str] = None
    owasp_mapping: Optional[str] = Field(None, max_length=100)
    cwe_mapping: Optional[str] = Field(None, max_length=50)


class FindingResponse(BaseModel):
    """Response model for finding data."""
    id: str
    scan_id: str
    title: str
    severity: str
    category: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    code_snippet: Optional[str] = None
    tool: str
    owasp_mapping: Optional[str] = None
    cwe_mapping: Optional[str] = None
    status: str
    resolution_note: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_attack_path: Optional[List[str]] = None
    ai_fix_guidance: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Request model for updating a finding."""
    status: Optional[FindingStatus] = None
    resolution_note: Optional[str] = None


class FindingSummary(BaseModel):
    """Summary model for finding counts."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    class Config:
        from_attributes = True