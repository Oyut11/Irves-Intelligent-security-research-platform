"""
IRVES — Report Pydantic Models
Request/response schemas for report generation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class ReportTemplate(str, Enum):
    """Report template types."""
    MASVS = "masvs"
    OWASP_TOP_10 = "owasp_top10"
    SBOM = "sbom"
    PRIVACY = "privacy"
    EXECUTIVE = "executive"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Report output formats."""
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


class ReportScope(str, Enum):
    """Report scope options."""
    FULL = "full"
    SELECTED = "selected"


class ReportCreate(BaseModel):
    """Request model for creating a report."""
    project_id: str = Field(..., min_length=1, max_length=8)
    scan_id: Optional[str] = Field(None, min_length=1, max_length=8)
    template: ReportTemplate
    format: ReportFormat = ReportFormat.PDF
    scope: ReportScope = ReportScope.FULL
    selected_findings: Optional[List[str]] = Field(None, max_items=100)


class ReportResponse(BaseModel):
    """Response model for report data."""
    id: str
    project_id: str
    scan_id: Optional[str] = None
    template: str
    format: str
    scope: str
    file_path: Optional[str] = None
    generated_at: datetime

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Response model for report listing."""
    reports: List[ReportResponse]
    total: int