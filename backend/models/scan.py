"""
IRVES — Scan Pydantic Models
Request/response schemas for scan operations.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class ScanProfile(str, Enum):
    """Scan profile types."""
    FULL = "full"
    QUICK = "quick"
    RUNTIME = "runtime"
    CUSTOM = "custom"


class ScanStatus(str, Enum):
    """Scan status types."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanCreate(BaseModel):
    """Request model for creating a new scan."""
    project_id: str = Field(..., min_length=1, max_length=8)
    profile: ScanProfile = Field(default=ScanProfile.FULL)
    custom_tools: Optional[List[str]] = Field(default=None, max_items=10)


class ScanResponse(BaseModel):
    """Response model for scan data."""
    id: str
    project_id: str
    profile: str
    status: str
    progress: int = Field(ge=0, le=100)
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    """Response model for scan status check."""
    scan_id: str
    status: str
    progress: int = Field(ge=0, le=100)
    error_message: Optional[str] = None
    current_tool: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanProgressResponse(BaseModel):
    """Response model for SSE progress updates."""
    type: str  # "progress", "tool_start", "tool_complete", "finding", "complete", "error"
    scan_id: str
    data: dict