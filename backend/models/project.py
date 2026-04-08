"""
IRVES — Project Pydantic Models
Request/response schemas for project operations.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class Platform(str, Enum):
    """Supported platforms."""
    ANDROID = "android"
    IOS = "ios"
    DESKTOP = "desktop"
    WEB = "web"


class ProjectCreate(BaseModel):
    """Request model for creating a new project."""
    name: str = Field(..., min_length=1, max_length=255)
    platform: Platform
    target_path: Optional[str] = Field(None, max_length=2000)
    package_name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure project name is not empty after trimming."""
        v = v.strip()
        if not v:
            raise ValueError("Project name cannot be empty")
        return v


class ProjectUpdate(BaseModel):
    """Request model for updating a project."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    """Response model for project data."""
    id: str
    name: str
    platform: str
    target_path: Optional[str] = None
    package_name: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    # Computed fields for UI
    status: str = "clean"  # clean, issues, scanning
    issue_count: int = 0
    worst_severity: Optional[str] = None
    last_scan: Optional[str] = None

    class Config:
        from_attributes = True


class ProjectSummary(BaseModel):
    """Summary model for project listing."""
    id: str
    name: str
    platform: str
    package_name: Optional[str] = None
    status: str
    issue_count: int
    worst_severity: Optional[str] = None
    last_scan: Optional[str] = None

    class Config:
        from_attributes = True