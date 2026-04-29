"""
IRVES — Project Pydantic Models
Request/response schemas for project operations.
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class Platform(str, Enum):
    """Supported platforms."""
    ANDROID = "android"
    IOS = "ios"
    DESKTOP = "desktop"
    WEB = "web"
    REPOSITORY = "repository"


class ProjectCreate(BaseModel):
    """Request model for creating a new project."""
    name: str = Field(..., min_length=1, max_length=255)
    platform: Platform
    target_path: Optional[str] = Field(None, max_length=2000)
    package_name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    # Git integration (optional — only set for repository scans)
    source_type: Optional[str] = Field("upload", pattern="^(upload|git)$")
    repo_url: Optional[str] = Field(None, max_length=2000)
    repo_branch: Optional[str] = Field("main", max_length=255)
    repo_token: Optional[str] = Field(None, max_length=2000)  # PAT

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure project name is not empty after trimming."""
        v = v.strip()
        if not v:
            raise ValueError("Project name cannot be empty")
        return v

    @model_validator(mode="before")
    @classmethod
    def check_git_requires_url(cls, values):
        if values.get("source_type") == "git" and not values.get("repo_url"):
            raise ValueError("repo_url is required when source_type is 'git'")
        return values


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
    # Git fields
    source_type: Optional[str] = "upload"
    repo_url: Optional[str] = None
    repo_branch: Optional[str] = None

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