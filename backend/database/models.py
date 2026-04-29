"""
IRVES — Database Models
SQLAlchemy ORM models for SQLite database.
"""

from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, UniqueConstraint, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.sqlite import JSON
from datetime import datetime
import enum
import uuid

from database.connection import Base


def generate_id() -> str:
    """Generate short unique ID."""
    return uuid.uuid4().hex[:8]


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SourceType(str, enum.Enum):
    """How the project target was supplied."""
    UPLOAD = "upload"   # Binary file uploaded
    GIT = "git"         # Cloned from GitHub / GitLab


class FindingSeverity(str, enum.Enum):
    """Finding severity enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Finding status enumeration."""
    OPEN = "open"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class ToolExecutionStatus(str, enum.Enum):
    """Tool execution status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AnalysisCategory(str, enum.Enum):
    """Source code analysis category enumeration."""
    ARCHITECTURE = "architecture"
    SCALABILITY = "scalability"
    CODE_QUALITY = "code_quality"
    SECURITY = "security"
    DEPENDENCIES = "dependencies"
    SECRETS = "secrets"
    TECHNICAL_DEBT = "technical_debt"
    CONTRIBUTOR_RISK = "contributor_risk"


class AnalysisStatus(str, enum.Enum):
    """Analysis status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Project(Base):
    """
    Project model - represents a security analysis project.
    Each project can have multiple scans.
    """
    __tablename__ = "projects"

    id = Column(String(8), primary_key=True, default=generate_id)
    name = Column(String(255), nullable=False, index=True)
    platform = Column(String(20), nullable=False, index=True)  # android, ios, desktop, web
    target_path = Column(Text, nullable=True)  # File path or URL being analyzed
    package_name = Column(String(255), nullable=True, index=True)  # Android/iOS package identifier
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Git / source-code integration (all nullable for backward-compat)
    source_type = Column(String(10), nullable=True, default="upload")  # upload | git
    repo_url = Column(Text, nullable=True)      # HTTPS or SSH repo URL
    repo_branch = Column(String(255), nullable=True, default="main")
    repo_token = Column(Text, nullable=True)    # PAT (stored as-is; encrypt in production)

    # Relationships
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Project(id={self.id}, name={self.name}, platform={self.platform})>"


class Scan(Base):
    """
    Scan model - represents a single security scan.
    Each scan runs multiple tools and produces findings.
    """
    __tablename__ = "scans"

    id = Column(String(8), primary_key=True, default=generate_id)
    project_id = Column(String(8), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    # Scan configuration
    profile = Column(String(20), nullable=False)  # full, quick, runtime, custom
    custom_tools = Column(JSON, nullable=True)  # List of tools for custom profile

    # Status tracking
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    error_message = Column(Text, nullable=True)

    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Analysis State Tree (Phase 2) - stores task tree as JSON
    ast_data = Column(JSON, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_executions = relationship("ToolExecution", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, project_id={self.project_id}, status={self.status})>"

    @property
    def duration_seconds(self) -> float | None:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class Finding(Base):
    """
    Finding model - represents a security vulnerability finding.
    Generated by tools and enhanced by AI analysis.
    """
    __tablename__ = "findings"

    id = Column(String(8), primary_key=True, default=generate_id)
    scan_id = Column(String(8), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Finding details
    title = Column(String(500), nullable=False)
    severity = Column(SQLEnum(FindingSeverity), nullable=False, index=True)
    category = Column(String(100), nullable=True, index=True)  # OWASP category
    description = Column(Text, nullable=True)

    # Location information
    location = Column(String(500), nullable=True)  # File:line reference
    code_snippet = Column(Text, nullable=True)

    # Tool information
    tool = Column(String(50), nullable=False)  # Which tool found this
    owasp_mapping = Column(String(100), nullable=True)  # e.g., "M9: Insecure Data Storage"
    cwe_mapping = Column(String(50), nullable=True)  # e.g., "CWE-798"

    # Status
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    resolution_note = Column(Text, nullable=True)

    # AI enhancement
    ai_analysis = Column(Text, nullable=True)  # JSON from AI service
    ai_attack_path = Column(JSON, nullable=True)  # List of attack steps
    ai_fix_guidance = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title={self.title[:30]}..., severity={self.severity})>"


class ToolExecution(Base):
    """
    ToolExecution model - tracks individual tool runs within a scan.
    """
    __tablename__ = "tool_executions"

    id = Column(String(8), primary_key=True, default=generate_id)
    scan_id = Column(String(8), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Tool info
    tool_name = Column(String(50), nullable=False, index=True)
    status = Column(SQLEnum(ToolExecutionStatus), default=ToolExecutionStatus.PENDING, nullable=False)

    # Output
    output_path = Column(Text, nullable=True)  # Path to tool output files
    error_message = Column(Text, nullable=True)

    # Metrics
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    metrics = Column(JSON, nullable=True)  # Tool-specific metrics

    # Relationships
    scan = relationship("Scan", back_populates="tool_executions")

    def __repr__(self) -> str:
        return f"<ToolExecution(id={self.id}, tool={self.tool_name}, status={self.status})>"

    @property
    def duration_ms(self) -> int | None:
        """Calculate execution duration in milliseconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return None


class Report(Base):
    """
    Report model - generated compliance reports.
    """
    __tablename__ = "reports"

    id = Column(String(8), primary_key=True, default=generate_id)
    project_id = Column(String(8), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(8), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)

    # Report configuration
    template = Column(String(50), nullable=False)  # masvs, owasp_top10, sbom, privacy, executive
    format = Column(String(10), nullable=False)  # pdf, markdown, json, html
    scope = Column(String(20), default="full")  # full, selected
    selected_findings = Column(JSON, nullable=True)  # List of finding IDs for selected scope

    # Output
    file_path = Column(Text, nullable=True)

    # Timestamps
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    project = relationship("Project", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, template={self.template}, format={self.format})>"


class SourceAnalysisResult(Base):
    """
    SourceAnalysisResult model - stores comprehensive source code analysis results.
    One result per category per project/scan combination.
    """
    __tablename__ = "source_analysis_results"
    __table_args__ = (
        UniqueConstraint('project_id', 'scan_id', 'category', name='uq_source_analysis_results_project_scan_category'),
    )

    id = Column(String(8), primary_key=True, default=generate_id)
    project_id = Column(String(8), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(8), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)

    # Analysis category
    category = Column(SQLEnum(AnalysisCategory), nullable=False, index=True)

    # Cache invalidation
    code_hash = Column(String(64), nullable=True, index=True)  # SHA256 of source files

    # Analysis status
    status = Column(SQLEnum(AnalysisStatus), default=AnalysisStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    error_message = Column(Text, nullable=True)

    # Summary metrics (JSON for flexibility)
    summary_metrics = Column(JSON, nullable=True)  # counts, severity_scores, key_signals

    # Detailed findings (JSON for flexible schema)
    detailed_findings = Column(JSON, nullable=True)  # Full tool output

    # AI enhancement
    ai_explanation = Column(Text, nullable=True)  # AI-generated category explanation
    ai_recommendations = Column(JSON, nullable=True)  # AI-generated remediation steps

    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    project = relationship("Project")
    scan = relationship("Scan")
    findings = relationship("CategoryFinding", back_populates="analysis_result", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<SourceAnalysisResult(id={self.id}, category={self.category}, status={self.status})>"

    @property
    def duration_seconds(self) -> float | None:
        """Calculate analysis duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class CategoryFinding(Base):
    """
    CategoryFinding model - individual findings within a source analysis category.
    Allows granular querying and filtering of specific issues.
    """
    __tablename__ = "category_findings"

    id = Column(String(8), primary_key=True, default=generate_id)
    analysis_result_id = Column(String(8), ForeignKey("source_analysis_results.id", ondelete="CASCADE"), nullable=False, index=True)

    # Finding details
    finding_type = Column(String(100), nullable=False, index=True)  # e.g., "high_cyclomatic_complexity", "sql_injection"
    severity = Column(SQLEnum(FindingSeverity), nullable=False, index=True)

    # Location
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)

    # Description
    message = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)

    # Tool that generated this finding
    tool = Column(String(50), nullable=True)

    # Additional metadata (JSON for flexibility)
    extra_data = Column(JSON, nullable=True)  # Tool-specific data, CWE, OWASP mapping, etc.

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    analysis_result = relationship("SourceAnalysisResult", back_populates="findings")

    def __repr__(self) -> str:
        return f"<CategoryFinding(id={self.id}, type={self.finding_type}, severity={self.severity})>"