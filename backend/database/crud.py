"""
IRVES — CRUD Operations
Database operations for all models.
"""

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from datetime import datetime
from typing import Optional, List
import logging

from database.models import (
    Project,
    Scan,
    Finding,
    ToolExecution,
    Report,
    ScanStatus,
    FindingSeverity,
    FindingStatus,
    ToolExecutionStatus,
)

logger = logging.getLogger(__name__)


# ── Project CRUD ──────────────────────────────────────────────────────────────

async def create_project(
    db: AsyncSession,
    name: str,
    platform: str,
    target_path: Optional[str] = None,
    package_name: Optional[str] = None,
    description: Optional[str] = None,
) -> Project:
    """Create a new project."""
    project = Project(
        name=name,
        platform=platform,
        target_path=target_path,
        package_name=package_name,
        description=description,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    logger.info(f"Created project: {project.id} - {name}")
    return project


async def get_project(db: AsyncSession, project_id: str) -> Optional[Project]:
    """Get a project by ID."""
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    return result.scalar_one_or_none()


async def get_projects(
    db: AsyncSession,
    platform: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Project]:
    """Get all projects, optionally filtered by platform."""
    query = select(Project).order_by(Project.updated_at.desc())

    if platform:
        query = query.where(Project.platform == platform)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_project(
    db: AsyncSession,
    project_id: str,
    **kwargs,
) -> Optional[Project]:
    """Update a project's attributes."""
    project = await get_project(db, project_id)
    if not project:
        return None

    for key, value in kwargs.items():
        if hasattr(project, key) and value is not None:
            setattr(project, key, value)

    project.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(project)
    return project


async def delete_project(db: AsyncSession, project_id: str) -> bool:
    """Delete a project and all its related data."""
    project = await get_project(db, project_id)
    if not project:
        return False

    await db.delete(project)
    await db.flush()
    logger.info(f"Deleted project: {project_id}")
    return True


# ── Scan CRUD ────────────────────────────────────────────────────────────────

async def create_scan(
    db: AsyncSession,
    project_id: str,
    profile: str,
    custom_tools: Optional[List[str]] = None,
) -> Scan:
    """Create a new scan for a project."""
    scan = Scan(
        project_id=project_id,
        profile=profile,
        custom_tools=custom_tools,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    logger.info(f"Created scan: {scan.id} for project {project_id}")
    return scan


async def get_scan(db: AsyncSession, scan_id: str) -> Optional[Scan]:
    """Get a scan by ID with relationships."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.project))
        .where(Scan.id == scan_id)
    )
    return result.scalar_one_or_none()


async def get_scans_by_project(
    db: AsyncSession,
    project_id: str,
    status: Optional[ScanStatus] = None,
    limit: int = 50,
) -> List[Scan]:
    """Get all scans for a project."""
    query = (
        select(Scan)
        .where(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
    )

    if status:
        query = query.where(Scan.status == status)

    query = query.limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_scan_status(
    db: AsyncSession,
    scan_id: str,
    status: ScanStatus,
    error_message: Optional[str] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> Optional[Scan]:
    """Update scan status."""
    scan = await get_scan(db, scan_id)
    if not scan:
        return None

    scan.status = status
    if error_message:
        scan.error_message = error_message
    if started_at:
        scan.started_at = started_at
    if completed_at:
        scan.completed_at = completed_at

    await db.flush()
    await db.refresh(scan)
    return scan


async def update_scan_progress(
    db: AsyncSession,
    scan_id: str,
    progress: int,
) -> Optional[Scan]:
    """Update scan progress (0-100)."""
    scan = await get_scan(db, scan_id)
    if not scan:
        return None

    scan.progress = max(0, min(100, progress))
    await db.flush()
    await db.refresh(scan)
    return scan


# ── Finding CRUD ─────────────────────────────────────────────────────────────

async def create_finding(
    db: AsyncSession,
    scan_id: str,
    title: str,
    severity: FindingSeverity,
    tool: str,
    category: Optional[str] = None,
    location: Optional[str] = None,
    code_snippet: Optional[str] = None,
    description: Optional[str] = None,
    owasp_mapping: Optional[str] = None,
    cwe_mapping: Optional[str] = None,
) -> Finding:
    """Create a new finding."""
    finding = Finding(
        scan_id=scan_id,
        title=title,
        severity=severity,
        tool=tool,
        category=category,
        location=location,
        code_snippet=code_snippet,
        description=description,
        owasp_mapping=owasp_mapping,
        cwe_mapping=cwe_mapping,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


async def get_finding(db: AsyncSession, finding_id: str) -> Optional[Finding]:
    """Get a finding by ID."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    return result.scalar_one_or_none()


async def get_findings_by_scan(
    db: AsyncSession,
    scan_id: str,
    severity: Optional[FindingSeverity] = None,
    status: Optional[FindingStatus] = None,
    limit: int = 100,
) -> List[Finding]:
    """Get all findings for a scan."""
    query = select(Finding).where(Finding.scan_id == scan_id)

    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)

    query = query.order_by(Finding.created_at).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_finding_status(
    db: AsyncSession,
    finding_id: str,
    status: FindingStatus,
    resolution_note: Optional[str] = None,
) -> Optional[Finding]:
    """Update finding status."""
    finding = await get_finding(db, finding_id)
    if not finding:
        return None

    finding.status = status
    if resolution_note:
        finding.resolution_note = resolution_note

    finding.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(finding)
    return finding


async def count_findings_by_severity(
    db: AsyncSession,
    scan_id: str,
) -> dict:
    """Count findings by severity for a scan."""
    from sqlalchemy import func

    result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    )

    counts = {s.value: 0 for s in FindingSeverity}
    for severity, count in result.all():
        counts[severity.value] = count

    return counts


# ── ToolExecution CRUD ───────────────────────────────────────────────────────

async def create_tool_execution(
    db: AsyncSession,
    scan_id: str,
    tool_name: str,
) -> ToolExecution:
    """Create a tool execution record."""
    execution = ToolExecution(
        scan_id=scan_id,
        tool_name=tool_name,
        status=ToolExecutionStatus.PENDING,
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    return execution


async def update_tool_execution(
    db: AsyncSession,
    execution_id: str,
    status: Optional[ToolExecutionStatus] = None,
    output_path: Optional[str] = None,
    error_message: Optional[str] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    metrics: Optional[dict] = None,
) -> Optional[ToolExecution]:
    """Update tool execution status."""
    result = await db.execute(
        select(ToolExecution).where(ToolExecution.id == execution_id)
    )
    execution = result.scalar_one_or_none()

    if not execution:
        return None

    if status:
        execution.status = status
    if output_path:
        execution.output_path = output_path
    if error_message:
        execution.error_message = error_message
    if started_at:
        execution.started_at = started_at
    if completed_at:
        execution.completed_at = completed_at
    if metrics:
        execution.metrics = metrics

    await db.flush()
    await db.refresh(execution)
    return execution


async def get_tool_executions_by_scan(
    db: AsyncSession,
    scan_id: str,
) -> List[ToolExecution]:
    """Get all tool executions for a scan."""
    result = await db.execute(
        select(ToolExecution)
        .where(ToolExecution.scan_id == scan_id)
        .order_by(ToolExecution.started_at)
    )
    return list(result.scalars().all())


# ── Report CRUD ──────────────────────────────────────────────────────────────

async def create_report(
    db: AsyncSession,
    project_id: str,
    template: str,
    format: str,
    scan_id: Optional[str] = None,
    scope: str = "full",
    selected_findings: Optional[List[str]] = None,
) -> Report:
    """Create a report record."""
    report = Report(
        project_id=project_id,
        scan_id=scan_id,
        template=template,
        format=format,
        scope=scope,
        selected_findings=selected_findings,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return report


async def get_report(db: AsyncSession, report_id: str) -> Optional[Report]:
    """Get a report by ID."""
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    return result.scalar_one_or_none()


async def get_reports_by_project(
    db: AsyncSession,
    project_id: str,
    limit: int = 50,
) -> List[Report]:
    """Get all reports for a project."""
    result = await db.execute(
        select(Report)
        .where(Report.project_id == project_id)
        .order_by(Report.generated_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def update_report_file(
    db: AsyncSession,
    report_id: str,
    file_path: str,
) -> Optional[Report]:
    """Update report file path after generation."""
    report = await get_report(db, report_id)
    if not report:
        return None

    report.file_path = file_path
    await db.flush()
    await db.refresh(report)
    return report


async def update_scan_progress_standalone(scan_id: str, progress: int) -> None:
    """Update scan progress using an independent DB session (safe for background tasks)."""
    from database.connection import get_db
    async with get_db() as db:
        await update_scan_progress(db, scan_id, progress)