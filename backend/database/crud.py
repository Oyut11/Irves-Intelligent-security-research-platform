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
    SourceAnalysisResult,
    CategoryFinding,
    ScanStatus,
    FindingSeverity,
    FindingStatus,
    ToolExecutionStatus,
    AnalysisCategory,
    AnalysisStatus,
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
    source_type: Optional[str] = "upload",
    repo_url: Optional[str] = None,
    repo_branch: Optional[str] = "main",
    repo_token: Optional[str] = None,
) -> Project:
    """Create a new project."""
    project = Project(
        name=name,
        platform=platform,
        target_path=target_path,
        package_name=package_name,
        description=description,
        source_type=source_type,
        repo_url=repo_url,
        repo_branch=repo_branch,
        repo_token=repo_token,
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


async def count_findings_by_category(
    db: AsyncSession,
    scan_id: str,
) -> dict:
    """Count findings by category for a scan."""
    from sqlalchemy import func

    result = await db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.category)
    )

    counts = {}
    for category, count in result.all():
        counts[category or "General"] = count

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


# ── SourceAnalysisResult CRUD ───────────────────────────────────────────────────

async def create_source_analysis_result(
    db: AsyncSession,
    project_id: str,
    category: AnalysisCategory = None,
    scan_id: Optional[str] = None,
    code_hash: Optional[str] = None,
    status: Optional[AnalysisStatus] = None,
) -> SourceAnalysisResult:
    """Create a new source analysis result."""
    result = SourceAnalysisResult(
        project_id=project_id,
        category=category,
        scan_id=scan_id,
        code_hash=code_hash,
        status=status or AnalysisStatus.PENDING,
    )
    db.add(result)
    await db.flush()
    await db.refresh(result)
    logger.info(f"Created source analysis result: {result.id} - {category}")
    return result


async def get_source_analysis_result(
    db: AsyncSession,
    result_id: str,
) -> Optional[SourceAnalysisResult]:
    """Get a source analysis result by ID with findings."""
    result = await db.execute(
        select(SourceAnalysisResult)
        .options(selectinload(SourceAnalysisResult.findings))
        .where(SourceAnalysisResult.id == result_id)
    )
    return result.scalar_one_or_none()


async def get_source_analysis_results_by_project(
    db: AsyncSession,
    project_id: str,
    category: Optional[AnalysisCategory] = None,
) -> List[SourceAnalysisResult]:
    """Get all source analysis results for a project, optionally filtered by category."""
    query = (
        select(SourceAnalysisResult)
        .where(SourceAnalysisResult.project_id == project_id)
        .order_by(SourceAnalysisResult.created_at.desc())
    )

    if category:
        query = query.where(SourceAnalysisResult.category == category)

    result = await db.execute(query)
    return list(result.scalars().all())


async def get_latest_source_analysis(
    db: AsyncSession,
    project_id: str,
    category: AnalysisCategory,
) -> Optional[SourceAnalysisResult]:
    """Get the latest source analysis result for a project and category."""
    result = await db.execute(
        select(SourceAnalysisResult)
        .where(SourceAnalysisResult.project_id == project_id)
        .where(SourceAnalysisResult.category == category)
        .order_by(SourceAnalysisResult.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def update_source_analysis_result(
    db: AsyncSession,
    result_id: str,
    status: Optional[AnalysisStatus] = None,
    progress: Optional[int] = None,
    error_message: Optional[str] = None,
    summary_metrics: Optional[dict] = None,
    detailed_findings: Optional[dict] = None,
    ai_explanation: Optional[str] = None,
    ai_recommendations: Optional[dict] = None,
    code_hash: Optional[str] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> Optional[SourceAnalysisResult]:
    """Update source analysis result."""
    result = await get_source_analysis_result(db, result_id)
    if not result:
        return None

    if status is not None:
        result.status = status
    if progress is not None:
        result.progress = max(0, min(100, progress))
    if error_message is not None:
        result.error_message = error_message
    if summary_metrics is not None:
        result.summary_metrics = summary_metrics
    if detailed_findings is not None:
        result.detailed_findings = detailed_findings
    if ai_explanation is not None:
        result.ai_explanation = ai_explanation
    if ai_recommendations is not None:
        result.ai_recommendations = ai_recommendations
    if code_hash is not None:
        result.code_hash = code_hash
    if started_at is not None:
        result.started_at = started_at
    if completed_at is not None:
        result.completed_at = completed_at

    result.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(result)
    return result


async def delete_source_analysis_results(
    db: AsyncSession,
    project_id: str,
) -> int:
    """Delete all source analysis results (and their findings) for a project."""
    # Explicitly delete child findings first — SQLite may not enforce FK cascades.
    result_ids = await db.execute(
        select(SourceAnalysisResult.id).where(SourceAnalysisResult.project_id == project_id)
    )
    ids = [r[0] for r in result_ids.all()]
    if ids:
        await db.execute(
            delete(CategoryFinding).where(CategoryFinding.analysis_result_id.in_(ids))
        )

    result = await db.execute(
        delete(SourceAnalysisResult).where(SourceAnalysisResult.project_id == project_id)
    )
    await db.flush()
    deleted_count = result.rowcount
    logger.info(f"Deleted {deleted_count} source analysis results for project {project_id}")
    return deleted_count


# ── CategoryFinding CRUD ───────────────────────────────────────────────────────

async def create_category_finding(
    db: AsyncSession,
    analysis_result_id: str,
    finding_type: str,
    severity: FindingSeverity,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    column_number: Optional[int] = None,
    message: Optional[str] = None,
    code_snippet: Optional[str] = None,
    tool: Optional[str] = None,
    extra_data: Optional[dict] = None,
) -> CategoryFinding:
    """Create a new category finding."""
    finding = CategoryFinding(
        analysis_result_id=analysis_result_id,
        finding_type=finding_type,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        column_number=column_number,
        message=message,
        code_snippet=code_snippet,
        tool=tool,
        extra_data=extra_data,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


async def get_category_findings(
    db: AsyncSession,
    analysis_result_id: str,
    severity: Optional[FindingSeverity] = None,
    limit: int = 100,
) -> List[CategoryFinding]:
    """Get all category findings for an analysis result."""
    query = select(CategoryFinding).where(CategoryFinding.analysis_result_id == analysis_result_id)

    if severity:
        query = query.where(CategoryFinding.severity == severity)

    query = query.order_by(CategoryFinding.created_at).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_category_findings_by_project(
    db: AsyncSession,
    project_id: str,
    severity: Optional[FindingSeverity] = None,
    limit: int = 1000,
) -> List[CategoryFinding]:
    """Get all category findings across all analysis results for a project."""
    query = (
        select(CategoryFinding)
        .join(SourceAnalysisResult, CategoryFinding.analysis_result_id == SourceAnalysisResult.id)
        .where(SourceAnalysisResult.project_id == project_id)
    )

    if severity:
        query = query.where(CategoryFinding.severity == severity)

    query = query.order_by(CategoryFinding.created_at.desc()).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def delete_category_findings(
    db: AsyncSession,
    analysis_result_id: str,
) -> int:
    """Delete all category findings for an analysis result."""
    result = await db.execute(
        delete(CategoryFinding).where(CategoryFinding.analysis_result_id == analysis_result_id)
    )
    await db.flush()
    return result.rowcount