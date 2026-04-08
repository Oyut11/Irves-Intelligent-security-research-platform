"""
IRVES — Reports Routes (Phase 7 complete)
Generate compliance reports: OWASP MASVS, SBOM, Privacy Audit.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from pathlib import Path
import logging
from datetime import datetime

from database import (
    get_db_session,
    get_project,
    get_scan,
    get_findings_by_scan,
    create_report,
    get_report,
    get_reports_by_project,
    update_report_file,
)
from models.report import ReportCreate, ReportResponse, ReportFormat, ReportTemplate
from services.report_generator import report_generator
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

_MEDIA_TYPES = {
    "pdf": "application/pdf",
    "markdown": "text/markdown",
    "json": "application/json",
    "html": "text/html",
}


async def _run_generation(report_id: str, project_id: str, scan_id: Optional[str],
                           template: str, fmt: str, selected_findings: Optional[list]):
    """Background task: run report generation and persist file path."""
    from database.connection import get_db
    from database import crud
    try:
        file_path = await report_generator.generate(
            project_id=project_id,
            scan_id=scan_id,
            template=template,
            fmt=fmt,
            selected_finding_ids=selected_findings,
        )
        async with get_db() as db:
            await crud.update_report_file(db, report_id, str(file_path))
        logger.info(f"[Report] Generated {fmt} {template} report → {file_path}")
    except Exception as e:
        logger.exception(f"[Report] Generation failed for report {report_id}: {e}")


# ── Report Generation ───────────────────────────────────────────────────────────

@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Generate a compliance report asynchronously.

    Templates:  masvs | sbom | privacy
    Formats:    pdf | html | json | markdown

    The report record is created immediately; file generation runs in the background.
    Poll GET /report/{report_id} to check if `file_path` is populated.
    """
    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if request.scan_id:
        scan = await get_scan(db, request.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    report = await create_report(
        db=db,
        project_id=request.project_id,
        scan_id=request.scan_id,
        template=request.template.value,
        format=request.format.value,
        scope=request.scope.value,
        selected_findings=request.selected_findings,
    )

    # Kick off generation in background so we return immediately
    background_tasks.add_task(
        _run_generation,
        str(report.id),
        request.project_id,
        request.scan_id,
        request.template.value,
        request.format.value,
        request.selected_findings,
    )

    logger.info(f"[Report] Queued {request.template.value} report {report.id}")

    return ReportResponse(
        id=report.id,
        project_id=report.project_id,
        scan_id=report.scan_id,
        template=report.template,
        format=report.format,
        scope=report.scope,
        file_path=report.file_path,
        generated_at=report.generated_at,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report_status(
    report_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Poll generation status. `file_path` will be populated once ready."""
    report = await get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportResponse(
        id=report.id,
        project_id=report.project_id,
        scan_id=report.scan_id,
        template=report.template,
        format=report.format,
        scope=report.scope,
        file_path=report.file_path,
        generated_at=report.generated_at,
    )


@router.get("/list/{project_id}", response_model=list[ReportResponse])
async def list_reports(
    project_id: str,
    limit: int = 20,
    db: AsyncSession = Depends(get_db_session),
):
    """List all reports for a project."""
    reports = await get_reports_by_project(db, project_id, limit=limit)
    return [
        ReportResponse(
            id=r.id,
            project_id=r.project_id,
            scan_id=r.scan_id,
            template=r.template,
            format=r.format,
            scope=r.scope,
            file_path=r.file_path,
            generated_at=r.generated_at,
        )
        for r in reports
    ]


@router.get("/download/{report_id}")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Download a generated report file."""
    report = await get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.file_path:
        raise HTTPException(status_code=202, detail="Report is still generating, try again shortly")

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file missing from disk")

    return FileResponse(
        path=file_path,
        media_type=_MEDIA_TYPES.get(report.format, "application/octet-stream"),
        filename=f"irves_{report.template}_{report.id}.{report.format}",
    )


# ── Convenience shortcuts ──────────────────────────────────────────────────────

@router.post("/owasp", response_model=ReportResponse)
async def generate_owasp_report(
    request: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """Shortcut: Generate OWASP MASVS report."""
    from models.report import ReportTemplate
    request.template = ReportTemplate.MASVS
    return await generate_report(request, background_tasks, db)


@router.post("/sbom", response_model=ReportResponse)
async def generate_sbom_report(
    request: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """Shortcut: Generate SBOM report."""
    from models.report import ReportTemplate
    request.template = ReportTemplate.SBOM
    return await generate_report(request, background_tasks, db)


@router.post("/privacy", response_model=ReportResponse)
async def generate_privacy_report(
    request: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """Shortcut: Generate Privacy Audit report."""
    from models.report import ReportTemplate
    request.template = ReportTemplate.PRIVACY
    return await generate_report(request, background_tasks, db)