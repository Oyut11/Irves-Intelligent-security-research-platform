"""
IRVES — Scan Routes
Scan orchestration endpoints for Android, iOS, Desktop, and Web targets.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from pathlib import Path
import logging

from database import (
    get_db_session,
    create_project,
    get_project,
    create_scan,
    get_scan,
    update_scan_status,
    update_scan_progress,
    ScanStatus,
)
from models.scan import ScanCreate, ScanResponse, ScanStatusResponse
from models.project import ProjectCreate, ProjectResponse, Platform
from config import settings
from utils.file_utils import ensure_directory, safe_filename, detect_platform, get_file_hash, extract_package_name

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Project Endpoints ───────────────────────────────────────────────────────────

@router.post("/projects", response_model=ProjectResponse)
async def create_new_project(
    request: ProjectCreate,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Create a new project for analysis.

    A project represents a target application (APK, IPA, EXE, or URL)
    that will be analyzed.
    """
    try:
        project = await create_project(
            db=db,
            name=request.name,
            platform=request.platform.value,
            target_path=request.target_path,
            description=request.description,
        )

        return ProjectResponse(
            id=project.id,
            name=project.name,
            platform=project.platform,
            target_path=project.target_path,
            package_name=project.package_name,
            description=project.description,
            created_at=project.created_at,
            updated_at=project.updated_at,
            status="clean",
            issue_count=0,
        )

    except Exception as e:
        logger.error(f"Failed to create project: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/projects", response_model=list[ProjectResponse])
async def list_projects(
    platform: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
):
    """List all projects, optionally filtered by platform."""
    from database.crud import get_projects
    from database.crud import count_findings_by_severity
    from database.crud import get_scans_by_project

    projects = await get_projects(db, platform=platform)

    result = []
    for project in projects:
        # Get latest scan info
        scans = await get_scans_by_project(db, project.id, limit=1)
        latest_scan = scans[0] if scans else None

        # Calculate status
        status = "clean"
        issue_count = 0
        worst_severity = None

        if latest_scan:
            if latest_scan.status == ScanStatus.RUNNING:
                status = "scanning"
            elif latest_scan.status == ScanStatus.COMPLETED:
                counts = await count_findings_by_severity(db, latest_scan.id)
                issue_count = sum(counts.values())
                if counts.get("critical", 0) > 0:
                    worst_severity = "critical"
                    status = "issues"
                elif counts.get("high", 0) > 0:
                    worst_severity = "high"
                    status = "issues"
                elif counts.get("medium", 0) > 0:
                    worst_severity = "medium"
                    status = "issues"
                elif counts.get("low", 0) > 0:
                    worst_severity = "low"

        result.append(ProjectResponse(
            id=project.id,
            name=project.name,
            platform=project.platform,
            target_path=project.target_path,
            description=project.description,
            created_at=project.created_at,
            updated_at=project.updated_at,
            status=status,
            issue_count=issue_count,
            worst_severity=worst_severity,
            last_scan=latest_scan.created_at.isoformat() if latest_scan else None,
        ))

    return result


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project_by_id(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Get a specific project by ID."""
    project = await get_project(db, project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return ProjectResponse(
        id=project.id,
        name=project.name,
        platform=project.platform,
        target_path=project.target_path,
        description=project.description,
        created_at=project.created_at,
        updated_at=project.updated_at,
        status="clean",
        issue_count=0,
    )


# ── File Upload ────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_target_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Upload a target file (APK, IPA, EXE, etc.) for analysis.

    Creates a project automatically based on the file.
    """
    # Validate file extension
    allowed_extensions = {".apk", ".ipa", ".exe", ".msi", ".dmg", ".deb", ".rpm", ".appimage"}
    file_ext = Path(file.filename).suffix.lower()

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_ext}. Allowed: {', '.join(allowed_extensions)}"
        )

    # Safe filename
    safe_name = safe_filename(file.filename)

    # Detect platform
    platform = detect_platform(Path(safe_name))

    # Create project directory
    project_dir = settings.projects_path / safe_name.replace(file_ext, "")
    ensure_directory(project_dir)

    # Save file
    file_path = project_dir / safe_name

    try:
        # Write file in chunks
        with open(file_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                f.write(chunk)

        # Calculate hash
        file_hash = get_file_hash(file_path)

        # Extract package name (for Android/iOS apps)
        package_name = extract_package_name(file_path)

        # Create project
        project = await create_project(
            db=db,
            name=safe_name,
            platform=platform,
            target_path=str(file_path),
            package_name=package_name,
            description=f"Uploaded file (SHA256: {file_hash[:16]}...)",
        )

        logger.info(f"Created project {project.id} from uploaded file: {safe_name}")

        return {
            "project_id": project.id,
            "filename": safe_name,
            "platform": platform,
            "package_name": package_name,
            "file_hash": file_hash,
            "file_size": file_path.stat().st_size,
        }

    except Exception as e:
        logger.error(f"Failed to process uploaded file: {e}")
        # Cleanup on error
        if file_path.exists():
            file_path.unlink()
        raise HTTPException(status_code=500, detail=str(e))


# ── Scan Endpoints ─────────────────────────────────────────────────────────────

@router.post("/android", response_model=ScanResponse)
async def scan_android(
    request: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
):
    """Start an Android scan using the unified ScannerService."""
    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.scanner import scanner_service
    scan_id = await scanner_service.start_scan(
        project_id=request.project_id,
        target=Path(project.target_path) if project.target_path else None,
        profile=request.profile.value if hasattr(request.profile, 'value') else str(request.profile),
        custom_tools=request.custom_tools
    )
    scan = await get_scan(db, scan_id)
    logger.info(f"Created Android scan {scan.id} for project {project.id}")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        profile=scan.profile,
        status=scan.status.value,
        progress=scan.progress,
        created_at=scan.created_at,
    )


@router.post("/ios", response_model=ScanResponse)
async def scan_ios(
    request: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
):
    """Start an iOS scan using the unified ScannerService."""
    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.scanner import scanner_service
    scan_id = await scanner_service.start_scan(
        project_id=request.project_id,
        target=Path(project.target_path) if project.target_path else None,
        profile=request.profile.value if hasattr(request.profile, 'value') else str(request.profile),
        custom_tools=request.custom_tools
    )
    scan = await get_scan(db, scan_id)
    logger.info(f"Created iOS scan {scan.id} for project {project.id}")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        profile=scan.profile,
        status=scan.status.value,
        progress=scan.progress,
        created_at=scan.created_at,
    )


@router.post("/desktop", response_model=ScanResponse)
async def scan_desktop(
    request: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
):
    """Start a Desktop application scan using the unified ScannerService."""
    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.scanner import scanner_service
    scan_id = await scanner_service.start_scan(
        project_id=request.project_id,
        target=Path(project.target_path) if project.target_path else None,
        profile=request.profile.value if hasattr(request.profile, 'value') else str(request.profile),
        custom_tools=request.custom_tools
    )
    scan = await get_scan(db, scan_id)
    logger.info(f"Created Desktop scan {scan.id} for project {project.id}")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        profile=scan.profile,
        status=scan.status.value,
        progress=scan.progress,
        created_at=scan.created_at,
    )


@router.post("/web", response_model=ScanResponse)
async def scan_web(
    request: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
):
    """Start a Web application scan using the unified ScannerService."""
    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.scanner import scanner_service
    scan_id = await scanner_service.start_scan(
        project_id=request.project_id,
        target=Path(project.target_path) if project.target_path else None,
        profile=request.profile.value if hasattr(request.profile, 'value') else str(request.profile),
        custom_tools=request.custom_tools
    )
    scan = await get_scan(db, scan_id)
    logger.info(f"Created Web scan {scan.id} for project {project.id}")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        profile=scan.profile,
        status=scan.status.value,
        progress=scan.progress,
        created_at=scan.created_at,
    )


# ── Scan Status ────────────────────────────────────────────────────────────────

@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get current status of a scan.

    Poll this endpoint for progress updates.
    """
    scan = await get_scan(db, scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status.value,
        progress=scan.progress,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.post("/cancel/{scan_id}")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Cancel a running scan."""
    scan = await get_scan(db, scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Scan is not running")

    # Update status
    await update_scan_status(db, scan_id, ScanStatus.CANCELLED)

    # TODO: Cancel actual running tasks

    return {"status": "cancelled", "scan_id": scan_id}


# ── Import dependencies that need database ─────────────────────────────────────

from database.crud import get_scans_by_project