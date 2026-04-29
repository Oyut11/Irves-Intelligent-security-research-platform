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
import asyncio

from database import (
    get_db_session,
    create_project,
    get_project,
    update_project,
    delete_project,
    create_scan,
    get_scan,
    update_scan_status,
    update_scan_progress,
    ScanStatus,
)

from models.scan import ScanCreate, ScanResponse, ScanStatusResponse
from models.project import ProjectCreate, ProjectUpdate, ProjectResponse, Platform
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
            source_type=getattr(request, 'source_type', 'upload') or 'upload',
            repo_url=getattr(request, 'repo_url', None),
            repo_branch=getattr(request, 'repo_branch', 'main'),
            repo_token=getattr(request, 'repo_token', None),
        )

        return ProjectResponse(
            id=project.id,
            name=project.name,
            platform=project.platform,
            target_path=project.target_path,
            package_name=project.package_name,
            description=project.description,
            source_type=project.source_type or 'upload',
            repo_url=project.repo_url,
            repo_branch=project.repo_branch,
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


@router.patch("/projects/{project_id}", response_model=ProjectResponse)
async def update_project_api(
    project_id: str,
    request: ProjectUpdate,
    db: AsyncSession = Depends(get_db_session),
):
    """Update a project's details (name, description)."""
    project = await update_project(
        db=db,
        project_id=project_id,
        name=request.name,
        description=request.description,
    )

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
    )


@router.delete("/projects/{project_id}")
async def delete_project_api(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Delete a project and all associated data."""
    success = await delete_project(db, project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")

    return {"status": "success", "message": "Project deleted"}



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


# ── Git / Repository Scan Endpoints ───────────────────────────────────────────

from pydantic import BaseModel as _PBM


@router.post("/verify-repo")
async def verify_repository(request: dict):
    """
    Verify that a Git repository URL is accessible before cloning.
    Accepts JSON: {repo_url, repo_token}
    Returns:      {reachable, default_branch, branches, error}
    """
    from services.git_service import git_service

    repo_url = request.get("repo_url", "")
    token = request.get("repo_token")
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required")

    result = await git_service.verify_repo(repo_url, token=token)
    return result


# Mapping of repo profile names to category lists
_REPO_PROFILE_CATEGORIES: dict = {
    "full_source":    ["architecture", "scalability", "code_quality", "security", "dependencies", "secrets", "technical_debt", "contributor_risk"],
    "security_audit": ["security", "secrets", "dependencies"],
    "code_health":    ["architecture", "code_quality", "technical_debt", "scalability"],
    # Legacy names — keep backward-compat
    "full":           ["architecture", "scalability", "code_quality", "security", "dependencies", "secrets", "technical_debt", "contributor_risk"],
    "quick":          ["security", "secrets", "dependencies"],
}


class GitScanRequest(_PBM):
    project_id: str
    profile: str = "full_source"
    custom_categories: list = []


@router.post("/git-repo", response_model=ScanResponse)
async def scan_git_repo(
    request: GitScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Start a source-code security scan on a git-connected project.
    Clones the repo, runs Secrets + SAST + Dependency audit + Semgrep.
    """
    from services.git_service import git_service, GitCloneError
    from services.source_analysis_service import SourceAnalysisService
    from database.crud import create_scan, update_scan_status, update_scan_progress, create_finding
    from database.models import ScanStatus, FindingSeverity
    from services.events import event_bus

    project = await get_project(db, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Log state for diagnostics
    logger.info(f"[git-repo] project {project.id}: source_type={project.source_type!r}, repo_url={bool(project.repo_url)}")

    # Accept 'git', 'github', 'gitlab', or any non-upload value if repo_url is set
    is_git = project.source_type not in (None, "upload") or bool(project.repo_url)
    if not is_git or not project.repo_url:
        logger.error(
            f"[git-repo] Rejected: source_type={project.source_type!r} repo_url={project.repo_url!r}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Project has no repository URL (source_type={project.source_type!r}). "
                   "Ensure repo_url was set when creating the project."
        )

    scan = await create_scan(db=db, project_id=project.id, profile=request.profile)
    scan_id = scan.id

    async def run_source_scan():
        from database.connection import get_db as _get_db
        import shutil as _shutil

        # Helper: run a DB operation in its own short-lived session so we
        # never hold a write lock for the entire scan duration (SQLite can
        # only have one writer at a time).
        async def _db_op(fn):
            async with _get_db() as s:
                return await fn(s)

        try:
            # Small delay to ensure SSE client is connected before events fire
            await asyncio.sleep(0.8)

            async def _set_status(st, err=None):
                async with _get_db() as s:
                    await update_scan_status(s, scan_id, st, err)

            async def _set_progress(pct):
                async with _get_db() as s:
                    await update_scan_progress(s, scan_id, pct)

            await _set_status(ScanStatus.RUNNING)
            await event_bus.emit(scan_id, "status", {"message": "Starting source-code scan…"})

            clone_dir = settings.projects_path / f"{scan_id}_src"

            # Clean up any stale clone from a previous failed scan
            if clone_dir.exists():
                _shutil.rmtree(clone_dir, ignore_errors=True)
                logger.info(f"[git-repo scan] Cleaned up existing clone dir: {clone_dir}")

            async def _cb(msg: str):
                await event_bus.emit(scan_id, "progress", {"message": msg})

            # Determine which categories to run based on profile
            profile = request.profile
            categories = (
                request.custom_categories
                if profile == "custom_repo" and request.custom_categories
                else _REPO_PROFILE_CATEGORIES.get(profile, _REPO_PROFILE_CATEGORIES["full_source"])
            )
            logger.info(f"[git-repo scan] profile={profile!r}, categories={categories}")

            # 1. Clone (no DB session needed — pure I/O)
            await event_bus.emit(scan_id, "tool_start", {"tool": "repo_clone", "message": "Cloning repository…"})
            try:
                clone_path = await git_service.clone(
                    repo_url=project.repo_url,
                    dest_dir=clone_dir,
                    branch=project.repo_branch or "main",
                    token=project.repo_token,
                    progress_callback=lambda m: None,
                )
                await _cb("Repository cloned — running source code analysis…")
                # Persist clone path in its own short session
                async with _get_db() as s:
                    from database.crud import get_project as _get_proj
                    proj = await _get_proj(s, project.id)
                    if proj:
                        proj.target_path = str(clone_path)
                        await s.commit()
            except GitCloneError as e:
                await _set_status(ScanStatus.FAILED, str(e))
                await event_bus.emit(scan_id, "error", {"message": f"Clone failed: {e}"})
                return
            await event_bus.emit(scan_id, "tool_complete", {"tool": "repo_clone", "findings_count": 0})
            await _set_progress(10)

            # 2. Analyze with SourceAnalysisService using selected categories
            _stage_map = {
                "architecture":    "repo_arch",
                "scalability":     "repo_quality",
                "code_quality":    "repo_quality",
                "security":        "repo_security",
                "dependencies":    "repo_deps",
                "secrets":         "repo_secrets",
                "technical_debt":  "repo_debt",
                "contributor_risk":"repo_contrib",
            }
            total_cats = len(categories)
            for i, cat in enumerate(categories):
                stage = _stage_map.get(cat, "repo_quality")
                await event_bus.emit(scan_id, "tool_start", {"tool": stage, "message": f"Analyzing {cat.replace('_', ' ')}…"})
                await event_bus.emit(scan_id, "progress_pct", {"progress": 10 + int(70 * i / max(total_cats, 1))})

            # SourceAnalysisService gets its own session internally per category
            await event_bus.emit(scan_id, "progress", {"message": "Running source code analysis…"})
            async with _get_db() as analysis_session:
                analysis_service = SourceAnalysisService(session=analysis_session)
                results = await analysis_service.run_selective_analysis(
                    project_id=project.id,
                    repo_path=clone_path,
                    categories=categories,
                    scan_id=scan_id,
                    progress_callback=lambda pct, msg: None,
                )

            # Mark all active category stages complete with real finding counts
            cat_results = results.get("results", {})
            for cat in categories:
                stage = _stage_map.get(cat, "repo_quality")
                cat_data = cat_results.get(cat, {})
                fcount = len(cat_data.get("findings", [])) if cat_data else 0
                await event_bus.emit(scan_id, "tool_complete", {"tool": stage, "findings_count": fcount})
            await _set_progress(80)

            # 3. Emit findings from the new CategoryFinding table
            from database.crud import get_category_findings_by_project, get_source_analysis_result
            async with _get_db() as s:
                findings = await get_category_findings_by_project(s, project.id)
                _clone_prefix = str(clone_dir) + "/"
                _ar_cat_cache: dict = {}
                for f in findings:
                    cat_value = _ar_cat_cache.get(f.analysis_result_id)
                    if cat_value is None:
                        ar = await get_source_analysis_result(s, f.analysis_result_id)
                        cat_value = ar.category.value if ar and hasattr(ar.category, 'value') else (str(ar.category) if ar else "unknown")
                        _ar_cat_cache[f.analysis_result_id] = cat_value
                    loc = f.file_path
                    if loc and loc.startswith(_clone_prefix):
                        loc = loc[len(_clone_prefix):]
                    await event_bus.emit(scan_id, "finding", {
                        "finding_id": f.id,
                        "title": f.finding_type,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "location": loc,
                        "category": cat_value,
                        "tool": f.tool,
                    })

            # 4. AI triage
            await event_bus.emit(scan_id, "tool_start", {"tool": "repo_ai", "message": "AI triage — correlating findings…"})
            await event_bus.emit(scan_id, "tool_complete", {"tool": "repo_ai", "findings_count": len(findings)})
            await _set_progress(90)

            # 5. Keep clone dir alive — source analysis page needs the repo for browsing
            # git_service.cleanup(clone_dir)

            await _set_status(ScanStatus.COMPLETED)
            await _set_progress(100)
            await event_bus.emit(scan_id, "complete", {"findings_count": len(findings)})

        except Exception as e:
            logger.error(f"[git-repo scan] Unhandled error: {e}", exc_info=True)
            try:
                async with _get_db() as s:
                    await update_scan_status(s, scan_id, ScanStatus.FAILED, str(e))
            except Exception:
                pass
            await event_bus.emit(scan_id, "error", {"message": str(e)})

    background_tasks.add_task(run_source_scan)

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        profile=scan.profile,
        status=scan.status.value,
        progress=scan.progress,
        created_at=scan.created_at,
    )