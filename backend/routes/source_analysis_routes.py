"""
IRVES — Source Code Analysis Routes
API endpoints for source code analysis across 8 categories.

Endpoints:
- POST /api/source-analysis/{project_id}/run - Trigger full analysis
- GET /api/source-analysis/{project_id} - Get latest analysis results
- GET /api/source-analysis/{project_id}/status - Check analysis progress
- GET /api/source-analysis/{project_id}/category/{category} - Get specific category
- POST /api/source-analysis/{project_id}/invalidate - Force recompute
- POST /api/source-analysis/{project_id}/chat - AI assistant (SSE)
"""

from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db_session
from database.models import AnalysisCategory, AnalysisStatus, FindingSeverity
from database.crud import (
    get_project,
    get_source_analysis_results_by_project,
    get_latest_source_analysis,
    get_category_findings,
    update_source_analysis_result,
    delete_category_findings,
)
from services.source_analysis_service import source_analysis_service, SourceAnalysisService
from services.ai_service import ai_service
from config import settings

router = APIRouter(prefix="/api/source-analysis", tags=["source-analysis"])


# ── Request/Response Models ─────────────────────────────────────────────────────

class AnalysisRunRequest(BaseModel):
    """Request to run source code analysis."""
    scan_id: Optional[str] = Field(None, description="Optional scan ID to link results")


class AnalysisStatusResponse(BaseModel):
    """Response with analysis status."""
    status: str
    progress: int
    current_category: Optional[str] = None
    error_message: Optional[str] = None


class CategorySummaryResponse(BaseModel):
    """Response with category summary."""
    category: str
    status: str
    summary_metrics: Dict[str, Any]
    finding_count: int
    severity_breakdown: Dict[str, int]


class ChatRequest(BaseModel):
    """Request for AI chat about analysis."""
    message: str = Field(..., description="User message")
    category: Optional[str] = Field(None, description="Optional category to focus on")


# ── Progress Tracking ───────────────────────────────────────────────────────────

_analysis_progress: Dict[str, Dict[str, Any]] = {}  # project_id -> {status, progress, current_category}


def _update_progress(project_id: str, progress: int, current_category: str = None):
    """Update analysis progress for a project."""
    _analysis_progress[project_id] = {
        "status": "running",
        "progress": progress,
        "current_category": current_category,
        "error_message": None,
    }


def _complete_analysis(project_id: str, error: str = None):
    """Mark analysis as complete or failed."""
    _analysis_progress[project_id] = {
        "status": "completed" if not error else "failed",
        "progress": 100 if not error else 0,
        "current_category": None,
        "error_message": error,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/{project_id}/run")
async def run_analysis(
    project_id: str,
    request: AnalysisRunRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Trigger full source code analysis across all 8 categories.

    Runs in background to avoid blocking. Progress can be tracked via /status endpoint.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.platform != "repository":
        raise HTTPException(
            status_code=400,
            detail="Source code analysis only available for repository projects"
        )

    if not project.target_path:
        # For git projects, derive clone path from project ID
        if project.repo_url:
            clone_dir = settings.projects_path / f"{project.id}_src"
            if clone_dir.exists():
                repo_path = clone_dir
            else:
                raise HTTPException(status_code=400, detail="Repository not cloned yet. Run a scan first.")
        else:
            raise HTTPException(status_code=400, detail="Repository path not set")
    else:
        repo_path = Path(project.target_path)

    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="Repository directory not found")

    # Initialize progress tracking
    _update_progress(project_id, 0, "initializing")

    # Run analysis in background
    background_tasks.add_task(
        _run_analysis_background,
        project_id,
        repo_path,
        request.scan_id,
    )

    return {
        "success": True,
        "project_id": project_id,
        "status": "started",
        "message": "Source code analysis started in background",
    }


async def _run_analysis_background(
    project_id: str,
    repo_path: Path,
    scan_id: Optional[str],
):
    """Background task to run full analysis."""
    try:
        svc = SourceAnalysisService()
        await svc.run_full_analysis(
            project_id=project_id,
            repo_path=repo_path,
            scan_id=scan_id,
            progress_callback=lambda p, cat: _update_progress(project_id, p, cat),
        )
        _complete_analysis(project_id)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"[SourceAnalysis] Background analysis failed: {e}")
        _complete_analysis(project_id, str(e))


@router.get("/{project_id}")
async def get_analysis_results(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get latest source code analysis results for a project.

    Returns summary metrics and findings for all 8 categories.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    results = await get_source_analysis_results_by_project(db, project_id)

    if not results:
        return {
            "success": True,
            "project_id": project_id,
            "has_analysis": False,
            "categories": {},
        }

    # Group results by category
    categories = {}
    for result in results:
        # Get findings count
        findings = await get_category_findings(db, result.id)

        # Severity breakdown
        severity_breakdown = {}
        for f in findings:
            sev = f.severity.value
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        categories[result.category.value] = {
            "status": result.status.value,
            "progress": result.progress,
            "summary_metrics": result.summary_metrics or {},
            "finding_count": len(findings),
            "severity_breakdown": severity_breakdown,
            "ai_explanation": result.ai_explanation,
            "ai_recommendations": result.ai_recommendations,
            "created_at": result.created_at.isoformat() if result.created_at else None,
            "duration_seconds": result.duration_seconds,
        }

    return {
        "success": True,
        "project_id": project_id,
        "has_analysis": True,
        "categories": categories,
    }


@router.get("/{project_id}/status")
async def get_analysis_status(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Check analysis progress for a project.

    Returns current status, progress percentage, and current category being analyzed.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check in-memory progress first
    if project_id in _analysis_progress:
        return {
            "success": True,
            "project_id": project_id,
            **_analysis_progress[project_id],
        }

    # Fall back to database
    results = await get_source_analysis_results_by_project(db, project_id)

    if not results:
        return {
            "success": True,
            "project_id": project_id,
            "status": "not_started",
            "progress": 0,
            "current_category": None,
            "error_message": None,
        }

    # Calculate overall progress
    total_categories = len(AnalysisCategory)
    completed = sum(1 for r in results if r.status == AnalysisStatus.COMPLETED)
    progress = int((completed / total_categories) * 100)

    # Get current running category
    running = [r for r in results if r.status == AnalysisStatus.RUNNING]
    current_category = running[0].category.value if running else None

    return {
        "success": True,
        "project_id": project_id,
        "status": "running" if running else "completed",
        "progress": progress,
        "current_category": current_category,
        "error_message": None,
    }


@router.get("/{project_id}/category/{category}")
async def get_category_analysis(
    project_id: str,
    category: str,
    limit: int = Query(100, description="Maximum number of findings to return"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get detailed analysis for a specific category.

    Includes summary metrics and individual findings.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate category
    try:
        category_enum = AnalysisCategory(category)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: {category}. Must be one of: {[c.value for c in AnalysisCategory]}"
        )

    result = await get_latest_source_analysis(db, project_id, category_enum)

    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"No analysis found for category: {category}"
        )

    # Get findings
    severity_filter = None
    if severity:
        try:
            severity_filter = FindingSeverity(severity)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity: {severity}"
            )

    findings = await get_category_findings(db, result.id, severity_filter, limit)

    # Convert findings to dict — strip clone dir prefix from file_path
    clone_prefix = str(settings.projects_path / f"{project_id}_src") + "/"
    findings_list = []
    for f in findings:
        fp = f.file_path
        if fp and fp.startswith(clone_prefix):
            fp = fp[len(clone_prefix):]
        elif fp and fp.startswith("/"):
            # Try to make any absolute path relative to clone dir
            for suffix in ["_src/"]:
                idx = fp.find(suffix)
                if idx != -1:
                    fp = fp[idx + len(suffix):]
                    break
        findings_list.append({
            "id": f.id,
            "type": f.finding_type,
            "severity": f.severity.value,
            "file_path": fp,
            "line_number": f.line_number,
            "column_number": f.column_number,
            "message": f.message,
            "code_snippet": f.code_snippet,
            "tool": f.tool,
            "metadata": f.extra_data,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    return {
        "success": True,
        "project_id": project_id,
        "category": category,
        "status": result.status.value,
        "progress": result.progress,
        "summary_metrics": result.summary_metrics or {},
        "detailed_findings": result.detailed_findings or {},
        "ai_explanation": result.ai_explanation,
        "ai_recommendations": result.ai_recommendations,
        "findings": findings_list,
        "created_at": result.created_at.isoformat() if result.created_at else None,
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "duration_seconds": result.duration_seconds,
    }


@router.post("/{project_id}/invalidate")
async def invalidate_cache(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Force recompute of source code analysis.

    Deletes cached analysis results. Next analysis will run fresh.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    await source_analysis_service.invalidate_cache(project_id, db)

    # Clear progress tracking
    if project_id in _analysis_progress:
        del _analysis_progress[project_id]

    return {
        "success": True,
        "project_id": project_id,
        "message": "Cache invalidated. Next analysis will run fresh.",
    }


@router.post("/{project_id}/chat")
async def analysis_chat(
    project_id: str,
    payload: ChatRequest,
    request,
    db: AsyncSession = Depends(get_db_session),
):
    """
    AI assistant for source code analysis.

    Stream AI responses about analysis findings, recommendations, and explanations.
    Uses Server-Sent Events (SSE) for real-time streaming.
    """
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(
            status_code=503,
            detail="AI analysis not configured. Set an API key in Settings → AI Reasoning Layer"
        )

    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    # Get analysis results as context
    results = await get_source_analysis_results_by_project(db, project_id)

    context = {
        "project_name": project.name,
        "project_platform": project.platform,
        "analysis_results": {},
    }

    for result in results:
        if payload.category and result.category.value != payload.category:
            continue

        findings = await get_category_findings(db, result.id, limit=50)
        context["analysis_results"][result.category.value] = {
            "summary_metrics": result.summary_metrics,
            "finding_count": len(findings),
            "ai_explanation": result.ai_explanation,
            "top_findings": [
                {
                    "type": f.finding_type,
                    "severity": f.severity.value,
                    "message": f.message,
                    "file_path": f.file_path,
                }
                for f in findings[:10]
            ],
        }

    # Generate user ID for conversation tracking
    user_id = _get_user_id(request)
    session_id = f"source_analysis_{project_id}"

    async def event_gen():
        try:
            user_context = ai_service.conversation_memory.get_context(user_id, session_id)
            yield f"data: {json.dumps({'metadata': {'expertise_level': user_context.user_expertise_level, 'source_analysis_session': True}})}\n\n"

            async for chunk in ai_service.stream_source_analysis_chat(
                question=payload.message,
                analysis_context=context,
                user_id=user_id,
                session_id=session_id,
            ):
                yield f"data: {json.dumps({'token': chunk})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _get_user_id(request) -> str:
    """Generate consistent user ID from request."""
    import hashlib
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    user_string = f"{client_ip}:{user_agent}"
    return hashlib.md5(user_string.encode()).hexdigest()[:12]
