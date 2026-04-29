"""
IRVES — Session Persistence Routes
Phase F: API endpoints for analysis session management.

Endpoints:
- POST /api/sessions - Create new session
- GET /api/sessions - List sessions
- GET /api/sessions/{id} - Get session details
- POST /api/sessions/{id}/checkpoint - Create checkpoint
- POST /api/sessions/{id}/pause - Pause session
- POST /api/sessions/{id}/resume - Resume session
- GET /api/scans/{scan_id}/session - Get session for scan
- POST /api/sessions/{id}/auto-save - Trigger auto-save
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db_session
from database.models import Scan, Project
from services.session_store import session_store, AnalysisSession, SessionStatus

router = APIRouter(prefix="/api", tags=["sessions"])


# Request/Response Models
class CreateSessionRequest(BaseModel):
    scan_id: str
    scan_config: Optional[Dict[str, Any]] = None


class CreateCheckpointRequest(BaseModel):
    name: str
    description: str = ""
    phase: str
    task_id: Optional[str] = None
    progress: int = Field(0, ge=0, le=100)
    findings_count: int = 0
    metadata: Optional[Dict[str, Any]] = None


class ResumeRequest(BaseModel):
    from_checkpoint: Optional[str] = None


class UpdateNotesRequest(BaseModel):
    notes: str


@router.post("/sessions")
async def create_session(
    request: CreateSessionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """
    Create a new analysis session for a scan.

    Sessions track progress and enable resumable analysis.
    """
    # Verify scan exists
    scan = await db.get(Scan, request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get project info
    project = await db.get(Project, scan.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        session = await session_store.create_session(
            scan_id=request.scan_id,
            project_id=project.id,
            project_name=project.name,
            platform=project.platform,
            scan_config=request.scan_config,
        )

        return {
            "success": True,
            "session": session.to_dict(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create session: {str(e)}")


@router.get("/sessions")
async def list_sessions(
    project_id: Optional[str] = Query(None, description="Filter by project"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> Dict[str, Any]:
    """
    List analysis sessions.

    Args:
        project_id: Filter by project
        status: Filter by status (active, paused, completed, failed)
    """
    try:
        status_filter = SessionStatus(status) if status else None
        sessions = await session_store.list_sessions(
            project_id=project_id,
            status=status_filter,
        )

        return {
            "success": True,
            "sessions": [s.to_dict() for s in sessions],
            "count": len(sessions),
        }

    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Get detailed session information."""
    session = await session_store.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "session": session.to_dict(),
    }


@router.get("/scans/{scan_id}/session")
async def get_scan_session(
    scan_id: str = Path(..., description="Scan ID"),
) -> Dict[str, Any]:
    """Get the active session for a scan."""
    session = await session_store.get_session_by_scan(scan_id)

    if not session:
        return {
            "success": True,
            "has_session": False,
            "session": None,
        }

    return {
        "success": True,
        "has_session": True,
        "session": session.to_dict(),
    }


@router.post("/sessions/{session_id}/checkpoint")
async def create_checkpoint(
    request: CreateCheckpointRequest,
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Create a checkpoint in the analysis session."""
    checkpoint = await session_store.create_checkpoint(
        session_id=session_id,
        name=request.name,
        description=request.description,
        phase=request.phase,
        task_id=request.task_id,
        progress=request.progress,
        findings_count=request.findings_count,
        metadata=request.metadata,
    )

    if not checkpoint:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "checkpoint": {
            "checkpoint_id": checkpoint.checkpoint_id,
            "name": checkpoint.name,
            "phase": checkpoint.phase,
            "progress_percentage": checkpoint.progress_percentage,
            "timestamp": checkpoint.timestamp.isoformat(),
        },
    }


@router.post("/sessions/{session_id}/pause")
async def pause_session(
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Pause an active analysis session."""
    session = await session_store.pause_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "message": "Session paused",
        "session_id": session_id,
        "status": session.status.value,
    }


@router.post("/sessions/{session_id}/resume")
async def resume_session(
    request: ResumeRequest,
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """
    Resume a paused analysis session.

    Optionally resume from a specific checkpoint.
    """
    session = await session_store.resume_session(
        session_id=session_id,
        from_checkpoint=request.from_checkpoint,
    )

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    response = {
        "success": True,
        "message": "Session resumed",
        "session_id": session_id,
        "status": session.status.value,
    }

    if session.resume_from_phase:
        response["resume_from"] = {
            "phase": session.resume_from_phase,
            "task_id": session.resume_from_task,
        }

    return response


@router.post("/sessions/{session_id}/auto-save")
async def trigger_auto_save(
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Manually trigger auto-save for a session."""
    success = await session_store.auto_save(session_id)

    if not success:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "message": "Session auto-saved",
        "session_id": session_id,
    }


@router.post("/sessions/{session_id}/complete")
async def complete_session(
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Mark a session as completed."""
    session = await session_store.complete_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "message": "Session completed",
        "session_id": session_id,
        "status": session.status.value,
    }


@router.post("/sessions/{session_id}/notes")
async def update_session_notes(
    request: UpdateNotesRequest,
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Update session notes."""
    session = await session_store.update_session(
        session_id=session_id,
        updates={"user_notes": request.notes},
    )

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "message": "Notes updated",
        "session_id": session_id,
    }


@router.get("/sessions/{session_id}/checkpoints")
async def get_session_checkpoints(
    session_id: str = Path(..., description="Session ID"),
) -> Dict[str, Any]:
    """Get all checkpoints for a session."""
    session = await session_store.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "success": True,
        "session_id": session_id,
        "checkpoints": [
            {
                "checkpoint_id": c.checkpoint_id,
                "name": c.name,
                "description": c.description,
                "phase": c.phase,
                "progress_percentage": c.progress_percentage,
                "findings_count": c.findings_count,
                "timestamp": c.timestamp.isoformat(),
            }
            for c in session.checkpoints
        ],
        "count": len(session.checkpoints),
        "current_checkpoint_id": session.current_checkpoint_id,
    }
