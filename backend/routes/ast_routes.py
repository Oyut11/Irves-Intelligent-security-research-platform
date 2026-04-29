"""
IRVES — AST API Routes
Phase 2: Analysis State Tree endpoints for task tracking.

Endpoints:
- GET /api/scans/{id}/ast - Get full AST for a scan
- GET /api/scans/{id}/ast/progress - Get progress summary
- GET /api/scans/{id}/next-task - Get next suggested task
- POST /api/scans/{id}/skip-phase - Skip a phase
- POST /api/scans/{id}/reset-ast - Reset AST to initial state
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession

from ast_engine.manager import ast_manager
from ast_engine.models import AnalysisPhase, PlatformType
from database.connection import get_db_session
from database.models import Scan, ScanStatus

router = APIRouter(prefix="/api/scans", tags=["ast"])


@router.get("/{scan_id}/ast")
async def get_ast(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Get the complete Analysis State Tree for a scan.

    Returns:
        Full AST with tasks, phases, and progress
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load AST
    ast = await ast_manager.load_ast(scan_id)

    if not ast:
        # Create new AST if not exists
        platform = PlatformType(scan.project.platform) if scan.project else PlatformType.ANDROID
        ast = ast_manager.create_ast(scan_id, platform)
        await ast_manager.save_ast(ast)

    return {
        "scan_id": scan_id,
        "platform": ast.platform.value,
        "current_phase": ast.current_phase.value if ast.current_phase else None,
        "current_task_id": ast.current_task_id,
        "tasks": [t.to_dict() for t in ast.tasks],
        "progress": ast.get_progress_stats(),
        "created_at": ast.created_at.isoformat(),
        "updated_at": ast.updated_at.isoformat(),
    }


@router.get("/{scan_id}/ast/progress")
async def get_ast_progress(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Get progress summary for a scan.

    Returns:
        Progress statistics including percentage and task counts
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    progress = await ast_manager.get_progress(scan_id)

    if not progress:
        return {
            "scan_id": scan_id,
            "progress_percentage": scan.progress,
            "total_tasks": 0,
            "by_status": {},
            "by_phase": {},
        }

    return {
        "scan_id": scan_id,
        **progress,
    }


@router.get("/{scan_id}/next-task")
async def get_next_task(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Get the next task that should be executed.

    Returns:
        Next task details or null if all complete
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ensure AST exists
    ast = await ast_manager.load_ast(scan_id)
    if not ast:
        platform = PlatformType(scan.project.platform) if scan.project else PlatformType.ANDROID
        ast = ast_manager.create_ast(scan_id, platform)
        await ast_manager.save_ast(ast)

    next_task = await ast_manager.get_next_task(scan_id)

    if not next_task:
        return {
            "scan_id": scan_id,
            "has_next_task": False,
            "message": "All tasks completed or no available tasks",
        }

    return {
        "scan_id": scan_id,
        "has_next_task": True,
        "task": next_task.to_dict(),
        "phase_display": ast_manager.get_phase_display_name(next_task.phase),
    }


@router.get("/{scan_id}/suggested-tasks")
async def get_suggested_tasks(
    scan_id: str = Path(..., description="Scan ID"),
    limit: int = 3,
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Get AI-suggested next tasks based on priority and dependencies.

    Args:
        limit: Maximum number of suggestions (default 3)

    Returns:
        List of suggested tasks with rationale
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ensure AST exists
    ast = await ast_manager.load_ast(scan_id)
    if not ast:
        platform = PlatformType(scan.project.platform) if scan.project else PlatformType.ANDROID
        ast = ast_manager.create_ast(scan_id, platform)
        await ast_manager.save_ast(ast)

    suggestions = await ast_manager.get_suggested_tasks(scan_id, limit)

    return {
        "scan_id": scan_id,
        "suggestions": [t.to_dict() for t in suggestions],
        "count": len(suggestions),
    }


@router.post("/{scan_id}/skip-phase")
async def skip_phase(
    scan_id: str = Path(..., description="Scan ID"),
    phase: AnalysisPhase = AnalysisPhase.STATIC,
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Skip all tasks in a specific phase.

    Args:
        phase: Phase to skip (static, dynamic, network, exploit)

    Returns:
        Success status and number of tasks skipped
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    ast = await ast_manager.load_ast(scan_id)
    if not ast:
        raise HTTPException(status_code=400, detail="No AST exists for this scan")

    # Count tasks in phase
    phase_tasks = [t for t in ast.tasks if t.phase == phase]
    skipped_count = len([t for t in phase_tasks if t.status.value == "pending"])

    # Skip the phase
    success = await ast_manager.skip_phase(scan_id, phase)

    if not success:
        raise HTTPException(status_code=400, detail=f"No tasks to skip in phase {phase.value}")

    return {
        "scan_id": scan_id,
        "phase": phase.value,
        "phase_display": ast_manager.get_phase_display_name(phase),
        "tasks_skipped": skipped_count,
        "success": True,
    }


@router.post("/{scan_id}/reset-ast")
async def reset_ast(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Reset AST to initial state for re-analysis.

    This clears all task progress but keeps the task structure.
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    success = await ast_manager.reset_ast(scan_id)

    if not success:
        raise HTTPException(status_code=400, detail="Failed to reset AST")

    # Reset scan progress
    scan.progress = 0
    scan.status = ScanStatus.PENDING
    await db.commit()

    return {
        "scan_id": scan_id,
        "success": True,
        "message": "AST reset successfully. All tasks returned to pending state.",
    }


@router.get("/{scan_id}/ast/tree")
async def get_ast_tree_view(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Get AST formatted as a tree for UI display.

    Returns:
        Hierarchical tree structure with phases and tasks
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    ast = await ast_manager.load_ast(scan_id)
    if not ast:
        platform = PlatformType(scan.project.platform) if scan.project else PlatformType.ANDROID
        ast = ast_manager.create_ast(scan_id, platform)
        await ast_manager.save_ast(ast)

    # Build tree structure
    phases = {}
    for phase in AnalysisPhase:
        phase_tasks = ast.get_tasks_by_phase(phase)
        if phase_tasks:
            phases[phase.value] = {
                "name": ast_manager.get_phase_display_name(phase),
                "tasks": [t.to_dict() for t in phase_tasks],
                "completed": sum(1 for t in phase_tasks if t.is_complete),
                "total": len(phase_tasks),
                "locked": phase_tasks[0].status.value == "blocked" if phase_tasks else False,
            }

    return {
        "scan_id": scan_id,
        "platform": ast.platform.value,
        "phases": phases,
        "current_task_id": ast.current_task_id,
        "progress": ast.get_progress_stats(),
    }
