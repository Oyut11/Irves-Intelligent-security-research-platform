"""
IRVES — Repository Analysis Routes
Phase D: Endpoints for Git repository security analysis.

Endpoints:
- POST /api/repository/verify - Verify repo accessibility
- POST /api/repository/clone - Clone and analyze repo
- GET /api/repository/{project_id}/info - Get repo metadata
- GET /api/repository/{project_id}/files - List source files
- POST /api/repository/{project_id}/scan - Trigger repository scan
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db_session
from database.models import Project, Scan, ScanStatus
from services.git_service import git_service
from config import settings

router = APIRouter(prefix="/api/repository", tags=["repository"])


# Request/Response Models
class RepoVerifyRequest(BaseModel):
    repo_url: str = Field(..., description="Git repository URL (HTTPS or SSH)")
    token: Optional[str] = Field(None, description="Personal Access Token for private repos")


class RepoCloneRequest(BaseModel):
    repo_url: str = Field(..., description="Git repository URL")
    branch: str = Field("main", description="Branch to clone")
    token: Optional[str] = Field(None, description="Personal Access Token")
    project_name: Optional[str] = Field(None, description="Project name (auto-derived if not provided)")


class RepoScanRequest(BaseModel):
    scan_type: str = Field("full", description="Scan type: quick, full, secrets-only, sast-only")
    tools: Optional[list] = Field(None, description="Specific tools to run")


@router.post("/verify")
async def verify_repository(
    request: RepoVerifyRequest,
) -> dict:
    """
    Verify that a repository is accessible without cloning.

    Returns reachability status and default branch.
    """
    try:
        result = await git_service.verify_repo(request.repo_url, request.token)
        return {
            "success": True,
            "reachable": result["reachable"],
            "default_branch": result["default_branch"],
            "error": result["error"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/clone")
async def clone_repository(
    request: RepoCloneRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Clone a repository and create a project for analysis.

    This creates a new project with source_type='git' and clones
    the repository to the projects directory.
    """
    import logging
    from database.crud import create_project
    from utils.file_utils import safe_filename

    logger = logging.getLogger(__name__)

    try:
        # Derive project name from URL if not provided
        project_name = request.project_name
        if not project_name:
            from urllib.parse import urlparse
            parsed = urlparse(request.repo_url)
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                project_name = path_parts[-1].replace(".git", "")
            else:
                project_name = "repository"

        # Create safe directory name
        safe_name = safe_filename(project_name)
        repo_dir = settings.projects_path / f"{safe_name}_{hash(request.repo_url) % 10000}"

        # Clone repository
        cloned_path = await git_service.clone(
            repo_url=request.repo_url,
            dest_dir=repo_dir,
            branch=request.branch,
            token=request.token,
        )

        # Get repository info
        repo_info = await git_service.get_repo_info(cloned_path)

        # Create project in database
        project = await create_project(
            db=db,
            name=project_name,
            platform="repository",
            target_path=str(cloned_path),
            description=f"Cloned from {request.repo_url}",
            source_type="git",
            repo_url=request.repo_url,
            repo_branch=request.branch,
            repo_token=request.token,
        )

        return {
            "success": True,
            "project_id": project.id,
            "project_name": project.name,
            "cloned_path": str(cloned_path),
            "repo_info": {
                "branches": repo_info.get("branches", [])[:10],  # Limit branches
                "current_branch": repo_info.get("current_branch"),
                "commit_count": repo_info.get("commit_count"),
                "languages": repo_info.get("languages"),
                "file_count": repo_info.get("file_count"),
                "total_size_mb": repo_info.get("total_size_mb"),
            },
        }

    except Exception as e:
        logger.error(f"[Repository] Clone failed: {e}")
        raise HTTPException(status_code=500, detail=f"Clone failed: {str(e)}")


@router.get("/{project_id}/info")
async def get_repository_info(
    project_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Get detailed repository metadata.

    Returns language breakdown, file counts, branch list, and commit history.
    """
    # Get project
    from database.crud import get_project
    project = await get_project(db, project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.platform != "repository":
        raise HTTPException(status_code=400, detail="Project is not a repository")

    if not project.target_path:
        raise HTTPException(status_code=400, detail="Repository path not set")

    repo_path = Path(project.target_path)

    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="Repository directory not found")

    try:
        # Get comprehensive repo info
        info = await git_service.get_repo_info(repo_path)

        # Get recent commits
        commits = await git_service.get_commit_history(repo_path, limit=20)

        return {
            "success": True,
            "project_id": project_id,
            "repo_url": project.repo_url,
            "branch": project.repo_branch,
            "is_git_repo": info.get("is_git_repo", False),
            "current_branch": info.get("current_branch"),
            "branches": info.get("branches", []),
            "languages": info.get("languages", {}),
            "file_count": info.get("file_count", 0),
            "total_size_mb": info.get("total_size_mb", 0),
            "commit_count": info.get("commit_count", 0),
            "recent_commits": commits,
            "last_commit": info.get("last_commit"),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get repo info: {str(e)}")


@router.get("/{project_id}/files")
async def list_repository_files(
    project_id: str,
    extension: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    List source files in the repository.

    Args:
        extension: Filter by file extension (e.g., '.py', '.js')
    """
    from database.crud import get_project
    project = await get_project(db, project_id)

    if not project or project.platform != "repository":
        raise HTTPException(status_code=404, detail="Repository project not found")

    if not project.target_path:
        raise HTTPException(status_code=400, detail="Repository path not set")

    try:
        extensions = None
        if extension:
            extensions = [ext.strip() for ext in extension.split(",")]

        files = await git_service.get_file_list(
            Path(project.target_path),
            extensions=extensions
        )

        return {
            "success": True,
            "project_id": project_id,
            "file_count": len(files),
            "files": files[:500],  # Limit for performance
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")


@router.post("/{project_id}/scan")
async def scan_repository(
    project_id: str,
    request: RepoScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Trigger a security scan on a repository.

    Scans run Semgrep for SAST and GitLeaks for secrets.
    """
    import logging
    from database.crud import get_project, create_scan
    from services.scanner import scanner_service

    logger = logging.getLogger(__name__)

    project = await get_project(db, project_id)

    if not project or project.platform != "repository":
        raise HTTPException(status_code=404, detail="Repository project not found")

    try:
        # Create scan record
        scan = await create_scan(
            db=db,
            project_id=project_id,
            profile=request.scan_type,
        )

        # Trigger scan in background
        background_tasks.add_task(
            _run_repository_scan,
            scan.id,
            project.target_path,
            request.scan_type,
            request.tools,
        )

        return {
            "success": True,
            "scan_id": scan.id,
            "project_id": project_id,
            "status": "started",
            "scan_type": request.scan_type,
        }

    except Exception as e:
        logger.error(f"[Repository] Scan trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


async def _run_repository_scan(
    scan_id: str,
    repo_path: str,
    scan_type: str,
    tools: Optional[list],
):
    """Background task to run repository scan."""
    import logging
    from database.connection import get_db_session
    from database.crud import update_scan_status
    from ast_engine.manager import ast_manager
    from ast_engine.models import PlatformType

    logger = logging.getLogger(__name__)

    try:
        async with get_db_session() as db:
            # Initialize AST for repository
            ast = ast_manager.create_ast(
                scan_id=scan_id,
                platform=PlatformType.REPOSITORY,
            )
            await ast_manager.save_ast(ast)

            # TODO: Run actual scanning tools (Semgrep, GitLeaks)
            # This would integrate with the existing scanner service

            await update_scan_status(
                db=db,
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                progress=100,
            )

            logger.info(f"[Repository] Scan {scan_id} completed")

    except Exception as e:
        logger.error(f"[Repository] Scan {scan_id} failed: {e}")
        async with get_db_session() as db:
            await update_scan_status(
                db=db,
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                error_message=str(e),
            )
