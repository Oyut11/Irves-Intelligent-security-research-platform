"""
IRVES — AST Manager
Operations and lifecycle management for Analysis State Trees.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ast_engine.models import (
    AnalysisPhase,
    AnalysisStateTree,
    AnalysisTask,
    PlatformType,
    TaskStatus,
)
from ast_engine.templates import get_template_for_platform
from database.connection import get_db_session
from database.models import Scan, ScanStatus

logger = logging.getLogger(__name__)


class ASTManager:
    """
    Manager for Analysis State Tree lifecycle.

    Handles:
    - Creating new ASTs from templates
    - Loading/saving AST to database
    - Task execution flow
    - Progress tracking
    """

    def __init__(self):
        self._cache: Dict[str, AnalysisStateTree] = {}

    def create_ast(
        self,
        scan_id: str,
        platform: PlatformType,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> AnalysisStateTree:
        """
        Create a new AST for a scan from platform template.

        Args:
            scan_id: Associated scan ID
            platform: Target platform
            custom_config: Optional custom configuration

        Returns:
            New AnalysisStateTree instance
        """
        tasks = get_template_for_platform(platform)

        ast = AnalysisStateTree(
            scan_id=scan_id,
            platform=platform,
            tasks=tasks,
            custom_config=custom_config or {},
        )

        # Cache it
        self._cache[scan_id] = ast

        logger.info(f"[ASTManager] Created AST for scan {scan_id} with {len(tasks)} tasks")
        return ast

    async def load_ast(self, scan_id: str) -> Optional[AnalysisStateTree]:
        """
        Load AST from database or cache.

        Args:
            scan_id: Scan ID to load AST for

        Returns:
            AnalysisStateTree or None if not found
        """
        # Check cache first
        if scan_id in self._cache:
            return self._cache[scan_id]

        # Load from database
        try:
            async with get_db_session() as db:
                scan = await db.get(Scan, scan_id)
                if not scan:
                    return None

                # AST is stored in scan.ast_data (JSON column)
                ast_data = getattr(scan, 'ast_data', None)
                if not ast_data:
                    return None

                if isinstance(ast_data, str):
                    ast = AnalysisStateTree.from_json(ast_data)
                else:
                    ast = AnalysisStateTree.from_dict(ast_data)

                self._cache[scan_id] = ast
                return ast
        except Exception as e:
            logger.error(f"[ASTManager] Failed to load AST for scan {scan_id}: {e}")
            return None

    async def save_ast(self, ast: AnalysisStateTree) -> bool:
        """
        Save AST to database.

        Args:
            ast: AST to save

        Returns:
            True if saved successfully
        """
        try:
            async with get_db_session() as db:
                scan = await db.get(Scan, ast.scan_id)
                if not scan:
                    logger.error(f"[ASTManager] Scan {ast.scan_id} not found")
                    return False

                # Update the ast_data field
                scan.ast_data = ast.to_dict()
                await db.commit()

                # Update cache
                self._cache[ast.scan_id] = ast

                return True
        except Exception as e:
            logger.error(f"[ASTManager] Failed to save AST for scan {ast.scan_id}: {e}")
            return False

    async def start_task(self, scan_id: str, task_id: str) -> Tuple[bool, str]:
        """
        Mark a task as in progress.

        Args:
            scan_id: Scan ID
            task_id: Task ID to start

        Returns:
            (success, error_message)
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return False, "AST not found"

        task = ast.get_task(task_id)
        if not task:
            return False, f"Task {task_id} not found"

        if not task.can_start:
            return False, f"Task cannot be started (status: {task.status.value})"

        # Check dependencies
        if task.dependencies:
            for dep_id in task.dependencies:
                dep = ast.get_task(dep_id)
                if not dep or not dep.is_complete:
                    return False, f"Dependency {dep_id} not complete"

        # Update status
        ast.update_task_status(task_id, TaskStatus.IN_PROGRESS)

        # Save
        await self.save_ast(ast)

        logger.info(f"[ASTManager] Started task {task_id} for scan {scan_id}")
        return True, ""

    async def complete_task(
        self,
        scan_id: str,
        task_id: str,
        findings_count: int = 0,
        output_summary: str = "",
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark a task as completed or failed.

        Args:
            scan_id: Scan ID
            task_id: Task ID to complete
            findings_count: Number of findings from this task
            output_summary: Brief summary of results
            error_message: Error if task failed

        Returns:
            True if updated successfully
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return False

        task = ast.get_task(task_id)
        if not task:
            return False

        # Determine final status
        if error_message:
            status = TaskStatus.FAILED
        else:
            status = TaskStatus.COMPLETED

        # Update task
        task.findings_count = findings_count
        task.output_summary = output_summary
        if error_message:
            task.error_message = error_message

        # Update AST
        ast.update_task_status(task_id, status)

        # Save
        await self.save_ast(ast)

        # Update scan progress
        await self._update_scan_progress(scan_id, ast)

        logger.info(
            f"[ASTManager] Completed task {task_id} for scan {scan_id} "
            f"(status: {status.value}, findings: {findings_count})"
        )
        return True

    async def skip_phase(self, scan_id: str, phase: AnalysisPhase) -> bool:
        """
        Skip all tasks in a phase.

        Args:
            scan_id: Scan ID
            phase: Phase to skip

        Returns:
            True if skipped successfully
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return False

        skipped = False
        for task in ast.tasks:
            if task.phase == phase and task.status == TaskStatus.PENDING:
                ast.update_task_status(task.task_id, TaskStatus.SKIPPED)
                skipped = True

        if skipped:
            await self.save_ast(ast)
            await self._update_scan_progress(scan_id, ast)
            logger.info(f"[ASTManager] Skipped phase {phase.value} for scan {scan_id}")

        return skipped

    async def get_next_task(self, scan_id: str) -> Optional[AnalysisTask]:
        """
        Get the next task that should be executed.

        Args:
            scan_id: Scan ID

        Returns:
            Next task or None if all complete
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return None

        return ast.get_next_pending_task()

    async def get_suggested_tasks(self, scan_id: str, limit: int = 3) -> List[AnalysisTask]:
        """
        Get AI-suggested next tasks.

        Args:
            scan_id: Scan ID
            limit: Maximum number of suggestions

        Returns:
            List of suggested tasks
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return []

        return ast.get_suggested_next_tasks(limit)

    async def get_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get progress statistics for a scan.

        Args:
            scan_id: Scan ID

        Returns:
            Progress statistics or None
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return None

        return ast.get_progress_stats()

    async def _update_scan_progress(self, scan_id: str, ast: AnalysisStateTree) -> None:
        """Update the scan's progress field based on AST."""
        try:
            stats = ast.get_progress_stats()
            progress = stats.get("progress_percentage", 0)

            async with get_db_session() as db:
                scan = await db.get(Scan, scan_id)
                if scan:
                    scan.progress = progress

                    # Update scan status if complete
                    if progress >= 100:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()

                    await db.commit()
        except Exception as e:
            logger.warning(f"[ASTManager] Failed to update scan progress: {e}")

    def get_phase_display_name(self, phase: AnalysisPhase) -> str:
        """Get human-readable phase name."""
        names = {
            AnalysisPhase.STATIC: "Static Analysis",
            AnalysisPhase.DYNAMIC: "Dynamic Analysis",
            AnalysisPhase.NETWORK: "Network Analysis",
            AnalysisPhase.EXPLOIT: "Exploit Development",
        }
        return names.get(phase, phase.value.title())

    def get_task_chain(self, ast: AnalysisStateTree, task_id: str) -> List[AnalysisTask]:
        """
        Get the dependency chain for a task.

        Returns tasks in order they need to be completed.
        """
        task = ast.get_task(task_id)
        if not task:
            return []

        chain = []
        for dep_id in task.dependencies:
            dep = ast.get_task(dep_id)
            if dep:
                chain.extend(self.get_task_chain(ast, dep_id))
                chain.append(dep)

        return chain

    async def reset_ast(self, scan_id: str) -> bool:
        """
        Reset AST to initial state (for re-analysis).

        Args:
            scan_id: Scan ID

        Returns:
            True if reset
        """
        ast = await self.load_ast(scan_id)
        if not ast:
            return False

        for task in ast.tasks:
            task.status = TaskStatus.PENDING
            task.started_at = None
            task.completed_at = None
            task.findings_count = 0
            task.output_summary = ""
            task.error_message = None

        ast.current_phase = None
        ast.current_task_id = None
        ast.updated_at = datetime.utcnow()

        await self.save_ast(ast)
        await self._update_scan_progress(scan_id, ast)

        logger.info(f"[ASTManager] Reset AST for scan {scan_id}")
        return True


# Global manager instance
ast_manager = ASTManager()
