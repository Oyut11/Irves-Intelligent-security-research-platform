"""
IRVES — Analysis State Tree (AST) Module
Phase 2: Task tracking system for security analysis.

Provides:
- AnalysisTask: Individual task within a phase
- AnalysisPhase: Collection of tasks (Static, Dynamic, Network, Exploit)
- ASTManager: Operations on the task tree
- Platform templates: Android, iOS, Repository

The AST tracks scan progress with dependencies between phases.
"""

from ast_engine.models import (
    TaskStatus,
    AnalysisPhase,
    AnalysisTask,
    AnalysisStateTree,
    PlatformType,
    Priority,
)
from ast_engine.manager import ASTManager
from ast_engine.templates import get_template_for_platform

__all__ = [
    # Enums
    "TaskStatus",
    "AnalysisPhase",
    "PlatformType",
    "Priority",
    # Models
    "AnalysisTask",
    "AnalysisStateTree",
    # Manager
    "ASTManager",
    # Templates
    "get_template_for_platform",
]
