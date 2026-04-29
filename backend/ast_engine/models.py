"""
IRVES — AST Data Models
Core models for Analysis State Tree.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import json
import logging

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Status of an analysis task."""
    PENDING = "pending"         # Not started yet
    IN_PROGRESS = "in_progress" # Currently running
    COMPLETED = "completed"     # Successfully finished
    FAILED = "failed"           # Failed to complete
    BLOCKED = "blocked"         # Waiting for dependencies
    SKIPPED = "skipped"         # Manually skipped by user


class AnalysisPhase(str, Enum):
    """Analysis phases in order of execution."""
    STATIC = "static"           # Code analysis, manifest review
    DYNAMIC = "dynamic"         # Runtime hooking, memory analysis
    NETWORK = "network"         # Traffic capture, API analysis
    EXPLOIT = "exploit"         # PoC generation, verification


class PlatformType(str, Enum):
    """Supported platform types."""
    ANDROID = "android"
    IOS = "ios"
    REPOSITORY = "repository"
    DESKTOP = "desktop"
    WEB = "web"


class Priority(str, Enum):
    """Task priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AnalysisTask:
    """
    Individual task within an analysis phase.

    task_id format: "{phase}.{subphase}.{task}" e.g., "1.2.1"
    - phase: 1=Static, 2=Dynamic, 3=Network, 4=Exploit
    - subphase: Category within phase
    - task: Sequential task number
    """
    task_id: str
    name: str
    description: str
    phase: AnalysisPhase
    status: TaskStatus = TaskStatus.PENDING
    priority: Priority = Priority.MEDIUM

    # Dependencies - list of task_ids that must complete before this task
    dependencies: List[str] = field(default_factory=list)

    # Execution details
    tool_name: Optional[str] = None  # Tool to execute (e.g., "apk_analyzer", "frida")
    tool_config: Dict[str, Any] = field(default_factory=dict)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_duration_ms: int = 0  # Estimated time in milliseconds

    # Results
    findings_count: int = 0
    output_summary: str = ""  # Brief summary of results (< 100 chars)
    error_message: Optional[str] = None

    # AI-generated fields
    ai_suggested: bool = False  # Was this task suggested by AI?
    ai_rationale: str = ""    # Why AI suggested this task

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "name": self.name,
            "description": self.description,
            "phase": self.phase.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "dependencies": self.dependencies,
            "tool_name": self.tool_name,
            "tool_config": self.tool_config,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "estimated_duration_ms": self.estimated_duration_ms,
            "findings_count": self.findings_count,
            "output_summary": self.output_summary,
            "error_message": self.error_message,
            "ai_suggested": self.ai_suggested,
            "ai_rationale": self.ai_rationale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisTask":
        """Create task from dictionary."""
        return cls(
            task_id=data["task_id"],
            name=data["name"],
            description=data.get("description", ""),
            phase=AnalysisPhase(data.get("phase", "static")),
            status=TaskStatus(data.get("status", "pending")),
            priority=Priority(data.get("priority", "medium")),
            dependencies=data.get("dependencies", []),
            tool_name=data.get("tool_name"),
            tool_config=data.get("tool_config", {}),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            estimated_duration_ms=data.get("estimated_duration_ms", 0),
            findings_count=data.get("findings_count", 0),
            output_summary=data.get("output_summary", ""),
            error_message=data.get("error_message"),
            ai_suggested=data.get("ai_suggested", False),
            ai_rationale=data.get("ai_rationale", ""),
        )

    @property
    def is_blocked(self) -> bool:
        """Check if task is blocked by dependencies."""
        return self.status == TaskStatus.BLOCKED

    @property
    def is_complete(self) -> bool:
        """Check if task is completed."""
        return self.status == TaskStatus.COMPLETED

    @property
    def can_start(self) -> bool:
        """Check if task can be started (pending and not blocked)."""
        return self.status == TaskStatus.PENDING

    @property
    def duration_ms(self) -> Optional[int]:
        """Calculate actual duration if completed."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return None


@dataclass
class AnalysisStateTree:
    """
    Complete Analysis State Tree for a scan.

    Tracks all tasks across all phases with their dependencies.
    Can be serialized to JSON for database storage.
    """
    scan_id: str
    platform: PlatformType
    tasks: List[AnalysisTask] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Current state
    current_phase: Optional[AnalysisPhase] = None
    current_task_id: Optional[str] = None

    # Metadata
    version: str = "1.0"  # For future migrations
    custom_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert AST to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "platform": self.platform.value,
            "tasks": [t.to_dict() for t in self.tasks],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "current_phase": self.current_phase.value if self.current_phase else None,
            "current_task_id": self.current_task_id,
            "version": self.version,
            "custom_config": self.custom_config,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisStateTree":
        """Create AST from dictionary."""
        return cls(
            scan_id=data["scan_id"],
            platform=PlatformType(data.get("platform", "android")),
            tasks=[AnalysisTask.from_dict(t) for t in data.get("tasks", [])],
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.utcnow(),
            current_phase=AnalysisPhase(data["current_phase"]) if data.get("current_phase") else None,
            current_task_id=data.get("current_task_id"),
            version=data.get("version", "1.0"),
            custom_config=data.get("custom_config", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AnalysisStateTree":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def get_task(self, task_id: str) -> Optional[AnalysisTask]:
        """Get task by ID."""
        for task in self.tasks:
            if task.task_id == task_id:
                return task
        return None

    def get_tasks_by_phase(self, phase: AnalysisPhase) -> List[AnalysisTask]:
        """Get all tasks for a specific phase."""
        return [t for t in self.tasks if t.phase == phase]

    def get_next_pending_task(self) -> Optional[AnalysisTask]:
        """Get next task that can be started (pending, dependencies met)."""
        for task in self.tasks:
            if task.can_start and not task.dependencies:
                return task

        # Check tasks with dependencies
        for task in self.tasks:
            if task.can_start:
                # Check if all dependencies are complete
                deps_complete = all(
                    self.get_task(dep_id) and self.get_task(dep_id).is_complete
                    for dep_id in task.dependencies
                )
                if deps_complete:
                    return task

        return None

    def get_blocked_tasks(self) -> List[AnalysisTask]:
        """Get all tasks that are blocked by incomplete dependencies."""
        blocked = []
        for task in self.tasks:
            if task.status == TaskStatus.PENDING and task.dependencies:
                # Check if any dependency is not complete
                deps_incomplete = any(
                    not self.get_task(dep_id) or not self.get_task(dep_id).is_complete
                    for dep_id in task.dependencies
                )
                if deps_incomplete:
                    blocked.append(task)
        return blocked

    def update_task_status(self, task_id: str, status: TaskStatus, error_message: str = None) -> bool:
        """Update task status and cascade to dependent tasks."""
        task = self.get_task(task_id)
        if not task:
            return False

        task.status = status
        if error_message:
            task.error_message = error_message

        if status == TaskStatus.IN_PROGRESS and not task.started_at:
            task.started_at = datetime.utcnow()
        elif status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED):
            task.completed_at = datetime.utcnow()

        # Update current phase
        if status == TaskStatus.IN_PROGRESS:
            self.current_phase = task.phase
            self.current_task_id = task_id

        self.updated_at = datetime.utcnow()

        # Update dependent tasks
        self._update_dependent_tasks()

        return True

    def _update_dependent_tasks(self) -> None:
        """Update status of tasks based on dependencies."""
        for task in self.tasks:
            if task.status == TaskStatus.PENDING and task.dependencies:
                # Check if all dependencies are complete
                all_complete = all(
                    self.get_task(dep_id) and self.get_task(dep_id).is_complete
                    for dep_id in task.dependencies
                )
                if all_complete:
                    task.status = TaskStatus.PENDING  # Ready to start
                else:
                    any_failed = any(
                        self.get_task(dep_id) and self.get_task(dep_id).status == TaskStatus.FAILED
                        for dep_id in task.dependencies
                    )
                    if any_failed:
                        task.status = TaskStatus.BLOCKED

    def get_progress_stats(self) -> Dict[str, Any]:
        """Get progress statistics for the entire tree."""
        total = len(self.tasks)
        by_status = {
            "pending": sum(1 for t in self.tasks if t.status == TaskStatus.PENDING),
            "in_progress": sum(1 for t in self.tasks if t.status == TaskStatus.IN_PROGRESS),
            "completed": sum(1 for t in self.tasks if t.status == TaskStatus.COMPLETED),
            "failed": sum(1 for t in self.tasks if t.status == TaskStatus.FAILED),
            "blocked": sum(1 for t in self.tasks if t.status == TaskStatus.BLOCKED),
            "skipped": sum(1 for t in self.tasks if t.status == TaskStatus.SKIPPED),
        }

        by_phase = {}
        for phase in AnalysisPhase:
            phase_tasks = self.get_tasks_by_phase(phase)
            by_phase[phase.value] = {
                "total": len(phase_tasks),
                "completed": sum(1 for t in phase_tasks if t.is_complete),
            }

        progress_pct = int((by_status["completed"] / total * 100)) if total > 0 else 0

        return {
            "total_tasks": total,
            "by_status": by_status,
            "by_phase": by_phase,
            "progress_percentage": progress_pct,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "current_task_id": self.current_task_id,
        }

    def get_suggested_next_tasks(self, limit: int = 3) -> List[AnalysisTask]:
        """Get AI-suggested next tasks based on priority and dependencies."""
        available = []

        for task in self.tasks:
            if task.can_start:
                if not task.dependencies:
                    available.append(task)
                else:
                    deps_complete = all(
                        self.get_task(dep_id) and self.get_task(dep_id).is_complete
                        for dep_id in task.dependencies
                    )
                    if deps_complete:
                        available.append(task)

        # Sort by priority
        priority_order = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
        }
        available.sort(key=lambda t: priority_order.get(t.priority, 4))

        return available[:limit]
