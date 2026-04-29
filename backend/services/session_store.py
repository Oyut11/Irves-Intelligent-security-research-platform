"""
IRVES — Analysis Session Store
Phase F: Session persistence for resumable analysis.

Responsibilities:
- Save/restore analysis sessions (scan state, AST, findings)
- Auto-save during long-running scans
- Checkpoint system for resuming from specific points
- Session metadata and recovery
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum
import asyncio

from config import settings

logger = logging.getLogger(__name__)


class SessionStatus(str, Enum):
    """Status of an analysis session."""
    ACTIVE = "active"           # Currently running
    PAUSED = "paused"          # Manually paused
    COMPLETED = "completed"    # Finished successfully
    FAILED = "failed"          # Error occurred
    AUTO_SAVED = "auto_saved"  # Auto-saved during run


@dataclass
class AnalysisCheckpoint:
    """A checkpoint in the analysis process."""
    checkpoint_id: str
    name: str
    description: str
    timestamp: datetime
    phase: str  # static, dynamic, network, exploit
    task_id: Optional[str] = None
    progress_percentage: int = 0
    findings_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisSession:
    """
    Represents a persistable analysis session.

    Contains all state needed to resume analysis:
    - Scan configuration and progress
    - AST state (task tree)
    - Findings discovered so far
    - Correlation results
    - User annotations
    """
    session_id: str  # Format: "{scan_id}_{timestamp}"
    scan_id: str
    project_id: str
    project_name: str
    platform: str

    # Session metadata
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_auto_save: Optional[datetime] = None

    # Analysis state
    scan_config: Dict[str, Any] = field(default_factory=dict)
    ast_data: Optional[Dict[str, Any]] = None  # Serialized AST
    current_phase: Optional[str] = None
    current_task_id: Optional[str] = None
    progress_percentage: int = 0

    # Results so far
    findings: List[Dict[str, Any]] = field(default_factory=list)
    correlations: Optional[Dict[str, Any]] = None
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)

    # Checkpoints
    checkpoints: List[AnalysisCheckpoint] = field(default_factory=list)
    current_checkpoint_id: Optional[str] = None

    # User state
    user_notes: str = ""
    tags: List[str] = field(default_factory=list)

    # Recovery info
    resume_from_phase: Optional[str] = None
    resume_from_task: Optional[str] = None
    skipped_phases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "platform": self.platform,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_auto_save": self.last_auto_save.isoformat() if self.last_auto_save else None,
            "scan_config": self.scan_config,
            "ast_data": self.ast_data,
            "current_phase": self.current_phase,
            "current_task_id": self.current_task_id,
            "progress_percentage": self.progress_percentage,
            "findings": self.findings,
            "correlations": self.correlations,
            "attack_chains": self.attack_chains,
            "checkpoints": [
                {
                    "checkpoint_id": c.checkpoint_id,
                    "name": c.name,
                    "description": c.description,
                    "timestamp": c.timestamp.isoformat(),
                    "phase": c.phase,
                    "task_id": c.task_id,
                    "progress_percentage": c.progress_percentage,
                    "findings_count": c.findings_count,
                    "metadata": c.metadata,
                }
                for c in self.checkpoints
            ],
            "current_checkpoint_id": self.current_checkpoint_id,
            "user_notes": self.user_notes,
            "tags": self.tags,
            "resume_from_phase": self.resume_from_phase,
            "resume_from_task": self.resume_from_task,
            "skipped_phases": self.skipped_phases,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisSession":
        """Create session from dictionary."""
        session = cls(
            session_id=data["session_id"],
            scan_id=data["scan_id"],
            project_id=data["project_id"],
            project_name=data["project_name"],
            platform=data["platform"],
            status=SessionStatus(data.get("status", "active")),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            last_auto_save=datetime.fromisoformat(data["last_auto_save"]) if data.get("last_auto_save") else None,
            scan_config=data.get("scan_config", {}),
            ast_data=data.get("ast_data"),
            current_phase=data.get("current_phase"),
            current_task_id=data.get("current_task_id"),
            progress_percentage=data.get("progress_percentage", 0),
            findings=data.get("findings", []),
            correlations=data.get("correlations"),
            attack_chains=data.get("attack_chains", []),
            checkpoints=[
                AnalysisCheckpoint(
                    checkpoint_id=c["checkpoint_id"],
                    name=c["name"],
                    description=c["description"],
                    timestamp=datetime.fromisoformat(c["timestamp"]),
                    phase=c["phase"],
                    task_id=c.get("task_id"),
                    progress_percentage=c.get("progress_percentage", 0),
                    findings_count=c.get("findings_count", 0),
                    metadata=c.get("metadata", {}),
                )
                for c in data.get("checkpoints", [])
            ],
            current_checkpoint_id=data.get("current_checkpoint_id"),
            user_notes=data.get("user_notes", ""),
            tags=data.get("tags", []),
            resume_from_phase=data.get("resume_from_phase"),
            resume_from_task=data.get("resume_from_task"),
            skipped_phases=data.get("skipped_phases", []),
        )
        return session


class AnalysisSessionStore:
    """
    Store for analysis sessions with persistence.

    Provides:
    - Session CRUD operations
    - Auto-save functionality
    - Checkpoint management
    - Session recovery
    """

    def __init__(self):
        self._sessions: Dict[str, AnalysisSession] = {}
        self._storage_dir = settings.projects_path / ".." / "sessions"
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._auto_save_task: Optional[asyncio.Task] = None
        self._auto_save_interval = 60  # seconds

    async def create_session(
        self,
        scan_id: str,
        project_id: str,
        project_name: str,
        platform: str,
        scan_config: Optional[Dict] = None,
    ) -> AnalysisSession:
        """
        Create a new analysis session.

        Returns:
            New AnalysisSession
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        session_id = f"{scan_id}_{timestamp}"

        session = AnalysisSession(
            session_id=session_id,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            platform=platform,
            scan_config=scan_config or {},
            status=SessionStatus.ACTIVE,
        )

        self._sessions[session_id] = session
        await self._persist_session(session)

        logger.info(f"[SessionStore] Created session {session_id}")
        return session

    async def get_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Get session by ID."""
        # Check memory first
        if session_id in self._sessions:
            return self._sessions[session_id]

        # Load from disk
        session = await self._load_session(session_id)
        if session:
            self._sessions[session_id] = session

        return session

    async def get_session_by_scan(self, scan_id: str) -> Optional[AnalysisSession]:
        """Get most recent session for a scan."""
        # Find sessions for this scan
        matching = [s for s in self._sessions.values() if s.scan_id == scan_id]

        # Also check disk
        for session_file in self._storage_dir.glob(f"{scan_id}_*.json"):
            session_id = session_file.stem
            if session_id not in [s.session_id for s in matching]:
                session = await self._load_session(session_id)
                if session:
                    matching.append(session)

        if not matching:
            return None

        # Return most recent
        return max(matching, key=lambda s: s.updated_at)

    async def update_session(
        self,
        session_id: str,
        updates: Dict[str, Any],
    ) -> Optional[AnalysisSession]:
        """Update session with new data."""
        session = await self.get_session(session_id)
        if not session:
            return None

        # Apply updates
        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)

        session.updated_at = datetime.utcnow()

        await self._persist_session(session)
        return session

    async def create_checkpoint(
        self,
        session_id: str,
        name: str,
        description: str,
        phase: str,
        task_id: Optional[str] = None,
        progress: int = 0,
        findings_count: int = 0,
        metadata: Optional[Dict] = None,
    ) -> Optional[AnalysisCheckpoint]:
        """Create a checkpoint in the analysis."""
        session = await self.get_session(session_id)
        if not session:
            return None

        checkpoint = AnalysisCheckpoint(
            checkpoint_id=f"chk_{datetime.utcnow().timestamp():.0f}",
            name=name,
            description=description,
            timestamp=datetime.utcnow(),
            phase=phase,
            task_id=task_id,
            progress_percentage=progress,
            findings_count=findings_count,
            metadata=metadata or {},
        )

        session.checkpoints.append(checkpoint)
        session.current_checkpoint_id = checkpoint.checkpoint_id
        session.current_phase = phase
        session.current_task_id = task_id
        session.progress_percentage = progress

        await self._persist_session(session)

        logger.info(f"[SessionStore] Created checkpoint {checkpoint.checkpoint_id} for {session_id}")
        return checkpoint

    async def auto_save(self, session_id: str) -> bool:
        """Auto-save current session state."""
        session = await self.get_session(session_id)
        if not session:
            return False

        session.last_auto_save = datetime.utcnow()
        session.status = SessionStatus.AUTO_SAVED

        await self._persist_session(session)
        return True

    async def pause_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Pause an active session."""
        session = await self.get_session(session_id)
        if not session:
            return None

        session.status = SessionStatus.PAUSED
        session.updated_at = datetime.utcnow()

        await self._persist_session(session)
        logger.info(f"[SessionStore] Paused session {session_id}")
        return session

    async def resume_session(
        self,
        session_id: str,
        from_checkpoint: Optional[str] = None,
    ) -> Optional[AnalysisSession]:
        """Resume a paused session."""
        session = await self.get_session(session_id)
        if not session:
            return None

        session.status = SessionStatus.ACTIVE
        session.updated_at = datetime.utcnow()

        if from_checkpoint:
            checkpoint = next((c for c in session.checkpoints if c.checkpoint_id == from_checkpoint), None)
            if checkpoint:
                session.resume_from_phase = checkpoint.phase
                session.resume_from_task = checkpoint.task_id
                session.current_checkpoint_id = from_checkpoint

        await self._persist_session(session)
        logger.info(f"[SessionStore] Resumed session {session_id}")
        return session

    async def complete_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Mark session as completed."""
        session = await self.get_session(session_id)
        if not session:
            return None

        session.status = SessionStatus.COMPLETED
        session.progress_percentage = 100
        session.updated_at = datetime.utcnow()

        await self._persist_session(session)
        logger.info(f"[SessionStore] Completed session {session_id}")
        return session

    async def fail_session(self, session_id: str, error: str) -> Optional[AnalysisSession]:
        """Mark session as failed."""
        session = await self.get_session(session_id)
        if not session:
            return None

        session.status = SessionStatus.FAILED
        session.user_notes += f"\nError: {error}"
        session.updated_at = datetime.utcnow()

        await self._persist_session(session)
        logger.info(f"[SessionStore] Marked session {session_id} as failed")
        return session

    async def list_sessions(
        self,
        project_id: Optional[str] = None,
        status: Optional[SessionStatus] = None,
    ) -> List[AnalysisSession]:
        """List sessions, optionally filtered."""
        sessions = []

        # Load all from disk
        for session_file in self._storage_dir.glob("*.json"):
            session_id = session_file.stem
            if session_id not in self._sessions:
                session = await self._load_session(session_id)
                if session:
                    self._sessions[session_id] = session

        # Filter
        for session in self._sessions.values():
            if project_id and session.project_id != project_id:
                continue
            if status and session.status != status:
                continue
            sessions.append(session)

        return sorted(sessions, key=lambda s: s.updated_at, reverse=True)

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        # Remove from memory
        if session_id in self._sessions:
            del self._sessions[session_id]

        # Remove from disk
        session_file = self._storage_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()

        logger.info(f"[SessionStore] Deleted session {session_id}")
        return True

    async def _persist_session(self, session: AnalysisSession) -> None:
        """Save session to disk."""
        session_file = self._storage_dir / f"{session.session_id}.json"

        try:
            with open(session_file, "w") as f:
                json.dump(session.to_dict(), f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[SessionStore] Failed to persist session: {e}")

    async def _load_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Load session from disk."""
        session_file = self._storage_dir / f"{session_id}.json"

        if not session_file.exists():
            return None

        try:
            with open(session_file, "r") as f:
                data = json.load(f)
            return AnalysisSession.from_dict(data)
        except Exception as e:
            logger.error(f"[SessionStore] Failed to load session {session_id}: {e}")
            return None

    def start_auto_save(self, session_id: str) -> None:
        """Start auto-save background task for a session."""
        if self._auto_save_task:
            self._auto_save_task.cancel()

        async def auto_save_loop():
            while True:
                try:
                    await asyncio.sleep(self._auto_save_interval)
                    await self.auto_save(session_id)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"[SessionStore] Auto-save error: {e}")

        self._auto_save_task = asyncio.create_task(auto_save_loop())

    def stop_auto_save(self) -> None:
        """Stop auto-save background task."""
        if self._auto_save_task:
            self._auto_save_task.cancel()
            self._auto_save_task = None


# Global instance
session_store = AnalysisSessionStore()
