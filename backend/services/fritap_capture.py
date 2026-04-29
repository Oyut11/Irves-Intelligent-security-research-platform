"""
IRVES friTap Capture Service — SSL/TLS Key Extraction for Wireshark Analysis

Provides keylog + PCAP export for pinned apps, complementing the real-time
BoringSSL capture hook. Runs friTap in a background thread to avoid blocking
the async event loop.

Usage:
    from services.fritap_capture import fritap_service
    result = await fritap_service.start_capture("com.example.app", device_serial)
    # ... later ...
    files = await fritap_service.stop_capture("com.example.app")
    # files = {"keylog": "/tmp/irves/com.example.app_keys.log", "pcap": "..."}
"""

import asyncio
import logging
import os
import time
import signal
import shlex
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Output directory for keylog and PCAP files
FRITAP_OUTPUT_DIR = Path("/tmp/irves/fritap")
FRITAP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Check if friTap is available
FRITAP_AVAILABLE = False
try:
    import friTap  # noqa: F401
    FRITAP_AVAILABLE = True
    logger.info("[friTap] Module loaded successfully")
except ImportError as e:
    logger.warning(f"[friTap] Not available: {e}. Install with: pip install fritap")


@dataclass
class FriTapSession:
    """Represents an active friTap capture session."""
    package: str
    device_id: str
    keylog_path: str
    pcap_path: Optional[str]
    started_at: float = field(default_factory=time.time)
    fritap_instance: Any = None
    process: Optional[asyncio.subprocess.Process] = None
    task: Optional[asyncio.Task] = None
    status: str = "starting"
    error: Optional[str] = None


class FriTapCaptureService:
    """
    Manages friTap capture sessions for SSL/TLS key extraction.
    
    Provides keylog + PCAP export for Wireshark analysis, complementing
    the real-time BoringSSL capture hook for pinned apps.
    """

    def __init__(self):
        self._sessions: Dict[str, FriTapSession] = {}  # package → session
        self._lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        """Check if friTap is installed and available."""
        return FRITAP_AVAILABLE

    def _session_key(self, package: str, device_id: str = "") -> str:
        """Generate a unique session key."""
        return f"{device_id}:{package}" if device_id else package

    def is_active(self, package: str, device_id: str = "") -> bool:
        """Check if a friTap session is active for this package."""
        key = self._session_key(package, device_id)
        session = self._sessions.get(key)
        return session is not None and session.status in ("starting", "running")

    def get_session(self, package: str, device_id: str = "") -> Optional[FriTapSession]:
        """Get the session for a package if it exists."""
        return self._sessions.get(self._session_key(package, device_id))

    async def start_capture(
        self,
        package: str,
        device_id: str = "",
        generate_pcap: bool = True,
        custom_script: Optional[str] = None,
        spawn: bool = True,
    ) -> Dict[str, Any]:
        """
        Start a friTap capture session for a package.

        Args:
            package: App package name (e.g., "com.example.app")
            device_id: Device serial (for mobile). Empty for local.
            generate_pcap: Whether to generate a PCAP file alongside keylog.
            custom_script: Optional path to a custom Frida script to co-inject.
            spawn: Whether to spawn the app (True) or attach to running process.

        Returns:
            {"status": "started", "keylog_path": "...", "pcap_path": "..."}
            or {"status": "error", "message": "..."}
        """
        if not FRITAP_AVAILABLE:
            return {
                "status": "error",
                "message": "friTap not installed. Run: pip install fritap",
            }

        key = self._session_key(package, device_id)

        async with self._lock:
            # Check for existing session
            if key in self._sessions and self._sessions[key].status in ("starting", "running"):
                return {
                    "status": "error",
                    "message": f"friTap session already active for {package}",
                    "session": self._get_session_info(self._sessions[key]),
                }

            # Prepare output paths
            timestamp = int(time.time())
            safe_pkg = package.replace(".", "_")
            keylog_path = str(FRITAP_OUTPUT_DIR / f"{safe_pkg}_{timestamp}_keys.log")
            pcap_path = str(FRITAP_OUTPUT_DIR / f"{safe_pkg}_{timestamp}.pcap") if generate_pcap else None

            # Create session
            session = FriTapSession(
                package=package,
                device_id=device_id,
                keylog_path=keylog_path,
                pcap_path=pcap_path,
            )
            self._sessions[key] = session

        # Start friTap in background thread
        try:
            session.task = asyncio.create_task(
                self._run_fritap(session, spawn, custom_script)
            )
            logger.info(f"[friTap] Started capture for {package} → {keylog_path}")
            return {
                "status": "started",
                "package": package,
                "device_id": device_id,
                "keylog_path": keylog_path,
                "pcap_path": pcap_path,
            }
        except Exception as e:
            session.status = "error"
            session.error = str(e)
            logger.error(f"[friTap] Failed to start capture for {package}: {e}")
            return {"status": "error", "message": str(e)}

    async def _run_fritap(
        self,
        session: FriTapSession,
        spawn: bool,
        custom_script: Optional[str],
    ):
        """Run friTap in a subprocess (main-thread safe)."""
        try:
            session.status = "running"
            cmd = ["fritap"]
            if session.device_id:
                cmd.extend(["-m", session.device_id])
            if spawn:
                cmd.append("-s")
                cmd.append("--enable_spawn_gating")
            if session.keylog_path:
                cmd.extend(["-k", session.keylog_path])
            if session.pcap_path:
                cmd.extend(["-f", "-p", session.pcap_path])
            if custom_script:
                cmd.extend(["-c", custom_script])
            cmd.append(session.package)

            logger.info(f"[friTap] Launching subprocess: {' '.join(shlex.quote(c) for c in cmd)}")

            session.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await session.process.communicate()
            rc = session.process.returncode

            if session.status == "stopped":
                return

            if rc == 0:
                session.status = "stopped"
            else:
                err = (stderr or b"").decode(errors="replace").strip()
                out = (stdout or b"").decode(errors="replace").strip()
                session.error = err or out or f"friTap exited with code {rc}"
                session.status = "error"
                logger.error(f"[friTap] Process exited abnormally for {session.package}: rc={rc} err={session.error}")

        except asyncio.CancelledError:
            logger.info(f"[friTap] Capture cancelled for {session.package}")
            session.status = "stopped"
        except Exception as e:
            session.status = "error"
            session.error = str(e)
            logger.error(f"[friTap] Capture failed for {session.package}: {e}")

    async def stop_capture(self, package: str, device_id: str = "") -> Dict[str, Any]:
        """
        Stop a friTap capture session and return file paths.

        Returns:
            {"status": "stopped", "keylog_path": "...", "pcap_path": "...", "duration": ...}
            or {"status": "error", "message": "..."}
        """
        key = self._session_key(package, device_id)

        async with self._lock:
            session = self._sessions.get(key)
            if not session:
                return {"status": "error", "message": f"No active session for {package}"}

            duration = time.time() - session.started_at

            # Stop friTap process
            if session.process and session.process.returncode is None:
                try:
                    session.process.send_signal(signal.SIGINT)
                    await asyncio.wait_for(session.process.wait(), timeout=5.0)
                except Exception:
                    try:
                        session.process.terminate()
                        await asyncio.wait_for(session.process.wait(), timeout=3.0)
                    except Exception:
                        session.process.kill()
                        await asyncio.wait_for(session.process.wait(), timeout=3.0)

            # Cancel the task
            if session.task and not session.task.done():
                session.task.cancel()
                try:
                    await asyncio.wait_for(session.task, timeout=5.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

            session.status = "stopped"

            # Check if files were created
            keylog_exists = os.path.exists(session.keylog_path)
            pcap_exists = session.pcap_path and os.path.exists(session.pcap_path)

            result = {
                "status": "stopped",
                "package": package,
                "duration_seconds": round(duration, 2),
                "keylog_path": session.keylog_path if keylog_exists else None,
                "pcap_path": session.pcap_path if pcap_exists else None,
                "keylog_size": os.path.getsize(session.keylog_path) if keylog_exists else 0,
                "pcap_size": os.path.getsize(session.pcap_path) if pcap_exists else 0,
            }

            logger.info(f"[friTap] Stopped capture for {package} after {duration:.1f}s")
            return result

    def _get_session_info(self, session: FriTapSession) -> Dict[str, Any]:
        """Get info about a session."""
        return {
            "package": session.package,
            "device_id": session.device_id,
            "status": session.status,
            "started_at": session.started_at,
            "duration_seconds": round(time.time() - session.started_at, 2),
            "keylog_path": session.keylog_path,
            "pcap_path": session.pcap_path,
            "error": session.error,
        }

    def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get info about all active sessions."""
        return {
            key: self._get_session_info(session)
            for key, session in self._sessions.items()
        }

    async def get_keylog_content(self, package: str, device_id: str = "") -> Optional[str]:
        """Read the keylog file content for a session."""
        session = self.get_session(package, device_id)
        if not session or not os.path.exists(session.keylog_path):
            return None
        try:
            return await asyncio.to_thread(
                lambda: Path(session.keylog_path).read_text()
            )
        except Exception as e:
            logger.error(f"[friTap] Error reading keylog: {e}")
            return None

    async def cleanup_old_files(self, max_age_hours: int = 24):
        """Clean up old keylog and PCAP files."""
        cutoff = time.time() - (max_age_hours * 3600)
        cleaned = 0
        for f in FRITAP_OUTPUT_DIR.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                try:
                    f.unlink()
                    cleaned += 1
                except Exception:
                    pass
        if cleaned:
            logger.info(f"[friTap] Cleaned up {cleaned} old files")
        return cleaned


# Singleton instance
fritap_service = FriTapCaptureService()
