"""
IRVES — Tool Runner Base Class
Abstract base class for security tool execution.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Callable, List
from pathlib import Path
import logging
import shutil

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    output: str
    error: str
    duration_ms: int
    artifacts_path: Optional[Path] = None
    findings_count: int = 0
    metrics: dict = field(default_factory=dict)


@dataclass
class ToolHealth:
    """Health status of a security tool."""
    name: str
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None


class ToolRunner(ABC):
    """
    Base class for all security tool runners.

    Each tool (APKTool, JADX, Frida, mitmproxy, etc.) should inherit from this
    and implement the run() method.
    """

    def __init__(self):
        self.process: Optional[asyncio.subprocess.Process] = None
        self.cancelled: bool = False
        self._start_time: float = 0

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name for logging and display."""
        pass

    @property
    def tool_path(self) -> str:
        """Path to the tool executable. Override in subclass if needed."""
        return getattr(settings, f"{self.name.upper()}_PATH", self.name.lower())

    @abstractmethod
    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        """
        Execute the tool.

        Args:
            target: Path to the target file (APK, IPA, etc.)
            output_dir: Directory for tool output artifacts
            progress_callback: Optional callback for progress updates

        Returns:
            ToolResult with success status, output, and artifacts path
        """
        pass

    async def cancel(self) -> None:
        """Gracefully cancel the running process."""
        self.cancelled = True
        if self.process:
            logger.info(f"[{self.name}] Cancelling process...")
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning(f"[{self.name}] Process did not terminate, killing...")
                self.process.kill()
                await self.process.wait()
            except ProcessLookupError:
                pass  # Process already terminated

    async def check_installed(self) -> ToolHealth:
        """Check if the tool is installed and get version."""
        tool_path = self.tool_path
        installed = shutil.which(tool_path) is not None

        if not installed:
            return ToolHealth(
                name=self.name,
                installed=False,
                error=f"{self.name} not found in PATH",
            )

        version = await self._get_version()
        return ToolHealth(
            name=self.name,
            installed=True,
            path=shutil.which(tool_path),
            version=version,
        )

    async def _get_version(self) -> Optional[str]:
        """Get tool version. Override in subclass for custom version flags."""
        return None

    async def _run_command(
        self,
        cmd: List[str],
        cwd: Path,
        env: dict = None,
        progress_callback: Optional[Callable[[str], None]] = None,
        timeout: int = 3600,
    ) -> tuple[str, str, int]:
        """
        Execute a command and capture output.

        Args:
            cmd: Command and arguments
            cwd: Working directory
            env: Environment variables
            progress_callback: Callback for progress updates
            timeout: Maximum execution time in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        self._start_time = time.time()

        # Prepare environment
        run_env = None
        if env:
            import os
            run_env = os.environ.copy()
            run_env.update(env)

        # Create subprocess
        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=run_env,
            )
        except FileNotFoundError:
            logger.error(f"[{self.name}] Executable not found: {cmd[0]}")
            if progress_callback:
                progress_callback(f"Error: {cmd[0]} not found in PATH")
            return ("", f"Executable not found: {cmd[0]}", 1)

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        async def read_stream(
            stream: asyncio.StreamReader,
            chunks: List[str],
            callback: Optional[Callable[[str], None]],
        ):
            """Read from a stream line by line."""
            while True:
                try:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").strip()
                    chunks.append(decoded)
                    if callback:
                        callback(decoded)
                except Exception as e:
                    logger.debug(f"[{self.name}] Error reading stream: {e}")
                    break

        try:
            # Read both streams concurrently
            await asyncio.wait_for(
                asyncio.gather(
                    read_stream(self.process.stdout, stdout_chunks, progress_callback),
                    read_stream(self.process.stderr, stderr_chunks, progress_callback),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Command timed out after {timeout}s")
            await self.cancel()
            raise TimeoutError(f"{self.name} execution timed out after {timeout} seconds")

        await self.process.wait()

        return (
            "\n".join(stdout_chunks),
            "\n".join(stderr_chunks),
            self.process.returncode or 0,
        )

    def _elapsed_ms(self) -> int:
        """Get elapsed time in milliseconds."""
        return int((time.time() - self._start_time) * 1000)

    def _ensure_output_dir(self, output_dir: Path) -> Path:
        """Ensure output directory exists."""
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir