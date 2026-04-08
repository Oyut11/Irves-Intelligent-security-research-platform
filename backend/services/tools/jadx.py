"""
IRVES — JADX Runner
Decompile APK to readable Java source code.
"""

import asyncio
from pathlib import Path
from typing import Optional, Callable
import logging

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)


class JADXRunner(ToolRunner):
    """
    JADX runner for decompiling APK to Java source code.

    Produces:
    - Java source files
    - Resources
    - AndroidManifest.xml
    """

    @property
    def name(self) -> str:
        return "jadx"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        """
        Decompile APK using JADX.

        Args:
            target: Path to the APK file
            output_dir: Directory for output
            progress_callback: Optional callback for progress messages

        Returns:
            ToolResult with decompiled Java sources
        """
        if not target.exists():
            return ToolResult(
                success=False,
                output="",
                error=f"Target file not found: {target}",
                duration_ms=0,
            )

        # Ensure output directory exists
        output_path = self._ensure_output_dir(output_dir / "jadx")

        if progress_callback:
            progress_callback(f"Decompiling {target.name} to Java...")

        # Build command
        cmd = [
            settings.JADX_PATH,
            "-d", str(output_path),
            "--show-bad-code",  # Include problematic code
            "--no-res",  # Skip resources (faster, already done by APKTool)
            "--threads-count", "4",
            "--no-debug-info",  # Skip debug info
            str(target),
        ]

        # Run JADX
        stdout, stderr, return_code = await self._run_command(
            cmd,
            output_dir,
            progress_callback=progress_callback,
            timeout=1800,  # 30 minutes max for large APKs
        )

        duration_ms = self._elapsed_ms()

        if return_code == 0:
            if progress_callback:
                progress_callback(f"Decompiled to {output_path}")

            # Count Java files
            java_files = list(output_path.rglob("*.java"))
            sources_path = output_path / "sources"

            return ToolResult(
                success=True,
                output=stdout,
                error="",
                duration_ms=duration_ms,
                artifacts_path=output_path,
                metrics={
                    "java_files": len(java_files),
                    "sources_exists": sources_path.exists(),
                },
            )
        else:
            # JADX may return non-zero but still produce output
            # Check if output exists
            if (output_path / "sources").exists():
                java_files = list(output_path.rglob("*.java"))
                logger.warning(f"[{self.name}] JADX returned {return_code} but output exists")

                return ToolResult(
                    success=True,
                    output=stdout,
                    error=stderr,
                    duration_ms=duration_ms,
                    artifacts_path=output_path,
                    metrics={"java_files": len(java_files)},
                )

            error_msg = stderr or stdout or f"JADX failed with code {return_code}"
            logger.error(f"[{self.name}] {error_msg}")

            return ToolResult(
                success=False,
                output=stdout,
                error=error_msg,
                duration_ms=duration_ms,
            )

    async def _get_version(self) -> Optional[str]:
        """Get JADX version."""
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.JADX_PATH,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return None