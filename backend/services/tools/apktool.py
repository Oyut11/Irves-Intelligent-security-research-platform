"""
IRVES — APKTool Runner
Decompile APK files to smali and extract manifest.
"""

import asyncio
from pathlib import Path
from typing import Optional, Callable
import logging

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)


class APKToolRunner(ToolRunner):
    """
    APKTool runner for decompiling APK files.

    Extracts:
    - AndroidManifest.xml
    - smali code
    - resources
    """

    @property
    def name(self) -> str:
        return "apktool"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        """
        Decompile APK using APKTool.

        Args:
            target: Path to the APK file
            output_dir: Directory for output
            progress_callback: Optional callback for progress messages

        Returns:
            ToolResult with decompiled files path
        """
        if not target.exists():
            return ToolResult(
                success=False,
                output="",
                error=f"Target file not found: {target}",
                duration_ms=0,
            )

        # Ensure output directory exists
        output_path = self._ensure_output_dir(output_dir / "apktool")

        if progress_callback:
            progress_callback(f"Decompiling {target.name}...")

        # Build command
        cmd = [
            settings.APKTOOL_PATH,
            "d",  # Decode
            str(target),
            "-o", str(output_path),
            "-f",  # Force overwrite
        ]

        # Run APKTool
        stdout, stderr, return_code = await self._run_command(
            cmd,
            output_dir,
            progress_callback=progress_callback,
        )

        duration_ms = self._elapsed_ms()

        if return_code == 0:
            if progress_callback:
                progress_callback(f"Decompiled to {output_path}")

            # Verify output
            manifest = output_path / "AndroidManifest.xml"
            smali_dir = output_path / "smali"

            if not manifest.exists():
                logger.warning(f"[{self.name}] AndroidManifest.xml not found")

            return ToolResult(
                success=True,
                output=stdout,
                error="",
                duration_ms=duration_ms,
                artifacts_path=output_path,
                metrics={
                    "manifest_exists": manifest.exists(),
                    "smali_exists": smali_dir.exists(),
                },
            )
        else:
            error_msg = stderr or stdout or f"APKTool failed with code {return_code}"
            logger.error(f"[{self.name}] {error_msg}")

            return ToolResult(
                success=False,
                output=stdout,
                error=error_msg,
                duration_ms=duration_ms,
            )

    async def _get_version(self) -> Optional[str]:
        """Get APKTool version."""
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.APKTOOL_PATH,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return None