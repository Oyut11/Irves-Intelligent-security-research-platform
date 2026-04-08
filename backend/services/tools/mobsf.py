"""
IRVES — MobSF Runner
Static and dynamic analysis via Mobile Security Framework API.
"""

import asyncio
from pathlib import Path
from typing import Optional, Callable
import json
import logging

import httpx

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)


class MobSFRunner(ToolRunner):
    """
    MobSF runner for comprehensive mobile security analysis.

    Requires a running MobSF server instance.
    Uses MobSF REST API for:
    - APK upload
    - Static analysis
    - Report retrieval
    """

    @property
    def name(self) -> str:
        return "mobsf"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        """
        Run MobSF analysis on APK file.

        Args:
            target: Path to the APK file
            output_dir: Directory for output
            progress_callback: Optional callback for progress messages

        Returns:
            ToolResult with MobSF analysis report
        """
        if not target.exists():
            return ToolResult(
                success=False,
                output="",
                error=f"Target file not found: {target}",
                duration_ms=0,
            )

        if not settings.MOBSF_API_KEY:
            return ToolResult(
                success=False,
                output="",
                error="MobSF API key not configured. Set MOBSF_API_KEY in environment.",
                duration_ms=0,
            )

        # Ensure output directory exists
        output_path = self._ensure_output_dir(output_dir / "mobsf")

        headers = {
            "Authorization": settings.MOBSF_API_KEY,
        }

        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                # Step 1: Upload APK
                if progress_callback:
                    progress_callback("Uploading APK to MobSF...")

                upload_url = f"{settings.MOBSF_URL}/api/v1/upload"

                with open(target, "rb") as f:
                    files = {"file": (target.name, f, "application/vnd.android.package-archive")}
                    upload_resp = await client.post(
                        upload_url,
                        files=files,
                        headers=headers,
                    )

                if upload_resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"MobSF upload failed: {upload_resp.text}",
                        duration_ms=self._elapsed_ms(),
                    )

                upload_data = upload_resp.json()
                scan_hash = upload_data.get("hash")

                if not scan_hash:
                    return ToolResult(
                        success=False,
                        output="",
                        error="No hash returned from MobSF upload",
                        duration_ms=self._elapsed_ms(),
                    )

                if progress_callback:
                    progress_callback(f"Upload complete. Scan hash: {scan_hash}")

                # Step 2: Trigger scan
                if progress_callback:
                    progress_callback("Running MobSF analysis...")

                scan_url = f"{settings.MOBSF_URL}/api/v1/scan"
                scan_resp = await client.post(
                    scan_url,
                    json={"hash": scan_hash},
                    headers=headers,
                )

                if scan_resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"MobSF scan failed: {scan_resp.text}",
                        duration_ms=self._elapsed_ms(),
                    )

                # Step 3: Get JSON report
                if progress_callback:
                    progress_callback("Retrieving analysis report...")

                report_url = f"{settings.MOBSF_URL}/api/v1/report_json"
                report_resp = await client.get(
                    report_url,
                    params={"hash": scan_hash},
                    headers=headers,
                )

                if report_resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"MobSF report retrieval failed: {report_resp.text}",
                        duration_ms=self._elapsed_ms(),
                    )

                report_data = report_resp.json()

                # Save report
                report_file = output_path / "report.json"
                with open(report_file, "w") as f:
                    json.dump(report_data, f, indent=2)

                # Count findings
                findings_count = self._count_findings(report_data)

                if progress_callback:
                    progress_callback(f"Analysis complete. Found {findings_count} issues.")

                return ToolResult(
                    success=True,
                    output=json.dumps(report_data, indent=2),
                    error="",
                    duration_ms=self._elapsed_ms(),
                    artifacts_path=output_path,
                    findings_count=findings_count,
                    metrics={
                        "scan_hash": scan_hash,
                        "findings_count": findings_count,
                    },
                )

        except httpx.ConnectError:
            return ToolResult(
                success=False,
                output="",
                error=f"Cannot connect to MobSF at {settings.MOBSF_URL}. Ensure MobSF server is running.",
                duration_ms=self._elapsed_ms(),
            )
        except Exception as e:
            logger.exception(f"[{self.name}] Unexpected error")
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                duration_ms=self._elapsed_ms(),
            )

    def _count_findings(self, report: dict) -> int:
        """Count total findings in MobSF report."""
        count = 0

        # Security findings
        if "security" in report:
            count += len(report["security"])

        # Manifest analysis
        if "manifest_analysis" in report:
            count += len(report["manifest_analysis"])

        # Code analysis
        if "code_analysis" in report:
            count += len(report["code_analysis"])

        # NIAP analysis
        if "niap_analysis" in report:
            count += len(report["niap_analysis"])

        return count

    async def check_server_status(self) -> dict:
        """Check if MobSF server is running and accessible."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{settings.MOBSF_URL}/api/v1/version")

                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "running": True,
                        "version": data.get("version", "unknown"),
                        "url": settings.MOBSF_URL,
                    }

                return {
                    "running": False,
                    "error": f"Server returned {resp.status_code}",
                    "url": settings.MOBSF_URL,
                }
        except httpx.ConnectError:
            return {
                "running": False,
                "error": "Cannot connect to MobSF server",
                "url": settings.MOBSF_URL,
            }
        except Exception as e:
            return {
                "running": False,
                "error": str(e),
                "url": settings.MOBSF_URL,
            }