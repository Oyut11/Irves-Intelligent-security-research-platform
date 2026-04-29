import asyncio
import json
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import logging

from database import crud
from database.connection import get_db
from database.models import ScanStatus, FindingSeverity, ToolExecutionStatus
from config import settings

logger = logging.getLogger(__name__)


class ScannerService:
    """Orchestrates security scans using Python-native + available system tools."""

    def __init__(self):
        self.active_scans: dict = {}

    async def start_scan(
        self,
        project_id: str,
        target: Optional[Path],
        profile: str,
        custom_tools: List[str] = None,
    ) -> str:
        """Create a scan record and launch the background pipeline."""
        async with get_db() as db:
            scan = await crud.create_scan(db, project_id=project_id, profile=profile)
            scan_id = str(scan.id)

        # create output dir
        output_dir = settings.projects_path / project_id / "scans" / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        task = asyncio.create_task(
            self._run_pipeline(scan_id, project_id, target, output_dir, profile, custom_tools)
        )
        self.active_scans[scan_id] = task
        return scan_id

    # ─────────────────────────────────────────────────────────────────────────
    async def _run_pipeline(
        self,
        scan_id: str,
        project_id: str,
        target: Optional[Path],
        output_dir: Path,
        profile: str,
        custom_tools: List[str] = None,
    ):
        """Main scan pipeline. Runs inside an asyncio.Task."""
        async with get_db() as db:
            await crud.update_scan_status(
                db, scan_id, ScanStatus.RUNNING, started_at=datetime.utcnow()
            )

        await self._broadcast(scan_id, {"type": "status", "status": "running", "message": "Pipeline started"})

        # Guard: runtime-only profile must be launched via the Runtime Workspace (Frida)
        # — it should never arrive here through the static scan pipeline.
        if profile == "runtime":
            await self._broadcast(scan_id, {
                "type": "error",
                "message": "Runtime profile cannot be run through the static pipeline. "
                           "Please use the Runtime Workspace (Frida) instead.",
            })
            async with get_db() as db:
                await crud.update_scan_status(
                    db, scan_id, ScanStatus.FAILED, completed_at=datetime.utcnow()
                )
            self.active_scans.pop(scan_id, None)
            return

        all_findings = []

        # ── Platform dispatch ────────────────────────────────────────────────────
        if target and target.exists():
            suffix = target.suffix.lower()
            if suffix == ".apk":
                await self._run_stage(
                    scan_id, project_id, target, output_dir, all_findings, profile,
                    analyzer_cls_path="services.tools.apk_analyzer.APKAnalyzerRunner",
                    tool_name="apk_analyzer",
                )
            elif suffix == ".ipa":
                await self._run_stage(
                    scan_id, project_id, target, output_dir, all_findings, profile,
                    analyzer_cls_path="services.tools.ios_analyzer.IPAAnalyzerRunner",
                    tool_name="ios_analyzer",
                )
            elif suffix in (".exe", ".msi", ".dmg", ".deb", ".rpm", ".appimage"):
                await self._run_stage(
                    scan_id, project_id, target, output_dir, all_findings, profile,
                    analyzer_cls_path="services.tools.desktop_analyzer.DesktopAnalyzerRunner",
                    tool_name="desktop_analyzer",
                )
            else:
                await self._broadcast(scan_id, {
                    "type": "progress", "tool": "scanner",
                    "message": f"No static analyzer for {suffix} — skipping",
                })
        elif target and (str(target).startswith("http://") or str(target).startswith("https://")):
            await self._run_stage(
                scan_id, project_id, target, output_dir, all_findings, profile,
                analyzer_cls_path="services.tools.web_analyzer.WebAnalyzerRunner",
                tool_name="web_analyzer",
            )
        else:
            await self._broadcast(scan_id, {
                "type": "progress", "tool": "scanner",
                "message": "No target file — skipping static analysis",
            })

        # ── AI Auto-Triage Phase ────────────────────────────────────────────────
        await self._broadcast(scan_id, {
            "type": "tool_start", "tool": "ai",
            "message": "AI Auto-Triage…",
        })
        
        critical_findings = [f for f in all_findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)]
        findings_analyzed = 0
        if critical_findings:
            # Pre-analyze up to 2 top critical findings
            top_findings = sorted(critical_findings, key=lambda x: (x.severity.value, x.id))[:2]
            try:
                from services.ai_service import AIService
                from database.models import FindingStatus
                ai_srv = AIService()
                for top_finding in top_findings:
                    analysis_result = await ai_srv.analyze_finding({
                        "title": top_finding.title,
                        "severity": top_finding.severity.value,
                        "tool": top_finding.tool,
                        "category": top_finding.category,
                        "location": top_finding.location,
                        "owasp_mapping": top_finding.owasp_mapping,
                        "cwe_mapping": top_finding.cwe_mapping,
                        "description": top_finding.description,
                        "code_snippet": top_finding.code_snippet,
                    })
                    async with get_db() as db:
                        f_to_update = await crud.get_finding(db, str(top_finding.id))
                        if f_to_update:
                            f_to_update.ai_analysis = json.dumps(analysis_result)
                            f_to_update.status = FindingStatus.OPEN
                            await db.flush()
                    findings_analyzed += 1
                    await self._broadcast(scan_id, {
                        "type": "progress", "tool": "ai",
                        "message": f"Pre-analyzed: {top_finding.title[:20]}...",
                    })
            except Exception as e:
                logger.warning(f"[scanner] AI Auto-Triage failed: {e}")
                await self._broadcast(scan_id, {
                    "type": "progress", "tool": "ai",
                    "message": "AI skipped (no API key configured or provider error)",
                })
        else:
            await self._broadcast(scan_id, {
                "type": "progress", "tool": "ai",
                "message": "No critical findings for AI",
            })
            
        await self._broadcast(scan_id, {
            "type": "tool_complete", "tool": "ai",
            "findings_count": findings_analyzed,
            "message": "Completed",
        })

        # Mark complete
        async with get_db() as db:
            await crud.update_scan_status(
                db, scan_id, ScanStatus.COMPLETED, completed_at=datetime.utcnow()
            )
        await crud.update_scan_progress_standalone(scan_id, 100)
        await self._broadcast(scan_id, {
            "type": "complete",
            "findings_count": len(all_findings),
            "scan_id": scan_id,
        })
        logger.info(f"[scanner] scan {scan_id} complete — {len(all_findings)} findings")
        self.active_scans.pop(scan_id, None)

    # ── Universal stage dispatcher ────────────────────────────────────────────
    async def _run_stage(
        self,
        scan_id: str,
        project_id: str,
        target: Path,
        output_dir: Path,
        all_findings: list,
        profile: str,
        analyzer_cls_path: str,
        tool_name: str,
    ):
        """Universal dispatcher: loads any ToolRunner by dotted import path and runs it."""
        await self._broadcast(scan_id, {
            "type": "tool_start", "tool": tool_name,
            "message": f"Analyzing {target.name}…",
        })
        await self._update_progress(scan_id, 5)

        async with get_db() as db:
            exec_rec = await crud.create_tool_execution(db, scan_id, tool_name)
            exec_id = str(exec_rec.id)
            await crud.update_tool_execution(
                db, exec_id, status=ToolExecutionStatus.RUNNING, started_at=datetime.utcnow()
            )

        def on_progress(msg: str):
            asyncio.create_task(self._broadcast(scan_id, {
                "type": "progress", "tool": tool_name, "message": msg,
            }))

        try:
            module_path, cls_name = analyzer_cls_path.rsplit(".", 1)
            import importlib
            module = importlib.import_module(module_path)
            runner = getattr(module, cls_name)()
        except Exception as e:
            logger.error(f"[scanner] Could not load {analyzer_cls_path}: {e}")
            await self._broadcast(scan_id, {"type": "tool_error", "tool": tool_name, "message": str(e)})
            return

        try:
            result = await asyncio.wait_for(
                runner.run(target, output_dir, on_progress),
                timeout=600
            )
        except asyncio.TimeoutError:
            msg = f"{tool_name} analysis timed out after 10 minutes"
            logger.warning(f"[scanner] {msg}")
            await self._broadcast(scan_id, {"type": "tool_error", "tool": tool_name, "message": msg})
            async with get_db() as db:
                await crud.update_tool_execution(db, exec_id, status=ToolExecutionStatus.FAILED, error_message=msg)
            return
        except Exception as e:
            logger.exception(f"[scanner] {tool_name} crashed")
            async with get_db() as db:
                await crud.update_tool_execution(db, exec_id, status=ToolExecutionStatus.FAILED, error_message=str(e))
            await self._broadcast(scan_id, {"type": "tool_error", "tool": tool_name, "message": str(e)})
            return

        await self._update_progress(scan_id, 80)
        findings_raw = []
        malware_score = None
        score_label = None
        try:
            payload = json.loads(result.output or "{}")
            findings_raw = payload.get("findings", [])
            malware_score = payload.get("malware_score")
            score_label = payload.get("score_label")
        except Exception as e:
            logger.warning(f"[scanner] Failed to parse JSON output from {tool_name}: {e}")

        sev_map = {
            "critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        saved = 0
        for f in findings_raw:
            try:
                async with get_db() as db:
                    finding = await crud.create_finding(
                        db, scan_id=scan_id,
                        title=f.get("title", "Unknown"),
                        severity=sev_map.get(f.get("severity", "medium"), FindingSeverity.MEDIUM),
                        tool=f.get("tool", tool_name),
                        category=f.get("category", "General"),
                        location=f.get("location", ""),
                        description=f.get("description", ""),
                        code_snippet=f.get("code_snippet", ""),
                        owasp_mapping=f.get("owasp_mapping", ""),
                        cwe_mapping=f.get("cwe_mapping", ""),
                    )
                all_findings.append(finding)
                await self._broadcast(scan_id, {
                    "type": "finding",
                    "title": f.get("title"), "severity": f.get("severity", "medium"),
                    "location": f.get("location", ""), "category": f.get("category", ""),
                    "tool": tool_name,
                })
                saved += 1
            except Exception as e:
                logger.error(f"[scanner] Failed to save finding: {e}")

        await self._update_progress(scan_id, 95)
        async with get_db() as db:
            metrics = {"findings": saved, "duration_ms": result.duration_ms}
            if malware_score is not None:
                metrics["malware_score"] = malware_score
            if score_label is not None:
                metrics["score_label"] = score_label
            await crud.update_tool_execution(
                db, exec_id,
                status=ToolExecutionStatus.COMPLETED if result.success else ToolExecutionStatus.FAILED,
                completed_at=datetime.utcnow(),
                metrics=metrics,
                error_message=result.error if not result.success else None,
            )
        await self._broadcast(scan_id, {
            "type": "tool_complete", "tool": tool_name,
            "findings_count": saved, "message": f"Completed: {saved} findings",
        })

    # ── Legacy APK stage (kept for backward compat) ───────────────────────────
    async def _run_apk_stage(
        self,
        scan_id: str,
        project_id: str,
        target: Path,
        output_dir: Path,
        all_findings: list,
        profile: str,
    ):
        from services.tools.apk_analyzer import APKAnalyzerRunner

        runner = APKAnalyzerRunner()
        tool_name = "apk_analyzer"

        await self._broadcast(scan_id, {
            "type": "tool_start", "tool": tool_name,
            "message": f"Analyzing {target.name}…",
        })
        await self._update_progress(scan_id, 5)

        # Create tool execution record
        async with get_db() as db:
            exec_rec = await crud.create_tool_execution(db, scan_id, tool_name)
            exec_id = str(exec_rec.id)
            await crud.update_tool_execution(
                db, exec_id, status=ToolExecutionStatus.RUNNING, started_at=datetime.utcnow()
            )

        def on_progress(msg: str):
            asyncio.create_task(self._broadcast(scan_id, {
                "type": "progress", "tool": tool_name, "message": msg,
            }))

        try:
            result = await runner.run(target, output_dir, on_progress)
        except Exception as e:
            logger.exception(f"[scanner] APK analyzer crashed: {e}")
            async with get_db() as db:
                await crud.update_tool_execution(
                    db, exec_id, status=ToolExecutionStatus.FAILED, error_message=str(e)
                )
            await self._broadcast(scan_id, {
                "type": "tool_error", "tool": tool_name, "message": str(e),
            })
            return

        await self._update_progress(scan_id, 80)

        # Parse and persist findings
        findings_raw = []
        try:
            payload = json.loads(result.output or "{}")
            findings_raw = payload.get("findings", [])
        except Exception:
            pass

        sev_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }

        saved = 0
        for f in findings_raw:
            try:
                async with get_db() as db:
                    finding = await crud.create_finding(
                        db,
                        scan_id=scan_id,
                        title=f.get("title", "Unknown"),
                        severity=sev_map.get(f.get("severity", "medium"), FindingSeverity.MEDIUM),
                        tool=f.get("tool", tool_name),
                        category=f.get("category", "General"),
                        location=f.get("location", ""),
                        description=f.get("description", ""),
                        code_snippet=f.get("code_snippet", ""),
                        owasp_mapping=f.get("owasp_mapping", ""),
                        cwe_mapping=f.get("cwe_mapping", ""),
                    )
                all_findings.append(finding)
                await self._broadcast(scan_id, {
                    "type": "finding",
                    "title": f.get("title"),
                    "severity": f.get("severity", "medium"),
                    "location": f.get("location", ""),
                    "category": f.get("category", ""),
                    "tool": tool_name,
                })
                saved += 1
            except Exception as e:
                logger.error(f"[scanner] Failed to save finding: {e}")

        await self._update_progress(scan_id, 95)

        async with get_db() as db:
            await crud.update_tool_execution(
                db, exec_id,
                status=ToolExecutionStatus.COMPLETED if result.success else ToolExecutionStatus.FAILED,
                completed_at=datetime.utcnow(),
                metrics={"findings": saved, "duration_ms": result.duration_ms},
                error_message=result.error if not result.success else None,
            )

        await self._broadcast(scan_id, {
            "type": "tool_complete", "tool": tool_name,
            "findings_count": saved,
            "message": f"Completed: {saved} findings",
        })

    # ─────────────────────────────────────────────────────────────────────────
    async def _broadcast(self, scan_id: str, payload: dict):
        try:
            from services.events import event_bus
            await event_bus.emit(scan_id, payload["type"], payload)
        except Exception as e:
            logger.debug(f"[scanner] broadcast error: {e}")

    async def _update_progress(self, scan_id: str, pct: int):
        try:
            async with get_db() as db:
                await crud.update_scan_progress(db, scan_id, pct)
            await self._broadcast(scan_id, {"type": "progress_pct", "progress": pct})
        except Exception as e:
            logger.debug(f"[scanner] progress update error: {e}")

    def cancel(self, scan_id: str):
        task = self.active_scans.get(scan_id)
        if task:
            task.cancel()
            self.active_scans.pop(scan_id, None)


# Global singleton
scanner_service = ScannerService()
