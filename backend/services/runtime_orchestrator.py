"""
IRVES — Runtime Orchestrator
Coordinates the elite runtime analysis pipeline:
  Step 1: Initialization  → eBPF probe pushed to kernel via KernelSU
  Step 2: Hardening       → Target app forced into MTE SYNC mode
  Step 3: Execution       → App spawned via Spawn Gating (Zymbiote)
  Step 4: Analysis        → AI reads eBPF traces + MTE faults
"""

import asyncio
import json
import logging
from typing import AsyncIterator, Dict, Any, Optional, List
from datetime import datetime

from services.ebpf_service import ebpf_service, eBPFEvent
from services.mte_service import mte_service, MTEFault
from services.frida_service import frida_service
from services.ai_service import ai_service

logger = logging.getLogger(__name__)


class RuntimeOrchestrator:
    """Orchestrates the elite runtime analysis pipeline.

    Coordinates eBPF kernel monitoring, MTE hardware memory detection,
    and Zymbiote stealth Frida injection into a single automated flow.
    """

    def __init__(self):
        self._active_sessions: Dict[str, dict] = {}

    async def start_elite_analysis(
        self,
        serial: str,
        package: str,
        device_id: str,
        duration_seconds: int = 300,
        inject_hooks: Optional[List[str]] = None,
    ) -> AsyncIterator[dict]:
        """Execute the full 4-step elite analysis pipeline.

        Yields progress events as SSE-compatible dicts with:
          step, phase, status, message, data

        Args:
            serial: ADB device serial
            package: Target Android package name
            device_id: Frida device identifier
            duration_seconds: Max monitoring duration
            inject_hooks: Optional list of BUILTIN_HOOKS keys to inject
        """
        session_key = f"{serial}:{package}"
        self._active_sessions[session_key] = {
            "serial": serial,
            "package": package,
            "started_at": datetime.utcnow().isoformat(),
            "status": "running",
        }

        try:
            # ── Step 1: Initialization — Deploy eBPF probe ──────────────
            yield {
                "step": 1, "phase": "initialization", "status": "running",
                "message": "Deploying eBPF probe to kernel via KernelSU…",
            }
            probe_result = await ebpf_service.deploy_probe(serial)
            yield {
                "step": 1, "phase": "initialization",
                "status": "done" if probe_result.get("status") in ("deployed", "deployed_fallback") else "error",
                "message": probe_result.get("message", "eBPF probe deployment complete"),
                "data": probe_result,
            }
            if probe_result.get("status") not in ("deployed", "deployed_fallback"):
                # eBPF failed — continue without it (graceful degradation)
                logger.warning(f"[Orchestrator] eBPF probe failed, continuing without kernel monitoring")

            # ── Step 2: Hardening — Enable MTE SYNC ─────────────────────
            yield {
                "step": 2, "phase": "hardening", "status": "running",
                "message": "Forcing MTE SYNC mode on target app…",
            }
            mte_result = await mte_service.harden_analysis(serial, package)
            yield {
                "step": 2, "phase": "hardening",
                "status": "done" if mte_result.get("status") in ("hardened", "unsupported") else "error",
                "message": mte_result.get("message", "MTE hardening complete"),
                "data": mte_result,
            }

            # ── Step 3: Execution — Spawn via Zymbiote ──────────────────
            yield {
                "step": 3, "phase": "execution", "status": "running",
                "message": "Spawning app via Zymbiote (spawn gating)…",
            }
            spawn_result = await frida_service.spawn_gate(device_id, package)
            pid = spawn_result.get("pid", 0)
            is_stealth = spawn_result.get("is_stealth", False)

            # Verify stealth
            stealth_result = {}
            if is_stealth and pid:
                stealth_result = await frida_service.verify_stealth(serial, pid)

            yield {
                "step": 3, "phase": "execution",
                "status": "done",
                "message": f"App spawned: {'STEALTH (Zymbiote)' if is_stealth else 'STANDARD (fallback)'} PID={pid}",
                "data": {**spawn_result, "stealth_verification": stealth_result},
            }

            # Inject hooks if specified
            session_id = spawn_result.get("session_id", "")
            if inject_hooks and session_id:
                for hook_name in inject_hooks:
                    hook_script = frida_service.BUILTIN_HOOKS.get(hook_name)
                    if hook_script:
                        yield {
                            "step": 3, "phase": "execution", "status": "running",
                            "message": f"Injecting hook: {hook_name}…",
                        }
                        try:
                            # Wrap existing logger with orchestrator handler for AI observability
                            def _combined_handler(msg, data):
                                logger.info(f"[Orchestrator-Hook:{hook_name}] {msg}")
                                _orchestrator_frida_handler(msg, data)

                            await frida_service.inject_script(
                                session_id, hook_script, _combined_handler
                            )
                            yield {
                                "step": 3, "phase": "execution", "status": "done",
                                "message": f"Hook injected: {hook_name}",
                            }
                        except Exception as e:
                            yield {
                                "step": 3, "phase": "execution", "status": "error",
                                "message": f"Hook injection failed ({hook_name}): {e}",
                            }

            # ── Step 4: Analysis — AI reads live telemetry ───────────────
            yield {
                "step": 4, "phase": "analysis", "status": "running",
                "message": "Monitoring eBPF traces + MTE faults for AI analysis…",
            }

            # Collect events from both eBPF and MTE monitors concurrently
            ebpf_events: List[dict] = []
            mte_faults: List[dict] = []
            frida_errors: List[dict] = []

            # Wire up Frida error collection if session exists
            if session_id:
                def _orchestrator_frida_handler(msg, data):
                    if msg.get("type") == "error":
                        frida_errors.append({
                            "type": "frida_error",
                            "message": msg.get("description", "Unknown error"),
                            "stack": msg.get("stack", ""),
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
                # We need a way to attach this handler to the existing session
                # For now, we'll assume the orchestrator can intercept messages
                # by wrapping the existing inject_script or adding a listener.
                # The frida_service.inject_script already takes a handler.

            async def _collect_ebpf():
                try:
                    async for event in ebpf_service.monitor_dex_magic(
                        serial, target_pid=pid or None,
                        duration_seconds=duration_seconds,
                    ):
                        ebpf_events.append({
                            "event_type": event.event_type,
                            "pid": event.pid,
                            "addr": hex(event.addr) if event.addr else "0x0",
                            "size": event.size,
                            "fd": event.fd,
                            "is_dex": event.is_dex,
                            "magic": event.magic,
                            "comm": event.comm,
                            "file_backed": event.file_backed,
                        })
                except Exception as e:
                    logger.error(f"[Orchestrator] eBPF monitor error: {e}")

            async def _collect_mte():
                try:
                    async for fault in mte_service.monitor_mte_faults(
                        serial, package=package,
                        duration_seconds=duration_seconds,
                    ):
                        mte_faults.append({
                            "fault_type": fault.code,
                            "pc": fault.pc,
                            "lr": fault.lr,
                            "sp": fault.sp,
                            "fault_addr": fault.fault_addr,
                            "tag_mismatch": fault.tag_mismatch,
                            "registers": fault.registers,
                            "backtrace": fault.backtrace,
                        })
                except Exception as e:
                    logger.error(f"[Orchestrator] MTE monitor error: {e}")

            # Run both monitors concurrently with periodic AI analysis
            ebpf_task = asyncio.create_task(_collect_ebpf())
            mte_task = asyncio.create_task(_collect_mte())

            # Periodically yield collected events for AI analysis
            analysis_interval = 10  # seconds between AI analysis bursts
            total_elapsed = 0
            while total_elapsed < duration_seconds:
                await asyncio.sleep(analysis_interval)
                total_elapsed += analysis_interval

                # Snapshot current events
                current_ebpf = list(ebpf_events)
                current_mte = list(mte_faults)
                current_frida = list(frida_errors)
                ebpf_events.clear()
                mte_faults.clear()
                frida_errors.clear()

                if current_ebpf or current_mte or current_frida:
                    # Yield raw telemetry first
                    yield {
                        "step": 4, "phase": "analysis", "status": "data",
                        "message": f"Telemetry batch: {len(current_ebpf)} eBPF, {len(current_mte)} MTE, {len(current_frida)} Frida errors",
                        "data": {
                            "ebpf_events": current_ebpf,
                            "mte_faults": current_mte,
                            "frida_errors": current_frida,
                            "elapsed_seconds": total_elapsed,
                            "is_stealth": is_stealth,
                        },
                    }

                    # ── AI Analysis of telemetry batch ───────────────────────
                    try:
                        ai_chunks = []
                        async for chunk in ai_service.stream_runtime_orchestration(
                            telemetry_batch={
                                "ebpf_events": current_ebpf,
                                "mte_faults": current_mte,
                                "frida_errors": current_frida,
                                "elapsed_seconds": total_elapsed,
                                "is_stealth": is_stealth,
                            },
                            user_id=f"elite_{serial}",
                            session_id=f"elite_{serial}:{package}",
                        ):
                            ai_chunks.append(chunk)
                            yield {
                                "step": 4, "phase": "analysis", "status": "ai_chunk",
                                "message": chunk,
                            }
                        if ai_chunks:
                            ai_analysis = "".join(ai_chunks)
                            yield {
                                "step": 4, "phase": "analysis", "status": "ai_complete",
                                "message": "AI analysis complete for this batch",
                                "data": {"ai_analysis": ai_analysis},
                            }
                    except Exception as e:
                        logger.error(f"[Orchestrator] AI analysis failed: {e}")
                        yield {
                            "step": 4, "phase": "analysis", "status": "ai_error",
                            "message": f"AI analysis failed: {e}",
                        }
                else:
                    yield {
                        "step": 4, "phase": "analysis", "status": "heartbeat",
                        "message": f"No events in last {analysis_interval}s (elapsed: {total_elapsed}s)",
                        "data": {"elapsed_seconds": total_elapsed},
                    }

            # Cancel monitors
            ebpf_task.cancel()
            mte_task.cancel()
            try:
                await ebpf_task
            except asyncio.CancelledError:
                pass
            try:
                await mte_task
            except asyncio.CancelledError:
                pass

            # Final summary
            yield {
                "step": 4, "phase": "analysis", "status": "done",
                "message": f"Analysis complete. Duration: {duration_seconds}s",
                "data": {
                    "total_ebpf_events": len(ebpf_events),
                    "total_mte_faults": len(mte_faults),
                    "is_stealth": is_stealth,
                    "pid": pid,
                },
            }

        except Exception as e:
            logger.error(f"[Orchestrator] Pipeline error: {e}")
            yield {
                "step": 0, "phase": "error", "status": "error",
                "message": f"Pipeline failed: {e}",
            }
        finally:
            # Cleanup
            try:
                await ebpf_service.teardown_probe(serial)
            except Exception:
                pass
            self._active_sessions.pop(session_key, None)

    async def quick_analysis(
        self,
        serial: str,
        package: str,
        device_id: str,
    ) -> AsyncIterator[dict]:
        """Quick analysis — just spawn + stealth check, no eBPF/MTE.

        Useful for fast Frida injection without the full pipeline.
        """
        yield {"step": 1, "phase": "spawn", "status": "running",
               "message": f"Spawning {package} via Zymbiote…"}

        spawn_result = await frida_service.spawn_gate(device_id, package)
        pid = spawn_result.get("pid", 0)

        yield {"step": 1, "phase": "spawn", "status": "done",
               "message": f"Spawned: {'STEALTH' if spawn_result.get('is_stealth') else 'STANDARD'} PID={pid}",
               "data": spawn_result}

        if pid:
            stealth = await frida_service.verify_stealth(serial, pid)
            yield {"step": 2, "phase": "stealth_check", "status": "done",
                   "message": f"Stealth: {'PASS' if stealth.get('overall_stealth') else 'FAIL'}",
                   "data": stealth}

    def get_active_sessions(self) -> Dict[str, dict]:
        return dict(self._active_sessions)


# Global singleton
runtime_orchestrator = RuntimeOrchestrator()
