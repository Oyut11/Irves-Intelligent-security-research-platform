"""
IRVES — Runtime WebSocket Router
Frida WebSocket + Xposed logcat-bridge WebSocket + SSE setup streams.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
from datetime import datetime

from services.frida_service import frida_service, BUILTIN_HOOKS
from services.xposed_service import xposed_service
from services.mte_service import mte_service
from services.ebpf_service import ebpf_service
from services.runtime_orchestrator import runtime_orchestrator
from services.ai_service import ai_service
from database import get_db, get_finding

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/preflight")
async def runtime_preflight():
    """Check Frida availability, ADB devices, and connected USB phones."""
    return await frida_service.preflight_check()


@router.get("/preflight/xposed")
async def xposed_preflight():
    """Check Java + ADB availability and LSPatch cached assets."""
    return await xposed_service.preflight_check()


@router.get("/adb-devices")
async def adb_devices():
    """Return raw `adb devices` list — works even without frida-server on device."""
    return await frida_service.adb_devices()


@router.get("/apps/{serial}")
async def installed_apps(serial: str):
    """List 3rd-party user installed apps directly from the device."""
    try:
        proc = await asyncio.create_subprocess_shell(
            f"adb -s {serial} shell pm list packages -3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode('utf-8', errors='ignore').strip().split('\n')
        packages = []
        for line in lines:
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.replace("package:", ""))
        return {"status": "success", "packages": sorted(packages)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/setup-frida-server/{serial}")
async def setup_frida_server(serial: str):
    """
    SSE stream that pushes and starts frida-server on the given ADB device.
    Events: data: {step, status, message}
    """
    async def event_stream():
        try:
            async for progress in frida_service.push_and_start_frida_server(serial):
                if progress.get("step") == "complete":
                    event_name = "done"
                elif progress.get("status") == "error":
                    event_name = "error_event"
                else:
                    event_name = "step"
                yield f"event: {event_name}\ndata: {json.dumps(progress)}\n\n"
        except Exception as e:
            yield f"event: error_event\ndata: {json.dumps({'step': 'error', 'status': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/setup-xposed/{serial}")
async def setup_xposed(serial: str, package: str):
    """
    Server-Sent Events endpoint to stream the LSPatch/Xposed setup process.
    Requires the target `package` query parameter.
    """
    async def event_generator():
        try:
            async for step_result in xposed_service.patch_and_install_generator(serial, package):
                if step_result.get("status") == "error":
                    yield f"event: error_event\ndata: {json.dumps({'message': step_result.get('message')})}\n\n"
                    # Do not break — generator may have more final steps
                    continue

                # Emit 'done' event on the final cleanup-done step
                ev_name = (
                    "done"
                    if step_result["step"] == "cleanup" and step_result["status"] == "done"
                    else "step"
                )
                yield f"event: {ev_name}\ndata: {json.dumps(step_result)}\n\n"
                await asyncio.sleep(0.05)

        except Exception as e:
            logger.exception("SSE Xposed setup error")
            yield f"event: error_event\ndata: {json.dumps({'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.websocket("/ws/xposed/{serial}/{package}")
async def xposed_logcat_websocket(websocket: WebSocket, serial: str, package: str):
    """
    WebSocket endpoint for a live Xposed/LSPatch session.
    Streams logcat output from the patched app in real time.

    Protocol:
      Server → Client:
        { "type": "output",    "payload": "<logcat line>" }
        { "type": "connected", "payload": "Logcat stream started" }
        { "type": "error",     "payload": "<message>" }
        { "type": "ping" }   — keepalive
    """
    await websocket.accept()

    async def send(msg: dict):
        try:
            await websocket.send_json(msg)
        except Exception:
            pass

    await send({"type": "connected",
                "payload": f"Xposed logcat stream — watching {package} on {serial}"})

    xposed_pivot_in_progress = False

    async def _xposed_trigger_pivot(error_line: str):
        """Auto-trigger AI pivot when an Xposed error is detected in logcat."""
        nonlocal xposed_pivot_in_progress
        if xposed_pivot_in_progress:
            return
        xposed_pivot_in_progress = True
        try:
            await send({"type": "ai_pivot_start", "payload": "Xposed error detected — pivoting strategy..."})
            full_response = ""
            async for chunk in ai_service.generate_realtime_pivot(
                error_msg=error_line,
                package=package,
            ):
                full_response += chunk
                await send({"type": "ai_pivot_token", "payload": chunk})
            await send({"type": "ai_pivot_done", "payload": full_response})
        except Exception as e:
            logger.error(f"[Xposed WS] AI pivot failed: {e}")
        finally:
            xposed_pivot_in_progress = False

    _XPOSED_ERROR_KEYWORDS = ("exception", "error", "fatal", "crash", "failed", "classnotfound", "nosuchmethod")

    try:
        # Run logcat stream and forward to WebSocket
        async for line in xposed_service.logcat_stream(serial, package):
            if line == "__ping__":
                await send({"type": "ping"})
            else:
                await send({"type": "output", "payload": line})
                # Detect Xposed errors in logcat and auto-pivot
                if any(kw in line.lower() for kw in _XPOSED_ERROR_KEYWORDS):
                    # Use consistent session key that matches chat endpoint (session_id only)
                    xposed_session_key = f"xposed_{serial}:{package}"
                    ai_service.record_runtime_error(xposed_session_key, line)
                    await _xposed_trigger_pivot(line)

            # Check if client disconnected
            try:
                await asyncio.wait_for(
                    asyncio.shield(websocket.receive_text()), timeout=0.01
                )
            except (asyncio.TimeoutError, Exception):
                pass

    except WebSocketDisconnect:
        logger.info(f"[Xposed WS] Client disconnected from {serial}/{package}")
    except Exception as e:
        logger.exception(f"[Xposed WS] Error: {e}")
        await send({"type": "error", "payload": str(e)})


@router.get("/devices")
async def list_devices():
    """List all connected devices visible to Frida."""
    try:
        return await frida_service.list_devices()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices/{device_id}/processes")
async def list_processes(device_id: str):
    """List running processes on a device."""
    try:
        return await frida_service.list_processes(device_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hooks")
async def list_builtin_hooks():
    """Return structured metadata for all built-in hooks."""
    HOOK_META = {
        "apk_info": {
            "label": "App Context & Info Extractor",
            "category": "Reconnaissance",
            "description": "Hooks the ActivityThread to pull hidden metadata directly from the live application context, such as full package versioning and local path bindings.",
            "risk": "low",
            "tags": ["recon", "metadata"],
        },
        "ssl_bypass": {
            "label": "SSL Pinning Bypass",
            "category": "Network Security",
            "description": "Disables OkHttp3 certificate pinning and TrustManagerImpl chain verification, allowing interception of HTTPS traffic with a proxy.",
            "risk": "high",
            "tags": ["ssl", "mitm", "network"],
        },
        "root_detection_bypass": {
            "label": "Root Detection Bypass",
            "category": "Anti-Tamper",
            "description": "Patches common root detection libraries (RootBeer, SuperUser) and blocks su binary execution attempts.",
            "risk": "medium",
            "tags": ["root", "evasion"],
        },
        "crypto_capture": {
            "label": "Crypto Operation Capture",
            "category": "Cryptography",
            "description": "Intercepts javax.crypto.Cipher calls to log algorithm names and plaintext input/output bytes in real time.",
            "risk": "high",
            "tags": ["crypto", "aes", "keys"],
        },
        "network_intercept": {
            "label": "Network Connection Monitor",
            "category": "Network Security",
            "description": "Hooks java.net.URL.openConnection to log every outbound network request including full URL.",
            "risk": "low",
            "tags": ["network", "http", "urls"],
        },
        "intent_monitor": {
            "label": "Android Intent Monitor",
            "category": "IPC / Components",
            "description": "Monitors all explicitly-created Intents, logging source context and destination component class names.",
            "risk": "low",
            "tags": ["intents", "ipc", "components"],
        },
        "zymbiote_stealth": {
            "label": "Zymbiote Stealth Cloak",
            "category": "Anti-Detection",
            "description": "Hides Frida from /proc/self/maps and /proc/self/fd, masks frida-agent thread names, and makes the instrumentation invisible to RASP-based detections.",
            "risk": "high",
            "tags": ["stealth", "anti-detection", "rasp", "frida"],
        },
        "boring_ssl_capture": {
            "label": "BoringSSL Native Capture",
            "category": "Network Security",
            "description": "Hooks SSL_read/SSL_write in the native TLS layer (BoringSSL/libssl). Captures plaintext traffic post-decryption regardless of certificate pinning, TrustManagers, or HPKP. Works even when Java-layer bypasses fail.",
            "risk": "high",
            "tags": ["ssl", "tls", "native", "plaintext", "boringssl"],
        },
    }
    result = []
    for key, script in BUILTIN_HOOKS.items():
        meta = HOOK_META.get(key, {})
        result.append({
            "name": key,
            "label": meta.get("label", key.replace("_", " ").title()),
            "category": meta.get("category", "General"),
            "description": meta.get("description", ""),
            "risk": meta.get("risk", "medium"),
            "tags": meta.get("tags", []),
        })
    return result


@router.get("/hooks/{hook_name}")
async def get_hook_script(hook_name: str):
    """Return the raw script code for a specific built-in hook."""
    if hook_name not in BUILTIN_HOOKS:
        raise HTTPException(status_code=404, detail=f"Hook not found: {hook_name}")
    return {"name": hook_name, "script": BUILTIN_HOOKS[hook_name]}


@router.websocket("/ws/{device_id}/{package}")
async def runtime_websocket(websocket: WebSocket, device_id: str, package: str):
    """
    WebSocket endpoint for a live Frida session.

    Protocol (JSON messages):
      Client → Server:
        { "type": "spawn" }                                  — spawn & attach
        { "type": "attach" }                                 — attach only
        { "type": "inject", "hook_name": "ssl_bypass" }     — inject built-in hook
        { "type": "inject", "script": "<js code>" }         — inject custom script
        { "type": "call", "script_id": "...", "fn": "...", "args": [] }
        { "type": "detach" }                                 — detach session

      Server → Client:
        { "type": "attached", "session_id": "..." }
        { "type": "injected", "script_id": "..." }
        { "type": "output", "payload": "..." }
        { "type": "error", "payload": "..." }
        { "type": "ai_pivot_start", "payload": "..." }  — AI detected error, starting pivot
        { "type": "ai_pivot_token", "payload": "..." }  — streaming AI pivot response
        { "type": "ai_pivot_done", "payload": "..." }   — full AI pivot response
        { "type": "detached" }
    """
    await websocket.accept()

    # ── Load finding context if arriving from a finding detail page ──────────
    finding_id = websocket.query_params.get("finding_id")
    finding_context = None
    if finding_id:
        try:
            async with get_db() as db:
                finding = await get_finding(db, finding_id)
                if finding:
                    _ai_analysis = finding.ai_analysis or ""
                    finding_context = {
                        "title": finding.title,
                        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
                        "category": finding.category,
                        "location": finding.location,
                        "description": finding.description,
                        "code_snippet": finding.code_snippet,
                        "owasp_mapping": finding.owasp_mapping,
                        "cwe_mapping": finding.cwe_mapping,
                        "tool": finding.tool,
                        "ai_analysis": _ai_analysis,
                        "ai_attack_path": finding.ai_attack_path,
                        "ai_fix_guidance": finding.ai_fix_guidance,
                    }
                    logger.info(f"[Runtime WS] Loaded finding context for {finding_id}: {finding.title}")
        except Exception as e:
            logger.warning(f"[Runtime WS] Could not load finding context: {e}")

    session_id = None
    last_script_code = ""       # Track the last injected script for AI pivot context
    pivot_in_progress = False    # Prevent overlapping AI pivot calls
    loop = asyncio.get_event_loop()  # capture loop for thread-safe callbacks
    session_history_log: list[dict] = []  # Track injected scripts, outputs, errors for AI context

    async def send_msg(msg: dict):
        try:
            await websocket.send_json(msg)
        except Exception:
            pass

    def _build_session_history() -> str:
        """Build a human-readable session timeline from the session log."""
        if not session_history_log:
            return "No previous session activity."
        lines = []
        for entry in session_history_log[-10:]:
            ts = entry.get("timestamp", "")
            evt = entry.get("event", "")
            detail = entry.get("detail", "")
            if evt == "inject":
                lines.append(f"[{ts}] Injected script: {detail}")
            elif evt == "output":
                lines.append(f"[{ts}] Output: {detail[:200]}")
            elif evt == "error":
                lines.append(f"[{ts}] Error: {detail[:200]}")
            elif evt == "attach":
                lines.append(f"[{ts}] Attached to target")
        return "\n".join(lines)

    async def _trigger_ai_pivot(error_msg: str, script_ctx: str):
        """Auto-trigger AI pivot when a Frida error is detected in real time."""
        nonlocal pivot_in_progress
        if pivot_in_progress:
            logger.warning(f"[AI-PIVOT] Already in progress, skipping")
            return
        pivot_in_progress = True
        logger.warning(f"[AI-PIVOT] Starting for package={package}")
        try:
            await send_msg({"type": "ai_pivot_start", "payload": "Analyzing error and pivoting strategy..."})
            logger.warning("[AI-PIVOT] Sent ai_pivot_start to client")
            full_response = ""
            chunk_count = 0
            session_history = _build_session_history()
            async for chunk in ai_service.generate_realtime_pivot(
                error_msg=error_msg,
                script_context=script_ctx,
                package=package,
                finding_context=finding_context,
                session_history=session_history,
            ):
                full_response += chunk
                chunk_count += 1
                await send_msg({"type": "ai_pivot_token", "payload": chunk})
            logger.warning(f"[AI-PIVOT] Complete: {chunk_count} chunks, {len(full_response)} chars")
            await send_msg({"type": "ai_pivot_done", "payload": full_response})
        except Exception as e:
            logger.error(f"[Runtime WS] AI pivot failed: {e}")
            await send_msg({"type": "ai_pivot_error", "payload": str(e)})
        finally:
            pivot_in_progress = False

    def frida_message_handler(message, data):
        """Forward Frida script messages → WebSocket. Called from Frida's thread."""
        msg_type = message.get("type")
        # Use WARNING level to ensure these always appear in logs
        logger.warning(f"[FRIDA-MSG] type={msg_type}, keys={list(message.keys())}, msg={str(message)[:200]}")

        if msg_type == "send":
            payload = message.get("payload")
            session_history_log.append({"event": "output", "detail": str(payload)[:500], "timestamp": datetime.utcnow().isoformat()})
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": "output", "payload": payload}), loop
            )
        elif msg_type == "log":
            level   = message.get("level", "info")
            payload = message.get("payload", "")
            out_type = "error" if level == "error" else "warn" if level == "warning" else "output"
            session_history_log.append({"event": out_type, "detail": str(payload)[:500], "timestamp": datetime.utcnow().isoformat()})
            # ── Push live output to AI log buffer ──
            ai_service.record_runtime_log("frida_runtime", f"[{out_type}] {payload}")
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": out_type, "payload": payload}), loop
            )
            # ── AUTO-PIVOT: trigger on log errors too (Frida reports some errors as logs) ──
            if level == "error":
                logger.warning(f"[FRIDA-LOG-ERROR] {payload[:150]}")
                # Use consistent session key that matches chat endpoint (session_id only)
                ai_service.record_runtime_error("frida_runtime", payload, script_context=last_script_code)
                asyncio.run_coroutine_threadsafe(
                    _trigger_ai_pivot(payload, last_script_code), loop
                )
        elif msg_type == "error":
            desc  = message.get("description", "Unknown error")
            stack = message.get("stack", "")
            fname = message.get("fileName", "")
            lnum  = message.get("lineNumber", "")
            err   = desc
            if fname and lnum:
                err += f" ({fname}:{lnum})"
            if stack:
                err += f"\n{stack}"
            session_history_log.append({"event": "error", "detail": err[:500], "timestamp": datetime.utcnow().isoformat()})
            # ── Push live error to AI log buffer ──
            ai_service.record_runtime_log("frida_runtime", f"[error] {err}")
            logger.warning(f"[FRIDA-ERROR] {err[:200]}")
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": "error", "payload": err}), loop
            )
            # ── AUTO-PIVOT: trigger AI strategy change on script error ──
            logger.warning(f"[AI-PIVOT] Triggering from error handler")
            # Use consistent session key that matches chat endpoint (session_id only)
            ai_service.record_runtime_error("frida_runtime", err, stack=stack, script_context=last_script_code)
            asyncio.run_coroutine_threadsafe(
                _trigger_ai_pivot(err, last_script_code), loop
            )
        else:
            if "payload" in message:
                session_history_log.append({"event": "output", "detail": str(message["payload"])[:500], "timestamp": datetime.utcnow().isoformat()})
                # ── Push live output to AI log buffer ──
                ai_service.record_runtime_log("frida_runtime", f"[output] {message['payload']}")
                asyncio.run_coroutine_threadsafe(
                    send_msg({"type": "output", "payload": str(message["payload"])}), loop
                )

    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=120.0)
                data = json.loads(raw)
            except asyncio.TimeoutError:
                await send_msg({"type": "ping"})
                continue

            msg_type = data.get("type")

            if msg_type == "attach":
                try:
                    session_id = await frida_service.attach(device_id, package)
                    session_history_log.append({"event": "attach", "detail": f"attach to {package}", "timestamp": datetime.utcnow().isoformat()})
                    await send_msg({"type": "attached", "session_id": session_id})
                except Exception as e:
                    logger.error(f"[Runtime WS] attach failed: {e}")
                    err_msg = f"Attach failed: {e}"
                    session_history_log.append({"event": "error", "detail": f"attach failed: {e}", "timestamp": datetime.utcnow().isoformat()})
                    ai_service.record_runtime_log("frida_runtime", f"[error] {err_msg}")
                    await send_msg({"type": "error", "payload": err_msg})

            elif msg_type == "spawn":
                try:
                    session_id = await frida_service.spawn(device_id, package)
                    session_history_log.append({"event": "attach", "detail": f"spawn {package}", "timestamp": datetime.utcnow().isoformat()})
                    await send_msg({"type": "attached", "session_id": session_id, "mode": "spawned"})
                except Exception as e:
                    logger.error(f"[Runtime WS] spawn failed: {e}")
                    err_msg = f"Spawn failed: {e}"
                    session_history_log.append({"event": "error", "detail": f"spawn failed: {e}", "timestamp": datetime.utcnow().isoformat()})
                    ai_service.record_runtime_log("frida_runtime", f"[error] {err_msg}")
                    await send_msg({"type": "error", "payload": err_msg})

            elif msg_type == "inject":
                if not session_id:
                    await send_msg({"type": "error", "payload": "Not attached — send 'attach' first"})
                    continue

                hook_name   = data.get("hook_name")
                script_code = data.get("script") or BUILTIN_HOOKS.get(hook_name)

                if not script_code:
                    await send_msg({"type": "error", "payload": f"Unknown hook: {hook_name}"})
                    continue

                try:
                    last_script_code = script_code  # Track for AI pivot context
                    logger.warning(f"[INJECT] Starting: {len(script_code)} chars")
                    script_id = await frida_service.inject_script(session_id, script_code, frida_message_handler)
                    logger.warning(f"[INJECT] Success: {script_id}")
                    session_history_log.append({"event": "inject", "detail": hook_name or f"custom ({len(script_code)} chars)", "timestamp": datetime.utcnow().isoformat()})
                    # Mark last suggested script as successfully injected
                    ai_service.update_script_outcome("default", "frida_runtime", "success")
                    await send_msg({"type": "injected", "script_id": script_id, "hook": hook_name or "custom"})
                except Exception as e:
                    logger.error(f"[Runtime WS] inject failed: {e}")
                    err_msg = f"Inject failed: {e}"
                    logger.warning(f"[INJECT-FAIL] Error: {err_msg[:100]}")
                    session_history_log.append({"event": "error", "detail": err_msg[:500], "timestamp": datetime.utcnow().isoformat()})
                    ai_service.record_runtime_log("frida_runtime", f"[error] {err_msg}")
                    # Mark last suggested script as failed so AI knows not to repeat it
                    ai_service.update_script_outcome("default", "frida_runtime", "failed", error=err_msg)
                    await send_msg({"type": "error", "payload": err_msg})
                    # ── AUTO-PIVOT on injection failure — fire as background task ──
                    logger.warning(f"[INJECT-FAIL] Recording error & scheduling AI pivot")
                    ai_service.record_runtime_error("frida_runtime", err_msg, script_context=script_code)
                    task = asyncio.ensure_future(_trigger_ai_pivot(err_msg, script_code))
                    task.add_done_callback(lambda t: logger.error(f"[AI-PIVOT] Background task failed: {t.exception()}") if t.exception() else None)


            elif msg_type == "call":
                if not session_id:
                    await send_msg({"type": "error", "payload": "Not attached to a session"})
                    continue
                try:
                    result = await frida_service.call_export(
                        session_id, data["script_id"], data["fn"], data.get("args", [])
                    )
                    await send_msg({"type": "result", "payload": result})
                except Exception as e:
                    await send_msg({"type": "error", "payload": str(e)})

            elif msg_type == "detach":
                break

            else:
                await send_msg({"type": "error", "payload": f"Unknown message type: {msg_type}"})

    except WebSocketDisconnect:
        logger.info(f"[Runtime WS] Client disconnected from {device_id}/{package}")
    except Exception as e:
        logger.exception(f"[Runtime WS] Unhandled error: {e}")
    finally:
        if session_id:
            await frida_service.detach(session_id)
            await send_msg({"type": "detached"})
        # Clear AI log buffer so stale logs don't carry over to new sessions
        ai_service._rt_log_buffer.pop("frida_runtime", None)


# ── Elite Runtime Routes (Zymbiote + eBPF + MTE) ──────────────────────────


@router.get("/elite/preflight/{serial}")
async def elite_preflight(serial: str, package: str = ""):
    """Check device capabilities for elite runtime analysis.

    Returns ebpf, mte, probe compilation status, and net probe state.
    """
    ebpf_status  = await ebpf_service.check_kernelsu(serial)
    mte_status   = await mte_service.check_device_mte_support(serial)
    probe_status = await ebpf_service.get_probe_status(serial)
    return {
        "ebpf": ebpf_status,
        "mte": mte_status,
        "package": package,
        "dex_probe_compiled": probe_status["dex_probe_compiled"],
        "net_probe_compiled": probe_status["net_probe_compiled"],
        "dex_probe_active":   probe_status["probe_active"],
        "net_probe_active":   probe_status["net_probe_active"],
    }


@router.post("/elite/spawn-gate")
async def spawn_gate(device_id: str, package: str, serial: str = ""):
    """Spawn app via Zymbiote spawn gating (stealth injection)."""
    try:
        result = await frida_service.spawn_gate(device_id, package)
        if serial and result.get("pid"):
            stealth = await frida_service.verify_stealth(serial, result["pid"])
            result["stealth_verification"] = stealth
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/stealth-verify/{serial}/{pid}")
async def verify_stealth(serial: str, pid: int):
    """Verify Zymbiote stealth status for a given PID."""
    try:
        return await frida_service.verify_stealth(serial, pid)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elite/mte/enable")
async def mte_enable(serial: str, package: str, mode: str = "sync"):
    """Enable MTE for target package. Mode: 'sync' (brutal) or 'async' (silent)."""
    try:
        if mode == "async":
            return await mte_service.enable_mte_async(serial, package)
        return await mte_service.enable_mte_sync(serial, package)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elite/mte/disable")
async def mte_disable(serial: str, package: str):
    """Disable MTE for target package."""
    try:
        return await mte_service.disable_mte(serial, package)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/mte/status/{serial}")
async def mte_status(serial: str, package: str):
    """Get current MTE status for a package."""
    try:
        return await mte_service.get_mte_status(serial, package)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/mte/faults/{serial}")
async def mte_extract_faults(serial: str, pid: int = 0):
    """Extract MTE fault register dumps from logcat."""
    try:
        return await mte_service.extract_register_dump(serial, pid or None)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elite/ebpf/deploy/{serial}")
async def ebpf_deploy(serial: str):
    """Deploy eBPF probe to device kernel via KernelSU."""
    try:
        return await ebpf_service.deploy_probe(serial)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/ebpf/status/{serial}")
async def ebpf_status(serial: str):
    """Check eBPF probe status on device."""
    return await ebpf_service.get_probe_status(serial)


@router.post("/elite/ebpf/teardown/{serial}")
async def ebpf_teardown(serial: str):
    """Teardown eBPF probe on device."""
    try:
        return await ebpf_service.teardown_probe(serial)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/analysis/{serial}/{package}")
async def elite_analysis(
    serial: str,
    package: str,
    device_id: str = "",
    duration: int = 300,
    hooks: str = "",
):
    """SSE stream for the full 4-step elite analysis pipeline.

    Steps: eBPF init → MTE harden → Zymbiote spawn → AI analysis

    Args:
        serial: ADB device serial
        package: Target package name
        device_id: Frida device ID (defaults to serial)
        duration: Max monitoring duration in seconds
        hooks: Comma-separated list of BUILTIN_HOOKS to inject (e.g. "ssl_bypass,crypto_capture")
    """
    if not device_id:
        device_id = serial

    inject_hooks = [h.strip() for h in hooks.split(",") if h.strip()] if hooks else None

    async def event_stream():
        try:
            async for event in runtime_orchestrator.start_elite_analysis(
                serial=serial,
                package=package,
                device_id=device_id,
                duration_seconds=duration,
                inject_hooks=inject_hooks,
            ):
                status = event.get("status", "")
                if status == "error":
                    ev_name = "error_event"
                elif status == "done":
                    ev_name = "step_done"
                elif status == "data":
                    ev_name = "telemetry"
                elif status == "heartbeat":
                    ev_name = "heartbeat"
                elif status == "ai_chunk":
                    ev_name = "ai_chunk"
                elif status == "ai_complete":
                    ev_name = "ai_complete"
                elif status == "ai_error":
                    ev_name = "ai_error"
                else:
                    ev_name = "step"
                yield f"event: {ev_name}\ndata: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"event: error_event\ndata: {json.dumps({'step': 0, 'phase': 'error', 'status': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/elite/quick/{serial}/{package}")
async def elite_quick(serial: str, package: str, device_id: str = ""):
    """SSE stream for quick spawn + stealth check (no eBPF/MTE)."""
    if not device_id:
        device_id = serial

    async def event_stream():
        try:
            async for event in runtime_orchestrator.quick_analysis(
                serial=serial, package=package, device_id=device_id,
            ):
                ev_name = "step_done" if event.get("status") == "done" else "step"
                yield f"event: {ev_name}\ndata: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"event: error_event\ndata: {json.dumps({'phase': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/elite/sessions")
async def elite_active_sessions():
    """List currently active elite analysis sessions."""
    return runtime_orchestrator.get_active_sessions()


# ── Phase 6 — AI Orchestration Layer Routes ────────────────────────────────


@router.get("/elite/ai-chat/{serial}/{package}")
async def elite_ai_chat(
    serial: str,
    package: str,
    question: str = "",
):
    """SSE stream — AI chat within an active elite analysis session.

    The AI has full context of the current session's telemetry and
    conversation history. Clients send a 'question' query parameter.

    Events: data: {"token": str} | data: [DONE]
    """
    if not question:
        raise HTTPException(status_code=400, detail="question parameter is required")

    # Look up session telemetry context from active sessions
    session_key = f"{serial}:{package}"
    active = runtime_orchestrator.get_active_sessions()
    session_info = active.get(session_key, {})
    telemetry_context = {
        "ebpf_events":     session_info.get("ebpf_events", []),
        "mte_faults":      session_info.get("mte_faults", []),
        "elapsed_seconds": session_info.get("elapsed_seconds", 0),
        "is_stealth":      session_info.get("is_stealth", False),
    }

    user_id    = f"elite_{serial}"
    session_id = f"elite_{serial}:{package}"

    async def _generate():
        try:
            async for token in ai_service.chat_runtime_orchestration(
                question=question,
                telemetry_context=telemetry_context,
                user_id=user_id,
                session_id=session_id,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            logger.error(f"[Elite AI Chat] error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/elite/ai-chat/{serial}/{package}")
async def elite_ai_chat_post(
    serial: str,
    package: str,
    request: Request,
):
    """POST variant of elite AI chat — body: {"question": str, "telemetry": {...}}.

    Accepts an explicit telemetry snapshot in the body so callers can
    include eBPF/MTE data collected client-side without requiring an
    active server-side session.
    """
    try:
        body           = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    question       = body.get("question", "")
    extra_telemetry = body.get("telemetry", {})

    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    session_key = f"{serial}:{package}"
    active = runtime_orchestrator.get_active_sessions()
    session_info = active.get(session_key, {})
    telemetry_context = {
        "ebpf_events":     extra_telemetry.get("ebpf_events",     session_info.get("ebpf_events", [])),
        "mte_faults":      extra_telemetry.get("mte_faults",      session_info.get("mte_faults", [])),
        "elapsed_seconds": extra_telemetry.get("elapsed_seconds", session_info.get("elapsed_seconds", 0)),
        "is_stealth":      extra_telemetry.get("is_stealth",      session_info.get("is_stealth", False)),
    }

    user_id    = f"elite_{serial}"
    session_id = f"elite_{serial}:{package}"

    async def _generate():
        try:
            async for token in ai_service.chat_runtime_orchestration(
                question=question,
                telemetry_context=telemetry_context,
                user_id=user_id,
                session_id=session_id,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/elite/ai-status")
async def elite_ai_status():
    """Check AI provider connectivity and return active elite session count.

    Returns: {"provider", "model", "is_local", "active_sessions", "status"}
    """
    from config import settings
    try:
        provider   = settings.AI_PROVIDER or "openai"
        model      = ai_service._get_model()
        is_local   = ai_service._is_local_provider()
        api_base   = ai_service._resolve_api_base()
        sessions   = runtime_orchestrator.get_active_sessions()
        return {
            "status":          "ok",
            "provider":        provider,
            "model":           model,
            "is_local":        is_local,
            "api_base":        api_base or "(cloud default)",
            "active_sessions": len(sessions),
            "session_keys":    list(sessions.keys()),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/elite/ai-stream-telemetry/{serial}/{package}")
async def elite_ai_stream_telemetry(
    serial: str,
    package: str,
    ebpf_json: str = "",
    mte_json: str = "",
    elapsed: int = 0,
    is_stealth: bool = False,
):
    """SSE endpoint — stream AI analysis of a telemetry snapshot provided by the client.

    Useful when the client has accumulated events outside of an active
    server-side RuntimeOrchestrator session (e.g. after the session ends).

    Query params:
      ebpf_json  — JSON-encoded list of eBPF event dicts
      mte_json   — JSON-encoded list of MTE fault dicts
      elapsed    — seconds elapsed
      is_stealth — Zymbiote stealth active

    Events: data: {"token": str} | data: [DONE]
    """
    try:
        ebpf_events = json.loads(ebpf_json) if ebpf_json else []
        mte_faults  = json.loads(mte_json)  if mte_json  else []
    except Exception as e:
        logger.warning(f"[Elite AI Chat] Failed to parse telemetry JSON: {e}")
        ebpf_events = []
        mte_faults  = []

    telemetry_batch = {
        "ebpf_events":     ebpf_events,
        "mte_faults":      mte_faults,
        "elapsed_seconds": elapsed,
        "is_stealth":      is_stealth,
    }
    user_id    = f"elite_{serial}"
    session_id = f"elite_{serial}:{package}"

    async def _generate():
        try:
            async for token in ai_service.stream_runtime_orchestration(
                telemetry_batch=telemetry_batch,
                user_id=user_id,
                session_id=session_id,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Phase 7 — eBPF CO-RE Compilation + Net Probe Routes ───────────────────


@router.get("/elite/ebpf/compile-status")
async def ebpf_compile_status():
    """Return host-side eBPF probe compilation status for all probes.

    Attempts to compile any missing .o files (requires clang on host).
    Safe to call with no device connected.
    """
    try:
        return await ebpf_service.compile_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elite/ebpf/compile")
async def ebpf_compile(probe: str = "all"):
    """Explicitly compile eBPF probe(s) on the host.

    Query param:
        probe: 'dex_monitor' | 'net_redirect' | 'all' (default)
    """
    valid_probes = ["dex_monitor", "net_redirect", "all"]
    if probe not in valid_probes:
        raise HTTPException(status_code=400, detail=f"Invalid probe '{probe}'. Valid options: {valid_probes}")

    probes = (
        ["dex_monitor", "net_redirect"] if probe == "all"
        else [probe]
    )
    results = {}
    for p in probes:
        results[p] = await ebpf_service._compile_probe(p)
    return {"compiled": results}


@router.post("/elite/ebpf/net-probe/deploy/{serial}")
async def net_probe_deploy(serial: str):
    """Deploy the net_redirect eBPF probe to device.

    Hooks sys_enter_connect — provides pre-handshake connection visibility
    alongside the mitmproxy flow table. Compiles automatically if .o is missing.
    """
    try:
        return await ebpf_service.deploy_net_probe(serial)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elite/ebpf/net-probe/teardown/{serial}")
async def net_probe_teardown(serial: str):
    """Detach and remove the net_redirect probe from the device."""
    try:
        return await ebpf_service.teardown_net_probe(serial)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/ebpf/net-probe/status/{serial}")
async def net_probe_status(serial: str):
    """Return net probe active flag + compilation status for this device."""
    try:
        return await ebpf_service.get_probe_status(serial)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elite/ebpf/connect-stream/{serial}")
async def connect_syscall_stream(
    serial: str,
    pid: int = 0,
    duration: int = 300,
    interesting_only: bool = True,
):
    """SSE stream of outbound TCP connect() events from the net_redirect probe.

    Provides early-bird visibility of connection attempts before the TLS
    handshake — complements mitmproxy flows with pre-decryption destination data.

    Query params:
        pid              — filter to a specific PID (0 = all)
        duration         — max seconds to stream (default 300)
        interesting_only — only emit ports 80/443/8080/… (default true)

    Events:
        event: connect   data: {pid, comm, port, af, addr, filtered, raw}
        event: error     data: {message}
        event: done      data: {}
    """
    async def event_stream():
        try:
            async for ev in ebpf_service.monitor_connect_syscalls(
                serial=serial,
                target_pid=pid or None,
                duration_seconds=duration,
                interesting_only=interesting_only,
            ):
                if ev.get("event_type") == "error":
                    yield f"event: error\ndata: {json.dumps(ev)}\n\n"
                else:
                    yield f"event: connect\ndata: {json.dumps(ev)}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
