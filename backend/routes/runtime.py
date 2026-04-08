"""
IRVES — Runtime WebSocket Router
Frida WebSocket + Xposed logcat-bridge WebSocket + SSE setup streams.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging

from services.frida_service import frida_service, BUILTIN_HOOKS
from services.xposed_service import xposed_service

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

    try:
        # Run logcat stream and forward to WebSocket
        async for line in xposed_service.logcat_stream(serial, package):
            if line == "__ping__":
                await send({"type": "ping"})
            else:
                await send({"type": "output", "payload": line})

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
        { "type": "detached" }
    """
    await websocket.accept()
    session_id = None
    loop = asyncio.get_event_loop()  # capture loop for thread-safe callbacks

    async def send_msg(msg: dict):
        try:
            await websocket.send_json(msg)
        except Exception:
            pass

    def frida_message_handler(message, data):
        """Forward Frida script messages → WebSocket. Called from Frida's thread."""
        msg_type = message.get("type")

        if msg_type == "send":
            payload = message.get("payload")
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": "output", "payload": payload}), loop
            )
        elif msg_type == "log":
            level   = message.get("level", "info")
            payload = message.get("payload", "")
            out_type = "error" if level == "error" else "warn" if level == "warning" else "output"
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": out_type, "payload": payload}), loop
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
            asyncio.run_coroutine_threadsafe(
                send_msg({"type": "error", "payload": err}), loop
            )
        else:
            if "payload" in message:
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
                    await send_msg({"type": "attached", "session_id": session_id})
                except Exception as e:
                    logger.error(f"[Runtime WS] attach failed: {e}")
                    await send_msg({"type": "error", "payload": f"Attach failed: {e}"})

            elif msg_type == "spawn":
                try:
                    session_id = await frida_service.spawn(device_id, package)
                    await send_msg({"type": "attached", "session_id": session_id, "mode": "spawned"})
                except Exception as e:
                    logger.error(f"[Runtime WS] spawn failed: {e}")
                    await send_msg({"type": "error", "payload": f"Spawn failed: {e}"})

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
                    script_id = await frida_service.inject_script(session_id, script_code, frida_message_handler)
                    await send_msg({"type": "injected", "script_id": script_id, "hook": hook_name or "custom"})
                except Exception as e:
                    logger.error(f"[Runtime WS] inject failed: {e}")
                    await send_msg({"type": "error", "payload": f"Inject failed: {e}"})


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
