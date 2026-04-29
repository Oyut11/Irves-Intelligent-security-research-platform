"""
IRVES — Frida SSL Capture
BoringSSL capture start/stop/status.
"""

import asyncio
import logging

from services.frida.hooks import BUILTIN_HOOKS

logger = logging.getLogger(__name__)


async def start_ssl_capture(
    sessions: dict,
    ssl_sessions: dict,
    device_id: str,
    package_name: str,
    flow_callback,
    mode: str = "attach_first",
    inject_bypass: bool = True,
    inject_delay_ms: int = 300,
    *,
    attach_fn,
    spawn_gate_fn,
    spawn_fn,
    inject_script_fn,
) -> dict:
    """
    Spawn-gate the app and inject the boring_ssl_capture hook.

    `flow_callback(flow_dict)` is called for every SSL payload received.

    Returns: {"session_id", "pid", "is_stealth", "hook_status"}
    """
    spawn_result: dict = {}
    session_id = ""
    pid = 0

    # 1. Resolve capture startup mode
    try:
        if mode == "attach":
            session_id = await attach_fn(device_id, package_name)
            spawn_result = {
                "session_id": session_id,
                "pid": 0,
                "is_stealth": False,
                "method": "attach",
                "package": package_name,
            }
        elif mode == "spawn_gate":
            spawn_result = await spawn_gate_fn(device_id, package_name)
            session_id = spawn_result.get("session_id", "")
            pid = spawn_result.get("pid", 0)
        elif mode == "spawn_clean":
            session_id = await spawn_fn(device_id, package_name)
            spawn_result = {
                "session_id": session_id,
                "pid": 0,
                "is_stealth": False,
                "method": "spawn_clean",
                "package": package_name,
            }
        else:
            # attach_first
            try:
                session_id = await attach_fn(device_id, package_name)
                spawn_result = {
                    "session_id": session_id,
                    "pid": 0,
                    "is_stealth": False,
                    "method": "attach",
                    "package": package_name,
                }
            except Exception as attach_error:
                logger.warning(
                    f"[SSL] attach_first attach failed for {package_name}: {attach_error}. Falling back to spawn_gate"
                )
                spawn_result = await spawn_gate_fn(device_id, package_name)
                spawn_result["attach_fallback_reason"] = str(attach_error)
                session_id = spawn_result.get("session_id", "")
                pid = spawn_result.get("pid", 0)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to start SSL capture session: {e}",
            "capture_mode": mode,
        }

    if not session_id or session_id not in sessions:
        return {**spawn_result, "hook_status": "error: session not established"}

    hook_script = BUILTIN_HOOKS.get("boring_ssl_capture", "")
    hook_status = "not_injected"
    bypass_status = "skipped"

    if inject_delay_ms > 0:
        delay_ms = max(0, min(inject_delay_ms, 5000))
        await asyncio.sleep(delay_ms / 1000.0)

    # 2. Inject the BoringSSL hook and wire up the ssl_payload message handler
    def _on_message(msg, data):
        try:
            payload = msg.get("payload", "")
            if not payload:
                return
            import json as _json
            parsed = _json.loads(payload) if isinstance(payload, str) else payload
            if isinstance(parsed, dict) and parsed.get("type") == "ssl_payload":
                flow_callback(parsed)
            else:
                logger.debug(f"[SSL-Hook] {payload}")
        except Exception:
            logger.debug(f"[SSL-Hook] raw: {msg}")

    try:
        if inject_bypass:
            bypass_script = BUILTIN_HOOKS.get("ssl_bypass", "")
            if bypass_script:
                try:
                    await inject_script_fn(session_id, bypass_script, lambda *_: None)
                    bypass_status = "active"
                except Exception as bypass_error:
                    bypass_status = f"error: {bypass_error}"
                    logger.warning(f"[SSL] ssl_bypass pre-inject failed: {bypass_error}")

        await inject_script_fn(session_id, hook_script, _on_message)
        hook_status = "active"
        ssl_sessions[session_id] = True
        logger.info(f"[SSL] BoringSSL capture active — session={session_id} pid={pid}")
    except Exception as e:
        hook_status = f"error: {e}"
        logger.error(f"[SSL] Failed to inject boring_ssl_capture: {e}")

    return {
        **spawn_result,
        "hook_status": hook_status,
        "bypass_status": bypass_status,
        "capture_mode": mode,
    }


async def stop_ssl_capture(
    sessions: dict,
    ssl_sessions: dict,
    device_id: str,
    package_name: str,
    *,
    detach_fn,
) -> dict:
    """Detach the SSL capture session for a package."""
    session_id = f"{device_id}:{package_name}:gated"
    alt_id     = f"{device_id}:{package_name}"
    sid = session_id if session_id in sessions else alt_id

    ssl_sessions.pop(sid, None)
    ssl_sessions.pop(session_id, None)

    if sid in sessions:
        try:
            await detach_fn(sid)
        except Exception as e:
            logger.warning(f"[SSL] detach error: {e}")
        return {"status": "stopped", "session_id": sid}
    return {"status": "not_found", "session_id": sid}


def ssl_capture_active(ssl_sessions: dict, device_id: str, package_name: str) -> bool:
    """Return True if a BoringSSL capture session is active for this package."""
    for sid in (f"{device_id}:{package_name}:gated", f"{device_id}:{package_name}"):
        if sid in ssl_sessions:
            return True
    return False
