"""
IRVES — Network Routes: Ssl
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
import time
import uuid
from services.network_service import network_service
from services.root_wrapper import root_wrapper
from services.ebpf_service import ebpf_service
from services.frida_service import frida_service
from services.ai_service import ai_service
from services.security_analyzer import security_analyzer
from services.ct_monitor import ct_monitor
from services.fritap_capture import fritap_service

logger = logging.getLogger(__name__)
router = APIRouter()

async def get_root_detection(serial: str):
    """
    Detect the root implementation on the device and report eBPF capability.
    Returns impl ('ksu'|'apatch'|'magisk'|'su'|'none'), kernel_version, ebpf_capable.
    """
    try:
        result = await ebpf_service.check_root_env(serial)
        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Stealth Mode (transparent iptables redirect) ───────────────────────────────

@router.post("/proxy/stealth/enable/{serial}")
async def stealth_enable(serial: str):
    """
    Enable transparent TCP redirect (ports 80 + 443 → mitmproxy :8080) via iptables.
    Ensures proxy is running before enabling stealth mode.
    Hides Settings.Global http_proxy so the target app sees a direct connection.
    Requires root. mitmproxy must already be running and adb reverse must be active.
    """
    try:
        # Ensure proxy is running before enabling stealth mode
        try:
            await network_service._ensure_running()
        except Exception as e:
            logger.error(f"[Network] Failed to start proxy for stealth mode: {e}")
            return {
                "status": "error",
                "message": f"Failed to start proxy: {str(e)}"
            }
        
        result = await ebpf_service.enable_transparent_redirect(serial)
        return result
    except Exception as e:
        logger.error(f"[Stealth] enable failed on {serial}: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/proxy/stealth/disable/{serial}")
async def stealth_disable(serial: str):
    """
    Disable transparent redirect: flush iptables nat OUTPUT rules and restore
    Settings.Global http_proxy to 127.0.0.1:8080.
    """
    try:
        result = await ebpf_service.disable_transparent_redirect(serial)
        return result
    except Exception as e:
        logger.error(f"[Stealth] disable failed on {serial}: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/proxy/stealth/status/{serial}")
async def stealth_status(serial: str):
    """Return whether transparent redirect is currently active for a serial."""
    return {
        "serial": serial,
        "stealth_active": ebpf_service.redirect_active(serial),
    }


# ── Phase 3 — BoringSSL SSL Capture ───────────────────────────────────────────

@router.post("/ssl-capture/start")
async def ssl_capture_start(request: Request):
    """
    Inject the boring_ssl_capture Frida hook into a running/spawned app.
    Captured SSL plaintext is ingested as flows into the live traffic table.

    Body: {
        "serial": str,
        "package": str,
        "mode": "attach_first"|"attach"|"spawn_gate"|"spawn_clean",
        "inject_bypass": bool,
        "inject_delay_ms": int
    }
    """
    try:
        body = await request.json()
        serial  = body.get("serial", "")
        package = body.get("package", "")
        if not serial or not package:
            return {"status": "error", "message": "serial and package are required"}

        def _ssl_flow_callback(ssl_payload: dict):
            """Relay a Frida ssl_payload message into the network flow table."""
            flow = {
                "id":          str(uuid.uuid4()),
                "method":      ssl_payload.get("dir", "?").upper(),
                "host":        package,
                "path":        f"[SSL-{ssl_payload.get('lib', 'native')}]",
                "url":         f"ssl://{package}",
                "status_code": 0,
                "content_length": ssl_payload.get("len", 0),
                "timestamp":   time.time(),
                "secrets":     [],
                "source":      "ssl",
                "body":        ssl_payload.get("data", ""),
                "headers":     {},
            }
            network_service.ingest_flow(flow)

        mode = body.get("mode", "attach_first")
        inject_bypass = bool(body.get("inject_bypass", True))
        inject_delay_ms = int(body.get("inject_delay_ms", 300))

        result = await frida_service.start_ssl_capture(
            serial,
            package,
            _ssl_flow_callback,
            mode=mode,
            inject_bypass=inject_bypass,
            inject_delay_ms=inject_delay_ms,
        )
        if result.get("status") == "error":
            return result
        return {"status": "success", **result}
    except Exception as e:
        logger.error(f"[SSL-Capture] start error: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/ssl-capture/stop")
async def ssl_capture_stop(request: Request):
    """
    Detach the BoringSSL capture session.
    Body: {"serial": str, "package": str}
    """
    try:
        body    = await request.json()
        serial  = body.get("serial", "")
        package = body.get("package", "")
        if not serial or not package:
            return {"status": "error", "message": "serial and package are required"}
        result = await frida_service.stop_ssl_capture(serial, package)
        return result
    except Exception as e:
        logger.error(f"[SSL-Capture] stop error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/ssl-capture/status")
async def ssl_capture_status(serial: str = "", package: str = ""):
    """Return whether SSL capture is active for a device/package pair."""
    return {
        "serial":  serial,
        "package": package,
        "active":  frida_service.ssl_capture_active(serial, package),
    }
