"""
IRVES — Network Routes: Fritap
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

@router.get("/fritap/status")
async def fritap_status():
    """
    Get friTap availability and active sessions.
    """
    return {
        "status": "success",
        "available": fritap_service.available,
        "sessions": fritap_service.get_all_sessions(),
    }


@router.post("/fritap/start")
async def fritap_start(request: Request):
    """
    Start a friTap capture session for SSL/TLS key extraction.
    
    Body: {
        "package": str,           # App package name (required)
        "device_id": str,         # Device serial for mobile (optional)
        "generate_pcap": bool,    # Generate PCAP file (default: true)
        "custom_script": str,     # Path to custom Frida script (optional)
        "spawn": bool             # Spawn app vs attach (default: true)
    }
    
    Returns keylog and PCAP file paths for Wireshark analysis.
    """
    if not fritap_service.available:
        return {
            "status": "error",
            "message": "friTap not installed. Run: pip install fritap",
        }

    try:
        body = await request.json()
        package = body.get("package", "")
        if not package:
            return {"status": "error", "message": "package is required"}

        # Check for conflict with BoringSSL capture
        device_id = body.get("device_id", "")
        if frida_service.ssl_capture_active(device_id, package):
            return {
                "status": "error",
                "message": f"BoringSSL capture already active for {package}. Stop it first to avoid hook conflicts.",
            }

        result = await fritap_service.start_capture(
            package=package,
            device_id=device_id,
            generate_pcap=body.get("generate_pcap", True),
            custom_script=body.get("custom_script"),
            spawn=body.get("spawn", True),
        )
        return result

    except Exception as e:
        logger.error(f"[friTap] Start error: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/fritap/stop")
async def fritap_stop(request: Request):
    """
    Stop a friTap capture session and get file paths.
    
    Body: {"package": str, "device_id": str (optional)}
    
    Returns paths to keylog and PCAP files for download.
    """
    try:
        body = await request.json()
        package = body.get("package", "")
        if not package:
            return {"status": "error", "message": "package is required"}

        result = await fritap_service.stop_capture(
            package=package,
            device_id=body.get("device_id", ""),
        )
        return result

    except Exception as e:
        logger.error(f"[friTap] Stop error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/fritap/session/{package}")
async def fritap_session_info(package: str, device_id: str = ""):
    """Get info about a specific friTap session."""
    session = fritap_service.get_session(package, device_id)
    if not session:
        return {"status": "error", "message": f"No session for {package}"}
    
    return {
        "status": "success",
        "session": fritap_service._get_session_info(session),
    }


@router.get("/fritap/keylog/{package}")
async def fritap_download_keylog(package: str, device_id: str = ""):
    """
    Download the NSS keylog file for Wireshark decryption.
    
    Usage in Wireshark:
    Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
    """
    import os
    from fastapi.responses import FileResponse
    
    session = fritap_service.get_session(package, device_id)
    if not session:
        return {"status": "error", "message": f"No session for {package}"}
    
    if not os.path.exists(session.keylog_path):
        return {"status": "error", "message": "Keylog file not found"}
    
    return FileResponse(
        session.keylog_path,
        media_type="text/plain",
        filename=f"{package}_keys.log",
    )


@router.get("/fritap/pcap/{package}")
async def fritap_download_pcap(package: str, device_id: str = ""):
    """Download the PCAP file for Wireshark analysis."""
    import os
    from fastapi.responses import FileResponse
    
    session = fritap_service.get_session(package, device_id)
    if not session or not session.pcap_path:
        return {"status": "error", "message": f"No PCAP for {package}"}
    
    if not os.path.exists(session.pcap_path):
        return {"status": "error", "message": "PCAP file not found"}
    
    return FileResponse(
        session.pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{package}.pcap",
    )


@router.post("/fritap/cleanup")
async def fritap_cleanup(max_age_hours: int = 24):
    """Clean up old friTap keylog and PCAP files."""
    try:
        cleaned = await fritap_service.cleanup_old_files(max_age_hours)
        return {"status": "success", "cleaned_files": cleaned}
    except Exception as e:
        logger.error(f"[friTap] Cleanup error: {e}")
        return {"status": "error", "message": str(e)}
