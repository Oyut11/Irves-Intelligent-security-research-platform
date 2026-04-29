"""
IRVES — Network Routes: Flows
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

@router.post("/internal/flow", include_in_schema=False)
async def ingest_flow(request: Request):
    """Internal endpoint — receives captured flows from the mitmdump addon."""
    try:
        flow_data = await request.json()
        network_service.ingest_flow(flow_data)
    except Exception:
        pass
    return {"ok": True}


# ── Status ────────────────────────────────────────────────────────────────────

@router.get("/status")
async def proxy_status():
    """Return current proxy running state and port."""
    return {
        "running": network_service.is_running,
        "port": network_service.proxy_port,
        "flows": len(network_service.flows),
    }


@router.get("/flow/{flow_id}")
async def get_flow_detail(flow_id: str):
    """Return full flow details including pinning information."""
    flow_data = network_service.flows.get(flow_id)
    if not flow_data:
        return {"status": "error", "message": "Flow not found"}
    
    return {
        "status": "success",
        "flow": flow_data,
    }

@router.get("/flows")
async def get_all_flows():
    """Return all captured flows (summary only) for UI initialization."""
    # Build summaries just like ingest_flow does
    summaries = []
    for fid, flow_data in network_service.flows.items():
        summaries.append({
            "id": fid,
            "method": flow_data.get("method", ""),
            "host": flow_data.get("host", ""),
            "path": flow_data.get("path", ""),
            "url": flow_data.get("url", ""),
            "status_code": flow_data.get("status_code", 0),
            "content_length": flow_data.get("content_length", 0),
            "timestamp": flow_data.get("timestamp", 0),
            "secrets": flow_data.get("secrets", []),
            "pinning_detected": flow_data.get("pinning_detected", False),
            "pinning_confidence": flow_data.get("pinning_confidence", ""),
            "error_type": flow_data.get("error_type", ""),
            "is_modified": flow_data.get("is_modified", False),
            "intercept_match": flow_data.get("intercept_match", False),
            "is_websocket": flow_data.get("is_websocket", False),
            "is_grpc": flow_data.get("is_grpc", False),
            "protocol_type": flow_data.get("protocol_type", "http"),
        })
    return {"status": "success", "flows": summaries}
