"""
IRVES — Network Routes: Ai Audit
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

@router.post("/ai/analyze-flow")
async def ai_analyze_flow(request: Request):
    """
    Analyze a single captured flow with the AI and return a risk assessment.
    Body: {"flow_id": str} — looks up the flow from the live store.
    Or pass the flow data directly: {"flow": {...}}.
    Returns: {"risk": "high"|"medium"|"low"|"info", "summary": str, "findings": [...]}
    """
    try:
        body    = await request.json()
        flow_id = body.get("flow_id")
        flow    = body.get("flow")

        if flow_id and not flow:
            flow = network_service.flows.get(flow_id)
            if not flow:
                return {"status": "error", "message": f"Flow {flow_id!r} not found"}

        if not flow:
            return {"status": "error", "message": "Provide flow_id or flow object"}

        result = await ai_service.analyze_flow(flow)
        # Persist risk level on the stored flow for the Risk column
        if flow_id and flow_id in network_service.flows:
            network_service.flows[flow_id]["ai_risk"]    = result.get("risk", "info")
            network_service.flows[flow_id]["ai_summary"] = result.get("summary", "")
        return {"status": "success", **result}
    except Exception as e:
        logger.error(f"[AI-Auditor] analyze-flow error: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/ai/repeater-suggest")
async def ai_repeater_suggest(request: Request):
    """
    Return 3 AI-generated fuzzing mutation variants for the given flow.
    Body: {"flow_id": str} or {"flow": {...}}
    Returns: {"status": "success", "variants": [...]}
    """
    try:
        body    = await request.json()
        flow_id = body.get("flow_id")
        flow    = body.get("flow")

        if flow_id and not flow:
            flow = network_service.flows.get(flow_id)
            if not flow:
                return {"status": "error", "message": f"Flow {flow_id!r} not found"}

        if not flow:
            return {"status": "error", "message": "Provide flow_id or flow object"}

        variants = await ai_service.repeater_suggest(flow)
        return {"status": "success", "variants": variants}
    except Exception as e:
        logger.error(f"[AI-Auditor] repeater-suggest error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/ai/stream-audit")
async def ai_stream_audit(flow_id: str = ""):
    """
    SSE endpoint — streams a real-time security narrative for a captured flow.
    Clients subscribe with ?flow_id=<id>. Each event: data: <token>\\n\\n
    Ends with data: [DONE]\\n\\n
    """
    flow = network_service.flows.get(flow_id) if flow_id else None

    async def _generate():
        if not flow:
            yield f"data: {json.dumps({'error': 'flow not found'})}\n\n"
            yield "data: [DONE]\n\n"
            return
        try:
            async for token in ai_service.stream_audit_flow(flow):
                yield f"data: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
