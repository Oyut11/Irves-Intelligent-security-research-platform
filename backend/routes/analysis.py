"""
IRVES — Analysis Routes (Phase 6 complete)
AI reasoning layer for per-finding explanation, attack path, and fix guidance.
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import json
import logging

from database import get_db_session, get_finding, update_finding_status
from models.finding import FindingCreate, FindingResponse, FindingUpdate
from services.ai_service import ai_service
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Finding Endpoints ──────────────────────────────────────────────────────────

@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding_detail(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Get detailed information about a specific finding."""
    finding = await get_finding(db, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        title=finding.title,
        severity=finding.severity.value,
        category=finding.category,
        description=finding.description,
        location=finding.location,
        code_snippet=finding.code_snippet,
        tool=finding.tool,
        owasp_mapping=finding.owasp_mapping,
        cwe_mapping=finding.cwe_mapping,
        status=finding.status.value,
        resolution_note=finding.resolution_note,
        ai_analysis=finding.ai_analysis,
        ai_attack_path=finding.ai_attack_path,
        ai_fix_guidance=finding.ai_fix_guidance,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    request: FindingUpdate,
    db: AsyncSession = Depends(get_db_session),
):
    """Update finding status (resolve, ignore, false-positive, etc.)."""
    finding = await get_finding(db, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    updated = await update_finding_status(
        db=db,
        finding_id=finding_id,
        status=request.status,
        resolution_note=request.resolution_note,
    )

    return FindingResponse(
        id=updated.id,
        scan_id=updated.scan_id,
        title=updated.title,
        severity=updated.severity.value,
        category=updated.category,
        description=updated.description,
        location=updated.location,
        code_snippet=updated.code_snippet,
        tool=updated.tool,
        owasp_mapping=updated.owasp_mapping,
        cwe_mapping=updated.cwe_mapping,
        status=updated.status.value,
        resolution_note=updated.resolution_note,
        ai_analysis=updated.ai_analysis,
        ai_attack_path=updated.ai_attack_path,
        ai_fix_guidance=updated.ai_fix_guidance,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
    )


# ── AI Analysis ───────────────────────────────────────────────────────────────

@router.post("/ai/{finding_id}")
async def analyze_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Generate structured AI analysis for a finding.

    Returns:
    - Plain-language explanation
    - Impact statement
    - Step-by-step attack path
    - Specific fix guidance with code examples
    - References
    """
    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI analysis not configured. Set ANTHROPIC_API_KEY in .env"
        )

    finding_dict = {
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "tool": finding.tool,
        "category": finding.category,
        "location": finding.location,
        "owasp_mapping": finding.owasp_mapping,
        "cwe_mapping": finding.cwe_mapping,
        "description": finding.description,
        "code_snippet": finding.code_snippet,
    }

    try:
        analysis = await ai_service.analyze_finding(finding_dict)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.exception("AI analysis failed")
        raise HTTPException(status_code=500, detail=f"AI analysis error: {e}")

    # Persist analysis back to finding record
    from datetime import datetime
    finding.ai_analysis = analysis.get("explanation")
    finding.ai_attack_path = analysis.get("attack_path")
    finding.ai_fix_guidance = analysis.get("fix")
    finding.updated_at = datetime.utcnow()
    await db.flush()

    return {
        "finding_id": finding_id,
        **analysis,
    }


@router.post("/ai/{finding_id}/stream")
async def stream_finding_analysis(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Stream AI analysis tokens in real-time via Server-Sent Events.
    Connect with EventSource for a live typing effect in the UI.
    """
    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    finding_dict = {
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "tool": finding.tool,
        "category": finding.category,
        "location": finding.location,
        "owasp_mapping": finding.owasp_mapping,
        "cwe_mapping": finding.cwe_mapping,
        "description": finding.description,
        "code_snippet": finding.code_snippet,
    }

    async def event_gen():
        try:
            async for chunk in ai_service.stream_analysis(finding_dict):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/ask")
async def ask_irves(
    payload: dict,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Contextual AI chat anchored to a specific finding.

    Body: { "finding_id": "...", "question": "How can I fix this?" }
    """
    finding_id = payload.get("finding_id")
    question = payload.get("question", "").strip()

    if not finding_id or not question:
        raise HTTPException(status_code=400, detail="finding_id and question are required")

    if len(question) > 2000:
        raise HTTPException(status_code=400, detail="Question too long (max 2000 characters)")

    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    context = {
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "category": finding.category,
        "location": finding.location,
        "description": finding.description,
        "code_snippet": finding.code_snippet,
        "owasp_mapping": finding.owasp_mapping,
        "ai_analysis": finding.ai_analysis,
        "ai_fix_guidance": finding.ai_fix_guidance,
    }

    try:
        response = await ai_service.chat(question, context)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.exception("AI chat failed")
        raise HTTPException(status_code=500, detail=f"AI chat error: {e}")

    return {
        "response": response,
        "finding_id": finding_id,
    }


# ── Route aliases (matching frontend JS) ──────────────────────────────────────

# The frontend calls POST /api/analysis/finding/{id} → maps to analyze_finding
# The frontend calls POST /api/analysis/chat/{id}    → maps to a per-finding stream

_rate_limit_store: dict = {}  # ip -> [timestamps]

def _check_rate_limit(client_ip: str, max_req: int = 10, window_sec: int = 60) -> None:
    """Simple in-memory sliding-window rate limiter."""
    import time
    from fastapi import HTTPException
    now = time.time()
    timestamps = _rate_limit_store.get(client_ip, [])
    # Prune old entries
    timestamps = [t for t in timestamps if now - t < window_sec]
    if len(timestamps) >= max_req:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {max_req} AI requests per {window_sec}s. Please wait."
        )
    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps


from fastapi import Request as FastAPIRequest

@router.post("/finding/{finding_id}")
async def analyze_finding_alias(
    finding_id: str,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """Alias for /ai/{finding_id} — used by the finding detail page."""
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return await analyze_finding(finding_id, db)


class ChatPayload(dict):
    pass

from pydantic import BaseModel

class ChatRequest(BaseModel):
    message: str

@router.post("/chat/{finding_id}")
async def chat_with_finding(
    finding_id: str,
    payload: ChatRequest,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Streaming chat scoped to a specific finding.
    Returns SSE stream for the frontend to consume via ReadableStream.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    if len(payload.message) > 2000:
        raise HTTPException(status_code=400, detail="Message too long (max 2000 chars)")

    context = {
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "category": finding.category,
        "location": finding.location,
        "description": finding.description,
        "code_snippet": finding.code_snippet,
        "owasp_mapping": finding.owasp_mapping,
        "ai_analysis": finding.ai_analysis,
        "ai_fix_guidance": finding.ai_fix_guidance,
    }

    async def event_gen():
        try:
            async for chunk in ai_service.stream_chat(payload.message, context):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.patch("/findings/{finding_id}/status")
async def set_finding_status(
    finding_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db_session),
):
    """Update a finding's status (resolved, ignored, open, false_positive)."""
    from database.models import FindingStatus
    status_str = payload.get("status", "open")
    try:
        new_status = FindingStatus(status_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status_str}")

    updated = await update_finding_status(
        db=db,
        finding_id=finding_id,
        status=new_status,
        resolution_note=payload.get("resolution_note"),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"finding_id": finding_id, "status": updated.status.value}