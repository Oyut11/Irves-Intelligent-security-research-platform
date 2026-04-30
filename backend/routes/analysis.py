"""
IRVES — Analysis Routes (Phase 6 complete)
AI reasoning layer for per-finding explanation, attack path, and fix guidance.
"""

from fastapi import APIRouter, HTTPException, Depends, Request as FastAPIRequest
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import json
import logging
import hashlib

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

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(
            status_code=503,
            detail="AI analysis not configured. Set an API key in Settings → AI Reasoning Layer"
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
    finding.ai_analysis = json.dumps(analysis)
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

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(status_code=503, detail="AI not configured. Set an API key in Settings → AI Reasoning Layer")

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


def _get_user_id(request: FastAPIRequest) -> str:
    """Generate a consistent user ID from request information."""
    # Use IP address and User-Agent to create a consistent user ID
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create a hash for privacy while maintaining consistency
    user_string = f"{client_ip}:{user_agent}"
    return hashlib.md5(user_string.encode()).hexdigest()[:12]

@router.post("/ask")
async def ask_irves(
    payload: dict,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Intelligent contextual AI chat anchored to a specific finding with conversation memory.

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
        "cwe_mapping": finding.cwe_mapping,
        "tool": finding.tool,
        "ai_analysis": finding.ai_analysis,
        "ai_attack_path": finding.ai_attack_path,
        "ai_fix_guidance": finding.ai_fix_guidance,
    }

    # Generate user ID and session ID for conversation tracking
    user_id = _get_user_id(request)
    session_id = f"finding_{finding_id}"

    try:
        response = await ai_service.chat(question, context, user_id, session_id)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.exception("AI chat failed")
        raise HTTPException(status_code=500, detail=f"AI chat error: {e}")

    return {
        "response": response,
        "finding_id": finding_id,
        "user_context": {
            "expertise_level": ai_service.conversation_memory.get_context(user_id, session_id).user_expertise_level,
            "interaction_count": ai_service.conversation_memory.get_context(user_id, session_id).interaction_count
        }
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
    Intelligent streaming chat scoped to a specific finding with conversation memory and adaptive responses.
    Returns SSE stream for the frontend to consume via ReadableStream.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(status_code=503, detail="AI not configured. Set an API key in Settings → AI Reasoning Layer")

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
        "cwe_mapping": finding.cwe_mapping,
        "tool": finding.tool,
        "ai_analysis": finding.ai_analysis,
        "ai_attack_path": finding.ai_attack_path,
        "ai_fix_guidance": finding.ai_fix_guidance,
    }

    # Generate user ID and session ID for intelligent conversation tracking
    user_id = _get_user_id(request)
    session_id = f"finding_{finding_id}"

    async def event_gen():
        try:
            # Get user context for metadata
            user_context = ai_service.conversation_memory.get_context(user_id, session_id)
            
            # Send initial context metadata
            yield f"data: {json.dumps({'metadata': {'expertise_level': user_context.user_expertise_level, 'mood': user_context.current_mood, 'interaction_count': user_context.interaction_count}})}\n\n"
            
            # Stream intelligent response
            async for chunk in ai_service.stream_chat(payload.message, context, user_id, session_id):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class RuntimeChatRequest(BaseModel):
    message: str
    script_context: str = ""
    logs: str = ""
    finding_id: Optional[str] = None
    runtime_state: Optional[dict] = {}

@router.post("/runtime-chat")
async def runtime_chat(
    payload: RuntimeChatRequest,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Intelligent streaming chat tailored for Frida scripting and runtime analysis with user context.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(status_code=503, detail="AI not configured. Set an API key in Settings → AI Reasoning Layer")

    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    finding_context = None
    if payload.finding_id:
        finding = await get_finding(db, payload.finding_id)
        if finding:
            finding_context = {
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

    # Generate user context for Frida session
    user_id = _get_user_id(request)
    session_id = "frida_runtime"

    # Update user context for Frida-specific expertise detection
    ai_service.conversation_memory.update_user_context(user_id, payload.message, session_id)

    # Merge live WebSocket buffer logs with the HTTP payload snapshot
    # Buffer always has the most recent lines since WebSocket pushes continuously
    buffer_logs = ai_service.get_runtime_logs(session_id, limit=50)
    merged_logs = payload.logs or ""
    if buffer_logs:
        if merged_logs:
            merged_logs = f"{merged_logs}\n--- LIVE LOGS (since last snapshot) ---\n{buffer_logs}"
        else:
            merged_logs = buffer_logs

    async def event_gen():
        try:
            # Send user context metadata
            user_context = ai_service.conversation_memory.get_context(user_id, session_id)
            yield f"data: {json.dumps({'metadata': {'expertise_level': user_context.user_expertise_level, 'frida_session': True}})}\n\n"

            async for chunk in ai_service.stream_frida_chat(
                question=payload.message,
                script_context=payload.script_context,
                logs=merged_logs,
                finding_context=finding_context,
                runtime_state=payload.runtime_state,
                user_id=user_id,
                session_id=session_id,
                rt_log_buffer=ai_service._rt_log_buffer.get(session_id, []),
            ):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class NetworkChatRequest(BaseModel):
    message: str
    packet_data: dict
    finding_id: Optional[str] = None

@router.post("/network-chat")
async def network_chat(
    payload: NetworkChatRequest,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Intelligent streaming chat tailored for network and API traversal analysis with user context.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    is_local = settings.AI_PROVIDER in ("ollama", "local") or any(s in (settings.AI_MODEL or "").lower() for s in ("ollama", "local", "localhost", "127.0.0.1"))
    if not key and not is_local and not settings.AI_API_BASE:
        raise HTTPException(status_code=503, detail="AI not configured. Set an API key in Settings → AI Reasoning Layer")

    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    finding_context = None
    if payload.finding_id:
        finding = await get_finding(db, payload.finding_id)
        if finding:
            finding_context = {
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

    # Generate user context for network analysis session
    user_id = _get_user_id(request)
    session_id = "network_analysis"

    # Update user context for network-specific expertise detection
    ai_service.conversation_memory.update_user_context(user_id, payload.message, session_id)

    async def event_gen():
        try:
            # Send user context metadata
            user_context = ai_service.conversation_memory.get_context(user_id, session_id)
            yield f"data: {json.dumps({'metadata': {'expertise_level': user_context.user_expertise_level, 'network_session': True}})}\n\n"

            async for chunk in ai_service.stream_network_chat(
                question=payload.message,
                packet_data=payload.packet_data,
                finding_context=finding_context,
                user_id=user_id,
                session_id=session_id,
            ):
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
    return {"status": "success", "new_status": updated.status.value}

class ProjectSummaryRequest(BaseModel):
    project_id: str
    message: str

@router.post("/project-summary")
async def project_summary_chat(
    payload: ProjectSummaryRequest,
    request: FastAPIRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Stream a high-level executive vulnerability summary for all project findings.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    from database.crud import get_scans_by_project, get_findings_by_scan, get_project
    scans = await get_scans_by_project(db, payload.project_id)
    project = await get_project(db, payload.project_id)
    project_platform = project.platform if project else "General"
    
    raw_findings = []
    if scans:
        # Get findings from latest scan
        latest_scan = scans[0]
        findings_list = await get_findings_by_scan(db, latest_scan.id, limit=5000)
        
        # Group identical findings to compress prompt length while retaining scale context
        grouped_findings = {}
        for f in findings_list:
            sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
            key = (f.title, sev, f.category)
            if key not in grouped_findings:
                grouped_findings[key] = {"title": f.title, "severity": sev, "category": f.category, "count": 1}
            else:
                grouped_findings[key]["count"] += 1
                
        # Sort so critical issues appear first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        grouped_list = list(grouped_findings.values())
        grouped_list.sort(key=lambda x: severity_order.get(x["severity"], 99))
        
        for grouped in grouped_list:
            raw_findings.append(grouped)

    key = settings.AI_API_KEY or settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY
    ai_model_lower = (settings.AI_MODEL or "").lower()
    if not key and "ollama" not in ai_model_lower and "local" not in ai_model_lower and not settings.AI_API_BASE:
         raise HTTPException(status_code=503, detail="AI API provider not configured")

    user_id = _get_user_id(request)
    session_id = f"project_{payload.project_id}"

    async def event_gen():
        try:
            async for chunk in ai_service.stream_project_summary(
                findings=raw_findings,
                user_message=payload.message,
                user_id=user_id,
                session_id=session_id,
                project_platform=project_platform
            ):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )