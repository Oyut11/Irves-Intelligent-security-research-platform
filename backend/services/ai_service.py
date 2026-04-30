"""
IRVES — AI Analysis Service (Phase 6)
Multi-Provider LLM powered per-finding vulnerability explanations, 
project summaries, and contextual chat.

Thin orchestrator — delegates to services.ai package modules.
"""

import asyncio
import json
import logging
from typing import AsyncIterator, Dict, Any, List, Optional
from collections import defaultdict

from services.ai.context import ConversationContext, ConversationMemory
from services.ai.prompts import (
    MASTER_FOUNDATION,
    ANALYSIS_SYSTEM,
    PROJECT_SUMMARY_SYSTEM,
    ANALYSIS_PROMPT,
    CHAT_SYSTEM,
    FRIDA_SYSTEM_PROMPT,
    NETWORK_SYSTEM_PROMPT,
    RUNTIME_ORCHESTRATOR_SYSTEM,
)
from services.ai.knowledge import (
    initialize_domain_knowledge,
    initialize_response_templates,
    initialize_semantic_analysis,
)
from services.ai.log_analyzer import analyze_logs_for_thinking, build_thinking_context
from services.ai.intent import (
    detect_intent,
    detect_platform_context,
    build_adaptive_system_prompt,
)
from services.ai.llm import (
    get_api_key,
    is_local_provider,
    get_model,
    resolve_api_base,
    stream_llm,
)
from services.ai.chat_streams import (
    analyze_finding,
    chat,
    stream_analysis,
    stream_chat,
    stream_frida_chat,
    stream_network_chat,
    stream_source_analysis_chat,
    stream_project_summary,
    stream_runtime_orchestration,
    chat_runtime_orchestration,
    analyze_flow,
    repeater_suggest,
    stream_audit_flow,
    record_runtime_error,
    get_runtime_errors,
)

logger = logging.getLogger(__name__)

# Re-export prompt constants for backward compatibility
_MASTER_FOUNDATION = MASTER_FOUNDATION
_ANALYSIS_SYSTEM = ANALYSIS_SYSTEM
_PROJECT_SUMMARY_SYSTEM = PROJECT_SUMMARY_SYSTEM
_ANALYSIS_PROMPT = ANALYSIS_PROMPT
_CHAT_SYSTEM = CHAT_SYSTEM
_FRIDA_SYSTEM_PROMPT = FRIDA_SYSTEM_PROMPT
_NETWORK_SYSTEM_PROMPT = NETWORK_SYSTEM_PROMPT
_RUNTIME_ORCHESTRATOR_SYSTEM = RUNTIME_ORCHESTRATOR_SYSTEM


class AIService:
    """Advanced AI service with contextual awareness and adaptive intelligence.
    
    Thin orchestrator — delegates to services.ai package modules.
    """
    
    def __init__(self):
        self.conversation_memory = ConversationMemory()
        self.domain_knowledge = initialize_domain_knowledge()
        self.response_templates = initialize_response_templates()
        self._semantic_data = initialize_semantic_analysis(self.domain_knowledge)
        # Real-time error buffer: keyed by session_id, stores recent errors
        self._rt_error_buffer: Dict[str, List[dict]] = defaultdict(list)
        # Real-time log buffer: keyed by session_id, stores recent output lines
        self._rt_log_buffer: Dict[str, List[str]] = defaultdict(list)

    # ── Error Buffer (delegated) ──────────────────────────────────────────────

    def record_runtime_error(self, session_key: str, error_msg: str, stack: str = "", script_context: str = ""):
        return record_runtime_error(self._rt_error_buffer, session_key, error_msg, stack, script_context)

    def get_runtime_errors(self, session_key: str):
        return get_runtime_errors(self._rt_error_buffer, session_key)

    def update_script_outcome(self, user_id: str, session_id: str, outcome: str, error: str = ""):
        """Update the most recent script injection outcome for a user/session."""
        ctx = self.conversation_memory.get_context(user_id, session_id)
        ctx.update_last_script_outcome(outcome, error)

    # ── Log Buffer ────────────────────────────────────────────────────────────

    def record_runtime_log(self, session_key: str, line: str, max_lines: int = 100):
        """Store a live log line for a session. Keeps last N lines."""
        buf = self._rt_log_buffer[session_key]
        buf.append(line)
        if len(buf) > max_lines:
            self._rt_log_buffer[session_key] = buf[-max_lines:]

    def get_runtime_logs(self, session_key: str, limit: int = 50) -> str:
        """Retrieve recent live log lines for a session as a single string."""
        lines = self._rt_log_buffer.get(session_key, [])
        return "\n".join(lines[-limit:])

    # ── Real-time AI Pivot ───────────────────────────────────────────────────

    async def generate_realtime_pivot(
        self,
        error_msg: str,
        script_context: str = "",
        package: str = "",
        user_id: str = "default",
        session_id: str = "frida_runtime",
        finding_context: Optional[dict] = None,
        session_history: str = "",
    ) -> AsyncIterator[str]:
        """Generate immediate AI pivot response when a runtime error occurs."""
        self.conversation_memory.update_user_context(user_id, f"[Runtime error: {error_msg[:100]}]", session_id)

        # ── THINKING PHASE for realtime pivot ──
        thinking_analysis = analyze_logs_for_thinking(
            logs=error_msg,
            script_history=session_history,
        )
        thinking_context = build_thinking_context(thinking_analysis)

        system_prompt = (
            f"{FRIDA_SYSTEM_PROMPT}\n\n"
            "## PIVOT MODE — Script Delivery Required\n"
            "A runtime error just occurred. You are providing a REPLACEMENT SCRIPT — this is a script delivery context.\n"
            "Use the Goal / Impact on the App / Injection Strategy format with ONE javascript block.\n"
            "Analyze the exact error, identify WHY it failed, and provide a DIFFERENT working approach.\n"
            "Do NOT suggest the same failed approach. Be decisive — one authoritative fix only.\n"
            "If an Investigation Brief is provided below, you MUST align your new script with the OWASP/CWE classification described there."
        )

        user_prompt = f"**Package:** {package}\n**Error:** {error_msg}\n"
        if thinking_context:
            user_prompt += f"\n{thinking_context}\n"
        if script_context:
            user_prompt += f"**Failed script:**\n```javascript\n{script_context}\n```\n"
        if session_history:
            user_prompt += f"**Session Timeline:**\n{session_history}\n\n"
        if finding_context:
            user_prompt += self._build_pivot_brief(finding_context)
        user_prompt += "\nPivot. Provide Goal / Impact on the App / Injection Strategy + one javascript script."

        async for chunk in stream_llm(system_prompt, user_prompt, temperature=0.2):
            yield chunk

    def _build_pivot_brief(self, finding_context: dict) -> str:
        """Build a brief Investigation Brief for the pivot prompt."""
        parts = ["\n**Investigation Brief:**\n"]
        parts.append(f"- Title: {finding_context.get('title', 'Unknown')}")
        parts.append(f"- Severity: {finding_context.get('severity', 'Unknown')}")
        if finding_context.get('owasp_mapping'):
            parts.append(f"- OWASP: {finding_context['owasp_mapping']}")
        if finding_context.get('cwe_mapping'):
            parts.append(f"- CWE: {finding_context['cwe_mapping']}")
        if finding_context.get('tool'):
            parts.append(f"- Discovered by: {finding_context['tool']}")
        if finding_context.get('location'):
            parts.append(f"- Location: {finding_context['location']}")
        if finding_context.get('category'):
            parts.append(f"- Category: {finding_context['category']}")
        if finding_context.get('description'):
            parts.append(f"\n- Description: {finding_context['description'][:500]}")
        _ai = finding_context.get('ai_analysis', '')
        if isinstance(_ai, str) and _ai.strip():
            try:
                _ai_parsed = json.loads(_ai)
                if _ai_parsed.get('explanation'):
                    parts.append(f"\n- AI Explanation: {_ai_parsed['explanation'][:400]}")
                if _ai_parsed.get('impact'):
                    parts.append(f"- Impact: {_ai_parsed['impact'][:400]}")
                if _ai_parsed.get('fix'):
                    parts.append(f"- Suggested Fix: {_ai_parsed['fix'][:400]}")
            except (json.JSONDecodeError, ValueError):
                parts.append(f"\n- AI Explanation: {_ai[:400]}")
        return '\n'.join(parts) + "\n"

    # ── LLM Config (backward-compatible private method delegators) ────────────

    def _get_api_key(self):
        return get_api_key()

    def _is_local_provider(self) -> bool:
        return is_local_provider()

    def _get_model(self) -> str:
        return get_model()

    def _resolve_api_base(self):
        return resolve_api_base()

    # ── Core AI Methods (delegated) ───────────────────────────────────────────

    async def analyze_finding(self, finding: dict) -> dict:
        return await analyze_finding(
            finding,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        )

    async def chat(self, question: str, context: dict, user_id: str = "default", session_id: str = "default", screen: str = "finding_detail") -> str:
        return await chat(
            question, context, user_id, session_id, screen,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        )

    async def stream_analysis(self, finding: dict) -> AsyncIterator[str]:
        async for chunk in stream_analysis(finding):
            yield chunk

    async def stream_chat(self, question: str, context: dict, user_id: str = "default", session_id: str = "default", screen: str = "finding_detail") -> AsyncIterator[str]:
        async for chunk in stream_chat(
            question, context, user_id, session_id, screen,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def stream_frida_chat(self, question: str, script_context: str, logs: str, finding_context: Optional[dict] = None, runtime_state: Optional[dict] = None, user_id: str = "default", session_id: str = "frida_runtime", rt_log_buffer: Optional[List[str]] = None) -> AsyncIterator[str]:
        async for chunk in stream_frida_chat(
            question, script_context, logs, finding_context, runtime_state, user_id, session_id,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
            rt_error_buffer=self._rt_error_buffer,
            rt_log_buffer=rt_log_buffer,
        ):
            yield chunk

    async def stream_network_chat(self, question: str, packet_data: dict, finding_context: Optional[dict] = None, user_id: str = "default", session_id: str = "network_analysis") -> AsyncIterator[str]:
        async for chunk in stream_network_chat(
            question, packet_data, finding_context, user_id, session_id,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def stream_project_summary(self, findings: List[dict], user_message: str = "", user_id: str = "default", session_id: str = "dashboard", project_platform: str = "General") -> AsyncIterator[str]:
        async for chunk in stream_project_summary(
            findings, user_message, user_id, session_id, project_platform,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def stream_runtime_orchestration(self, telemetry_batch: dict, user_id: str = "default", session_id: str = "runtime_orchestrator") -> AsyncIterator[str]:
        async for chunk in stream_runtime_orchestration(
            telemetry_batch, user_id, session_id,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def chat_runtime_orchestration(self, question: str, telemetry_context: dict, user_id: str = "elite", session_id: str = "elite_default") -> AsyncIterator[str]:
        async for chunk in chat_runtime_orchestration(
            question, telemetry_context, user_id, session_id,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def stream_source_analysis_chat(self, question: str, analysis_context: dict, user_id: str = "default", session_id: str = "source_analysis") -> AsyncIterator[str]:
        async for chunk in stream_source_analysis_chat(
            question, analysis_context, user_id, session_id,
            conversation_memory=self.conversation_memory,
            domain_knowledge=self.domain_knowledge,
            response_templates=self.response_templates,
            semantic_data=self._semantic_data,
        ):
            yield chunk

    async def analyze_flow(self, flow: dict) -> dict:
        return await analyze_flow(flow)

    async def repeater_suggest(self, flow: dict) -> list:
        return await repeater_suggest(flow)

    async def stream_audit_flow(self, flow: dict) -> AsyncIterator[str]:
        async for chunk in stream_audit_flow(flow):
            yield chunk


# Global singleton with periodic cleanup
ai_service = AIService()

# Periodic cleanup of old conversation contexts
async def _cleanup_conversations():
    """Periodic cleanup of old conversation contexts."""
    while True:
        try:
            ai_service.conversation_memory.cleanup_old_contexts()
            await asyncio.sleep(3600)  # Cleanup every hour
        except Exception as e:
            logger.error(f"Conversation cleanup error: {e}")
            await asyncio.sleep(3600)


def start_cleanup_task():
    """Start the conversation cleanup task. Call this during application startup."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_cleanup_conversations())
    except RuntimeError:
        # Event loop not running yet
        pass
