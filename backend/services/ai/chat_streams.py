"""
IRVES — Chat & Stream Methods
All stream_* and chat methods for the AI service, plus flow analysis.
"""

import asyncio
import json
import logging
import re
from typing import AsyncIterator, Dict, Any, List, Optional
from collections import defaultdict

from services.ai.context import ConversationContext, ConversationMemory
from services.ai.prompts import (
    ANALYSIS_SYSTEM,
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
    semantic_context_analysis,
    fallback_context_analysis,
)
from services.ai.intent import (
    detect_intent,
    detect_platform_context,
    build_adaptive_system_prompt,
    _is_casual_message,
)
from services.ai.llm import (
    get_api_key,
    is_local_provider,
    get_model,
    resolve_api_base,
    stream_llm,
)
from services.ai.log_analyzer import analyze_logs_for_thinking, build_thinking_context
from services.ai.rag import build_rag_context

logger = logging.getLogger(__name__)


async def analyze_finding(
    finding: dict,
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> dict:
    """Generate structured AI analysis for a finding."""
    prompt = ANALYSIS_PROMPT.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        tool=finding.get("tool", ""),
        category=finding.get("category", ""),
        location=finding.get("location", "N/A"),
        owasp=finding.get("owasp_mapping", "N/A"),
        cwe=finding.get("cwe_mapping", "N/A"),
        description=finding.get("description", ""),
        code_snippet=finding.get("code_snippet") or "Not available",
    )

    def _call():
        import os
        from litellm import completion

        # CRITICAL: Prevent local IRVES proxy from intercepting AI traffic
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        os.environ["http_proxy"] = ""
        os.environ["https_proxy"] = ""

        model = get_model()
        api_base = resolve_api_base()
        _is_local = is_local_provider()
        timeout = 300 if _is_local else 120
        logger.info(f"[IIE] Calling LLM: {model} (Base: {api_base or 'default'}) | local={_is_local} | timeout={timeout}s")

        response = completion(
            model=model,
            api_key=get_api_key(),
            api_base=api_base,
            messages=[
                {"role": "system", "content": ANALYSIS_SYSTEM},
                {"role": "user", "content": prompt}
            ],
            timeout=timeout,
        )
        return response.choices[0].message.content

    try:
        raw = await asyncio.get_event_loop().run_in_executor(None, _call)
    except Exception as e:
        logger.exception(f"[IIE] AI Analysis failed for {get_model()}")
        raise RuntimeError(f"Intelligence Engine failure: {str(e)}")

    # Extract JSON from response (model may wrap it in markdown)
    try:
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "explanation": raw,
            "impact": "",
            "attack_path": [],
            "fix": "",
            "references": [],
        }


async def chat(
    question: str,
    context: dict,
    user_id: str = "default",
    session_id: str = "default",
    screen: str = "finding_detail",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> str:
    """Intelligent contextual chat with adaptive responses."""
    # Update conversation memory
    conversation_memory.update_user_context(user_id, question, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    # Detect intent with full context awareness
    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))

    # Detect platform context from message
    detect_platform_context(question, conv_context, **_semantic_kwargs(semantic_data))

    # Build adaptive system prompt with screen context
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen=screen)

    # Add domain expertise context
    platform = conv_context.project_context.get('platform_detected', '')
    domain = conv_context.project_context.get('security_domain', '')
    if platform or domain:
        system_prompt += f"\n\n## Active Domain Context\nPlatform: {platform or 'General'}\nDomain: {domain or 'General Security'}\n"
    if context.get('category'):
        system_prompt += f"Finding Category: {context['category']}\n"
    if context.get('severity'):
        system_prompt += f"Severity: {context['severity']}\n"

    # Prepare natural user message
    context_parts = []
    if context.get('title'):
        context_parts.append(f"Finding: {context['title']} ({context.get('severity', 'Unknown')} severity)")
    if context.get('category'):
        context_parts.append(f"Category: {context['category']}")
    if context.get('location'):
        context_parts.append(f"Location: {context['location']}")
    if context.get('description'):
        context_parts.append(f"Description: {context['description'][:500]}")
    if context.get('code_snippet'):
        context_parts.append(f"Code snippet:\n```\n{context['code_snippet'][:500]}\n```")
    if context.get('owasp_mapping'):
        context_parts.append(f"OWASP: {context['owasp_mapping']}")
    if context.get('ai_analysis'):
        context_parts.append(f"Previous AI analysis: {context['ai_analysis'][:300]}...")
    if context.get('ai_fix_guidance'):
        context_parts.append(f"Fix guidance: {context['ai_fix_guidance'][:300]}...")

    conversation_summary = conv_context.get_recent_context(3)

    user_msg = ""
    if context_parts:
        user_msg += "**Context you can see:**\n" + "\n".join(context_parts) + "\n\n"
    user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n" \
                f"**User says:** {question}"

    def _call():
        import os
        from litellm import completion

        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        os.environ["http_proxy"] = ""
        os.environ["https_proxy"] = ""

        model = get_model()
        api_base = resolve_api_base()
        _is_local = is_local_provider()
        timeout = 300 if _is_local else 120
        logger.info(f"[IIE] Chat LLM: model={model} | base={api_base or 'default'} | local={_is_local} | timeout={timeout}s")

        response = completion(
            model=model,
            api_key=get_api_key(),
            api_base=api_base,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ],
            temperature=0.7,
            timeout=timeout,
        )
        return response.choices[0].message.content

    try:
        response = await asyncio.get_running_loop().run_in_executor(None, _call)

        conv_context.add_message("assistant", response, {
            "intent": intent_data.get("primary_intent", "technical"),
            "confidence": intent_data.get("confidence", 0.5)
        })

        return response
    except Exception as e:
        logger.exception(f"[IIE] Intelligent Chat failed for {get_model()}")
        raise RuntimeError(f"Intelligence Engine failure: {str(e)}")


async def stream_analysis(finding: dict) -> AsyncIterator[str]:
    """Stream AI analysis of a finding."""
    prompt = ANALYSIS_PROMPT.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        tool=finding.get("tool", ""),
        category=finding.get("category", ""),
        location=finding.get("location", "N/A"),
        owasp=finding.get("owasp_mapping", "N/A"),
        cwe=finding.get("cwe_mapping", "N/A"),
        description=finding.get("description", ""),
        code_snippet=finding.get("code_snippet") or "Not available",
    )
    async for chunk in stream_llm(ANALYSIS_SYSTEM, prompt):
        yield chunk


async def stream_chat(
    question: str,
    context: dict,
    user_id: str = "default",
    session_id: str = "default",
    screen: str = "finding_detail",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Stream intelligent chat responses with full context awareness."""
    conversation_memory.update_user_context(user_id, question, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))
    detect_platform_context(question, conv_context, **_semantic_kwargs(semantic_data))
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen=screen)

    platform = conv_context.project_context.get('platform_detected', '')
    domain = conv_context.project_context.get('security_domain', '')
    if platform or domain:
        system_prompt += f"\n\n## Active Domain Context\nPlatform: {platform or 'General'}\nDomain: {domain or 'General Security'}\n"
    if context.get('category'):
        system_prompt += f"Finding Category: {context['category']}\n"
    if context.get('severity'):
        system_prompt += f"Severity: {context['severity']}\n"

    context_parts = []
    if context.get('title'):
        context_parts.append(f"Finding: {context['title']} ({context.get('severity', 'Unknown')} severity)")
    if context.get('category'):
        context_parts.append(f"Category: {context['category']}")
    if context.get('location'):
        context_parts.append(f"Location: {context['location']}")
    if context.get('description'):
        context_parts.append(f"Description: {context['description'][:500]}")
    if context.get('code_snippet'):
        context_parts.append(f"Code snippet:\n```\n{context['code_snippet'][:500]}\n```")
    if context.get('owasp_mapping'):
        context_parts.append(f"OWASP: {context['owasp_mapping']}")
    if context.get('ai_analysis'):
        context_parts.append(f"Previous AI analysis: {context['ai_analysis'][:300]}...")
    if context.get('ai_fix_guidance'):
        context_parts.append(f"Fix guidance: {context['ai_fix_guidance'][:300]}...")

    conversation_summary = conv_context.get_recent_context(3)

    user_msg = ""
    if context_parts:
        user_msg += "**Context you can see:**\n" + "\n".join(context_parts) + "\n\n"
    user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n" \
                f"**User says:** {question}"

    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg):
        response_chunks.append(chunk)
        yield chunk

    complete_response = "".join(response_chunks)
    conv_context.add_message("assistant", complete_response, {
        "intent": intent_data.get("primary_intent", "technical"),
        "confidence": intent_data.get("confidence", 0.5),
        "streaming": True
    })


async def stream_frida_chat(
    question: str,
    script_context: str,
    logs: str,
    finding_context: Optional[dict] = None,
    runtime_state: Optional[dict] = None,
    user_id: str = "default",
    session_id: str = "frida_runtime",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
    rt_error_buffer: Dict[str, List[dict]],
    rt_log_buffer: Optional[List[str]] = None,
) -> AsyncIterator[str]:
    """Stream Frida chat with full context awareness, conversation memory, and adaptive prompts."""
    conversation_memory.update_user_context(user_id, question, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    # ALWAYS detect intent from what the user actually said — never override with log state
    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))
    user_intent = intent_data.get("primary_intent", "technical")

    # Behavioral casual check — works for any phrasing, any language
    is_casual = (
        user_intent == "casual_conversation"
        or _is_casual_message(question)
    )
    # Override casual when on frida_runtime screen with actual logs or errors
    # The user is asking about live output / errors — AI must analyze, not greet
    if is_casual and (logs or script_context or runtime_state):
        intent_data["primary_intent"] = "problem_solving"
        user_intent = "problem_solving"
        is_casual = False

    # ── THINKING PHASE: Analyze logs BEFORE AI generates any script ──
    thinking_analysis = analyze_logs_for_thinking(
        logs=logs,
        script_history=conv_context.get_script_history_summary(),
        active_hooks=runtime_state.get('active_hooks') if runtime_state else None,
        rt_errors=get_runtime_errors(rt_error_buffer, session_id) if not is_casual else None,
    )
    thinking_context = build_thinking_context(thinking_analysis)
    has_errors = bool(thinking_analysis["categories"])

    detect_platform_context(question, conv_context, **_semantic_kwargs(semantic_data))
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="frida_runtime")

    platform = conv_context.project_context.get('platform_detected', '')
    domain = conv_context.project_context.get('security_domain', '')
    if platform or domain:
        system_prompt += f"\n\n## Active Domain Context\nPlatform: {platform or 'General'}\nDomain: {domain or 'General Security'}\n"
    # Build rich Investigation Brief from finding context
    investigation_brief = ""
    if finding_context:
        _ai_analysis_raw = finding_context.get('ai_analysis', '')
        _ai_analysis_parsed = {}
        if isinstance(_ai_analysis_raw, str) and _ai_analysis_raw.strip():
            try:
                _ai_analysis_parsed = json.loads(_ai_analysis_raw)
            except json.JSONDecodeError:
                _ai_analysis_parsed = {"explanation": _ai_analysis_raw}
        elif isinstance(_ai_analysis_raw, dict):
            _ai_analysis_parsed = _ai_analysis_raw

        _attack_path = finding_context.get('ai_attack_path')
        if isinstance(_attack_path, str) and _attack_path.strip():
            try:
                _attack_path = json.loads(_attack_path)
            except json.JSONDecodeError:
                pass

        brief_parts = [
            f"## Investigation Brief — {finding_context.get('title', 'Unknown')}",
            f"- Severity: {finding_context.get('severity', 'Unknown')}",
        ]
        if finding_context.get('owasp_mapping'):
            brief_parts.append(f"- OWASP: {finding_context['owasp_mapping']}")
        if finding_context.get('cwe_mapping'):
            brief_parts.append(f"- CWE: {finding_context['cwe_mapping']}")
        if finding_context.get('tool'):
            brief_parts.append(f"- Discovered by: {finding_context['tool']}")
        if finding_context.get('location'):
            brief_parts.append(f"- Location: {finding_context['location']}")
        if finding_context.get('category'):
            brief_parts.append(f"- Category: {finding_context['category']}")
        if finding_context.get('description'):
            brief_parts.append(f"\n**Description:** {finding_context['description'][:500]}")
        if finding_context.get('code_snippet'):
            brief_parts.append(f"\n**Vulnerable Code:**\n```\n{finding_context['code_snippet'][:400]}\n```")
        if _ai_analysis_parsed.get('explanation'):
            brief_parts.append(f"\n**AI Explanation:** {_ai_analysis_parsed['explanation'][:400]}")
        if _ai_analysis_parsed.get('impact'):
            brief_parts.append(f"\n**Impact:** {_ai_analysis_parsed['impact'][:400]}")
        if _attack_path:
            _ap_str = _attack_path if isinstance(_attack_path, str) else '\n'.join(f"  - {s}" for s in _attack_path)
            brief_parts.append(f"\n**Attack Path:**\n{_ap_str[:600]}")
        if _ai_analysis_parsed.get('fix'):
            brief_parts.append(f"\n**Suggested Fix:** {_ai_analysis_parsed['fix'][:400]}")
        if finding_context.get('ai_fix_guidance'):
            brief_parts.append(f"\n**Fix Guidance:** {finding_context['ai_fix_guidance'][:400]}")

        investigation_brief = '\n'.join(brief_parts)
        system_prompt += f"\n\n{investigation_brief}\n\nWhen suggesting Frida scripts, ALWAYS align the hook strategy with the OWASP/CWE classification above."

    context_parts = []
    if finding_context:
        context_parts.append(f"Related finding: {finding_context.get('title', 'Unknown')} ({finding_context.get('severity', 'Unknown')} severity)")
        if finding_context.get('description'):
            context_parts.append(f"Description: {finding_context['description']}")
        if investigation_brief:
            context_parts.append(f"\nInvestigation Brief:\n{investigation_brief}")
    if runtime_state:
        st = runtime_state
        rs_lines = ["## Runtime State"]
        rs_lines.append(f"Engine: {st.get('engine', 'unknown')}")
        rs_lines.append(f"Device connected: {'yes' if st.get('device_connected') else 'no'}")
        rs_lines.append(f"Session active (WebSocket): {'yes' if st.get('websocket_connected') else 'no'}")
        rs_lines.append(f"Target package: {st.get('package') or 'none selected'}")
        rs_lines.append(f"Device ID/serial: {st.get('device') or 'none'}")
        hooks = st.get('active_hooks', [])
        if hooks:
            rs_lines.append(f"Active hooks: {', '.join(hooks)}")
        else:
            rs_lines.append("Active hooks: none")
        context_parts.append('\n'.join(rs_lines))
    if script_context:
        context_parts.append(f"Current Frida script:\n```javascript\n{script_context}\n```")
    if logs:
        if is_casual:
            context_parts.append(f"[Background session logs — user is chatting casually, do NOT treat these as errors to fix]\n```\n{logs[:800]}\n```")
        else:
            context_parts.append(f"Recent logs:\n```\n{logs[:2000]}\n```")

    # ── Insert structured thinking context BEFORE the AI generates response ──
    if not is_casual and thinking_context:
        context_parts.append(thinking_context)

    # ── RAG: Retrieve relevant knowledge for the query ──
    if not is_casual:
        rag_context = build_rag_context(
            query=question,
            logs=logs,
            finding_context=finding_context,
            max_results=3,
        )
        context_parts.append(rag_context)

    # Add script injection history to prevent repeating failed approaches
    context_parts.append(conv_context.get_script_history_summary())

    conversation_summary = conv_context.get_recent_context(3)

    user_msg = ""
    if context_parts:
        user_msg += "**Context:**\n" + "\n".join(context_parts) + "\n\n"
    user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n" \
                f"**User:** {question}"

    temperature = 0.8 if is_casual else (0.3 if has_errors else 0.7)
    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg, temperature=temperature):
        response_chunks.append(chunk)
        yield chunk

    complete_response = "".join(response_chunks)

    # Agentic enforcement removed — the frontend (runtime_ai_partner.js) reads the
    # ```javascript block directly and offers injection via the "Inject" button.
    # Adding a second ```json block caused confusing duplicate output.

    conv_context.add_message("assistant", complete_response, {
        "intent": intent_data.get("primary_intent", "technical"),
        "confidence": intent_data.get("confidence", 0.5),
        "screen": "frida_runtime",
        "streaming": True
    })

    # Detect and record script suggestion to prevent repetition
    if "```javascript" in complete_response or "```js" in complete_response:
        script_type = "custom_frida_script"
        # Try to identify the script category from the response
        lower_resp = complete_response.lower()
        if "stealth" in lower_resp or "cloak" in lower_resp or "zymbiote" in lower_resp:
            script_type = "zymbiote_stealth"
        elif "ssl" in lower_resp or "pinning" in lower_resp or "trustmanager" in lower_resp:
            if "boring" in lower_resp or "native" in lower_resp or "libssl" in lower_resp:
                script_type = "boring_ssl_capture"
            else:
                script_type = "ssl_bypass"
        elif "root" in lower_resp or "rootbeer" in lower_resp or "safety" in lower_resp:
            script_type = "root_detection_bypass"
        elif "crypto" in lower_resp or "cipher" in lower_resp or "aes" in lower_resp:
            script_type = "crypto_capture"
        elif "intent" in lower_resp:
            script_type = "intent_monitor"
        elif "network" in lower_resp or "url" in lower_resp or "connection" in lower_resp:
            script_type = "network_intercept"
        conv_context.record_script_suggestion(script_type, outcome="suggested")


async def stream_network_chat(
    question: str,
    packet_data: dict,
    finding_context: Optional[dict] = None,
    user_id: str = "default",
    session_id: str = "network_analysis",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Stream network chat with full context awareness."""
    conversation_memory.update_user_context(user_id, question, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))
    detect_platform_context(question, conv_context, **_semantic_kwargs(semantic_data))
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="network_intercept")

    platform = conv_context.project_context.get('platform_detected', '')
    domain = conv_context.project_context.get('security_domain', '')
    if platform or domain:
        system_prompt += f"\n\n## Active Domain Context\nPlatform: {platform or 'General'}\nDomain: {domain or 'General Security'}\n"
    if finding_context and finding_context.get('category'):
        system_prompt += f"Finding Category: {finding_context['category']}\n"
    if finding_context and finding_context.get('severity'):
        system_prompt += f"Severity: {finding_context['severity']}\n"

    context_parts = []
    if finding_context:
        context_parts.append(f"Related finding: {finding_context.get('title', 'Unknown')} ({finding_context.get('severity', 'Unknown')} severity)")
        if finding_context.get('description'):
            context_parts.append(f"Description: {finding_context['description']}")
        if finding_context.get('ai_analysis'):
            context_parts.append(f"Previous AI analysis: {finding_context['ai_analysis'][:300]}...")
    if packet_data:
        context_parts.append(f"Intercepted packet:\n```json\n{json.dumps(packet_data, indent=2)}\n```")

    conversation_summary = conv_context.get_recent_context(3)

    user_msg = ""
    if context_parts:
        user_msg += "**Context:**\n" + "\n".join(context_parts) + "\n\n"
    user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n" \
                f"**User:** {question}"

    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg, temperature=0.7):
        response_chunks.append(chunk)
        yield chunk

    complete_response = "".join(response_chunks)
    conv_context.add_message("assistant", complete_response, {
        "intent": intent_data.get("primary_intent", "technical"),
        "confidence": intent_data.get("confidence", 0.5),
        "screen": "network_intercept",
        "streaming": True
    })


async def stream_source_analysis_chat(
    question: str,
    analysis_context: dict,
    user_id: str = "default",
    session_id: str = "source_analysis",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Stream AI chat for the Source Code Analysis screen with full findings context."""
    conversation_memory.update_user_context(user_id, question, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))
    is_casual = (
        intent_data.get("primary_intent") == "casual_conversation"
        or _is_casual_message(question)
    )
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="source_analysis")

    # Build rich findings context — only when user wants technical help
    context_parts = []
    project_name = analysis_context.get("project_name", "")
    if project_name:
        context_parts.append(f"**Project:** {project_name}")

    analysis_results = analysis_context.get("analysis_results", {})
    if analysis_results and not is_casual:
        # Summary table: category → finding count + top severities
        summary_lines = []
        all_top_findings = []
        for cat, data in analysis_results.items():
            fc = data.get("finding_count", 0)
            metrics = data.get("summary_metrics") or {}
            ai_exp = data.get("ai_explanation") or ""
            summary_lines.append(f"- **{cat.replace('_',' ').title()}**: {fc} findings | {json.dumps(metrics)}")
            if ai_exp:
                summary_lines.append(f"  AI note: {ai_exp[:200]}")
            for f in data.get("top_findings", [])[:5]:
                all_top_findings.append(f)

        context_parts.append("**Analysis Summary (all categories):**\n" + "\n".join(summary_lines))

        if all_top_findings:
            findings_str = "\n".join(
                f"- [{f.get('severity','?').upper()}] {f.get('type','?')} — {f.get('file_path','?')}: {f.get('message','')[:120]}"
                for f in all_top_findings
            )
            context_parts.append(f"**Top Findings:**\n{findings_str}")
    elif not analysis_results:
        context_parts.append("**Note:** No analysis results available yet. The user should run the analysis first.")

    conversation_summary = conv_context.get_recent_context(3)
    user_msg = ""
    if context_parts:
        user_msg += "\n".join(context_parts) + "\n\n"
    user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n**User:** {question}"

    temperature = 0.8 if is_casual else 0.5
    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg, temperature=temperature):
        response_chunks.append(chunk)
        yield chunk

    complete_response = "".join(response_chunks)
    conv_context.add_message("assistant", complete_response, {
        "intent": intent_data.get("primary_intent", "deep_analysis"),
        "confidence": intent_data.get("confidence", 0.8),
        "screen": "source_analysis",
        "streaming": True,
    })


async def stream_project_summary(
    findings: List[dict],
    user_message: str = "",
    user_id: str = "default",
    session_id: str = "dashboard",
    project_platform: str = "General",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Summarize all project findings for the dashboard AI partner."""
    if user_message:
        conversation_memory.update_user_context(user_id, user_message, session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    if user_message:
        intent_data = detect_intent(user_message, conv_context, **_semantic_kwargs(semantic_data))
        detect_platform_context(user_message, conv_context, **_semantic_kwargs(semantic_data))
        conv_context.project_context['security_domain'] = project_platform.lower()
        conv_context.project_context['platform_detected'] = project_platform.title()
    else:
        intent_data = {"primary_intent": "deep_analysis", "confidence": 0.8}

    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="dashboard")

    clean_findings = []
    for f in findings:
        entry = {
            "title": f.get("title"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "frequency_count": f.get("count", 1)
        }
        if f.get("location"):
            entry["location"] = f.get("location")
        if f.get("description"):
            entry["description"] = f.get("description")[:200]
        clean_findings.append(entry)

    findings_str = json.dumps(clean_findings, indent=2)
    conversation_summary = conv_context.get_recent_context(3) if user_message else "No previous conversation."

    user_msg = f"**Project Platform:** {project_platform.title()}\n"
    user_msg += f"**Project Findings (Grouped):**\n```json\n{findings_str}\n```\n\n"
    if user_message:
        user_msg += f"**Recent conversation:**\n{conversation_summary}\n\n" \
                   f"**User asks:** {user_message}"
    else:
        user_msg += "Please provide an executive summary of the overall risk, top 3 severe issues, and broad architectural recommendations."

    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg, temperature=0.7):
        response_chunks.append(chunk)
        yield chunk

    if user_message:
        complete_response = "".join(response_chunks)
        conv_context.add_message("assistant", complete_response, {
            "intent": intent_data.get("primary_intent", "deep_analysis"),
            "confidence": intent_data.get("confidence", 0.8),
            "screen": "dashboard",
            "streaming": True
        })


async def stream_runtime_orchestration(
    telemetry_batch: dict,
    user_id: str = "default",
    session_id: str = "runtime_orchestrator",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Stream AI analysis of live runtime telemetry from eBPF + MTE + Zymbiote."""
    ebpf_events = telemetry_batch.get("ebpf_events", [])
    mte_faults = telemetry_batch.get("mte_faults", [])
    frida_errors = telemetry_batch.get("frida_errors", [])
    elapsed = telemetry_batch.get("elapsed_seconds", 0)
    is_stealth = telemetry_batch.get("is_stealth", False)

    if not ebpf_events and not mte_faults and not frida_errors:
        return

    conversation_memory.update_user_context(user_id, "runtime_telemetry_analysis", session_id)
    conv_context = conversation_memory.get_context(user_id, session_id)

    intent_data = {"primary_intent": "deep_analysis", "confidence": 0.9}
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="runtime_orchestrator")

    system_prompt += f"\n\n## Session Status\n"
    system_prompt += f"- Zymbiote Stealth: {'ACTIVE' if is_stealth else 'INACTIVE'}\n"
    system_prompt += f"- Elapsed: {elapsed}s\n"

    user_msg = "**Live Telemetry Batch:**\n\n"

    if ebpf_events:
        dex_dumps = [e for e in ebpf_events if e.get("is_dex") or e.get("event_type") == "dex_dump"]
        memfd_events = [e for e in ebpf_events if e.get("event_type") == "memfd_create"]
        mmap_events = [e for e in ebpf_events if e.get("event_type") == "mmap"]

        user_msg += f"### eBPF Events ({len(ebpf_events)} total)\n"
        if dex_dumps:
            user_msg += f"**DEX Dumps Detected: {len(dex_dumps)}**\n"
            for d in dex_dumps[:5]:
                user_msg += f"- PID={d.get('pid')} addr={d.get('addr')} size={d.get('size')} magic={d.get('magic','')}\n"
        if memfd_events:
            user_msg += f"**memfd_create: {len(memfd_events)}** — anonymous fd creation (packer indicator)\n"
        if mmap_events:
            non_file = [e for e in mmap_events if not e.get("file_backed", True)]
            user_msg += f"**mmap: {len(mmap_events)}** ({len(non_file)} non-file-backed)\n"

    if mte_faults:
        user_msg += f"\n### MTE Faults ({len(mte_faults)} total)\n"
        for f in mte_faults[:5]:
            user_msg += f"- **SEGV_MTESERR** at PC=`{f.get('pc','?')}` LR=`{f.get('lr','?')}` "
            user_msg += f"fault_addr=`{f.get('fault_addr','?')}` tag_mismatch=`{f.get('tag_mismatch','')}`\n"
            if f.get("backtrace"):
                for bt in f["backtrace"][:3]:
                    user_msg += f"  → {bt.get('pc','?')} {bt.get('location','')}\n"

    if frida_errors:
        user_msg += f"\n### Frida Runtime Errors ({len(frida_errors)} total)\n"
        for err in frida_errors[:10]:
            user_msg += f"- **ERROR:** {err.get('message')}\n"
            if err.get('stack'):
                user_msg += f"  Stack: {err.get('stack')[:500]}...\n"
        user_msg += "\nCRITICAL: A script failure occurred. Analyze the error and pivot your strategy immediately.\n"

    user_msg += "\nAnalyze this telemetry. Correlate events, identify packer signatures, assess memory corruption."

    response_chunks = []
    async for chunk in stream_llm(system_prompt, user_msg, temperature=0.5):
        response_chunks.append(chunk)
        yield chunk

    complete_response = "".join(response_chunks)
    conv_context.add_message("assistant", complete_response, {
        "intent": "deep_analysis",
        "confidence": 0.9,
        "screen": "runtime_orchestrator",
        "telemetry_events": len(ebpf_events) + len(mte_faults),
        "streaming": True
    })


async def chat_runtime_orchestration(
    question: str,
    telemetry_context: dict,
    user_id: str = "elite",
    session_id: str = "elite_default",
    *,
    conversation_memory: ConversationMemory,
    domain_knowledge: Dict[str, Any],
    response_templates: Dict[str, str],
    semantic_data: Dict[str, Any],
) -> AsyncIterator[str]:
    """Contextual chat within an active elite analysis session."""
    conv_context = conversation_memory.get_context(user_id, session_id)
    conv_context.add_message("user", question)

    intent_data = detect_intent(question, conv_context, **_semantic_kwargs(semantic_data))
    system_prompt = build_adaptive_system_prompt(intent_data, conv_context, screen="runtime_orchestrator")

    ebpf_count = len(telemetry_context.get("ebpf_events", []))
    mte_count = len(telemetry_context.get("mte_faults", []))
    is_stealth = telemetry_context.get("is_stealth", False)
    elapsed = telemetry_context.get("elapsed_seconds", 0)

    user_prompt = (
        f"[Live session — elapsed: {elapsed}s, stealth: {is_stealth}, "
        f"eBPF events: {ebpf_count}, MTE faults: {mte_count}]\n\n"
        f"User question: {question}"
    )

    response_chunks = []
    try:
        async for chunk in stream_llm(system_prompt, user_prompt, temperature=0.35):
            response_chunks.append(chunk)
            yield chunk
    except Exception as e:
        logger.error(f"[AI-Orchestrator] chat failed: {e}")
        yield f"[AI error: {e}]"
        return

    conv_context.add_message("assistant", "".join(response_chunks), {
        "intent": intent_data.get("primary_intent", "unknown"),
        "screen": "runtime_orchestrator",
        "streaming": True,
    })


async def analyze_flow(flow: dict) -> dict:
    """Analyze a single captured HTTP/SSL flow for security issues."""
    method = flow.get("method", "GET")
    url = flow.get("url", flow.get("host", ""))
    headers = flow.get("headers", {})
    body = flow.get("body", flow.get("content", ""))[:4000]
    status = flow.get("status_code", "")
    resp = flow.get("response_body", flow.get("response", ""))[:4000]
    source = flow.get("source", "mitmproxy")

    system_prompt = (
        "You are an elite mobile security analyst. Analyze the HTTP/TLS flow below for "
        "security vulnerabilities. Be concise and precise. Return ONLY valid JSON with keys: "
        '"risk" (high/medium/low/info), "summary" (1-2 sentences), '
        '"findings" (list of {title, severity, detail}). No markdown, no prose outside JSON.'
    )
    user_prompt = (
        f"Source: {source}\n"
        f"Request: {method} {url}\n"
        f"Headers: {str(headers)[:1500]}\n"
        f"Body: {body}\n"
        f"Response status: {status}\n"
        f"Response body: {resp}"
    )

    result_text = ""
    try:
        async for token in stream_llm(system_prompt, user_prompt, temperature=0.2):
            result_text += token
        parsed = json.loads(result_text.strip())
        return {
            "risk": parsed.get("risk", "info"),
            "summary": parsed.get("summary", ""),
            "findings": parsed.get("findings", []),
        }
    except Exception as e:
        logger.warning(f"[AI-Auditor] analyze_flow error: {e} — raw={result_text[:200]!r}")
        return {"risk": "info", "summary": "AI analysis unavailable", "findings": []}


async def repeater_suggest(flow: dict) -> list:
    """Given a captured request, return 3 AI-suggested mutation variants for fuzzing."""
    method = flow.get("method", "GET")
    url = flow.get("url", "")
    headers = flow.get("headers", {})
    body = flow.get("body", flow.get("content", ""))[:3000]

    system_prompt = (
        "You are a senior penetration tester specializing in mobile API security. "
        "Given the HTTP request below, suggest exactly 3 fuzzing mutation variants. "
        "Each mutation should test a specific vulnerability class (IDOR, injection, auth bypass, etc.). "
        'Return ONLY valid JSON: a list of 3 objects each with keys: '
        '"label" (short name), "method", "url", "headers" (object), "body" (string). '
        "No markdown, no explanation outside the JSON array."
    )
    user_prompt = (
        f"{method} {url}\n"
        f"Headers: {str(headers)[:1000]}\n"
        f"Body: {body}"
    )

    result_text = ""
    try:
        async for token in stream_llm(system_prompt, user_prompt, temperature=0.4):
            result_text += token
        variants = json.loads(result_text.strip())
        if isinstance(variants, list):
            return variants[:3]
        return []
    except Exception as e:
        logger.warning(f"[AI-Auditor] repeater_suggest error: {e}")
        return []


async def stream_audit_flow(flow: dict) -> AsyncIterator[str]:
    """Stream a narrative security audit of a flow as plain text tokens."""
    method = flow.get("method", "GET")
    url = flow.get("url", flow.get("host", ""))
    headers = flow.get("headers", {})
    body = flow.get("body", flow.get("content", ""))[:3000]
    status = flow.get("status_code", "")
    source = flow.get("source", "mitmproxy")

    system_prompt = (
        "You are an expert mobile security analyst providing a real-time security review of "
        "intercepted network traffic. Be direct, specific, and actionable. "
        "Flag risks, note PII exposure, identify weak auth patterns, and suggest hardening steps. "
        "Write in crisp bullet points. Max 200 words."
    )
    user_prompt = (
        f"[{source.upper()}] {method} {url}  (HTTP {status})\n"
        f"Headers: {str(headers)[:1000]}\n"
        f"Body: {body}"
    )
    async for token in stream_llm(system_prompt, user_prompt, temperature=0.3):
        yield token


# ── Helpers ────────────────────────────────────────────────────────────────────

def _semantic_kwargs(semantic_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract semantic analysis kwargs from the semantic_data dict."""
    return {
        "tfidf_vectorizer": semantic_data.get("tfidf_vectorizer"),
        "intent_vectors": semantic_data.get("intent_vectors"),
        "platform_vectors": semantic_data.get("platform_vectors"),
    }


def get_runtime_errors(rt_error_buffer: Dict[str, List[dict]], session_key: str) -> List[dict]:
    """Get and clear runtime errors from the buffer for a session."""
    return rt_error_buffer.pop(session_key, [])


def record_runtime_error(
    rt_error_buffer: Dict[str, List[dict]],
    session_key: str,
    error_msg: str,
    stack: str = "",
    script_context: str = "",
) -> None:
    """Record a runtime error in the buffer."""
    from datetime import datetime
    rt_error_buffer[session_key].append({
        "timestamp": datetime.now().isoformat(),
        "error": error_msg,
        "stack": stack,
        "script_context": script_context,
    })
