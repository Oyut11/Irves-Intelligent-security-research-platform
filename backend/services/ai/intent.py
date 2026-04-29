"""
IRVES — Intent Detection & Adaptive Prompt Building
Detects user intent, platform context, and builds adaptive system prompts.
"""

import re
import logging
from typing import Dict, Any, Optional

from services.ai.context import ConversationContext
from services.ai.prompts import (
    CHAT_SYSTEM,
    FRIDA_SYSTEM_PROMPT,
    NETWORK_SYSTEM_PROMPT,
    ANALYSIS_SYSTEM,
    PROJECT_SUMMARY_SYSTEM,
    RUNTIME_ORCHESTRATOR_SYSTEM,
    SOURCE_ANALYSIS_SYSTEM,
)
from services.ai.knowledge import (
    semantic_context_analysis,
    fallback_context_analysis,
    SKLEARN_AVAILABLE,
)

logger = logging.getLogger(__name__)

# ── Intent Detection Patterns ─────────────────────────────────────────────────

# Technical action signals — presence of any of these means the user wants technical help
_TECHNICAL_ACTION_SIGNALS = (
    "inject", "hook", "script", "bypass", "frida", "attach", "spawn",
    "error", "fail", "fix", "broken", "crash", "exception", "debug",
    "ssl", "intercept", "dump", "capture", "analyze",
    "what happened", "what went wrong", "help me", "why", "how",
)


def _is_casual_message(message: str) -> bool:
    """Behavioral check: no technical signals + short message = casual.
    Works for any language pattern — no keyword list can ever cover all casual phrases.
    """
    msg_lower = message.lower().strip()
    has_technical_signal = any(sig in msg_lower for sig in _TECHNICAL_ACTION_SIGNALS)
    is_short = len(message.split()) <= 10
    return is_short and not has_technical_signal


ANALYSIS_PATTERNS = re.compile(
    r"(analy[zs]e|analysis|review|assess|evaluate|investigate|explain|summarize|summary)"
    r"|((list|tell me|show me|give me|what are).{0,30}(finding|vulnerabilit|critical|issue|risk|flaw|weakness|problem))"
    r"|(attack (path|vector|surface)|exploit|remediat|mitigat|fix (this|the|it))"
    r"|(full (report|analysis|breakdown)|deep dive|comprehensive)"
    r"|(what should I (do|fix|patch|address)|how (serious|bad|critical) (is|are))"
    r"|(triage|auto.triage|priorit)",
    re.IGNORECASE
)


def detect_intent(
    message: str,
    conv_context: ConversationContext,
    *,
    tfidf_vectorizer=None,
    intent_vectors: Optional[Dict] = None,
    platform_vectors: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Professional semantic intent detection with conversation context analysis."""
    message_lower = message.lower().strip()
    
    # 1. Fast Path: Behavioral detection (no keyword list — works for any phrasing)
    if _is_casual_message(message):
        return {
            'primary_intent': 'casual_conversation',
            'confidence': 0.90,
            'platform': 'general',
            'platform_confidence': 0.0,
            'semantic_analysis': False
        }
    elif ANALYSIS_PATTERNS.search(message):
        return {
            'primary_intent': 'deep_analysis',
            'confidence': 0.85,
            'platform': 'general',
            'platform_confidence': 0.0,
            'semantic_analysis': False
        }
        
    # Get conversation history for context
    conversation_history = conv_context.messages if hasattr(conv_context, 'messages') else []
    
    # 2. Advanced Path: Semantic context analysis
    if tfidf_vectorizer and intent_vectors and platform_vectors:
        sem_analysis = semantic_context_analysis(
            message, conversation_history,
            tfidf_vectorizer, intent_vectors, platform_vectors,
        )
    else:
        sem_analysis = fallback_context_analysis(message, conversation_history)
    
    # 3. Fallback override if TF-IDF yields extremely low confidence
    if sem_analysis.get('confidence', 0.0) < 0.15:
        if any(word in message_lower for word in ['error', 'broken', 'fix', 'debug', 'fail']):
            sem_analysis['primary_intent'] = 'problem_solving'
            sem_analysis['confidence'] = 0.8
        elif any(word in message_lower for word in ['explain', 'what is', 'how does', 'teach']):
            sem_analysis['primary_intent'] = 'learning_inquiry'
            sem_analysis['confidence'] = 0.8
        elif '?' in message:
            sem_analysis['primary_intent'] = 'quick_question'
            sem_analysis['confidence'] = 0.5
        else:
            sem_analysis['primary_intent'] = 'deep_analysis'
            sem_analysis['confidence'] = 0.5
    
    return sem_analysis


def detect_platform_context(
    message: str,
    conv_context: ConversationContext,
    *,
    tfidf_vectorizer=None,
    intent_vectors: Optional[Dict] = None,
    platform_vectors: Optional[Dict] = None,
) -> None:
    """Detect and update platform context using semantic analysis."""
    # Use semantic context analysis for platform detection
    if tfidf_vectorizer and intent_vectors and platform_vectors:
        context_analysis = semantic_context_analysis(
            message, conv_context.messages,
            tfidf_vectorizer, intent_vectors, platform_vectors,
        )
    else:
        context_analysis = fallback_context_analysis(message, conv_context.messages)
    
    # Update conversation context with detected platform
    detected_platform = context_analysis.get('platform', 'general')
    platform_confidence = context_analysis.get('platform_confidence', 0.0)
    
    if platform_confidence > 0.3:  # Only update if confident
        conv_context.project_context['security_domain'] = detected_platform
        conv_context.project_context['platform_detected'] = detected_platform.title()
        conv_context.project_context['platform_confidence'] = platform_confidence


def build_adaptive_system_prompt(
    intent_data: Dict[str, Any],
    context: Optional[ConversationContext] = None,
    screen: str = "finding_detail",
) -> str:
    """Build highly adaptive system prompt based on intent, context, screen, and user state."""
    # Select base prompt based on screen
    screen_prompts = {
        "dashboard": PROJECT_SUMMARY_SYSTEM,
        "finding_detail": CHAT_SYSTEM,
        "frida_runtime": FRIDA_SYSTEM_PROMPT,
        "network_intercept": NETWORK_SYSTEM_PROMPT,
        "analysis": ANALYSIS_SYSTEM,
        "source_analysis": SOURCE_ANALYSIS_SYSTEM,
        "runtime_orchestrator": RUNTIME_ORCHESTRATOR_SYSTEM,
    }
    base = screen_prompts.get(screen, CHAT_SYSTEM)
    intent = intent_data.get("primary_intent", intent_data.get("primary", "technical"))
    confidence = intent_data["confidence"]

    # Get user context for personalization
    expertise_level = context.user_expertise_level if context else "intermediate"
    current_mood = context.current_mood if context else "neutral"
    conversation_history = context.get_recent_context(3) if context else "No previous conversation."

    # Human-readable screen descriptions
    screen_descriptions = {
        "dashboard": "Project Dashboard — the user is seeing an overview of all findings for a project",
        "finding_detail": "Finding Detail — the user is looking at a specific vulnerability finding",
        "frida_runtime": "Frida Runtime Workspace — the user is actively instrumenting a target app with Frida",
        "network_intercept": "Network Interception — the user is examining live network traffic",
        "analysis": "Auto-Analysis — the system is auto-analyzing a finding",
        "source_analysis": "Source Code Analysis — the user is reviewing automated analysis results across 8 categories",
        "runtime_orchestrator": "Elite Runtime Orchestration — live eBPF + MTE + Zymbiote telemetry analysis",
    }
    screen_desc = screen_descriptions.get(screen, screen)

    # Build adaptive prompt sections
    context_section = f"\n\n## Current Screen\n" \
                     f"- You are on screen: {screen_desc}\n" \
                     f"- User expertise level: {expertise_level}\n" \
                     f"- User mood: {current_mood}\n" \
                     f"- Intent: {intent} (confidence: {confidence:.0%})\n" \
                     f"- Recent conversation:\n{conversation_history}\n"

    # Intent-specific adaptations (mapped from semantic analysis names)
    if intent in ("casual", "casual_conversation"):
        return f"{base}{context_section}" \
               f"## Response Mode: Casual & Friendly\n" \
               f"Respond warmly and naturally — like a friend at the office. 1-3 sentences. " \
               f"Match their energy. No technical deep-dives unless they ask. " \
               f"Be yourself: sharp, helpful, but human."

    elif intent in ("quick_question",):
        return f"{base}{context_section}" \
               f"## Response Mode: Quick Answer\n" \
               f"Give a direct, concise answer (2-4 sentences). " \
               f"Short bullet list if needed (max 3-4 items). " \
               f"Save the deep dive for when they ask for it. No filler."

    elif intent in ("learning", "learning_inquiry"):
        return f"{base}{context_section}" \
               f"## Response Mode: Educational\n" \
               f"They want to learn. Adapt to their {expertise_level} level.\n" \
               f"- Balance depth with clarity\n" \
               f"- Practical examples, explain the why\n" \
               f"- Encourage questions, step-by-step understanding"

    elif intent in ("problem_solving",):
        mood_adaptation = ""
        if current_mood == "frustrated":
            mood_adaptation = "They seem frustrated. Be supportive and patient. Acknowledge the frustration, then give clear actionable steps."
        return f"{base}{context_section}" \
               f"## Response Mode: Problem-Solving\n" \
               f"{mood_adaptation}\n" \
               f"1. Acknowledge the issue\n" \
               f"2. Immediate actionable steps\n" \
               f"3. Root cause explanation\n" \
               f"4. Prevention strategies\n" \
               f"5. **Aggressively pivot to alternative solutions if initial approach fails**"

    elif intent in ("deep_analysis",):
        return f"{base}{context_section}" \
               f"## Response Mode: Comprehensive Analysis\n" \
               f"Provide thorough, structured analysis:\n" \
               f"## Executive Summary (2-3 sentences)\n" \
               f"## Technical Details (adapted to {expertise_level} level)\n" \
               f"## Impact Assessment\n" \
               f"## Recommendations\n" \
               f"## Next Steps"

    # Default: adaptive technical discussion
    return f"{base}{context_section}" \
           f"## Response Mode: Technical Discussion\n" \
           f"Engage naturally — conversational but informative, appropriate for {expertise_level} level. " \
           f"Ask follow-up questions when helpful. Don't over-explain unless they want depth."
