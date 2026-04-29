"""
IRVES — AI Service Package
Refactored from monolithic ai_service.py.
"""

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
from services.ai.knowledge import initialize_domain_knowledge, initialize_response_templates
from services.ai.intent import detect_intent, detect_platform_context, build_adaptive_system_prompt
from services.ai.llm import get_api_key, is_local_provider, get_model, resolve_api_base, stream_llm

__all__ = [
    "ConversationContext",
    "ConversationMemory",
    "MASTER_FOUNDATION",
    "ANALYSIS_SYSTEM",
    "PROJECT_SUMMARY_SYSTEM",
    "ANALYSIS_PROMPT",
    "CHAT_SYSTEM",
    "FRIDA_SYSTEM_PROMPT",
    "NETWORK_SYSTEM_PROMPT",
    "RUNTIME_ORCHESTRATOR_SYSTEM",
    "initialize_domain_knowledge",
    "initialize_response_templates",
    "detect_intent",
    "detect_platform_context",
    "build_adaptive_system_prompt",
    "get_api_key",
    "is_local_provider",
    "get_model",
    "resolve_api_base",
    "stream_llm",
]
