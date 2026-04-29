"""
IRVES — Three-Module AI System
Phase 3: Intelligent security analysis with modular AI architecture.

Modules:
- ParsingModule: Tool output → Structured findings
- ReasoningModule: Findings → Attack paths, risk assessment
- GenerationModule: Analysis → Remediation code, scripts, reports

Each module has:
- Specialized system prompts
- Cost tracking
- Memory/context management
- Streaming support
"""

from ai_modules.parsing_module import ParsingModule
from ai_modules.reasoning_module import ReasoningModule
from ai_modules.generation_module import GenerationModule
from ai_modules.cost_tracker import CostTracker, ModuleCost, AIModule
from ai_modules.llm_client import LLMClient

__all__ = [
    "ParsingModule",
    "ReasoningModule",
    "GenerationModule",
    "CostTracker",
    "ModuleCost",
    "AIModule",
    "LLMClient",
]
