"""
IRVES — Conversation Context & Memory Management
Tracks conversation state, user expertise, mood, and platform context.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ConversationContext:
    """Tracks conversation state and user context for intelligent responses."""
    user_id: str
    session_id: str
    messages: List[Dict[str, Any]] = field(default_factory=list)
    user_expertise_level: str = "intermediate"  # beginner, intermediate, advanced, expert
    current_mood: str = "neutral"  # frustrated, excited, confused, focused, casual
    preferred_tone: str = "professional"  # casual, professional, educational, direct
    project_context: Dict[str, Any] = field(default_factory=dict)
    recent_topics: List[str] = field(default_factory=list)
    last_interaction: datetime = field(default_factory=datetime.now)
    interaction_count: int = 0
    script_injections: List[Dict[str, Any]] = field(default_factory=list)  # track suggested scripts & outcomes
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Add a message to conversation history with automatic context updates."""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now(),
            "metadata": metadata or {}
        })
        self.last_interaction = datetime.now()
        self.interaction_count += 1
        
        # Auto-detect expertise level from conversation
        if role == "user":
            self._detect_expertise_from_message(content)
            self._detect_mood_from_message(content)
    
    def get_recent_context(self, max_messages: int = 5) -> str:
        """Get formatted recent conversation context."""
        recent = self.messages[-max_messages:] if self.messages else []
        if not recent:
            return "No previous conversation."
        
        context_lines = []
        for msg in recent:
            role = msg["role"].capitalize()
            content = msg["content"][:200]  # Truncate long messages
            context_lines.append(f"{role}: {content}")
        
        return "\n".join(context_lines)

    def record_script_suggestion(self, script_type: str, outcome: str = "unknown", error: str = ""):
        """Record a script suggestion and its outcome to avoid repetition."""
        self.script_injections.append({
            "type": script_type,
            "outcome": outcome,
            "error": error[:200],
            "timestamp": datetime.now().isoformat(),
        })
        # Keep last 10
        if len(self.script_injections) > 10:
            self.script_injections = self.script_injections[-10:]

    def get_script_history_summary(self) -> str:
        """Get a summary of previously suggested scripts for the AI."""
        if not self.script_injections:
            return "No previous scripts suggested."
        lines = ["## Previously Suggested Scripts"]
        for inj in self.script_injections[-5:]:
            lines.append(f"- [{inj['outcome']}] {inj['type']} | Error: {inj.get('error') or 'none'}")
        return "\n".join(lines)

    def update_last_script_outcome(self, outcome: str, error: str = ""):
        """Update the most recent script injection outcome (called from WebSocket handlers on success/failure)."""
        if not self.script_injections:
            return
        self.script_injections[-1]["outcome"] = outcome
        if error:
            self.script_injections[-1]["error"] = error[:200]
    
    def _detect_expertise_from_message(self, message: str):
        """Detect and update user expertise level based on message content."""
        message_lower = message.lower()
        
        expert_indicators = ["0-day", "exploit chain", "rop chain", "heap spray", "jop", "cve-", 
                            "fuzzing corpus", "symbolic execution", "differential fuzzing"]
        advanced_indicators = ["bypass", "hook", "intercept", "inject", "reverse engineer", 
                              "decompile", "instrument", "ptrace", "anti-debug"]
        intermediate_indicators = ["vulnerability", "pentest", "scan", "owasp", "finding", 
                                   "severity", "remediation", "hardening"]
        
        if any(indicator in message_lower for indicator in expert_indicators):
            self.user_expertise_level = "expert"
        elif any(indicator in message_lower for indicator in advanced_indicators):
            self.user_expertise_level = "advanced"
        elif any(indicator in message_lower for indicator in intermediate_indicators):
            if self.user_expertise_level == "beginner":
                self.user_expertise_level = "intermediate"
    
    def _detect_mood_from_message(self, message: str):
        """Detect and update user mood based on message content."""
        message_lower = message.lower()
        
        frustration_indicators = ["not working", "broken", "error again", "still failing", "wtf", "frustrating"]
        excitement_indicators = ["awesome", "great", "excellent", "perfect", "amazing", "worked"]
        confusion_indicators = ["confused", "don't understand", "what do you mean", "unclear", "lost"]
        
        if any(ind in message_lower for ind in frustration_indicators):
            self.current_mood = "frustrated"
        elif any(ind in message_lower for ind in excitement_indicators):
            self.current_mood = "excited"
        elif any(ind in message_lower for ind in confusion_indicators):
            self.current_mood = "confused"


class ConversationMemory:
    """Manages conversation contexts across users and sessions."""
    
    def __init__(self):
        self._contexts: Dict[str, ConversationContext] = {}
    
    def get_context(self, user_id: str, session_id: str) -> ConversationContext:
        """Get or create conversation context for a user/session."""
        key = f"{user_id}:{session_id}"
        if key not in self._contexts:
            self._contexts[key] = ConversationContext(user_id=user_id, session_id=session_id)
        return self._contexts[key]
    
    def cleanup_old_contexts(self, max_age_hours: int = 24):
        """Remove conversation contexts older than max_age_hours."""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        keys_to_remove = [
            key for key, ctx in self._contexts.items()
            if ctx.last_interaction < cutoff
        ]
        for key in keys_to_remove:
            del self._contexts[key]
        logger.info(f"[ConversationMemory] Cleaned up {len(keys_to_remove)} old contexts")
    
    def update_user_context(self, user_id: str, message: str, session_id: str):
        """Update conversation context with a new user message."""
        context = self.get_context(user_id, session_id)
        
        # Add to conversation history
        context.add_message("user", message)
