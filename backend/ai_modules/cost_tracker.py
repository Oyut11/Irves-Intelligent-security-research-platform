"""
IRVES — AI Cost Tracker
Track token usage and costs per module for budgeting and optimization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AIModule(str, Enum):
    """AI module identifiers for cost tracking."""
    PARSING = "parsing"
    REASONING = "reasoning"
    GENERATION = "generation"
    CHAT = "chat"


@dataclass
class ModuleCost:
    """Cost breakdown for a single AI operation."""
    module: AIModule
    operation: str  # e.g., "parse_findings", "analyze_attack_path", "generate_frida_script"
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0  # For models that support prompt caching
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration_ms: int = 0
    success: bool = True
    error_message: Optional[str] = None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def estimate_cost_usd(self) -> float:
        """Estimate cost in USD based on model pricing."""
        # Pricing per 1M tokens (approximate, update as needed)
        pricing = {
            "gpt-4o": {"input": 2.50, "output": 10.00, "cached": 1.25},
            "gpt-4o-mini": {"input": 0.15, "output": 0.60, "cached": 0.075},
            "claude-3-5-sonnet": {"input": 3.00, "output": 15.00, "cached": 1.50},
            "claude-3-haiku": {"input": 0.25, "output": 1.25, "cached": 0.125},
            "gemini-1.5-flash": {"input": 0.075, "output": 0.30, "cached": 0.0375},
            "gemini-1.5-pro": {"input": 1.25, "output": 5.00, "cached": 0.625},
        }

        model_lower = self.model.lower()
        prices = pricing.get(model_lower, {"input": 2.50, "output": 10.00, "cached": 1.25})

        input_cost = (self.input_tokens / 1_000_000) * prices["input"]
        output_cost = (self.output_tokens / 1_000_000) * prices["output"]
        cached_cost = (self.cached_tokens / 1_000_000) * prices["cached"]

        return round(input_cost + output_cost + cached_cost, 6)

    def to_dict(self) -> Dict:
        return {
            "module": self.module.value,
            "operation": self.operation,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": self.estimate_cost_usd(),
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "success": self.success,
            "error_message": self.error_message,
        }


class CostTracker:
    """Global cost tracker for AI operations across all modules."""

    def __init__(self):
        self.operations: List[ModuleCost] = []
        self._daily_budget_usd: float = 10.0  # Default $10/day budget
        self._alert_threshold: float = 0.8  # Alert at 80% of budget

    def record(self, cost: ModuleCost) -> None:
        """Record an AI operation cost."""
        self.operations.append(cost)

        # Log if expensive operation
        estimated = cost.estimate_cost_usd()
        if estimated > 0.50:  # $0.50+ is expensive
            logger.warning(
                f"[CostTracker] Expensive operation: {cost.operation} "
                f"(${estimated:.4f}, {cost.total_tokens} tokens)"
            )

    def get_stats(self, module: Optional[AIModule] = None) -> Dict:
        """Get cost statistics, optionally filtered by module."""
        operations = self.operations
        if module:
            operations = [op for op in operations if op.module == module]

        if not operations:
            return {
                "total_operations": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "by_operation": {},
            }

        total_tokens = sum(op.total_tokens for op in operations)
        total_cost = sum(op.estimate_cost_usd() for op in operations)

        # Group by operation type
        by_operation: Dict[str, Dict] = {}
        for op in operations:
            if op.operation not in by_operation:
                by_operation[op.operation] = {
                    "count": 0,
                    "total_tokens": 0,
                    "total_cost": 0.0,
                }
            by_operation[op.operation]["count"] += 1
            by_operation[op.operation]["total_tokens"] += op.total_tokens
            by_operation[op.operation]["total_cost"] += op.estimate_cost_usd()

        return {
            "total_operations": len(operations),
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 4),
            "by_operation": by_operation,
        }

    def get_module_stats(self) -> Dict[str, Dict]:
        """Get stats grouped by AI module."""
        return {
            "parsing": self.get_stats(AIModule.PARSING),
            "reasoning": self.get_stats(AIModule.REASONING),
            "generation": self.get_stats(AIModule.GENERATION),
            "chat": self.get_stats(AIModule.CHAT),
        }

    def get_daily_usage(self) -> Dict:
        """Get today's usage and budget status."""
        today = datetime.utcnow().date()
        today_ops = [op for op in self.operations if op.timestamp.date() == today]

        total_cost = sum(op.estimate_cost_usd() for op in today_ops)
        budget_pct = (total_cost / self._daily_budget_usd) * 100 if self._daily_budget_usd > 0 else 0

        return {
            "date": today.isoformat(),
            "daily_budget_usd": self._daily_budget_usd,
            "used_usd": round(total_cost, 4),
            "remaining_usd": round(self._daily_budget_usd - total_cost, 4),
            "budget_percentage": round(budget_pct, 2),
            "alert": budget_pct >= self._alert_threshold * 100,
            "operation_count": len(today_ops),
        }

    def set_budget(self, budget_usd: float) -> None:
        """Set daily budget limit."""
        self._daily_budget_usd = budget_usd

    def check_budget(self, estimated_cost: float) -> bool:
        """Check if operation would exceed budget."""
        daily = self.get_daily_usage()
        return (daily["used_usd"] + estimated_cost) <= self._daily_budget_usd

    def clear_history(self) -> None:
        """Clear all recorded operations."""
        self.operations.clear()


# Global instance
cost_tracker = CostTracker()
