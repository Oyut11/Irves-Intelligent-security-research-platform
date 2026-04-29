"""
IRVES — Reasoning Module (Three-Module AI)
Analyzes findings to generate attack paths, risk assessments, and strategies.

Responsibilities:
- Attack path analysis (how vulnerabilities chain together)
- Risk assessment (likelihood × impact)
- Strategy generation (what to analyze next)
- Finding correlation (static + dynamic = complete picture)
- Exploitability scoring
"""

import json
import logging
from typing import AsyncIterator, Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from ai_modules.cost_tracker import CostTracker, ModuleCost, AIModule
from ai_modules.llm_client import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """Represents an attack path from entry to impact."""
    path_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    entry_point: str
    target_asset: str
    difficulty: str  # easy, medium, hard
    likelihood: float  # 0.0 - 1.0
    impact: str  # critical, high, medium, low
    prerequisites: List[str]
    mitigations: List[str]
    tools_needed: List[str]


@dataclass
class RiskAssessment:
    """Risk assessment for a finding or group of findings."""
    overall_risk: str  # critical, high, medium, low
    risk_score: float  # 0.0 - 10.0
    likelihood: float  # 0.0 - 1.0
    business_impact: str
    technical_impact: str
    cvss_score: Optional[float] = None
    factors: List[str] = None


class ReasoningModule:
    """
    Reasoning Module for attack path and risk analysis.

    Analyzes security findings to:
    1. Build attack paths showing exploit chains
    2. Assess risk considering context
    3. Correlate findings across analysis phases
    4. Prioritize what to investigate next
    """

    SYSTEM_PROMPT_ATTACK_PATH = """You are the Reasoning Module of IRVES, analyzing attack paths.

Given security findings, construct realistic attack paths showing how an attacker could:
1. Enter the system (entry points)
2. Move through components (pivot points)
3. Reach valuable assets (targets)

For each attack path, provide:
{
  "attack_paths": [
    {
      "path_id": "unique-id",
      "name": "Short descriptive name",
      "description": "How this attack works",
      "steps": [
        {
          "step": 1,
          "action": "What attacker does",
          "finding_id": "Related finding if any",
          "technique": "MITRE ATT&CK technique if applicable"
        }
      ],
      "entry_point": "How attacker gets in",
      "target_asset": "What they reach",
      "difficulty": "easy|medium|hard",
      "likelihood": 0.0-1.0,
      "impact": "critical|high|medium|low",
      "prerequisites": ["What must be true"],
      "mitigations": ["How to prevent"],
      "tools_needed": ["Tools attacker uses"]
    }
  ]
}

Consider:
- OWASP Mobile Top 10 attack patterns
- MITRE ATT&CK for Mobile
- Real-world exploit chains
- Prerequisites and dependencies"""

    SYSTEM_PROMPT_RISK = """You are the Reasoning Module of IRVES, assessing security risk.

Given findings and context, assess:

{
  "risk_assessment": {
    "overall_risk": "critical|high|medium|low",
    "risk_score": 0.0-10.0,
    "likelihood": 0.0-1.0,
    "business_impact": "Description of business consequences",
    "technical_impact": "Description of technical consequences",
    "cvss_score": 0.0-10.0 or null,
    "factors": [
      "Factor increasing/decreasing risk"
    ]
  }
}

Consider:
- CVSS v3.1 vectors where applicable
- Business context (data sensitivity, user base)
- Technical context (exploitability, exposure)
- Compensating controls
- Attack surface size"""

    SYSTEM_PROMPT_STRATEGY = """You are the Reasoning Module of IRVES, generating analysis strategies.

Given current findings and what we know, suggest next steps:

{
  "strategy": {
    "current_state": "What we've learned so far",
    "gaps": ["What we don't know yet"],
    "recommended_actions": [
      {
        "action": "What to do next",
        "phase": "static|dynamic|network|exploit",
        "priority": "critical|high|medium|low",
        "rationale": "Why this matters",
        "expected_findings": "What we might discover"
      }
    ],
    "priority_order": ["action-id-1", "action-id-2"]
  }
}

Be strategic:
- Focus on high-value, achievable analysis
- Consider dependencies between phases
- Prioritize based on risk and likelihood
- Suggest specific tools and techniques"""

    def __init__(self, llm_client: Optional[LLMClient] = None, cost_tracker: Optional[CostTracker] = None):
        self.llm = llm_client or LLMClient()
        self.costs = cost_tracker or CostTracker()
        self.module = AIModule.REASONING

    async def analyze_attack_paths(
        self,
        findings: List[Dict[str, Any]],
        platform: str = "android",
        context: Optional[Dict[str, Any]] = None
    ) -> List[AttackPath]:
        """
        Analyze findings and construct attack paths.

        Args:
            findings: List of parsed findings
            platform: Target platform
            context: Additional context (app type, sensitivity, etc.)

        Returns:
            List of AttackPath objects
        """
        start_time = datetime.utcnow()

        prompt = self._build_attack_path_prompt(findings, platform, context)

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_ATTACK_PATH,
                user=prompt,
                temperature=0.3,
                max_tokens=4000,
            )

            result = self._extract_json(response)
            paths_data = result.get("attack_paths", [])

            attack_paths = []
            for path_data in paths_data:
                path = AttackPath(
                    path_id=path_data.get("path_id", "unknown"),
                    name=path_data.get("name", "Unnamed Path"),
                    description=path_data.get("description", ""),
                    steps=path_data.get("steps", []),
                    entry_point=path_data.get("entry_point", ""),
                    target_asset=path_data.get("target_asset", ""),
                    difficulty=path_data.get("difficulty", "medium"),
                    likelihood=float(path_data.get("likelihood", 0.5)),
                    impact=path_data.get("impact", "medium"),
                    prerequisites=path_data.get("prerequisites", []),
                    mitigations=path_data.get("mitigations", []),
                    tools_needed=path_data.get("tools_needed", []),
                )
                attack_paths.append(path)

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="analyze_attack_paths",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            logger.info(f"[ReasoningModule] Generated {len(attack_paths)} attack paths")
            return attack_paths

        except Exception as e:
            logger.error(f"[ReasoningModule] Attack path analysis failed: {e}")
            return []

    async def assess_risk(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Assess overall risk based on findings.

        Args:
            findings: List of parsed findings
            context: Business/technical context

        Returns:
            RiskAssessment object
        """
        start_time = datetime.utcnow()

        prompt = self._build_risk_prompt(findings, context)

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_RISK,
                user=prompt,
                temperature=0.2,
                max_tokens=2000,
            )

            result = self._extract_json(response)
            risk_data = result.get("risk_assessment", {})

            assessment = RiskAssessment(
                overall_risk=risk_data.get("overall_risk", "medium"),
                risk_score=float(risk_data.get("risk_score", 5.0)),
                likelihood=float(risk_data.get("likelihood", 0.5)),
                business_impact=risk_data.get("business_impact", ""),
                technical_impact=risk_data.get("technical_impact", ""),
                cvss_score=risk_data.get("cvss_score"),
                factors=risk_data.get("factors", []),
            )

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="assess_risk",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            return assessment

        except Exception as e:
            logger.error(f"[ReasoningModule] Risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk="unknown",
                risk_score=5.0,
                likelihood=0.5,
                business_impact="Assessment failed",
                technical_impact="Assessment failed",
            )

    async def generate_strategy(
        self,
        current_findings: List[Dict[str, Any]],
        completed_phases: List[str],
        platform: str = "android",
        goals: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate analysis strategy for what to do next.

        Args:
            current_findings: What we know so far
            completed_phases: Which phases are done
            platform: Target platform
            goals: Specific goals (e.g., ["find_api_keys", "check_ssl"])

        Returns:
            Strategy dict with recommended actions
        """
        start_time = datetime.utcnow()

        prompt = f"""Platform: {platform}
Completed Phases: {', '.join(completed_phases) if completed_phases else 'None'}
Goals: {', '.join(goals) if goals else 'Comprehensive security analysis'}

Current Findings ({len(current_findings)}):
{json.dumps(current_findings[:20], indent=2)}  # Limit to avoid token overflow

Generate analysis strategy."""

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_STRATEGY,
                user=prompt,
                temperature=0.4,
                max_tokens=3000,
            )

            result = self._extract_json(response)
            strategy = result.get("strategy", {})

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="generate_strategy",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            logger.info(f"[ReasoningModule] Generated strategy with {len(strategy.get('recommended_actions', []))} actions")
            return strategy

        except Exception as e:
            logger.error(f"[ReasoningModule] Strategy generation failed: {e}")
            return {
                "current_state": "Strategy generation failed",
                "gaps": ["Unknown"],
                "recommended_actions": [],
            }

    async def correlate_findings(
        self,
        static_findings: List[Dict[str, Any]],
        dynamic_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate static and dynamic findings to build complete picture.

        Args:
            static_findings: From code analysis
            dynamic_findings: From runtime analysis

        Returns:
            Correlation results with confirmed/invalidated findings
        """
        start_time = datetime.utcnow()

        prompt = f"""Correlate static and dynamic findings:

Static Findings ({len(static_findings)}):
{json.dumps(static_findings[:15], indent=2)}

Dynamic Findings ({len(dynamic_findings)}):
{json.dumps(dynamic_findings[:15], indent=2)}

Identify:
1. Confirmed issues (static + dynamic evidence)
2. Potential false positives (static flagged but not dynamic)
3. Runtime-only issues (dynamic found, static missed)
4. Exploit chains (findings that combine)

Output JSON with:
{{
  "confirmed": [{{"static_id": "...", "dynamic_id": "...", "confidence": "high"}}],
  "false_positives": [...],
  "runtime_only": [...],
  "attack_chains": [...]
}}"""

        try:
            response = await self.llm.complete(
                system="You are a security analyst correlating static and dynamic analysis results.",
                user=prompt,
                temperature=0.3,
                max_tokens=3000,
            )

            result = self._extract_json(response)

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="correlate_findings",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            return result

        except Exception as e:
            logger.error(f"[ReasoningModule] Correlation failed: {e}")
            return {"confirmed": [], "false_positives": [], "runtime_only": [], "attack_chains": []}

    def _build_attack_path_prompt(self, findings, platform, context) -> str:
        """Build prompt for attack path analysis."""
        ctx_str = json.dumps(context, indent=2) if context else "No additional context"

        return f"""Platform: {platform}
Context: {ctx_str}

Findings ({len(findings)}):
{json.dumps(findings[:20], indent=2)}

Construct attack paths showing how an attacker could exploit these vulnerabilities."""

    def _build_risk_prompt(self, findings, context) -> str:
        """Build prompt for risk assessment."""
        ctx_str = json.dumps(context, indent=2) if context else "No additional context"

        return f"""Context: {ctx_str}

Findings ({len(findings)}):
{json.dumps(findings[:20], indent=2)}

Assess the overall security risk."""

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from response."""
        import re

        # Try code blocks
        patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*(.*?)\s*```',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue

        # Try direct JSON
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start >= 0 and end > start:
                return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass

        return {}

    def get_stats(self) -> Dict[str, Any]:
        """Get reasoning module cost statistics."""
        return self.costs.get_stats(self.module)
