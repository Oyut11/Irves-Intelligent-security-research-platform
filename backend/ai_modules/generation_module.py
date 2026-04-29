"""
IRVES — Generation Module (Three-Module AI)
Generates remediation code, Frida scripts, reports, and fix guidance.

Responsibilities:
- Generate secure code fixes
- Create Frida scripts for dynamic analysis
- Write vulnerability reports
- Produce executive summaries
- Generate test cases
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
class GeneratedFix:
    """A generated code fix with metadata."""
    finding_id: str
    language: str
    original_code: str
    fixed_code: str
    explanation: str
    testing_notes: str
    confidence: str  # high, medium, low


@dataclass
class GeneratedScript:
    """A generated Frida or other script."""
    script_id: str
    name: str
    target: str  # function, class, or API to hook
    script_type: str  # frida, objection, custom
    code: str
    description: str
    usage_instructions: str
    expected_output: str


class GenerationModule:
    """
    Generation Module for creating remediation and analysis artifacts.

    Generates:
    - Secure code fixes
    - Frida hook scripts
    - PoC exploit code
    - Analysis reports
    - Test cases
    """

    SYSTEM_PROMPT_FIX = """You are the Generation Module of IRVES, creating secure code fixes.

Given a vulnerability finding, generate:
1. Fixed code that remediates the issue
2. Explanation of the fix
3. Testing notes

Output format:
{
  "fix": {
    "language": "java|swift|kotlin|javascript|python|etc",
    "original_code": "The vulnerable code (if known)",
    "fixed_code": "The corrected, secure implementation",
    "explanation": "Why this fixes the vulnerability",
    "testing_notes": "How to verify the fix works",
    "confidence": "high|medium|low"
  }
}

Guidelines:
- Follow language-specific security best practices
- Keep fixes minimal and focused
- Include proper error handling
- Add relevant comments explaining security considerations
- Consider performance impact"""

    SYSTEM_PROMPT_FRIDA = """You are the Generation Module of IRVES, creating Frida scripts.

Generate Frida scripts for dynamic analysis:

Output format:
{
  "script": {
    "name": "Descriptive script name",
    "target": "Class/method to hook",
    "script_type": "frida",
    "code": "Complete Frida JavaScript code",
    "description": "What this script does",
    "usage_instructions": "How to run: frida -U -f com.app -l script.js",
    "expected_output": "What user will see when running"
  }
}

Frida coding standards:
- Use Java.perform() wrapper
- Handle errors gracefully
- Log with console.log()
- Return useful data
- Include helpful comments"""

    SYSTEM_PROMPT_REPORT = """You are the Generation Module of IRVES, creating security reports.

Generate professional vulnerability reports:

Output format:
{
  "report": {
    "title": "Report title",
    "executive_summary": "Brief overview for leadership",
    "technical_summary": "Technical details for engineers",
    "findings": [
      {
        "title": "Finding title",
        "severity": "critical|high|medium|low",
        "description": "Detailed description",
        "impact": "Business/technical impact",
        "recommendation": "How to fix",
        "references": ["CVE", "CWE", "URL"]
      }
    ],
    "remediation_priority": ["Finding to fix first", "Second priority"],
    "appendix": "Additional technical details"
  }
}

Write for the audience:
- Executive summary: Non-technical, business-focused
- Technical details: Specific, actionable for developers"""

    def __init__(self, llm_client: Optional[LLMClient] = None, cost_tracker: Optional[CostTracker] = None):
        self.llm = llm_client or LLMClient()
        self.costs = cost_tracker or CostTracker()
        self.module = AIModule.GENERATION

    async def generate_fix(
        self,
        finding: Dict[str, Any],
        language: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[GeneratedFix]:
        """
        Generate a secure code fix for a finding.

        Args:
            finding: The vulnerability finding
            language: Programming language (auto-detected if not specified)
            context: Additional code context

        Returns:
            GeneratedFix object or None
        """
        start_time = datetime.utcnow()

        lang = language or finding.get("language", "unknown")
        prompt = f"""Language: {lang}
Finding: {json.dumps(finding, indent=2)}
Context: {json.dumps(context, indent=2) if context else 'None'}

Generate a secure fix for this vulnerability."""

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_FIX,
                user=prompt,
                temperature=0.2,
                max_tokens=3000,
            )

            result = self._extract_json(response)
            fix_data = result.get("fix", {})

            fix = GeneratedFix(
                finding_id=finding.get("id", "unknown"),
                language=fix_data.get("language", lang),
                original_code=fix_data.get("original_code", ""),
                fixed_code=fix_data.get("fixed_code", ""),
                explanation=fix_data.get("explanation", ""),
                testing_notes=fix_data.get("testing_notes", ""),
                confidence=fix_data.get("confidence", "medium"),
            )

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="generate_fix",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            logger.info(f"[GenerationModule] Generated fix for {finding.get('title', 'unknown')}")
            return fix

        except Exception as e:
            logger.error(f"[GenerationModule] Fix generation failed: {e}")
            return None

    async def generate_frida_script(
        self,
        target: str,
        purpose: str,
        platform: str = "android",
        additional_context: Optional[str] = None
    ) -> Optional[GeneratedScript]:
        """
        Generate a Frida script for dynamic analysis.

        Args:
            target: Function/class to hook (e.g., "com.app.CryptoUtils.encrypt")
            purpose: What to achieve (e.g., "Extract encryption keys")
            platform: android or ios
            additional_context: Any additional information

        Returns:
            GeneratedScript object or None
        """
        start_time = datetime.utcnow()

        prompt = f"""Platform: {platform}
Target: {target}
Purpose: {purpose}
Additional Context: {additional_context or 'None'}

Generate a complete Frida script."""

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_FRIDA,
                user=prompt,
                temperature=0.3,
                max_tokens=2500,
            )

            result = self._extract_json(response)
            script_data = result.get("script", {})

            script = GeneratedScript(
                script_id=f"frida_{target.replace('.', '_')}_{int(start_time.timestamp())}",
                name=script_data.get("name", f"Hook {target}"),
                target=target,
                script_type=script_data.get("script_type", "frida"),
                code=script_data.get("code", ""),
                description=script_data.get("description", ""),
                usage_instructions=script_data.get("usage_instructions", f"frida -U -f com.app -l script.js"),
                expected_output=script_data.get("expected_output", ""),
            )

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="generate_frida_script",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            logger.info(f"[GenerationModule] Generated Frida script for {target}")
            return script

        except Exception as e:
            logger.error(f"[GenerationModule] Script generation failed: {e}")
            return None

    async def generate_report(
        self,
        findings: List[Dict[str, Any]],
        title: str,
        report_type: str = "technical",  # technical, executive, compliance
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a security analysis report.

        Args:
            findings: List of findings to include
            title: Report title
            report_type: Type of report
            metadata: Additional metadata (app name, version, etc.)

        Returns:
            Report structure as dict
        """
        start_time = datetime.utcnow()

        prompt = f"""Report Type: {report_type}
Title: {title}
Metadata: {json.dumps(metadata, indent=2) if metadata else 'None'}

Findings ({len(findings)}):
{json.dumps(findings[:30], indent=2)}

Generate a complete security report."""

        try:
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT_REPORT,
                user=prompt,
                temperature=0.4,
                max_tokens=4000,
            )

            result = self._extract_json(response)
            report = result.get("report", {})

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation=f"generate_{report_type}_report",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            logger.info(f"[GenerationModule] Generated {report_type} report: {title}")
            return report

        except Exception as e:
            logger.error(f"[GenerationModule] Report generation failed: {e}")
            return {"title": title, "error": str(e)}

    async def generate_poc(
        self,
        finding: Dict[str, Any],
        platform: str = "android"
    ) -> Optional[str]:
        """
        Generate a Proof-of-Concept exploit script.

        Args:
            finding: Vulnerability to exploit
            platform: Target platform

        Returns:
            PoC code as string or None
        """
        start_time = datetime.utcnow()

        prompt = f"""Platform: {platform}
Finding: {json.dumps(finding, indent=2)}

Generate a Proof-of-Concept script that demonstrates this vulnerability.
Include:
1. Prerequisites
2. Step-by-step exploitation
3. Expected outcome
4. Safety warnings

Output the complete PoC code."""

        try:
            response = await self.llm.complete(
                system="You are a security researcher creating educational PoC exploits. "
                       "Include safety warnings and only generate PoCs for educational/defensive purposes.",
                user=prompt,
                temperature=0.4,
                max_tokens=3000,
            )

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="generate_poc",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            return response

        except Exception as e:
            logger.error(f"[GenerationModule] PoC generation failed: {e}")
            return None

    async def generate_test_case(
        self,
        finding: Dict[str, Any]
    ) -> Optional[str]:
        """
        Generate a test case to verify a finding is fixed.

        Args:
            finding: The finding to test

        Returns:
            Test code as string or None
        """
        start_time = datetime.utcnow()

        prompt = f"""Finding: {json.dumps(finding, indent=2)}

Generate a test case that:
1. Verifies the vulnerability exists (before fix)
2. Confirms it's fixed (after fix)

Output complete test code with assertions."""

        try:
            response = await self.llm.complete(
                system="Generate automated test cases for security verification.",
                user=prompt,
                temperature=0.3,
                max_tokens=2000,
            )

            # Record cost
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            cost = ModuleCost(
                module=self.module,
                operation="generate_test_case",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
            )
            self.costs.record(cost)

            return response

        except Exception as e:
            logger.error(f"[GenerationModule] Test case generation failed: {e}")
            return None

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from response."""
        import re

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

        try:
            start = text.find('{')
            end = text.rfind('}')
            if start >= 0 and end > start:
                return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass

        return {}

    def get_stats(self) -> Dict[str, Any]:
        """Get generation module cost statistics."""
        return self.costs.get_stats(self.module)
