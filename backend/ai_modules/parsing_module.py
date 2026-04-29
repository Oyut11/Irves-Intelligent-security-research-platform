"""
IRVES — Parsing Module (Three-Module AI)
Converts raw tool output into structured, AI-enriched findings.

Responsibilities:
- Parse apk_analyzer, ios_analyzer, Frida, Semgrep, GitLeaks output
- Extract structured findings with context
- Normalize severity and categories
- Generate condensed summaries for downstream modules
"""

import json
import logging
from typing import AsyncIterator, Dict, Any, List, Optional
from datetime import datetime

from ai_modules.cost_tracker import CostTracker, ModuleCost, AIModule
from ai_modules.llm_client import LLMClient

logger = logging.getLogger(__name__)


class ParsingModule:
    """
    Parsing Module for tool output analysis.

    Takes raw tool output and produces structured findings with:
    - Normalized severity (critical/high/medium/low/info)
    - OWASP/MSTG mapping
    - CWE classification
    - Evidence extraction
    - Context-aware descriptions
    """

    SYSTEM_PROMPT = """You are the Parsing Module of IRVES, a security analysis system.
Your job is to parse raw tool output and extract structured findings.

Input: Raw output from security tools (apk_analyzer, ios_analyzer, Frida, Semgrep, GitLeaks, etc.)
Output: Structured JSON with findings

For each finding, extract:
{
  "findings": [
    {
      "title": "Brief, specific title",
      "description": "Clear explanation of the vulnerability",
      "severity": "critical|high|medium|low|info",
      "category": "OWASP category (e.g., M1: Improper Platform Usage)",
      "cwe": "CWE-ID if identifiable",
      "location": "File path or memory address",
      "line_number": number or null,
      "evidence": "Code snippet, log line, or data extract",
      "confidence": "high|medium|low",
      "tool_source": "Name of the tool that found this",
      "recommendation": "Brief fix suggestion"
    }
  ],
  "summary": "Overall summary of findings",
  "tool_info": {
    "name": "Tool name",
    "version": "Version if available",
    "scan_time": "Duration if available"
  }
}

Rules:
1. Always normalize severity: critical (exploitable, data loss), high (security risk), medium (potential issue), low (informational)
2. Map to OWASP MASVS/MSTG categories where possible
3. Include actual code snippets in evidence field
4. If no findings, return empty findings array with summary
5. Never invent findings - only report what's in the input
6. Condense verbose output into concise, actionable findings"""

    def __init__(self, llm_client: Optional[LLMClient] = None, cost_tracker: Optional[CostTracker] = None):
        self.llm = llm_client or LLMClient()
        self.costs = cost_tracker or CostTracker()
        self.module = AIModule.PARSING

    async def parse_output(
        self,
        tool_name: str,
        raw_output: str,
        output_format: str = "auto",  # auto, json, xml, text
        platform: str = "android"
    ) -> Dict[str, Any]:
        """
        Parse raw tool output into structured findings.

        Args:
            tool_name: Name of the tool (apk_analyzer, ios_analyzer, frida, semgrep, gitleaks, etc.)
            raw_output: Raw output from the tool
            output_format: Format hint for the parser
            platform: Target platform (android, ios, repository)

        Returns:
            Structured findings with metadata
        """
        start_time = datetime.utcnow()

        # Build user prompt
        prompt = f"""Tool: {tool_name}
Platform: {platform}
Output Format: {output_format}

Raw Tool Output:
```
{raw_output[:8000]}  # Limit to avoid token overflow
```

Parse this output and extract all security findings."""

        try:
            # Call LLM
            response = await self.llm.complete(
                system=self.SYSTEM_PROMPT,
                user=prompt,
                temperature=0.1,  # Low temp for consistent parsing
                max_tokens=4000,
            )

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Parse response
            try:
                result = json.loads(response)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown
                result = self._extract_json_from_markdown(response)

            # Record cost
            cost = ModuleCost(
                module=self.module,
                operation=f"parse_{tool_name}",
                model=self.llm.model,
                input_tokens=self.llm.estimate_tokens(prompt),
                output_tokens=self.llm.estimate_tokens(response),
                duration_ms=duration_ms,
                success=True,
            )
            self.costs.record(cost)

            logger.info(f"[ParsingModule] Parsed {tool_name}: {len(result.get('findings', []))} findings")
            return result

        except Exception as e:
            logger.error(f"[ParsingModule] Failed to parse {tool_name}: {e}")

            # Record failed cost
            cost = ModuleCost(
                module=self.module,
                operation=f"parse_{tool_name}",
                model=self.llm.model,
                success=False,
                error_message=str(e),
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
            )
            self.costs.record(cost)

            # Return empty but valid structure
            return {
                "findings": [],
                "summary": f"Parsing failed: {str(e)}",
                "tool_info": {"name": tool_name, "error": str(e)},
            }

    async def parse_stream(
        self,
        tool_name: str,
        raw_output: str,
        output_format: str = "auto",
        platform: str = "android"
    ) -> AsyncIterator[str]:
        """
        Stream parsing results as they're generated.

        Yields JSON chunks as parsing progresses.
        """
        start_time = datetime.utcnow()

        prompt = f"""Tool: {tool_name}
Platform: {platform}

Raw Output:
```
{raw_output[:8000]}
```

Parse and extract findings. Stream JSON response."""

        full_response = ""
        async for chunk in self.llm.complete_stream(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            temperature=0.1,
        ):
            full_response += chunk
            yield chunk

        # Record cost after streaming
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        cost = ModuleCost(
            module=self.module,
            operation=f"parse_{tool_name}_stream",
            model=self.llm.model,
            input_tokens=self.llm.estimate_tokens(prompt),
            output_tokens=self.llm.estimate_tokens(full_response),
            duration_ms=duration_ms,
        )
        self.costs.record(cost)

    def _extract_json_from_markdown(self, text: str) -> Dict[str, Any]:
        """Extract JSON from markdown code blocks or plain text."""
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

        # Try to find JSON object directly
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start >= 0 and end > start:
                return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass

        # Fallback
        return {
            "findings": [],
            "summary": "Could not parse output",
            "raw_response": text[:1000],
        }

    async def batch_parse(
        self,
        tool_outputs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Parse multiple tool outputs in parallel.

        Args:
            tool_outputs: List of dicts with tool_name, raw_output, platform

        Returns:
            List of parsed results
        """
        import asyncio

        tasks = [
            self.parse_output(
                t["tool_name"],
                t["raw_output"],
                t.get("output_format", "auto"),
                t.get("platform", "android")
            )
            for t in tool_outputs
        ]

        return await asyncio.gather(*tasks, return_exceptions=True)

    def get_stats(self) -> Dict[str, Any]:
        """Get parsing module cost statistics."""
        return self.costs.get_stats(self.module)
