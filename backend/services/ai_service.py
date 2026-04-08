"""
IRVES — AI Analysis Service (Phase 6)
Claude-powered per-finding vulnerability explanations and contextual chat.
"""

import asyncio
import json
import logging
from typing import AsyncIterator, Optional

from config import settings

logger = logging.getLogger(__name__)

_ANALYSIS_SYSTEM = (
    "You are a senior mobile/application security researcher. "
    "You specialise in Android, iOS, and web vulnerability analysis. "
    "Be precise, technical, and actionable. Never hallucinate CVE numbers."
)

_ANALYSIS_PROMPT = """\
Analyse the following security finding and return a structured JSON response.

**Finding**
- Title      : {title}
- Severity   : {severity}
- Tool       : {tool}
- Category   : {category}
- Location   : {location}
- OWASP      : {owasp}
- CWE        : {cwe}
- Description: {description}

**Code Snippet**
```
{code_snippet}
```

Respond with ONLY valid JSON in this exact schema:
{{
  "explanation": "Plain-language explanation of the vulnerability",
  "impact": "What an attacker can achieve by exploiting this",
  "attack_path": ["Step 1", "Step 2", "Step 3"],
  "fix": "Specific, actionable remediation guidance with code example if relevant",
  "references": ["URL or standard reference 1", "URL 2"]
}}
"""

_CHAT_SYSTEM = (
    "You are a security assistant helping a developer understand a specific vulnerability "
    "in their application. Reference the finding context when answering."
)


class AIService:
    """Provides AI-powered analysis using Claude."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            from anthropic import Anthropic
            if not settings.ANTHROPIC_API_KEY:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is not configured. "
                    "Set it in your .env file to enable AI analysis."
                )
            self._client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        return self._client

    async def analyze_finding(self, finding: dict) -> dict:
        """
        Generate structured AI analysis for a finding.
        Returns explanation, attack path, fix guidance and references.
        """
        prompt = _ANALYSIS_PROMPT.format(
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
            client = self._get_client()
            response = client.messages.create(
                model=settings.AI_MODEL,
                max_tokens=1500,
                system=_ANALYSIS_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text

        raw = await asyncio.get_event_loop().run_in_executor(None, _call)

        # Extract JSON from response (model may wrap it in markdown)
        try:
            # Try to extract JSON block first
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0].strip()
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0].strip()
            return json.loads(raw)
        except json.JSONDecodeError:
            # Fall back to raw text if JSON parse fails
            return {
                "explanation": raw,
                "impact": "",
                "attack_path": [],
                "fix": "",
                "references": [],
            }

    async def chat(self, question: str, context: dict) -> str:
        """
        Answer a contextual question about a finding.
        Returns a plain-text response.
        """
        context_str = json.dumps(context, indent=2)
        user_msg = f"**Finding Context:**\n```json\n{context_str}\n```\n\n**Question:** {question}"

        def _call():
            client = self._get_client()
            response = client.messages.create(
                model=settings.AI_MODEL,
                max_tokens=800,
                system=_CHAT_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
            )
            return response.content[0].text

        return await asyncio.get_event_loop().run_in_executor(None, _call)

    async def stream_analysis(self, finding: dict) -> AsyncIterator[str]:
        """
        Stream AI analysis tokens as they arrive (SSE-compatible).
        Yields raw text chunks.
        """
        prompt = _ANALYSIS_PROMPT.format(
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

        client = self._get_client()
        queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

        def _stream():
            with client.messages.stream(
                model=settings.AI_MODEL,
                max_tokens=1500,
                system=_ANALYSIS_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                for text in stream.text_stream:
                    asyncio.get_event_loop().call_soon_threadsafe(queue.put_nowait, text)
            asyncio.get_event_loop().call_soon_threadsafe(queue.put_nowait, None)

        asyncio.get_event_loop().run_in_executor(None, _stream)

        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

    async def stream_chat(self, question: str, context: dict) -> AsyncIterator[str]:
        """
        Stream a contextual chat response about a finding, token-by-token.
        Yields raw text chunks compatible with SSE.
        """
        context_str = json.dumps(context, indent=2)
        user_msg = f"**Finding Context:**\n```json\n{context_str}\n```\n\n**Question:** {question}"

        client = self._get_client()
        queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

        def _stream():
            with client.messages.stream(
                model=settings.AI_MODEL,
                max_tokens=800,
                system=_CHAT_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
            ) as stream:
                for text in stream.text_stream:
                    asyncio.get_event_loop().call_soon_threadsafe(queue.put_nowait, text)
            asyncio.get_event_loop().call_soon_threadsafe(queue.put_nowait, None)

        asyncio.get_event_loop().run_in_executor(None, _stream)

        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk


# Global singleton
ai_service = AIService()
