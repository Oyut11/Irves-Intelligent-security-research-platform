"""
IRVES — LLM Client
Unified interface for multiple AI providers (OpenAI, Anthropic, Google).
"""

import json
import logging
from typing import AsyncIterator, Optional, Dict, Any
from dataclasses import dataclass

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: Optional[str] = None


class LLMClient:
    """
    Unified LLM client supporting multiple providers.

    Currently supports:
    - OpenAI (GPT-4o, GPT-4o-mini)
    - Anthropic (Claude 3.5 Sonnet, Claude 3 Haiku)
    - Google (Gemini 1.5 Flash, Gemini 1.5 Pro)
    """

    def __init__(self, model: Optional[str] = None, provider: Optional[str] = None):
        self.model = model or settings.AI_MODEL or "gpt-4o-mini"
        self.provider = provider or self._detect_provider(self.model)
        self.api_key = self._get_api_key()
        self.api_base = self._get_api_base()

    def _detect_provider(self, model: str) -> str:
        """Detect provider from model name."""
        model_lower = model.lower()
        if "claude" in model_lower:
            return "anthropic"
        elif "gemini" in model_lower:
            return "google"
        else:
            return "openai"

    def _get_api_key(self) -> str:
        """Get API key for current provider."""
        if self.provider == "anthropic":
            return settings.ANTHROPIC_API_KEY or settings.AI_API_KEY or ""
        elif self.provider == "google":
            return settings.GOOGLE_API_KEY or settings.AI_API_KEY or ""
        else:
            return settings.OPENAI_API_KEY or settings.AI_API_KEY or ""

    def _get_api_base(self) -> Optional[str]:
        """Get API base URL if custom."""
        if self.provider == "openai":
            return settings.AI_API_BASE
        return None

    async def complete(
        self,
        system: str,
        user: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> str:
        """
        Complete a prompt with the LLM.

        Returns:
            Response content as string
        """
        if self.provider == "anthropic":
            return await self._complete_anthropic(system, user, temperature, max_tokens)
        elif self.provider == "google":
            return await self._complete_google(system, user, temperature, max_tokens)
        else:
            return await self._complete_openai(system, user, temperature, max_tokens)

    async def complete_stream(
        self,
        system: str,
        user: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> AsyncIterator[str]:
        """
        Stream completion from LLM.

        Yields:
            Text chunks as they're generated
        """
        if self.provider == "anthropic":
            async for chunk in self._stream_anthropic(system, user, temperature, max_tokens):
                yield chunk
        elif self.provider == "google":
            async for chunk in self._stream_google(system, user, temperature, max_tokens):
                yield chunk
        else:
            async for chunk in self._stream_openai(system, user, temperature, max_tokens):
                yield chunk

    async def _complete_openai(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Complete using OpenAI API."""
        try:
            import openai

            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.api_base,
            )

            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return response.choices[0].message.content or ""

        except Exception as e:
            logger.error(f"[LLMClient] OpenAI error: {e}")
            raise

    async def _stream_openai(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream using OpenAI API."""
        try:
            import openai

            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.api_base,
            )

            stream = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )

            async for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    yield content

        except Exception as e:
            logger.error(f"[LLMClient] OpenAI stream error: {e}")
            raise

    async def _complete_anthropic(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Complete using Anthropic API."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(api_key=self.api_key)

            response = await client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )

            return response.content[0].text if response.content else ""

        except Exception as e:
            logger.error(f"[LLMClient] Anthropic error: {e}")
            raise

    async def _stream_anthropic(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream using Anthropic API."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(api_key=self.api_key)

            async with client.messages.stream(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            logger.error(f"[LLMClient] Anthropic stream error: {e}")
            raise

    async def _complete_google(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Complete using Google Gemini API."""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)

            model = genai.GenerativeModel(self.model)

            # Combine system and user for Gemini
            full_prompt = f"{system}\n\n{user}"

            response = await model.generate_content_async(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )

            return response.text or ""

        except Exception as e:
            logger.error(f"[LLMClient] Google error: {e}")
            raise

    async def _stream_google(
        self,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream using Google Gemini API."""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)

            model = genai.GenerativeModel(self.model)

            full_prompt = f"{system}\n\n{user}"

            response = await model.generate_content_async(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
                stream=True,
            )

            async for chunk in response:
                if chunk.text:
                    yield chunk.text

        except Exception as e:
            logger.error(f"[LLMClient] Google stream error: {e}")
            raise

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation (1 token ≈ 4 chars for English)."""
        return len(text) // 4
