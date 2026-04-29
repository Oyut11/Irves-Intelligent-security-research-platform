"""
IRVES — LLM Provider Configuration & Streaming Core
Handles API key resolution, model selection, and streaming LLM calls.
"""

import asyncio
import logging
import os
from typing import AsyncIterator, Optional

from config import settings

logger = logging.getLogger(__name__)


def get_api_key() -> str:
    """
    Retrieve the configured API key from settings.
    Prioritizes the generic AI_API_KEY, then falls back to provider-specific keys.
    Also ensures the provider-specific OS env var is set for LiteLLM routing.
    """
    key = settings.AI_API_KEY
    if not key:
        provider = (settings.AI_PROVIDER or "").lower()
        if provider == "anthropic": key = settings.ANTHROPIC_API_KEY
        elif provider == "openai": key = settings.OPENAI_API_KEY
        elif provider == "gemini": key = settings.GEMINI_API_KEY or settings.GOOGLE_API_KEY
        elif provider == "xai": key = settings.XAI_API_KEY
        elif provider == "deepseek": key = settings.DEEPSEEK_API_KEY
        elif provider == "together": key = settings.TOGETHER_AI_API_KEY
        elif provider == "huggingface": key = settings.HUGGINGFACE_API_KEY

    # Ensure the provider-specific env var is set for LiteLLM's native routing
    _ENV_MAP = {
        "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY", "xai": "XAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY", "together": "TOGETHER_AI_API_KEY",
        "huggingface": "HUGGINGFACE_API_KEY",
    }
    provider = (settings.AI_PROVIDER or "").lower()
    if key and provider in _ENV_MAP:
        env_name = _ENV_MAP[provider]
        os.environ[env_name] = key

    local_signatures = ["ollama", "local", "vllm", "localhost", "127.0.0.1"]
    is_local = (settings.AI_PROVIDER in ["ollama", "local"]) or any(sig in settings.AI_MODEL.lower() for sig in local_signatures)
    has_custom_endpoint = bool(settings.AI_API_BASE)

    if not key and not is_local and not has_custom_endpoint:
        raise RuntimeError(
            f"IRVES Intelligence Engine: No API key found for provider '{settings.AI_PROVIDER}'. "
            "Configure it in the 'AI Reasoning Layer' settings or your .env file."
        )

    # Local servers often require a non-empty header even if it's dummy
    return key or "sk-local-researcher"


def is_local_provider() -> bool:
    """Check if the current provider is local (Ollama, vLLM, etc.)."""
    provider = (settings.AI_PROVIDER or "").lower()
    if provider in ("ollama", "local"):
        return True
    base = (settings.AI_API_BASE or "").lower()
    return any(sig in base for sig in ("localhost", "127.0.0.1", "11434"))


def get_model() -> str:
    """Get the full model string, auto-prefixing for LiteLLM routing."""
    model = settings.AI_MODEL
    provider = (settings.AI_PROVIDER or "").lower()

    # Known LiteLLM provider prefixes — if the model already starts with one, don't touch it
    _KNOWN_PREFIXES = (
        "anthropic/", "openai/", "gemini/", "xai/", "deepseek/",
        "together_ai/", "huggingface/", "vertex_ai/",
    )
    if any(model.startswith(p) for p in _KNOWN_PREFIXES):
        return model

    # Strip stale ollama/ prefix — we now route Ollama through openai/ compat
    if model.startswith("ollama/"):
        model = model[len("ollama/"):]

    # Provider → LiteLLM prefix mapping
    # Always prefix — LiteLLM needs explicit routing for non-standard model names
    _PREFIX_MAP = {
        "anthropic":   "anthropic",
        "openai":      "openai",
        "gemini":      "gemini",
        "xai":         "xai",
        "deepseek":    "deepseek",
        "together":    "together_ai",
        "huggingface": "huggingface",
    }

    prefix = _PREFIX_MAP.get(provider)
    if prefix:
        return f"{prefix}/{model}"

    # Ollama → use OpenAI-compatible endpoint (LiteLLM's native ollama/
    # handler has timeout bugs with httpx). Route as openai/ and override
    # api_base to point at Ollama's /v1 endpoint.
    if provider == "ollama" or "11434" in (settings.AI_API_BASE or ""):
        return f"openai/{model}"

    # Local AI (OpenAI-compatible endpoint)
    if settings.AI_API_BASE or provider == "local":
        return f"openai/{model}"

    return model


def resolve_api_base() -> Optional[str]:
    """Resolve the correct api_base, handling Ollama's /v1 compat endpoint."""
    provider = (settings.AI_PROVIDER or "").lower()
    base = settings.AI_API_BASE or ""

    if provider == "ollama" or "11434" in base:
        # Ensure base points to Ollama's OpenAI-compatible /v1 endpoint
        raw = base or "http://localhost:11434"
        raw = raw.rstrip("/")
        if not raw.endswith("/v1"):
            raw += "/v1"
        return raw

    return base if base else None


async def stream_llm(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.7,
) -> AsyncIterator[str]:
    """Base streaming function wrapping LiteLLM stream generation.

    Designed for broad compatibility with ANY local model (Ollama, vLLM,
    LM Studio, etc.) as well as all cloud providers.
    """
    queue: asyncio.Queue[Optional[str]] = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def _stream():
        from litellm import completion

        # CRITICAL: Prevent local IRVES proxy from intercepting AI traffic
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        os.environ["http_proxy"] = ""
        os.environ["https_proxy"] = ""

        model = get_model()
        api_base = resolve_api_base()
        api_key = get_api_key()
        _is_local = is_local_provider()

        # Local models need much longer timeouts (cold-start, reasoning)
        timeout = 300 if _is_local else 120

        logger.info(f"[IIE] Streaming LLM: model={model} | base={api_base or 'default'} | local={_is_local} | timeout={timeout}s")

        # Build messages — some small models choke on very long system
        # prompts.  Truncate to a safe ceiling so they don't OOM / error.
        _MAX_SYS = 6000 if _is_local else 16000
        _sys = system_prompt[:_MAX_SYS] if len(system_prompt) > _MAX_SYS else system_prompt
        _MAX_USR = 8000 if _is_local else 32000
        _usr = user_prompt[:_MAX_USR] if len(user_prompt) > _MAX_USR else user_prompt
        messages = [
            {"role": "system", "content": _sys},
            {"role": "user", "content": _usr},
        ]

        def _do_completion(temp):
            """Inner helper so we can retry without temperature."""
            kwargs = dict(
                model=model,
                api_key=api_key,
                api_base=api_base,
                messages=messages,
                stream=True,
                timeout=timeout,
            )
            if temp is not None:
                kwargs["temperature"] = temp
            return completion(**kwargs)

        def _iter_chunks(response):
            """Safely iterate chunks — tolerant of varied delta formats."""
            for chunk in response:
                try:
                    choices = getattr(chunk, "choices", None) or []
                    if not choices:
                        continue
                    delta = getattr(choices[0], "delta", None)
                    if not delta:
                        continue
                    # Regular content (most models)
                    content = getattr(delta, "content", None)
                    if content:
                        loop.call_soon_threadsafe(queue.put_nowait, content)
                    # Reasoning models (deepseek-r1, qwq, marco-o1, etc.)
                    reasoning = getattr(delta, "reasoning_content", None)
                    if reasoning and not content:
                        loop.call_soon_threadsafe(queue.put_nowait, reasoning)
                except (IndexError, AttributeError, TypeError):
                    continue

        try:
            response = _do_completion(temperature)
            _iter_chunks(response)
        except Exception as e:
            active_exc = e
            err_str = str(e).lower()
            # ── Retry: some models reject the temperature param ────────
            if "temperature" in err_str or "unsupported" in err_str:
                logger.warning("[IIE] Model rejected temperature param, retrying without it")
                try:
                    response = _do_completion(None)
                    _iter_chunks(response)
                    return  # success on retry
                except Exception as e2:
                    active_exc = e2
                    err_str = str(e2).lower()
                    # fall through to error reporting below

            raw = str(active_exc)
            logger.error(f"[IIE] LiteLLM Stream error for {model}: {raw[:500]}")

            # ── User-friendly error messages ───────────────────────────
            if "timed out" in err_str or "timeout" in err_str:
                if _is_local:
                    friendly = (f"[Error: Local model timed out ({timeout}s). "
                                "The model may be loading into memory. Try again in 30s, "
                                "or switch to a smaller model.]")
                else:
                    friendly = f"[Error: Request timed out after {timeout}s. Check API key and network.]"
            elif "connection" in err_str or "refused" in err_str:
                if _is_local:
                    friendly = ("[Error: Cannot connect to local model server. "
                                "Make sure Ollama is running: `ollama serve`]")
                else:
                    friendly = f"[Error: Connection failed — {raw[:200]}]"
            elif "not found" in err_str or "does not exist" in err_str or "404" in err_str:
                friendly = (f"[Error: Model '{settings.AI_MODEL}' not found. "
                            "Make sure it is pulled: `ollama pull {}`]".format(settings.AI_MODEL))
            elif "context length" in err_str or "too long" in err_str or "maximum" in err_str:
                friendly = ("[Error: Input too long for this model's context window. "
                            "Try a shorter message or switch to a model with larger context.]")
            elif "rate" in err_str and "limit" in err_str:
                friendly = "[Error: Rate limit exceeded. Wait a moment and try again.]"
            else:
                friendly = f"[Error: {raw[:300]}]"

            loop.call_soon_threadsafe(queue.put_nowait, friendly)
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    loop.run_in_executor(None, _stream)

    while True:
        chunk = await queue.get()
        if chunk is None:
            break
        yield chunk
