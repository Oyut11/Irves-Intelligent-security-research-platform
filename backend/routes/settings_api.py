"""
IRVES — Settings Route (Phase 8)
Tool health checks, ADB device management, and settings persistence.
"""

import asyncio
import json
import shutil
import logging
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import settings

from services.settings_service import settings_service

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Pydantic models ───────────────────────────────────────────────────────────

class SettingsPayload(BaseModel):
    ai: Optional[dict] = None
    device: Optional[dict] = None
    scan: Optional[dict] = None
    integrations: Optional[dict] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_tool_version(executable: str) -> Optional[str]:

    """Probe a tool binary for its version string."""
    version_flags = {
        "apktool": ["--version"],
        "jadx": ["--version"],
        "frida": ["--version"],
        "mitmproxy": ["--version"],
        "mitmdump": ["--version"],
        "adb": ["version"],
    }
    flags = version_flags.get(executable, ["--version"])
    try:
        proc = await asyncio.create_subprocess_exec(
            executable, *flags,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8.0)
        raw = (stdout or stderr or b"").decode(errors="replace").strip()
        return raw.splitlines()[0] if raw else "unknown"
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return None


async def _check_adb_devices(adb_path: str = "adb") -> list[dict]:
    """List connected ADB devices."""
    try:
        proc = await asyncio.create_subprocess_exec(
            adb_path, "devices", "-l",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        lines = stdout.decode(errors="replace").splitlines()
        devices = []
        for line in lines[1:]:
            line = line.strip()
            if not line or "offline" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("device", "emulator"):
                devices.append({
                    "serial": parts[0],
                    "state": parts[1],
                    "model": next((p.split(":")[1] for p in parts if p.startswith("model:")), parts[0]),
                    "transport": "usb" if not parts[0].startswith("emulator") else "emulator",
                })
        return devices
    except (FileNotFoundError, asyncio.TimeoutError, OSError) as e:
        logger.warning(f"ADB check failed: {e}")
        return []


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/tools/status")
async def get_tools_status():
    """
    Check the installation status of all required security tools.
    Returns installed state, path, version, and any error for each tool.
    """
    cli_tools = ["apktool", "jadx", "frida", "mitmproxy"]

    # Run all checks concurrently
    async def _check_cli(name: str) -> dict:
        path = shutil.which(name)
        version = await _get_tool_version(name) if path else None
        return {
            "name": name,
            "installed": path is not None,
            "path": path,
            "version": version,
            "error": None if path else f"{name} not found in PATH",
        }

    tools = list(await asyncio.gather(*[_check_cli(t) for t in cli_tools]))

    # Summary
    installed_count = sum(1 for t in tools if t.get("installed"))
    return {
        "tools": tools,
        "summary": {
            "total": len(tools),
            "installed": installed_count,
            "missing": len(tools) - installed_count,
        },
    }


@router.get("/tools/{tool_name}/version")
async def get_tool_version(tool_name: str):
    """Get the version string for a specific tool."""
    allowed = {"apktool", "jadx", "frida", "mitmproxy", "mitmdump", "adb"}
    if tool_name not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown tool: {tool_name}")
    version = await _get_tool_version(tool_name)
    path = shutil.which(tool_name)
    return {"name": tool_name, "version": version, "path": path, "installed": path is not None}


@router.get("/devices")
async def list_adb_devices():
    """
    List all devices connected via ADB (USB + emulators).
    Useful for selecting a runtime target for Frida.
    """
    stored = settings_service.load()
    adb_path = stored.get("device", {}).get("adb_path", "adb") or "adb"
    devices = await _check_adb_devices(adb_path)
    return {"devices": devices, "count": len(devices)}


@router.post("/devices/refresh")
async def refresh_adb_devices():
    """Re-run adb kill-server && adb start-server, then return device list."""
    stored = settings_service.load()
    adb_path = stored.get("device", {}).get("adb_path", "adb") or "adb"

    async def _restart():
        try:
            for subcmd in [["kill-server"], ["start-server"]]:
                proc = await asyncio.create_subprocess_exec(
                    adb_path, *subcmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10.0)
        except Exception as e:
            logger.warning(f"ADB restart error: {e}")

    await _restart()
    devices = await _check_adb_devices(adb_path)
    return {"devices": devices, "count": len(devices)}


@router.post("/devices/{device_id}/deploy-frida")
async def deploy_frida(device_id: str):
    """Automatically resolve architecture and push/start frida-server to an Android device."""
    from services.frida_service import FridaService
    service = FridaService()
    try:
        msg = await service.deploy_server(device_id)
        return {"status": "success", "message": msg}
    except Exception as e:
        logger.error(f"Failed to deploy frida: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/settings")
async def get_settings():
    """Retrieve all persisted settings (API keys are masked)."""
    data = settings_service.load()
    # Mask secrets
    if data.get("ai", {}).get("api_key"):
        key = data["ai"]["api_key"]
        data["ai"]["api_key"] = key[:6] + "…" + key[-4:] if len(key) > 12 else "***"
    # Mask integrations
    integrations = data.get("integrations", {})
    for provider in ["github", "gitlab"]:
        if integrations.get(provider, {}).get("access_token"):
            token = integrations[provider]["access_token"]
            integrations[provider]["access_token"] = token[:4] + "…" + token[-4:] if len(token) > 10 else "***"
            
    return data


@router.post("/settings")
async def save_settings(payload: SettingsPayload):
    """
    Persist settings to disk (~/.irves/settings.json).
    Partial updates are supported — only provided sections are overwritten.
    """
    current = settings_service.load()

    if payload.ai is not None:
        # Never overwrite key with masked placeholder
        new_key = payload.ai.get("api_key", "")
        if new_key and "…" not in new_key and new_key != "***":
            current.setdefault("ai", {})["api_key"] = new_key
        for k, v in payload.ai.items():
            if k != "api_key":
                current.setdefault("ai", {})[k] = v
        # Apply AI settings to live config so they take effect immediately
        ai_cfg = current.get("ai", {})
        if ai_cfg.get("api_key"):
            settings.AI_API_KEY = ai_cfg["api_key"]
        if ai_cfg.get("model"):
            settings.AI_MODEL = ai_cfg["model"]
        if ai_cfg.get("api_base"):
            settings.AI_API_BASE = ai_cfg["api_base"]
        if ai_cfg.get("provider"):
            settings.AI_PROVIDER = ai_cfg["provider"]

        # Also set provider-specific key so LiteLLM can route natively
        _PROVIDER_KEY_MAP = {
            "anthropic":   "ANTHROPIC_API_KEY",
            "openai":      "OPENAI_API_KEY",
            "gemini":      "GEMINI_API_KEY",
            "xai":         "XAI_API_KEY",
            "deepseek":    "DEEPSEEK_API_KEY",
            "together":    "TOGETHER_AI_API_KEY",
            "huggingface": "HUGGINGFACE_API_KEY",
        }
        provider_name = ai_cfg.get("provider", "")
        key_val = ai_cfg.get("api_key", "")
        if provider_name in _PROVIDER_KEY_MAP and key_val:
            attr = _PROVIDER_KEY_MAP[provider_name]
            setattr(settings, attr, key_val)
            # Also persist the provider-specific key
            current.setdefault("ai", {})[attr] = key_val

    if payload.device is not None:
        current.setdefault("device", {}).update(payload.device)

    if payload.scan is not None:
        current.setdefault("scan", {}).update(payload.scan)

    if payload.integrations is not None:
        # Avoid masking overwrite
        for provider in ["github", "gitlab"]:
            if provider in payload.integrations:
                new_token = payload.integrations[provider].get("access_token", "")
                if new_token and "…" not in new_token and new_token != "***":
                    current.setdefault("integrations", {}).setdefault(provider, {})["access_token"] = new_token
                for k, v in payload.integrations[provider].items():
                    if k != "access_token":
                        current.setdefault("integrations", {}).setdefault(provider, {})[k] = v

    settings_service.save(current)
    logger.info("[Settings] Saved to disk")
    return {"status": "saved"}


@router.post("/test-ai")
async def test_ai_connection():
    """Quick probe to verify the configured AI provider responds."""
    from litellm import completion
    from services.ai_service import ai_service

    # Temporarily clear proxy vars for test connection only
    old_http_proxy = os.environ.get("HTTP_PROXY")
    old_https_proxy = os.environ.get("HTTPS_PROXY")
    old_http_proxy_lc = os.environ.get("http_proxy")
    old_https_proxy_lc = os.environ.get("https_proxy")
    try:
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        os.environ["http_proxy"] = ""
        os.environ["https_proxy"] = ""

        model    = ai_service._get_model()
        api_base = ai_service._resolve_api_base()
        api_key  = ai_service._get_api_key()
        is_local = ai_service._is_local_provider()
        timeout  = 60 if is_local else 30

        def _probe():
            resp = completion(
                model=model,
                api_key=api_key,
                api_base=api_base,
                messages=[{"role": "user", "content": "Reply with the single word: ok"}],
                max_tokens=16,
                stream=False,
                timeout=timeout,
            )
            return (resp.choices[0].message.content or "").strip()

        text = await _aio.get_event_loop().run_in_executor(None, _probe)
        return {"ok": True, "model": settings.AI_MODEL, "reply": text[:80]}
    except Exception as e:
        err = str(e).lower()
        provider = (settings.AI_PROVIDER or "").lower()
        is_local_provider = provider in ("ollama", "local")

        if "not found" in err or "404" in err:
            if is_local_provider:
                error = f"Model '{settings.AI_MODEL}' not found — run: ollama pull {settings.AI_MODEL}"
            else:
                error = f"Model '{settings.AI_MODEL}' not found on {provider.title()} — check the model name in your provider's dashboard"
        elif "refused" in err or "connect" in err:
            if is_local_provider:
                error = "Cannot connect to AI server — is Ollama running? (ollama serve)"
            else:
                error = f"Cannot connect to {provider.title()} API — check your network or API base URL"
        elif "timeout" in err or "timed out" in err:
            if is_local_provider:
                error = f"Timed out after {timeout}s — model may still be loading, try again"
            else:
                error = f"Timed out after {timeout}s — {provider.title()} may be experiencing high load"
        elif "api key" in err or "auth" in err or "unauthorized" in err or "401" in err:
            error = f"Authentication failed for {provider.title()} — check your API key"
        elif "quota" in err or "429" in err or "rate" in err:
            error = f"Rate limit or quota exceeded on {provider.title()} — check your billing/usage"
        else:
            error = str(e)[:200]
        return {"ok": False, "model": settings.AI_MODEL, "error": error}
    finally:
        # Restore original proxy values
        if old_http_proxy is not None:
            os.environ["HTTP_PROXY"] = old_http_proxy
        elif "HTTP_PROXY" in os.environ:
            del os.environ["HTTP_PROXY"]
        if old_https_proxy is not None:
            os.environ["HTTPS_PROXY"] = old_https_proxy
        elif "HTTPS_PROXY" in os.environ:
            del os.environ["HTTPS_PROXY"]
        if old_http_proxy_lc is not None:
            os.environ["http_proxy"] = old_http_proxy_lc
        elif "http_proxy" in os.environ:
            del os.environ["http_proxy"]
        if old_https_proxy_lc is not None:
            os.environ["https_proxy"] = old_https_proxy_lc
        elif "https_proxy" in os.environ:
            del os.environ["https_proxy"]


@router.get("/ollama-models")
async def list_ollama_models():
    """Auto-detect locally available Ollama models."""
    base = settings.AI_API_BASE or "http://localhost:11434"
    base = base.rstrip("/").replace("/v1", "")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        models = []
        for m in data.get("models", []):
            name = m.get("name", "")
            if not name:
                continue
            size_gb = round(m.get("size", 0) / 1e9, 1)
            details = m.get("details", {})
            models.append({
                "name": name,
                "size_gb": size_gb,
                "family": details.get("family", ""),
                "params": details.get("parameter_size", ""),
                "quant": details.get("quantization_level", ""),
            })
        return {"status": "ok", "models": models}
    except httpx.ConnectError:
        return {"status": "error", "message": "Cannot connect to Ollama. Make sure it is running: `ollama serve`", "models": []}
    except Exception as e:
        return {"status": "error", "message": str(e)[:200], "models": []}


@router.post("/settings/reset")
async def reset_settings():
    """Reset all settings to defaults."""
    from services.settings_service import _DEFAULT_SETTINGS
    settings_service.save(_DEFAULT_SETTINGS)
    return {"status": "reset"}
