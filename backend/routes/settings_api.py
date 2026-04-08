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

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Settings persistence path ─────────────────────────────────────────────────
_SETTINGS_FILE = Path.home() / ".irves" / "settings.json"
_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)

_DEFAULT_SETTINGS = {
    "ai": {
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "api_key": "",
    },
    "device": {
        "adb_path": "adb",
        "frida_server_path": "/data/local/tmp/frida-server",
    },
    "mobsf": {
        "url": "http://127.0.0.1:8000",
        "api_key": "",
    },
    "scan": {
        "default_profile": "standard",
        "output_dir": str(Path.home() / ".irves" / "projects"),
    },
}


# ── Pydantic models ───────────────────────────────────────────────────────────

class SettingsPayload(BaseModel):
    ai: Optional[dict] = None
    device: Optional[dict] = None
    mobsf: Optional[dict] = None
    scan: Optional[dict] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_settings() -> dict:
    """Load settings from disk, merging with defaults."""
    if _SETTINGS_FILE.exists():
        try:
            on_disk = json.loads(_SETTINGS_FILE.read_text())
            merged = {**_DEFAULT_SETTINGS}
            for section, values in on_disk.items():
                if section in merged and isinstance(values, dict):
                    merged[section] = {**merged[section], **values}
                else:
                    merged[section] = values
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_DEFAULT_SETTINGS)


def _save_settings(data: dict) -> None:
    """Persist settings to disk."""
    _SETTINGS_FILE.write_text(json.dumps(data, indent=2))


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


async def _check_mobsf(url: str, api_key: str = "") -> dict:
    """Probe the MobSF REST API."""
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = api_key
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{url}/api/v1/version", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            return {"running": True, "version": data.get("version"), "error": None}
        return {"running": False, "version": None, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"running": False, "version": None, "error": str(e)}


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
    stored = _load_settings()
    mobsf_url = stored.get("mobsf", {}).get("url", settings.MOBSF_URL)
    mobsf_key = stored.get("mobsf", {}).get("api_key", settings.MOBSF_API_KEY)

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

    cli_results = await asyncio.gather(*[_check_cli(t) for t in cli_tools])
    mobsf_result = await _check_mobsf(mobsf_url, mobsf_key)

    tools = list(cli_results) + [{
        "name": "mobsf",
        "installed": mobsf_result["running"],
        "running": mobsf_result["running"],
        "path": mobsf_url,
        "version": mobsf_result.get("version"),
        "error": mobsf_result.get("error"),
    }]

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
    stored = _load_settings()
    adb_path = stored.get("device", {}).get("adb_path", "adb") or "adb"
    devices = await _check_adb_devices(adb_path)
    return {"devices": devices, "count": len(devices)}


@router.post("/devices/refresh")
async def refresh_adb_devices():
    """Re-run adb kill-server && adb start-server, then return device list."""
    stored = _load_settings()
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


@router.get("/settings")
async def get_settings():
    """Retrieve all persisted settings (API keys are masked)."""
    data = _load_settings()
    # Mask secrets
    if data.get("ai", {}).get("api_key"):
        key = data["ai"]["api_key"]
        data["ai"]["api_key"] = key[:6] + "…" + key[-4:] if len(key) > 12 else "***"
    if data.get("mobsf", {}).get("api_key"):
        key = data["mobsf"]["api_key"]
        data["mobsf"]["api_key"] = key[:4] + "…" if len(key) > 6 else "***"
    return data


@router.post("/settings")
async def save_settings(payload: SettingsPayload):
    """
    Persist settings to disk (~/.irves/settings.json).
    Partial updates are supported — only provided sections are overwritten.
    """
    current = _load_settings()

    if payload.ai is not None:
        # Never overwrite key with masked placeholder
        new_key = payload.ai.get("api_key", "")
        if new_key and "…" not in new_key and new_key != "***":
            current.setdefault("ai", {})["api_key"] = new_key
        for k, v in payload.ai.items():
            if k != "api_key":
                current.setdefault("ai", {})[k] = v

    if payload.device is not None:
        current.setdefault("device", {}).update(payload.device)

    if payload.mobsf is not None:
        new_key = payload.mobsf.get("api_key", "")
        if new_key and "…" not in new_key and new_key != "***":
            current.setdefault("mobsf", {})["api_key"] = new_key
        for k, v in payload.mobsf.items():
            if k != "api_key":
                current.setdefault("mobsf", {})[k] = v

    if payload.scan is not None:
        current.setdefault("scan", {}).update(payload.scan)

    _save_settings(current)
    logger.info("[Settings] Saved to disk")
    return {"status": "saved"}


@router.post("/settings/reset")
async def reset_settings():
    """Reset all settings to defaults."""
    _save_settings(_DEFAULT_SETTINGS)
    return {"status": "reset"}
