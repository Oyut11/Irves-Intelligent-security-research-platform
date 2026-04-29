"""
IRVES — Frida Service (Phase 5)
Manages Frida sessions for real-time runtime analysis of mobile apps.

Thin orchestrator — delegates to services.frida package modules.
"""

import asyncio
import logging
from typing import Callable

from services.frida.hooks import BUILTIN_HOOKS
from services.frida.device import (
    resolve_device,
    list_devices,
    deploy_server,
    preflight_check,
    adb_devices,
    get_device_arch,
    push_and_start_frida_server,
)
from services.frida.ssl import (
    start_ssl_capture,
    stop_ssl_capture,
    ssl_capture_active,
)
from services.frida.core import (
    get_frida,
    list_processes,
    attach,
    spawn,
    spawn_gate,
    verify_stealth,
    inject_script,
    call_export,
    detach,
)

logger = logging.getLogger(__name__)


class FridaSession:
    """Represents an active Frida session."""

    def __init__(self, session_id: str, device_id: str, package: str):
        self.session_id = session_id
        self.device_id = device_id
        self.package = package
        self._session = None
        self._scripts: dict[str, object] = {}

    @property
    def is_attached(self) -> bool:
        return self._session is not None


class FridaService:
    """Manages Frida sessions for runtime analysis.

    Thin orchestrator — delegates to services.frida package modules.
    """

    def __init__(self):
        self.sessions: dict[str, FridaSession] = {}
        self._ssl_sessions: dict[str, object] = {}   # session_id → frida Script

    # ── BoringSSL capture (delegated) ────────────────────────────────────────

    async def start_ssl_capture(
        self,
        device_id: str,
        package_name: str,
        flow_callback,
        mode: str = "attach_first",
        inject_bypass: bool = True,
        inject_delay_ms: int = 300,
    ) -> dict:
        return await start_ssl_capture(
            self.sessions, self._ssl_sessions,
            device_id, package_name, flow_callback,
            mode, inject_bypass, inject_delay_ms,
            attach_fn=self.attach,
            spawn_gate_fn=self.spawn_gate,
            spawn_fn=self.spawn,
            inject_script_fn=self.inject_script,
        )

    async def stop_ssl_capture(self, device_id: str, package_name: str) -> dict:
        return await stop_ssl_capture(
            self.sessions, self._ssl_sessions,
            device_id, package_name,
            detach_fn=self.detach,
        )

    def ssl_capture_active(self, device_id: str, package_name: str) -> bool:
        return ssl_capture_active(self._ssl_sessions, device_id, package_name)

    # ── Device management (delegated) ────────────────────────────────────────

    def _get_frida(self):
        return get_frida()

    def _resolve_device(self, frida_mod, device_id: str):
        return resolve_device(frida_mod, device_id)

    async def list_devices(self) -> list[dict]:
        return await list_devices()

    async def deploy_server(self, device_id: str, adb_path: str = "adb") -> str:
        return await deploy_server(device_id, adb_path)

    async def preflight_check(self) -> dict:
        return await preflight_check()

    async def adb_devices(self) -> list[dict]:
        return await adb_devices()

    async def get_device_arch(self, serial: str) -> str:
        return await get_device_arch(serial)

    async def push_and_start_frida_server(self, serial: str):
        async for progress in push_and_start_frida_server(serial):
            yield progress

    # ── Core session operations (delegated) ──────────────────────────────────

    async def list_processes(self, device_id: str) -> list[dict]:
        return await list_processes(device_id)

    async def attach(self, device_id: str, package_name: str) -> str:
        return await attach(self.sessions, device_id, package_name)

    async def spawn(self, device_id: str, package_name: str) -> str:
        return await spawn(self.sessions, device_id, package_name)

    async def spawn_gate(self, device_id: str, package_name: str) -> dict:
        return await spawn_gate(self.sessions, device_id, package_name)

    async def verify_stealth(self, serial: str, pid: int) -> dict:
        return await verify_stealth(serial, pid)

    async def inject_script(
        self,
        session_id: str,
        script_code: str,
        message_handler: Callable,
    ) -> str:
        return await inject_script(self.sessions, session_id, script_code, message_handler)

    async def call_export(self, session_id: str, script_id: str, fn_name: str, args: list):
        return await call_export(self.sessions, session_id, script_id, fn_name, args)

    async def detach(self, session_id: str) -> None:
        return await detach(self.sessions, session_id)


# Global singleton
frida_service = FridaService()
