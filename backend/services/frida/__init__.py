"""
IRVES — Frida Service Package
Refactored from monolithic frida_service.py.
"""

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

__all__ = [
    "BUILTIN_HOOKS",
    "resolve_device",
    "list_devices",
    "deploy_server",
    "preflight_check",
    "adb_devices",
    "get_device_arch",
    "push_and_start_frida_server",
    "start_ssl_capture",
    "stop_ssl_capture",
    "ssl_capture_active",
    "get_frida",
    "list_processes",
    "attach",
    "spawn",
    "spawn_gate",
    "verify_stealth",
    "inject_script",
    "call_export",
    "detach",
]
