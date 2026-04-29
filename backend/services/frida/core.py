"""
IRVES — Frida Core Session Operations
Attach, spawn, spawn_gate, inject_script, verify_stealth, etc.
"""

import asyncio
import logging
import uuid
from typing import Callable

from services.frida.device import resolve_device

logger = logging.getLogger(__name__)


def get_frida():
    """Lazy import frida to avoid crash if not installed."""
    try:
        import frida
        return frida
    except ImportError:
        raise RuntimeError("frida Python package is not installed. Run: pip install frida")


async def list_processes(device_id: str) -> list[dict]:
    """List running processes on a device."""
    frida = get_frida()

    def _list():
        device = frida.get_device(device_id, timeout=5)
        logger.info(f"[Frida] Listing processes on {device.id}")
        processes = device.enumerate_processes()
        logger.info(f"[Frida] Found {len(processes)} processes")
        return [{"pid": p.pid, "name": p.name} for p in processes]

    return await asyncio.get_event_loop().run_in_executor(None, _list)


async def attach(sessions: dict, device_id: str, package_name: str) -> str:
    """Attach to the MAIN process of an Android app by package name."""
    frida = get_frida()
    session_id = f"{device_id}:{package_name}"

    def _find_main_pid(device) -> tuple[int, str]:
        """Return (pid, process_name) of the main app process, or (-1, '')."""
        try:
            procs = device.enumerate_processes(scope="full")
        except Exception:
            procs = device.enumerate_processes()

        candidates = []
        for p in procs:
            apps = p.parameters.get("applications", [])
            belongs = package_name in apps or p.name == package_name
            if belongs:
                candidates.append(p)

        if not candidates:
            return -1, ""

        for p in candidates:
            if p.name == package_name:
                logger.info(f"[Frida] Main process '{p.name}' at PID {p.pid} (exact name match)")
                return p.pid, p.name

        secondary_suffixes = (
            ":remote", ":push", ":analytics", ":background",
            ":firebase", ":sync", ":worker", ":service",
            ":privileged", ":sandboxed", ":renderer",
        )
        main_candidates = [
            p for p in candidates
            if not any(p.name.endswith(s) for s in secondary_suffixes)
        ]
        if main_candidates:
            chosen = min(main_candidates, key=lambda p: p.pid)
            logger.info(f"[Frida] Main process '{chosen.name}' at PID {chosen.pid} (filtered candidates)")
            return chosen.pid, chosen.name

        chosen = min(candidates, key=lambda p: p.pid)
        logger.warning(f"[Frida] Could not find clean main process, using '{chosen.name}' PID {chosen.pid}")
        return chosen.pid, chosen.name

    def _attach():
        device = resolve_device(frida, device_id)

        try:
            front = device.get_frontmost_application(scope="full")
            if front and front.identifier == package_name:
                try:
                    all_procs = device.enumerate_processes(scope="full")
                except Exception:
                    all_procs = device.enumerate_processes()

                front_proc = next((p for p in all_procs if p.pid == front.pid), None)
                is_main_proc = front_proc is not None and front_proc.name == package_name

                if is_main_proc:
                    logger.info(
                        f"[Frida] Attaching to frontmost app '{front.identifier}' "
                        f"PID {front.pid} (verified main process)"
                    )
                    return device.attach(front.pid)
                else:
                    sec_name = front_proc.name if front_proc else "unknown"
                    logger.warning(
                        f"[Frida] get_frontmost_application PID {front.pid} is "
                        f"secondary process '{sec_name}' — falling through to main process scan"
                    )
        except Exception as e:
            logger.debug(f"[Frida] get_frontmost_application failed: {e}")

        pid, proc_name = _find_main_pid(device)
        if pid == -1:
            raise RuntimeError(
                f"Process '{package_name}' is not running on the device. "
                "Launch the app first, then click Connect."
            )
        logger.info(f"[Frida] Attaching to main process '{proc_name}' PID {pid}")
        return device.attach(pid)

    raw_session = await asyncio.get_event_loop().run_in_executor(None, _attach)
    # Import FridaSession from the service level — avoid circular import
    from services.frida_service import FridaSession
    fs = FridaSession(session_id, device_id, package_name)
    fs._session = raw_session
    sessions[session_id] = fs
    logger.info(f"[Frida] Attached to main process of {package_name} on {device_id}")
    return session_id


async def spawn(sessions: dict, device_id: str, package_name: str) -> str:
    """Spawn a new process and attach to it."""
    frida = get_frida()
    session_id = f"{device_id}:{package_name}"

    def _find_main_pid(device) -> int:
        try:
            procs = device.enumerate_processes(scope="full")
        except Exception:
            procs = device.enumerate_processes()

        candidates = []
        for p in procs:
            apps = p.parameters.get("applications", [])
            if package_name in apps or p.name == package_name:
                candidates.append(p)

        if not candidates:
            return -1

        for p in candidates:
            if p.name == package_name:
                return p.pid

        secondary_suffixes = (
            ":remote", ":push", ":analytics", ":background",
            ":firebase", ":sync", ":worker", ":service",
            ":privileged", ":sandboxed", ":renderer",
        )
        main_candidates = [p for p in candidates if not any(p.name.endswith(s) for s in secondary_suffixes)]
        if main_candidates:
            return min(main_candidates, key=lambda p: p.pid).pid

        return min(candidates, key=lambda p: p.pid).pid

    def _spawn():
        device = resolve_device(frida, device_id)

        existing_pid = _find_main_pid(device)
        if existing_pid != -1:
            logger.info(f"[Frida] '{package_name}' already running at PID {existing_pid}, killing for clean spawn")
            try:
                device.kill(existing_pid)
                import time
                time.sleep(1)
            except Exception:
                pass

        logger.info(f"[Frida] Spawning clean instance of '{package_name}'")
        pid = device.spawn([package_name])
        session = device.attach(pid)
        device.resume(pid)
        logger.info(f"[Frida] Spawned '{package_name}' at PID {pid}")
        return session

    raw_session = await asyncio.get_event_loop().run_in_executor(None, _spawn)
    from services.frida_service import FridaSession
    fs = FridaSession(session_id, device_id, package_name)
    fs._session = raw_session
    sessions[session_id] = fs
    logger.info(f"[Frida] Spawned/attached to {package_name} on {device_id}")
    return session_id


async def spawn_gate(sessions: dict, device_id: str, package_name: str) -> dict:
    """Enable Spawn Gating mode — Zymbiote stealth injection."""
    frida = get_frida()
    session_id = f"{device_id}:{package_name}:gated"

    def _find_main_pid(device) -> int:
        try:
            procs = device.enumerate_processes(scope="full")
        except Exception:
            procs = device.enumerate_processes()
        candidates = []
        for p in procs:
            apps = p.parameters.get("applications", [])
            if package_name in apps or p.name == package_name:
                candidates.append(p)
        if not candidates:
            return -1
        for p in candidates:
            if p.name == package_name:
                return p.pid
        secondary_suffixes = (
            ":remote", ":push", ":analytics", ":background",
            ":firebase", ":sync", ":worker", ":service",
            ":privileged", ":sandboxed", ":renderer",
        )
        main_candidates = [p for p in candidates if not any(p.name.endswith(s) for s in secondary_suffixes)]
        if main_candidates:
            return min(main_candidates, key=lambda p: p.pid).pid
        return min(candidates, key=lambda p: p.pid).pid

    def _spawn_gate():
        device = resolve_device(frida, device_id)

        existing_pid = _find_main_pid(device)
        if existing_pid != -1:
            logger.info(f"[Frida-Zymbiote] '{package_name}' already running at PID {existing_pid}, killing for clean spawn gate")
            try:
                device.kill(existing_pid)
                import time
                time.sleep(1)
            except Exception:
                pass

        try:
            device.enable_spawn_gating()
            logger.info(f"[Frida-Zymbiote] Spawn gating enabled on {device_id}")
        except AttributeError:
            logger.warning(f"[Frida-Zymbiote] Spawn gating not available (Frida < 17.6), falling back to standard spawn")
            pid = device.spawn([package_name])
            session = device.attach(pid)
            device.resume(pid)
            return session, pid, False

        # Launch the app — Frida will intercept via spawn gating
        import subprocess as sp
        try:
            serial = device_id

            launch_cmd = None
            try:
                dump = sp.check_output(
                    ["adb", "-s", serial, "shell",
                     f"cmd package resolve-activity --brief -c android.intent.category.LAUNCHER {package_name}"],
                    stderr=sp.DEVNULL, timeout=5,
                ).decode(errors="replace").strip().splitlines()
                for line in dump:
                    line = line.strip()
                    if line and "/" in line and not line.startswith("package:"):
                        if line.startswith(package_name):
                            launch_cmd = line
                            break
            except Exception:
                pass

            if launch_cmd:
                sp.Popen(
                    ["adb", "-s", serial, "shell", "am", "start", "-n", launch_cmd],
                    stdout=sp.DEVNULL, stderr=sp.DEVNULL,
                )
            else:
                sp.Popen(
                    ["adb", "-s", serial, "shell", "monkey", "-p",
                     package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                    stdout=sp.DEVNULL, stderr=sp.DEVNULL,
                )
        except Exception:
            pass

        # Wait for spawn-gated session to appear
        import time
        for _ in range(30):
            try:
                procs = device.enumerate_processes(scope="full")
            except Exception:
                procs = device.enumerate_processes()
            for p in procs:
                if p.name == package_name or package_name in p.parameters.get("applications", []):
                    pid = p.pid
                    session = device.attach(pid)
                    logger.info(f"[Frida-Zymbiote] Spawn-gated session acquired: PID {pid}")
                    return session, pid, True
            time.sleep(0.5)

        logger.warning("[Frida-Zymbiote] Spawn gating timed out, falling back to standard spawn")
        pid = device.spawn([package_name])
        session = device.attach(pid)
        device.resume(pid)
        return session, pid, False

    raw_session, pid, is_stealth = await asyncio.get_event_loop().run_in_executor(None, _spawn_gate)
    from services.frida_service import FridaSession
    fs = FridaSession(session_id, device_id, package_name)
    fs._session = raw_session
    sessions[session_id] = fs

    result = {
        "session_id": session_id,
        "pid": pid,
        "is_stealth": is_stealth,
        "method": "spawn_gating" if is_stealth else "standard_spawn",
        "package": package_name,
    }

    logger.info(
        f"[Frida-Zymbiote] Spawn gated {package_name} on {device_id}: "
        f"stealth={'YES' if is_stealth else 'NO'} PID={pid}"
    )
    return result


async def verify_stealth(serial: str, pid: int) -> dict:
    """Verify Zymbiote is operating stealthily."""
    checks = {}

    # 1. TracerPid check
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            f"cat /proc/{pid}/status | grep TracerPid",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        tracer_line = stdout.decode(errors="replace").strip()
        tracer_pid = tracer_line.split(":")[-1].strip() if ":" in tracer_line else "unknown"
        checks["tracer_pid"] = tracer_pid
        checks["ptrace_stealth"] = tracer_pid == "0"
    except Exception as e:
        checks["tracer_pid"] = f"error: {e}"
        checks["ptrace_stealth"] = False

    # 2. Abstract socket check
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "cat /proc/net/unix | grep '@'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        sockets = stdout.decode(errors="replace").strip().split("\n")
        abstract_sockets = [s.strip() for s in sockets if s.strip() and "@" in s]
        frida_sockets = [s for s in abstract_sockets if "frida" in s.lower()]
        checks["abstract_sockets_count"] = len(abstract_sockets)
        checks["frida_named_sockets"] = frida_sockets
        checks["socket_stealth"] = len(frida_sockets) == 0
    except Exception as e:
        checks["socket_check"] = f"error: {e}"
        checks["socket_stealth"] = False

    # 3. Port 27042 visibility check
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            f"su -c 'netstat -tlnp 2>/dev/null | grep 27042 || ss -tlnp 2>/dev/null | grep 27042 || echo port-not-found'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        port_output = stdout.decode(errors="replace").strip()
        checks["port_27042_visible"] = "27042" in port_output and "port-not-found" not in port_output
    except Exception as e:
        checks["port_check"] = f"error: {e}"

    is_stealth = checks.get("ptrace_stealth", False) and checks.get("socket_stealth", False)
    checks["overall_stealth"] = is_stealth
    checks["pid"] = pid

    logger.info(f"[Frida-Zymbiote] Stealth verification for PID {pid}: {'STEALTHY' if is_stealth else 'DETECTED'}")
    return checks


async def inject_script(
    sessions: dict,
    session_id: str,
    script_code: str,
    message_handler: Callable,
) -> str:
    """Inject a Frida script into the attached session."""
    fs = sessions.get(session_id)
    if not fs or not fs._session:
        logger.error(f"[Frida] Session not found or not attached: {session_id}")
        raise ValueError(f"Session not found or not attached: {session_id}")

    logger.info(f"[Frida] Injecting script into session {session_id}")

    def _inject():
        try:
            script = fs._session.create_script(script_code)
            script.on("message", message_handler)
            script.load()
            logger.info(f"[Frida] Script loaded successfully")
            return script
        except Exception as e:
            logger.error(f"[Frida] Script injection failed: {e}")
            raise

    script = await asyncio.get_event_loop().run_in_executor(None, _inject)
    script_id = str(uuid.uuid4())[:8]
    fs._scripts[script_id] = script
    logger.info(f"[Frida] Injected script {script_id} into session {session_id}")
    return script_id


async def call_export(sessions: dict, session_id: str, script_id: str, fn_name: str, args: list):
    """Call an exported function from a loaded script."""
    fs = sessions.get(session_id)
    if not fs:
        raise ValueError(f"Session not found: {session_id}")
    script = fs._scripts.get(script_id)
    if not script:
        raise ValueError(f"Script not found: {script_id}")

    def _call():
        return script.exports[fn_name](*args)

    return await asyncio.get_event_loop().run_in_executor(None, _call)


async def detach(sessions: dict, session_id: str) -> None:
    """Detach from an active session and clean up."""
    fs = sessions.pop(session_id, None)
    if fs and fs._session:
        def _detach():
            try:
                fs._session.detach()
            except Exception:
                pass
        await asyncio.get_event_loop().run_in_executor(None, _detach)
        logger.info(f"[Frida] Detached session {session_id}")
