"""
IRVES — Root Wrapper
Unified privileged-command abstraction for Magisk, KernelSU, APatch, and plain su.
Detects the available root implementation once per device serial and caches it.
"""

import asyncio
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Known su binary locations per implementation ──────────────────────────────
_SU_BINARIES: Dict[str, str] = {
    "ksu":    "/data/adb/ksu/bin/su",
    "apatch": "/data/adb/ap/bin/su",
    "magisk": "su",   # Magisk bind-mounts su onto PATH
    "su":     "su",   # Plain su (SuperSU, etc.)
}

# Detection probes — each is a one-liner that echoes a sentinel on the device.
# Order matters: more specific first.
_PROBES = [
    ("ksu",    "ls /data/adb/ksu/bin/su 2>/dev/null && echo __ksu_ok__ || echo __ksu_no__",    "__ksu_ok__"),
    ("apatch", "ls /data/adb/ap/bin/su  2>/dev/null && echo __ap_ok__  || echo __ap_no__",     "__ap_ok__"),
    ("magisk", "ls /data/adb/magisk     2>/dev/null && echo __mg_ok__  || echo __mg_no__",     "__mg_ok__"),
    ("su",     "su -c id 2>/dev/null | grep -q uid=0 && echo __su_ok__ || echo __su_no__",     "__su_ok__"),
]

# SELinux-capable implementations (support magiskpolicy or ksupolicy)
_SELINUX_IMPLS = {"ksu", "magisk"}


class RootWrapper:
    """
    Per-device root implementation detector and privileged shell router.

    Usage:
        impl = await root_wrapper.detect(serial)       # "ksu"|"apatch"|"magisk"|"su"|"none"
        out, rc = await root_wrapper.shell(serial, "id")
        ok = await root_wrapper.magiskpolicy(serial, "allow untrusted_app system_file file read")
    """

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}   # serial → impl

    async def detect(self, serial: str, force: bool = False) -> str:
        """
        Detect root implementation on device.
        Returns 'ksu' | 'apatch' | 'magisk' | 'su' | 'none'.
        Caches result per serial; pass force=True to re-probe.
        """
        if not force and serial in self._cache:
            return self._cache[serial]

        logger.info(f"[RootWrapper] Detecting root impl on {serial}…")

        for impl, probe_cmd, sentinel in _PROBES:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell", probe_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                if sentinel in out.decode(errors="replace"):
                    logger.info(f"[RootWrapper] {serial} → {impl}")
                    self._cache[serial] = impl
                    return impl
            except asyncio.TimeoutError:
                logger.warning(f"[RootWrapper] Probe '{impl}' timed out on {serial}")
            except Exception as e:
                logger.debug(f"[RootWrapper] Probe '{impl}' error on {serial}: {e}")

        logger.warning(f"[RootWrapper] No root found on {serial}")
        self._cache[serial] = "none"
        return "none"

    def _su_binary(self, impl: str) -> str:
        """Return the su binary path for a given implementation name."""
        return _SU_BINARIES.get(impl, "su")

    async def shell(self, serial: str, cmd: str) -> Tuple[str, int]:
        """
        Run a privileged shell command on the device using the detected su.
        Returns (stdout_text, returncode).
        Raises RuntimeError if device has no root.
        """
        impl = await self.detect(serial)
        if impl == "none":
            raise RuntimeError(f"[RootWrapper] Device {serial} has no root access")

        su_bin = self._su_binary(impl)

        # Build the adb shell invocation
        # For path-based su we need the full path; for plain 'su' it's on PATH.
        if su_bin.startswith("/"):
            shell_cmd = f"{su_bin} -c '{cmd}'"
        else:
            shell_cmd = f"su -c '{cmd}'"

        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
            combined = (out + err).decode(errors="replace")
            logger.debug(f"[RootWrapper] shell({serial}, {cmd!r}) rc={proc.returncode}")
            return combined, proc.returncode
        except asyncio.TimeoutError:
            logger.warning(f"[RootWrapper] shell timeout: {serial} cmd={cmd!r}")
            return "", -1
        except Exception as e:
            logger.error(f"[RootWrapper] shell error: {e}")
            return str(e), -1

    async def magiskpolicy(self, serial: str, rule: str) -> bool:
        """
        Inject a SELinux policy rule via magiskpolicy (Magisk) or ksupolicy (KernelSU).
        No-op (returns False) on APatch/plain-su — those don't expose a policy CLI.
        Returns True if the rule was applied.
        """
        impl = await self.detect(serial)
        if impl not in _SELINUX_IMPLS:
            logger.debug(f"[RootWrapper] magiskpolicy skipped for impl={impl} on {serial}")
            return False

        if impl == "ksu":
            policy_cmd = f"ksupolicy --live '{rule}' 2>/dev/null || magiskpolicy --live '{rule}' 2>/dev/null"
        else:
            policy_cmd = f"magiskpolicy --live '{rule}' 2>/dev/null"

        out, rc = await self.shell(serial, policy_cmd)
        success = rc == 0
        if success:
            logger.info(f"[RootWrapper] SELinux policy applied on {serial}: {rule!r}")
        else:
            logger.warning(f"[RootWrapper] SELinux policy failed on {serial}: {out.strip()!r}")
        return success

    def invalidate(self, serial: str) -> None:
        """Remove cached detection result for a serial (e.g. after reboot)."""
        self._cache.pop(serial, None)

    def cached_impl(self, serial: str) -> Optional[str]:
        """Return cached impl without probing, or None if not yet detected."""
        return self._cache.get(serial)


# ── Global singleton ──────────────────────────────────────────────────────────
root_wrapper = RootWrapper()
