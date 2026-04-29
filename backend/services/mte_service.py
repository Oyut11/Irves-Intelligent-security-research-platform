"""
IRVES — MTE (Memory Tagging Extension) Service
Automates ARM MTE SYNC mode for hardware-level memory corruption detection
on Tensor G3 / Pixel 8 Pro and compatible devices.
"""

import asyncio
import re
import logging
from typing import AsyncIterator, Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# DEX magic bytes: "dex\n035\0"
DEX_MAGIC = bytes([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00])

# Regex patterns for MTE fault parsing
_SEGV_MTESERR_RE = re.compile(
    r"signal\s+(\d+)\s+\(SIGSEGV\),\s+code\s+(\d+)\s+\(SEGV_MTESERR\),\s+fault addr\s+([0-9a-fx]+)"
)
_PC_RE = re.compile(r"\bpc\s+([0-9a-fx]+)")
_LR_RE = re.compile(r"\blr\s+([0-9a-fx]+)")
_SP_RE = re.compile(r"\bsp\s+([0-9a-fx]+)")
_REGISTER_RE = re.compile(r"\b(x\d+)\s+([0-9a-fx]+)")
_BACKTRACE_RE = re.compile(r"#\d+\s+pc\s+([0-9a-fx]+)\s+(.*)")


@dataclass
class MTEFault:
    """Parsed MTE synchronous tag check fault."""
    fault_addr: str = ""
    signal: int = 0
    code: str = "SEGV_MTESERR"
    pc: str = ""          # Exact crash instruction — surgical precision
    lr: str = ""          # Return address (caller)
    sp: str = ""          # Stack pointer
    registers: Dict[str, str] = field(default_factory=dict)
    backtrace: List[Dict[str, str]] = field(default_factory=list)
    tag_mismatch: str = ""
    raw_log: str = ""


class MTEService:
    """MTE (Memory Tagging Extension) automation for IRVES.

    In SYNC mode, any out-of-bounds memory access (even 1 byte) triggers
    SIGSEGV instantly at the offending instruction. The Program Counter (PC)
    in the fault log is exactly where the corruption occurred — no guessing.
    """

    async def enable_mte_sync(self, serial: str, package: str) -> Dict[str, Any]:
        """Force target app into MTE SYNC mode.

        Uses Android's compat change system:
            adb shell am compat enable NATIVE_MEMTAG_SYNC <package>

        SYNC mode is the 'brutal' mode — instant SIGSEGV on tag mismatch.
        """
        logger.info(f"[MTE] Enabling NATIVE_MEMTAG_SYNC for {package} on {serial}")

        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "am", "compat", "enable", "NATIVE_MEMTAG_SYNC", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()

        if proc.returncode != 0:
            logger.error(f"[MTE] Failed to enable SYNC mode: {err}")
            return {
                "status": "error",
                "message": f"Failed to enable MTE SYNC: {err or out}",
                "package": package,
            }

        # Verify the change was applied
        verify_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "am", "compat", "get", "NATIVE_MEMTAG_SYNC", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        v_stdout, _ = await asyncio.wait_for(verify_proc.communicate(), timeout=10)
        current_mode = v_stdout.decode(errors="replace").strip()

        logger.info(f"[MTE] NATIVE_MEMTAG_SYNC enabled for {package}: {current_mode}")
        return {
            "status": "enabled",
            "mode": "SYNC",
            "package": package,
            "verified": current_mode,
        }

    async def enable_mte_async(self, serial: str, package: str) -> Dict[str, Any]:
        """Enable MTE ASYNC mode — silently logs mismatches, no crash.

        Less intrusive but won't pinpoint the exact instruction.
        Useful for initial reconnaissance before switching to SYNC.
        """
        logger.info(f"[MTE] Enabling NATIVE_MEMTAG_ASYNC for {package} on {serial}")

        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "am", "compat", "enable", "NATIVE_MEMTAG_ASYNC", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            return {"status": "error", "message": f"Failed to enable MTE ASYNC: {err}"}

        return {"status": "enabled", "mode": "ASYNC", "package": package}

    async def disable_mte(self, serial: str, package: str) -> Dict[str, Any]:
        """Revert MTE to default (disabled) for the package."""
        logger.info(f"[MTE] Disabling MTE for {package} on {serial}")

        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "am", "compat", "reset", "NATIVE_MEMTAG_SYNC", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=15)

        proc2 = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "am", "compat", "reset", "NATIVE_MEMTAG_ASYNC", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc2.communicate(), timeout=15)

        return {"status": "disabled", "package": package}

    async def get_mte_status(self, serial: str, package: str) -> Dict[str, Any]:
        """Check current MTE mode for a package."""
        results = {}
        for mode_name in ["NATIVE_MEMTAG_SYNC", "NATIVE_MEMTAG_ASYNC"]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                "am", "compat", "get", mode_name, package,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            results[mode_name] = stdout.decode(errors="replace").strip()

        return {
            "package": package,
            "sync": results.get("NATIVE_MEMTAG_SYNC", "unknown"),
            "async": results.get("NATIVE_MEMTAG_ASYNC", "unknown"),
        }

    async def check_device_mte_support(self, serial: str) -> Dict[str, Any]:
        """Check if the device supports MTE (ARMv8.5-A or later).

        Pixel 8 Pro (Tensor G3) supports MTE. Other devices may not.
        """
        # Check kernel for MTE support
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "cat /proc/cpuinfo | grep -i 'mte\\|memtag' || "
            "getprop ro.product.model && getprop ro.product.cpu.abi",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        info = stdout.decode(errors="replace").strip()

        # Check if MTE is available via kernel command line or sysfs
        mte_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "cat /sys/kernel/debug/mte 2>/dev/null || "
            "grep -i mte /proc/cmdline 2>/dev/null || echo 'mte-unknown'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        mte_stdout, _ = await asyncio.wait_for(mte_proc.communicate(), timeout=10)
        mte_info = mte_stdout.decode(errors="replace").strip()

        # Known MTE-capable devices
        mte_devices = [
            "Pixel 8", "Pixel 8 Pro", "Pixel 8a",
            "Pixel 9", "Pixel 9 Pro", "Pixel 9 Pro XL",
        ]

        model_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "getprop", "ro.product.model",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        model_stdout, _ = await asyncio.wait_for(model_proc.communicate(), timeout=10)
        model = model_stdout.decode(errors="replace").strip()

        supported = any(d in model for d in mte_devices) or "mte" in mte_info.lower()

        return {
            "model": model,
            "mte_supported": supported,
            "kernel_mte_info": mte_info,
            "cpu_info": info,
        }

    async def monitor_mte_faults(
        self,
        serial: str,
        package: Optional[str] = None,
        duration_seconds: int = 300,
    ) -> AsyncIterator[MTEFault]:
        """Monitor logcat for SEGV_MTESERR (Synchronous Tag Check Fault).

        When MTE SYNC fires, the PC in the log is EXACTLY where the
        memory corruption occurred. This is surgical precision.

        Args:
            serial: ADB device serial
            package: Optional package filter
            duration_seconds: Max monitoring duration (default 5 min)
        """
        logger.info(f"[MTE] Starting fault monitor on {serial} for {duration_seconds}s")

        # Clear logcat buffer first for clean capture
        clear_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "logcat", "-c",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(clear_proc.communicate(), timeout=10)

        # Start logcat with DEBUG tag for crash dumps
        cmd = ["adb", "-s", serial, "logcat", "-v", "threadtime", "*:E", "DEBUG:*"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        buffer = ""
        in_crash_section = False
        crash_buffer = ""
        elapsed = 0.0
        chunk_timeout = 2.0

        try:
            while elapsed < duration_seconds:
                try:
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(4096), timeout=chunk_timeout
                    )
                    if not chunk:
                        break
                    elapsed += chunk_timeout
                    text = chunk.decode(errors="replace")
                    buffer += text

                    # Process buffer for MTE faults
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()

                        # Detect start of crash dump section
                        if "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***" in line:
                            in_crash_section = True
                            crash_buffer = line + "\n"
                            continue

                        if in_crash_section:
                            crash_buffer += line + "\n"
                            # Check if this crash is an MTE fault
                            if "SEGV_MTESERR" in line:
                                # Continue collecting the full crash dump
                                pass
                            # End of crash section — empty line after registers
                            if not line and "SEGV_MTESERR" in crash_buffer:
                                fault = self._parse_mte_fault(crash_buffer)
                                if fault and (not package or package in crash_buffer):
                                    logger.info(
                                        f"[MTE] Fault detected at PC={fault.pc} "
                                        f"fault_addr={fault.fault_addr}"
                                    )
                                    yield fault
                                in_crash_section = False
                                crash_buffer = ""
                            elif not line:
                                in_crash_section = False
                                crash_buffer = ""

                        # Also catch inline MTE references in regular log lines
                        elif "SEGV_MTESERR" in line:
                            fault = self._parse_inline_mte(line)
                            if fault:
                                yield fault

                except asyncio.TimeoutError:
                    elapsed += chunk_timeout
                    continue
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def _parse_mte_fault(self, crash_dump: str) -> Optional[MTEFault]:
        """Parse a full tombstone/crash dump for MTE fault details."""
        fault = MTEFault(raw_log=crash_dump)

        # Extract signal and fault address
        m = _SEGV_MTESERR_RE.search(crash_dump)
        if not m:
            return None
        fault.signal = int(m.group(1))
        fault.code = "SEGV_MTESERR"
        fault.fault_addr = m.group(3)

        # Extract PC — the exact crash instruction
        m = _PC_RE.search(crash_dump)
        if m:
            fault.pc = m.group(1)

        # Extract LR — return address (caller)
        m = _LR_RE.search(crash_dump)
        if m:
            fault.lr = m.group(1)

        # Extract SP
        m = _SP_RE.search(crash_dump)
        if m:
            fault.sp = m.group(1)

        # Extract all registers
        for m in _REGISTER_RE.finditer(crash_dump):
            fault.registers[m.group(1)] = m.group(2)

        # Extract backtrace
        for m in _BACKTRACE_RE.finditer(crash_dump):
            fault.backtrace.append({
                "pc": m.group(1),
                "location": m.group(2).strip(),
            })

        # Extract tag mismatch info if present
        tag_re = re.compile(r"tag\s+.*?mismatch.*?([0-9a-fx]+)", re.IGNORECASE)
        m = tag_re.search(crash_dump)
        if m:
            fault.tag_mismatch = m.group(1)

        return fault

    def _parse_inline_mte(self, line: str) -> Optional[MTEFault]:
        """Parse an inline logcat line referencing MTE fault."""
        m = _SEGV_MTESERR_RE.search(line)
        if not m:
            return None
        return MTEFault(
            signal=int(m.group(1)),
            code="SEGV_MTESERR",
            fault_addr=m.group(3),
            raw_log=line,
        )

    async def extract_register_dump(
        self, serial: str, pid: Optional[int] = None
    ) -> Dict[str, Any]:
        """Pull the most recent register dump from logcat/tombstone.

        If pid is specified, filters to that process.
        """
        cmd = ["adb", "-s", serial, "logcat", "-d", "-v", "threadtime", "DEBUG:*"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        log_text = stdout.decode(errors="replace")

        if pid:
            # Filter to specific PID
            pid_str = str(pid)
            log_lines = [l for l in log_text.split("\n") if pid_str in l]
            log_text = "\n".join(log_lines)

        # Find the last crash dump
        sections = log_text.split(
            "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"
        )
        if len(sections) < 2:
            return {"status": "no_crash", "message": "No crash dump found"}

        last_crash = sections[-1]
        fault = self._parse_mte_fault(
            "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"
            + last_crash
        )

        if not fault:
            return {
                "status": "no_mte_fault",
                "message": "Crash dump found but no MTE fault",
                "raw": last_crash[:2000],
            }

        return {
            "status": "mte_fault",
            "fault_type": fault.code,
            "pc": fault.pc,
            "lr": fault.lr,
            "sp": fault.sp,
            "fault_addr": fault.fault_addr,
            "tag_mismatch": fault.tag_mismatch,
            "registers": fault.registers,
            "backtrace": fault.backtrace,
        }

    async def harden_analysis(self, serial: str, package: str) -> Dict[str, Any]:
        """One-shot hardened analysis setup.

        Enables MTE SYNC, clears logcat, returns status.
        Used by the RuntimeOrchestrator for Step 2.
        """
        # Check device support first
        support = await self.check_device_mte_support(serial)
        if not support.get("mte_supported"):
            return {
                "status": "unsupported",
                "message": f"Device {support.get('model', 'unknown')} does not support MTE",
                "device_info": support,
            }

        # Enable SYNC mode
        result = await self.enable_mte_sync(serial, package)
        if result.get("status") == "error":
            return result

        # Clear logcat for clean fault capture
        clear_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "logcat", "-c",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(clear_proc.communicate(), timeout=10)

        return {
            "status": "hardened",
            "mode": "SYNC",
            "package": package,
            "device_model": support.get("model", "unknown"),
            "message": f"MTE SYNC enabled for {package}. Any memory corruption will trigger instant SIGSEGV.",
        }


# Global singleton
mte_service = MTEService()
