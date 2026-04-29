"""
IRVES — eBPF Service (BPFDex Observer)
Kernel-level syscall observer for real-time DEX unpacking detection.
Uses CO-RE eBPF programs loaded via KernelSU on rooted devices.
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import AsyncIterator, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DEX_MAGIC_HEX = "6465780a30333500"
PROBE_DIR    = Path(__file__).parent / "ebpf_probes"
PROBE_BINARY = PROBE_DIR / "dex_monitor.bpf.o"
NET_PROBE_BINARY = PROBE_DIR / "net_redirect.bpf.o"


@dataclass
class eBPFEvent:
    event_type: str = ""
    pid: int = 0
    addr: int = 0
    size: int = 0
    fd: int = 0
    magic: str = ""
    comm: str = ""
    is_dex: bool = False
    file_backed: bool = True
    raw_line: str = ""


class EBPFService:
    """eBPF kernel observer — BPFDex-style DEX unpacking detection."""

    def __init__(self):
        self._active_probes: Dict[str, bool] = {}
        self._active_net_probes: Dict[str, bool] = {}

    async def check_kernelsu(self, serial: str) -> Dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "ls /data/adb/ksu 2>/dev/null && echo ksu-found || echo ksu-not-found",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        has_ksu = "ksu-found" in out.decode(errors="replace")

        kv_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "uname -r",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        kv_out, _ = await asyncio.wait_for(kv_proc.communicate(), timeout=10)
        kver = kv_out.decode(errors="replace").strip()

        return {"serial": serial, "kernelsu_available": has_ksu,
                "kernel_version": kver, "ebpf_capable": self._kv_supported(kver)}

    def _kv_supported(self, v: str) -> bool:
        try:
            parts = v.split(".")
            return (int(parts[0]), int(parts[1])) >= (5, 2)
        except Exception:
            return False

    async def deploy_probe(self, serial: str) -> Dict[str, Any]:
        logger.info(f"[eBPF] Deploying DEX probe to {serial}")
        status = await self.check_kernelsu(serial)
        if not status.get("ebpf_capable"):
            return {"status": "error", "message": f"Kernel {status.get('kernel_version')} doesn't support eBPF CO-RE"}
        if not status.get("kernelsu_available"):
            return {"status": "error", "message": "KernelSU not found"}

        if not PROBE_BINARY.exists():
            r = await self._compile_probe("dex_monitor")
            if not r.get("success"):
                return await self._deploy_fallback(serial)

        remote = "/data/local/tmp/irves_dex_monitor.bpf.o"
        p = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "push", str(PROBE_BINARY), remote,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, se = await asyncio.wait_for(p.communicate(), timeout=30)
        if p.returncode != 0:
            return {"status": "error", "message": se.decode(errors="replace").strip()}

        for cmd in [
            "su -c 'mkdir -p /sys/fs/bpf'",
            f"su -c 'bpftool prog load {remote} /sys/fs/bpf/irves_dex_monitor 2>&1'",
            "su -c 'bpftool prog attach /sys/fs/bpf/irves_dex_monitor tracepoint syscalls:sys_enter_memfd_create 2>&1 || true'",
            "su -c 'bpftool prog attach /sys/fs/bpf/irves_dex_monitor tracepoint syscalls:sys_enter_mmap 2>&1 || true'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=15)

        vp = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "su -c 'bpftool prog show name irves_dex_monitor 2>&1'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        vo, _ = await asyncio.wait_for(vp.communicate(), timeout=10)
        if "irves_dex_monitor" in vo.decode(errors="replace"):
            self._active_probes[serial] = True
            return {"status": "deployed", "serial": serial,
                    "message": "eBPF probe deployed (memfd_create + mmap tracepoints)"}
        return await self._deploy_fallback(serial)

    async def _deploy_fallback(self, serial: str) -> Dict[str, Any]:
        for cmd in [
            "su -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_memfd_create/enable'",
            "su -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/enable'",
            "su -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
        self._active_probes[serial] = True
        return {"status": "deployed_fallback", "serial": serial,
                "message": "Fallback probe active (debugfs tracepoints)"}

    async def _compile_probe(self, probe_name: str = "dex_monitor") -> Dict[str, Any]:
        """Compile a named eBPF CO-RE probe source to object file.

        Args:
            probe_name: Base name without extension (e.g. 'dex_monitor', 'net_redirect').
                        Source: {PROBE_DIR}/{probe_name}.bpf.c
                        Output: {PROBE_DIR}/{probe_name}.bpf.o
        """
        src = PROBE_DIR / f"{probe_name}.bpf.c"
        out = PROBE_DIR / f"{probe_name}.bpf.o"
        if not src.exists():
            return {"success": False, "message": f"Source not found: {src}", "probe": probe_name}
        PROBE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            proc = await asyncio.create_subprocess_exec(
                "clang", "-g", "-O2", "-target", "bpf", "-D__TARGET_ARCH_arm64",
                "-I", "/usr/include/bpf", "-c", str(src), "-o", str(out),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, se = await asyncio.wait_for(proc.communicate(), timeout=45)
            stderr_txt = se.decode(errors="replace").strip()
            ok = proc.returncode == 0
            logger.info(f"[eBPF] Compile {probe_name}: {'OK' if ok else 'FAIL'} {stderr_txt[:120]}")
            return {
                "success": ok,
                "probe": probe_name,
                "output": str(out),
                "message": "" if ok else stderr_txt,
            }
        except FileNotFoundError:
            return {"success": False, "probe": probe_name, "message": "clang not found on host — install clang/llvm"}
        except Exception as e:
            return {"success": False, "probe": probe_name, "message": str(e)}

    async def monitor_dex_magic(
        self, serial: str, target_pid: Optional[int] = None, duration_seconds: int = 300,
    ) -> AsyncIterator[eBPFEvent]:
        logger.info(f"[eBPF] Starting DEX monitor on {serial}")
        if not self._active_probes.get(serial):
            yield eBPFEvent(event_type="error", raw_line="No active probe — deploy first")
            return

        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "su -c 'cat /sys/kernel/debug/tracing/trace_pipe'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        elapsed = 0.0
        try:
            while elapsed < duration_seconds:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    elapsed += 2.0
                    for line in chunk.decode(errors="replace").split("\n"):
                        ev = self._parse_trace(line.strip())
                        if ev and (not target_pid or ev.pid == target_pid):
                            if ev.event_type == "mmap" and not ev.file_backed:
                                if await self._check_dex(serial, ev.pid, ev.addr):
                                    ev.is_dex = True
                                    ev.magic = DEX_MAGIC_HEX
                                    ev.event_type = "dex_dump"
                            yield ev
                except asyncio.TimeoutError:
                    elapsed += 2.0
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def _parse_trace(self, line: str) -> Optional[eBPFEvent]:
        try:
            m = re.match(r"^\s*(\S+)-(\d+)\s+\[(\d+)\]", line)
            if not m:
                return None
            ev = eBPFEvent(pid=int(m.group(2)), comm=m.group(1), raw_line=line)
            if "sys_enter_memfd_create" in line:
                ev.event_type = "memfd_create"
                fd = re.search(r"fd=(\d+)", line)
                if fd:
                    ev.fd = int(fd.group(1))
            elif "sys_enter_mmap" in line:
                ev.event_type = "mmap"
                addr = re.search(r"addr=([0-9a-fx]+)", line)
                if addr:
                    ev.addr = int(addr.group(1), 16)
                sz = re.search(r"len=([0-9a-fx]+)", line)
                if sz:
                    ev.size = int(sz.group(1), 16)
                fd = re.search(r"fd=(-?\d+)", line)
                if fd:
                    ev.fd = int(fd.group(1))
                    ev.file_backed = ev.fd >= 0
            else:
                return None
            return ev
        except Exception:
            return None

    async def _check_dex(self, serial: str, pid: int, addr: int) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"su -c 'dd if=/proc/{pid}/mem bs=1 skip={addr} count=8 2>/dev/null | xxd -p'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            return out.decode(errors="replace").strip().replace("\n", "").startswith(DEX_MAGIC_HEX[:8])
        except Exception:
            return False

    async def dump_memory_region(
        self, serial: str, pid: int, start_addr: int, size: int, output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        remote_tmp = f"/data/local/tmp/irves_dump_{pid}_{start_addr:x}.bin"
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"su -c 'dd if=/proc/{pid}/mem bs=1 skip={start_addr} count={size} of={remote_tmp} 2>&1'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
            if output_path:
                pull = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "pull", remote_tmp, output_path,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(pull.communicate(), timeout=30)
            return {"status": "dumped", "pid": pid, "start_addr": hex(start_addr),
                    "size": size, "remote_path": remote_tmp, "local_path": output_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def teardown_probe(self, serial: str) -> Dict[str, Any]:
        logger.info(f"[eBPF] Tearing down probe on {serial}")
        for cmd in [
            "su -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_memfd_create/enable 2>/dev/null || true'",
            "su -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/enable 2>/dev/null || true'",
            "su -c 'rm -f /sys/fs/bpf/irves_dex_monitor 2>/dev/null || true'",
            "su -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null || true'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
        self._active_probes.pop(serial, None)
        return {"status": "teardown", "serial": serial}

    async def get_probe_status(self, serial: str) -> Dict[str, Any]:
        """Return per-probe active flags and host-side compilation status."""
        return {
            "serial": serial,
            "probe_active":     self._active_probes.get(serial, False),
            "net_probe_active": self._active_net_probes.get(serial, False),
            "dex_probe_compiled": PROBE_BINARY.exists(),
            "net_probe_compiled": NET_PROBE_BINARY.exists(),
        }

    async def compile_status(self) -> Dict[str, Any]:
        """Return host-side compilation status for all probes.

        Also attempts compilation of any missing .o files.
        Suitable for the preflight UI check — safe to call with no device.
        """
        results = {}
        for name, binary in [
            ("dex_monitor", PROBE_BINARY),
            ("net_redirect", NET_PROBE_BINARY),
        ]:
            if binary.exists():
                results[name] = {"compiled": True, "path": str(binary)}
            else:
                r = await self._compile_probe(name)
                results[name] = {
                    "compiled": r.get("success", False),
                    "path": str(binary) if r.get("success") else None,
                    "error": r.get("message") or None,
                }
        return results

    # ── Phase 7: Network redirect probe ────────────────────────────────────────

    async def deploy_net_probe(self, serial: str) -> Dict[str, Any]:
        """Deploy net_redirect.bpf probe to device — hooks sys_enter_connect.

        Provides early-bird visibility of outbound connections *before* the
        TLS handshake.  The iptables nat OUTPUT rules (Phase 2B) do the
        actual redirection; this probe supplies the event stream.

        Returns {"status": "deployed"|"deployed_fallback"|"error", ...}
        """
        logger.info(f"[eBPF] Deploying net_redirect probe to {serial}")

        # Compile if not built yet
        if not NET_PROBE_BINARY.exists():
            r = await self._compile_probe("net_redirect")
            if not r.get("success"):
                logger.warning(f"[eBPF] net_redirect compile failed: {r.get('message')} — using fallback")
                return await self._deploy_net_fallback(serial)

        # Push binary to device
        remote = "/data/local/tmp/irves_net_redirect.bpf.o"
        push = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "push", str(NET_PROBE_BINARY), remote,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, push_err = await asyncio.wait_for(push.communicate(), timeout=30)
        if push.returncode != 0:
            return {"status": "error",
                    "message": f"adb push failed: {push_err.decode(errors='replace').strip()}"}

        # Load and attach via bpftool
        bpf_path = "/sys/fs/bpf/irves_net_redirect"
        for cmd in [
            "su -c 'mkdir -p /sys/fs/bpf'",
            f"su -c 'bpftool prog load {remote} {bpf_path} 2>&1'",
            f"su -c 'bpftool prog attach {bpf_path} tracepoint syscalls:sys_enter_connect 2>&1 || true'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=15)

        # Verify
        vp = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "su -c 'bpftool prog show name irves_net_redirect 2>&1'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        vo, _ = await asyncio.wait_for(vp.communicate(), timeout=10)
        if "irves_net_redirect" in vo.decode(errors="replace"):
            self._active_net_probes[serial] = True
            return {
                "status": "deployed",
                "serial": serial,
                "message": "net_redirect probe deployed (sys_enter_connect tracepoint)",
            }

        return await self._deploy_net_fallback(serial)

    async def _deploy_net_fallback(self, serial: str) -> Dict[str, Any]:
        """Fallback — enable sys_enter_connect tracepoint via debugfs."""
        for cmd in [
            "su -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/enable 2>/dev/null || true'",
            "su -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null || true'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
        self._active_net_probes[serial] = True
        return {
            "status": "deployed_fallback",
            "serial": serial,
            "message": "net_redirect fallback active (debugfs sys_enter_connect tracepoint)",
        }

    async def monitor_connect_syscalls(
        self,
        serial: str,
        target_pid: Optional[int] = None,
        duration_seconds: int = 300,
        interesting_only: bool = True,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Stream outbound TCP connect() events from trace_pipe.

        Parses lines emitted by net_redirect.bpf or the debugfs fallback.
        Each yielded dict: {pid, comm, port, addr, ts, filtered}

        Args:
            serial: ADB device serial
            target_pid: If set, filter to a specific PID
            duration_seconds: Max monitoring duration
            interesting_only: If True, only yield high-value ports (80/443/…)
        """
        logger.info(f"[eBPF] Starting connect monitor on {serial}")
        if not self._active_net_probes.get(serial):
            yield {"event_type": "error", "message": "No net probe active — call deploy_net_probe first"}
            return

        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            "su -c 'cat /sys/kernel/debug/tracing/trace_pipe'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        elapsed = 0.0
        INTERESTING_PORTS = {80, 443, 8080, 8443, 4443, 3000, 5000, 9090}

        try:
            while elapsed < duration_seconds:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    elapsed += 2.0
                    for line in chunk.decode(errors="replace").split("\n"):
                        ev = self._parse_connect_trace(line.strip())
                        if not ev:
                            continue
                        if target_pid and ev.get("pid") != target_pid:
                            continue
                        if interesting_only and ev.get("port") not in INTERESTING_PORTS:
                            continue
                        yield ev
                except asyncio.TimeoutError:
                    elapsed += 2.0
                    continue
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def _parse_connect_trace(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a trace_pipe line emitted by net_redirect.bpf.

        The probe emits via bpf_printk:
            irves_net: pid=<N> port=<P> af=<A>
        Plus the standard trace_pipe prefix:
            <comm>-<pid> [cpu] .... irves_net: ...
        """
        if "irves_net:" not in line:
            # Also try to parse sys_enter_connect fallback lines
            if "sys_enter_connect" not in line:
                return None
            m = re.match(r"^\s*(\S+)-(\d+)\s+\[(\d+)\]", line)
            if not m:
                return None
            return {
                "event_type": "connect",
                "comm": m.group(1),
                "pid": int(m.group(2)),
                "port": 0,
                "addr": "",
                "filtered": False,
                "raw": line,
            }

        # Parse bpf_printk output: irves_net: pid=N port=P af=A
        try:
            pid_m  = re.search(r"pid=(\d+)",  line)
            port_m = re.search(r"port=(\d+)", line)
            af_m   = re.search(r"af=(\d+)",   line)
            comm_m = re.match(r"^\s*(\S+)-(\d+)", line)

            pid  = int(pid_m.group(1))  if pid_m  else 0
            port = int(port_m.group(1)) if port_m else 0
            af   = int(af_m.group(1))   if af_m   else 0
            comm = comm_m.group(1)      if comm_m else ""

            return {
                "event_type": "connect",
                "pid":      pid,
                "comm":     comm,
                "port":     port,
                "af":       af,
                "addr":     "",      # ringbuf path has full addr; trace_pipe has port only
                "filtered": port in {80, 443, 8080, 8443, 4443, 3000, 5000, 9090},
                "raw":      line,
            }
        except Exception:
            return None

    async def teardown_net_probe(self, serial: str) -> Dict[str, Any]:
        """Detach and remove the net_redirect probe from the device."""
        logger.info(f"[eBPF] Tearing down net probe on {serial}")
        for cmd in [
            "su -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/enable 2>/dev/null || true'",
            "su -c 'rm -f /sys/fs/bpf/irves_net_redirect 2>/dev/null || true'",
        ]:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
        self._active_net_probes.pop(serial, None)
        return {"status": "teardown_net", "serial": serial}

    # ── Root environment detection (extended, new callers only) ───────────────

    async def check_root_env(self, serial: str) -> Dict[str, Any]:
        """
        Extended root environment detection.
        Returns impl, ebpf_capable, kernel_version, and a kernelsu_available
        alias for backward compatibility with existing callers of check_kernelsu().
        """
        from services.root_wrapper import root_wrapper
        impl = await root_wrapper.detect(serial)

        kv_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "uname -r",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        kv_out, _ = await asyncio.wait_for(kv_proc.communicate(), timeout=10)
        kver = kv_out.decode(errors="replace").strip()

        ebpf_ok = self._kv_supported(kver)

        return {
            "serial": serial,
            "impl": impl,
            "kernel_version": kver,
            "ebpf_capable": ebpf_ok,
            "kernelsu_available": impl == "ksu",   # compat alias
        }

    # ── Transparent TCP redirect via iptables nat ─────────────────────────────

    def __init__(self):
        self._active_redirects: Dict[str, int] = {}
        self._heartbeat_tasks: Dict[str, asyncio.Task] = {}

    async def _stealth_heartbeat(self, serial: str, proxy_port: int):
        """Background task to continuously re-apply stealth rules if netd flushes them."""
        from services.root_wrapper import root_wrapper
        logger.info(f"[Stealth-Heartbeat] Started for {serial}")
        
        while serial in self._active_redirects:
            try:
                # Check if our custom chain is still linked in the OUTPUT nat chain
                out, rc = await root_wrapper.shell(serial, "iptables -t nat -L OUTPUT 2>/dev/null | grep IRVES_STEALTH")
                
                if rc != 0 or "IRVES_STEALTH" not in out:
                    logger.warning(f"[Stealth-Heartbeat] Rules missing on {serial}! Re-applying...")
                    await self._apply_stealth_rules(serial, proxy_port, root_wrapper)

                # Also re-scrub proxy properties (Android may reset them)
                proxy_check, _ = await root_wrapper.shell(
                    serial, "settings get global http_proxy 2>/dev/null"
                )
                if proxy_check.strip() and proxy_check.strip() != ":0":
                    logger.warning(f"[Stealth-Heartbeat] Proxy setting leaked on {serial}: {proxy_check.strip()}")
                    await root_wrapper.shell(serial, "settings put global http_proxy :0")
                    await root_wrapper.shell(serial, "setprop http.proxyHost :0")
                    await root_wrapper.shell(serial, "setprop https.proxyHost :0")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Stealth-Heartbeat] Error on {serial}: {e}")
                
            await asyncio.sleep(3)  # Poll every 3 seconds
            
        logger.info(f"[Stealth-Heartbeat] Stopped for {serial}")

    async def _apply_stealth_rules(self, serial: str, proxy_port: int, root_wrapper) -> bool:
        """Applies the hardened stealth iptables rules using custom chains."""
        cmds = [
            # 1. Cleanup old chains if they exist
            "iptables -t nat -D OUTPUT -j IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -D OUTPUT -j IRVES_STEALTH_FLT 2>/dev/null || true",
            "iptables -t nat -F IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -F IRVES_STEALTH_FLT 2>/dev/null || true",
            "iptables -t nat -X IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -X IRVES_STEALTH_FLT 2>/dev/null || true",
            
            # 2. Create custom chains
            "iptables -t nat -N IRVES_STEALTH",
            "iptables -t filter -N IRVES_STEALTH_FLT",
            
            # 3. Add TCP Redirects (Ports 80, 443) -> Proxy
            f"iptables -t nat -A IRVES_STEALTH -p tcp --dport 443 -j REDIRECT --to-port {proxy_port}",
            f"iptables -t nat -A IRVES_STEALTH -p tcp --dport 80  -j REDIRECT --to-port {proxy_port}",
            
            # 4. Add UDP Reject (Kill QUIC to force TCP fallback)
            "iptables -t filter -A IRVES_STEALTH_FLT -p udp --dport 443 -j REJECT",
            
            # 5. Link custom chains to the top of the OUTPUT chains
            "iptables -t nat -I OUTPUT 1 -j IRVES_STEALTH",
            "iptables -t filter -I OUTPUT 1 -j IRVES_STEALTH_FLT",
            
            # 6. Disable IPv6 globally (Prevent "Dual-Stack Leak")
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=1",

            # 7. Scrub proxy indicators from Java system properties
            #    Apps check these via System.getProperty() to detect proxy presence.
            #    Standard setprop requires a value, so we use :0 (dead address).
            "setprop http.proxyHost :0",
            "setprop http.proxyPort :0",
            "setprop https.proxyHost :0",
            "setprop https.proxyPort :0",
            "setprop http.nonProxyHosts :0",
            "setprop persist.http.proxyHost :0",
            "setprop persist.http.proxyPort :0",
            "setprop persist.https.proxyHost :0",
            "setprop persist.https.proxyPort :0",

            # 8. Ensure Settings.Global http_proxy is blank (not just ":0")
            "settings put global http_proxy :0",
        ]
        
        success = True
        for cmd in cmds:
            out, rc = await root_wrapper.shell(serial, cmd)
            # We ignore errors on cleanup commands (which have || true)
            if rc != 0 and "|| true" not in cmd:
                logger.warning(f"[eBPF-Redirect] Rule failed: {cmd!r} → {out.strip()!r}")
                success = False
                
        return success

    async def enable_transparent_redirect(
        self, serial: str, proxy_port: int = 8080
    ) -> Dict[str, Any]:
        """
        Redirect all device TCP 80 + 443 traffic to proxy_port via hardened iptables nat.
        Blocks UDP 443 (QUIC), disables IPv6, and uses a heartbeat to prevent netd flushes.
        Clears Settings.Global http_proxy so apps see a direct connection.

        Returns: {"status": "active"|"error", "rules": [...], "message": "..."}
        """
        from services.root_wrapper import root_wrapper

        impl = await root_wrapper.detect(serial)
        if impl == "none":
            return {"status": "error", "message": "No root access on device"}

        logger.info(f"[eBPF-Redirect] Enabling hardened transparent redirect on {serial} → :{proxy_port}")

        # 1. Apply the hardened stealth rules
        success = await self._apply_stealth_rules(serial, proxy_port, root_wrapper)
        
        if not success:
             return {"status": "error", "message": "Failed to apply iptables stealth rules."}

        # 2. Hide proxy from apps via Settings.Global
        hide_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            'settings put global http_proxy ":0"',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(hide_proc.communicate(), timeout=8)

        # 3. Verify rules landed
        verify_out, _ = await root_wrapper.shell(
            serial, "iptables -t nat -L IRVES_STEALTH --line-numbers 2>/dev/null"
        )
        rules = [l.strip() for l in verify_out.splitlines() if "REDIRECT" in l]

        if rules:
            self._active_redirects[serial] = proxy_port
            
            # Start the heartbeat task
            if serial in self._heartbeat_tasks and not self._heartbeat_tasks[serial].done():
                self._heartbeat_tasks[serial].cancel()
            self._heartbeat_tasks[serial] = asyncio.create_task(self._stealth_heartbeat(serial, proxy_port))
            
            logger.info(f"[eBPF-Redirect] Active on {serial}: {rules}")
            return {"status": "active", "rules": rules,
                    "message": f"Hardened stealth mode active (TCP 80/443 → :{proxy_port}, UDP 443 blocked, IPv6 disabled)."}
        else:
            return {"status": "error",
                    "message": "iptables rules applied but could not be verified. "
                               "Device may not support iptables nat redirect."}

    async def disable_transparent_redirect(self, serial: str) -> Dict[str, Any]:
        """
        Remove hardened stealth mode: stop heartbeat, flush custom chains, restore IPv6,
        and restore the explicit proxy setting.
        """
        from services.root_wrapper import root_wrapper

        impl = await root_wrapper.detect(serial)
        if impl == "none":
            return {"status": "error", "message": "No root access on device"}

        logger.info(f"[eBPF-Redirect] Disabling hardened transparent redirect on {serial}")
        
        # 1. Stop heartbeat
        if serial in self._heartbeat_tasks:
            self._heartbeat_tasks[serial].cancel()
            del self._heartbeat_tasks[serial]

        self._active_redirects.pop(serial, None)

        # 2. Flush and remove custom chains, restore IPv6
        cmds = [
            "iptables -t nat -D OUTPUT -j IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -D OUTPUT -j IRVES_STEALTH_FLT 2>/dev/null || true",
            "iptables -t nat -F IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -F IRVES_STEALTH_FLT 2>/dev/null || true",
            "iptables -t nat -X IRVES_STEALTH 2>/dev/null || true",
            "iptables -t filter -X IRVES_STEALTH_FLT 2>/dev/null || true",
            "sysctl -w net.ipv6.conf.all.disable_ipv6=0",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=0",
            # Restore proxy system properties
            "setprop http.proxyHost :0",
            "setprop http.proxyPort :0",
            "setprop https.proxyHost :0",
            "setprop https.proxyPort :0",
        ]
        
        for cmd in cmds:
            await root_wrapper.shell(serial, cmd)

        # 3. Restore explicit proxy setting
        proxy_port = self._active_redirects.get(serial, 8080)
        restore_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            f'settings put global http_proxy "127.0.0.1:{proxy_port}"',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(restore_proc.communicate(), timeout=8)

        return {"status": "disabled",
                "message": f"Stealth mode removed. Proxy restored to 127.0.0.1:{proxy_port}."}

    def redirect_active(self, serial: str) -> bool:
        """Return True if transparent redirect is currently active for this serial."""
        return serial in self._active_redirects


ebpf_service = EBPFService()
