"""
IRVES Network Service — runs mitmdump as a subprocess.

Architecture:
  - mitmdump process listens on port 8080, runs mitm_addon.py
  - mitm_addon.py POSTs each completed flow to /internal/network/flow on the
    FastAPI server (same port, e.g. 127.0.0.1:8765)
  - The /internal/network/flow route (in routes/network.py) ingests the flow
    and fans it out to all registered WebSocket listeners
  - ADB reverse + proxy system settings bind the Android device to port 8080
"""
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

ADDON_PATH           = Path(__file__).parent / "mitm_addon.py"
PROXY_PORT           = 8080
MAX_RESTART_ATTEMPTS = 5
BASE_RETRY_DELAY     = 5   # seconds (doubles each failure, capped at 60s) - increased for TIME_WAIT


class NetworkService:
    def __init__(self):
        self._listeners: list[Callable] = []
        self.flows: dict[str, dict] = {}
        self._process: asyncio.subprocess.Process | None = None
        self.is_running: bool = False
        self.proxy_port: int = PROXY_PORT
        self._watchdog_task: asyncio.Task | None = None   # ONE watchdog ever
        self._fastapi_port: int = 8765

    # ── Listener management ───────────────────────────────────────────────────

    def add_listener(self, listener: Callable):
        self._listeners.append(listener)

    def remove_listener(self, listener: Callable):
        if listener in self._listeners:
            self._listeners.remove(listener)

    def ingest_flow(self, flow_data: dict):
        """
        Called by the /internal/network/flow route when mitm_addon POSTs a flow.
        Stores the full flow and broadcasts a compact summary to WS listeners.
        """
        fid = flow_data.get("id", "")
        if fid:
            self.flows[fid] = flow_data
            # Memory cap — keep only last 5 000 flows
            if len(self.flows) > 5000:
                oldest = next(iter(self.flows))
                del self.flows[oldest]

            summary = {
                "id":             fid,
                "method":         flow_data.get("method", ""),
                "host":           flow_data.get("host", ""),
                "path":           flow_data.get("path", ""),
                "url":            flow_data.get("url", ""),
                "status_code":    flow_data.get("status_code", 0),
                "content_length": flow_data.get("content_length", 0),
                "timestamp":      flow_data.get("timestamp", 0),
                "secrets":        flow_data.get("secrets", []),
                "pinning_detected": flow_data.get("pinning_detected", False),
                "pinning_confidence": flow_data.get("pinning_confidence", ""),
                "error_type": flow_data.get("error_type", ""),
                "is_modified": flow_data.get("is_modified", False),
                "intercept_match": flow_data.get("intercept_match", False),
                "matched_rule_id": flow_data.get("matched_rule_id"),
                "is_websocket": flow_data.get("is_websocket", False),
                "is_grpc": flow_data.get("is_grpc", False),
                "protocol_type": flow_data.get("protocol_type", "http"),
            }
            self._broadcast(summary)

    def _broadcast(self, data: dict):
        """Fan-out to all registered WebSocket listeners."""
        for listener in list(self._listeners):
            try:
                if asyncio.iscoroutinefunction(listener):
                    asyncio.create_task(listener(data))
                else:
                    listener(data)
            except Exception as e:
                logger.error(f"[Network] Listener error: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self, fastapi_port: int = 8765):
        """Initialize network service (lazy - doesn't spawn proxy until needed)."""
        self._fastapi_port = fastapi_port
        logger.info(f"[Network] Service initialized (proxy will start on demand)")

    async def _ensure_running(self):
        """Ensure proxy is running, spawn if needed."""
        if self.is_running:
            return
        
        try:
            await self._spawn_mitmdump()
            self.is_running = True
            logger.info(f"[Network] Proxy ready on 0.0.0.0:{PROXY_PORT}")
        except Exception as e:
            logger.error(f"[Network] Failed to start proxy: {e}")
            self.is_running = False
            raise

        # Guarantee ONE watchdog for the entire service lifetime
        if self._watchdog_task is None or self._watchdog_task.done():
            self._watchdog_task = asyncio.create_task(self._watchdog())

    async def stop(self):
        logger.info("[Network] Stopping proxy…")
        self.is_running = False   # signals watchdog to exit cleanly

        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass

        await self._kill_process()
        logger.info("[Network] Proxy stopped.")

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _spawn_mitmdump(self):
        """Launch the mitmdump subprocess. Never creates watchdog tasks."""
        venv_python = sys.executable
        mitmdump_bin = Path(venv_python).parent / "mitmdump"
        if not mitmdump_bin.exists():
            import shutil
            mitmdump_bin = shutil.which("mitmdump") or "mitmdump"

        # Verify addon exists
        if not ADDON_PATH.exists():
            raise RuntimeError(f"Addon script not found at {ADDON_PATH}")

        # Ensure certificate directory exists and is initialized (only when proxy is actually needed)
        await self._ensure_certificates()

        # Mitmproxy natively loads the Root CA from confdir/mitmproxy-ca.pem
        cmd = [
            str(mitmdump_bin),
            "-s", str(ADDON_PATH),
            "--listen-host", "0.0.0.0",
            "--listen-port", str(PROXY_PORT),
            "--ssl-insecure",
            "--set", "confdir=/tmp/irves_mitmproxy",
            "--set", "block_global=false",
        ]

        env = os.environ.copy()
        env["IRVES_INGEST_PORT"] = str(self._fastapi_port)

        logger.info(f"[Network] Spawning mitmdump on port {PROXY_PORT}, ingest→:{self._fastapi_port}")
        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        logger.info(f"[Network] mitmdump started (pid={self._process.pid})")
        
        # Wait a bit to ensure process doesn't crash immediately
        await asyncio.sleep(1.0)
        if self._process.returncode is not None:
            # Process exited, read remaining output
            try:
                stdout, stderr = await asyncio.wait_for(self._process.communicate(), timeout=2)
                error_msg = stderr.decode(errors='replace') if stderr else stdout.decode(errors='replace')
            except Exception:
                error_msg = "Unable to capture error output"
            logger.error(f"[Network] mitmdump stderr: {error_msg}")
            raise RuntimeError(f"mitmdump failed to start (rc={self._process.returncode}): {error_msg}")
        
        # Drain stderr and stdout for this specific process instance
        asyncio.create_task(self._drain_stderr(self._process))
        asyncio.create_task(self._drain_stdout(self._process))

    async def _drain_stdout(self, proc: asyncio.subprocess.Process):
        """Consume stdout of one mitmdump process to avoid pipe blocking."""
        while proc.returncode is None:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                if line:
                    decoded = line.decode(errors='replace').rstrip()
                    if "[IRVES addon]" in decoded:
                        logger.info(decoded)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    async def _drain_stderr(self, proc: asyncio.subprocess.Process):
        """Consume stderr of one mitmdump process to avoid pipe blocking."""
        while proc.returncode is None:
            try:
                line = await asyncio.wait_for(proc.stderr.readline(), timeout=1.0)
                if line:
                    decoded = line.decode(errors='replace').rstrip()
                    # Log errors and warnings at higher level
                    if 'error' in decoded.lower() or 'exception' in decoded.lower():
                        logger.warning(f"[mitmdump] {decoded}")
                    else:
                        logger.debug(f"[mitmdump] {decoded}")
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    async def _watchdog(self):
        """
        Single, persistent watchdog. Waits for the process to exit then
        restarts with exponential back-off. Resets failure counter after a
        stable run (>10 s). Stops when self.is_running is False.
        """
        consecutive_failures = 0

        while self.is_running:
            if self._process is None:
                await asyncio.sleep(1)
                continue

            await self._process.wait()   # blocks until the current process dies

            if not self.is_running:
                break   # intentional shutdown

            rc = self._process.returncode
            consecutive_failures += 1

            if consecutive_failures > MAX_RESTART_ATTEMPTS:
                logger.error(
                    "[Network] mitmdump failed to restart after max attempts — "
                    "proxy is down. Restart IRVES to try again."
                )
                self.is_running = False
                break

            delay = min(BASE_RETRY_DELAY * (2 ** (consecutive_failures - 1)), 60)
            logger.warning(
                f"[Network] mitmdump exited (rc={rc}), "
                f"restarting in {delay}s (attempt {consecutive_failures}/{MAX_RESTART_ATTEMPTS})…"
            )
            await asyncio.sleep(delay)

            try:
                await self._spawn_mitmdump()
                # Wait 10 s; if still alive, treat as a stable run & reset counter
                await asyncio.sleep(10)
                if self._process and self._process.returncode is None:
                    consecutive_failures = 0
                    logger.info("[Network] mitmdump stable — failure counter reset.")
            except Exception as e:
                logger.error(f"[Network] Restart failed: {e}")

    # ── Camouflaged CA subject — mimics a legitimate Android system CA ──────
    _CA_SUBJECT = (
        "/C=US/ST=California/L=Mountain View/O=Google LLC/"
        "OU=Android Security/CN=Android System CA"
    )

    async def _generate_camouflaged_ca(self, confdir: Path) -> bool:
        """
        Generate a custom CA with a legitimate-looking subject instead of
        mitmproxy's default O=mitmproxy / CN=mitmproxy which is instantly
        fingerprinted by pinning-aware apps.

        Returns True if the camouflaged CA was freshly generated.
        """
        ca_pem = confdir / "mitmproxy-ca-cert.pem"
        ca_key = confdir / "mitmproxy-ca-key.pem"
        ca_cer = confdir / "mitmproxy-ca-cert.cer"
        marker  = confdir / ".irves_camouflaged"

        # Already camouflaged? Skip regeneration.
        if marker.exists() and ca_pem.exists() and ca_key.exists():
            return False

        logger.info("[Network] Generating camouflaged CA (subject: %s)", self._CA_SUBJECT)

        # 1. Generate RSA key (2048-bit, same as mitmproxy default)
        key_gen = await asyncio.create_subprocess_exec(
            "openssl", "genrsa", "-out", str(ca_key), "2048",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(key_gen.communicate(), timeout=15)
        if key_gen.returncode != 0:
            logger.error("[Network] RSA key generation failed: %s", err.decode(errors="replace"))
            return False

        # 2. Generate self-signed CA cert with camouflaged subject.
        #    openssl req -x509 auto-generates a random 64-bit serial.
        #    Use -addext (OpenSSL 3.x) instead of -extfile/-extensions
        #    which are only valid for `openssl x509`, not `openssl req`.
        cert_gen = await asyncio.create_subprocess_exec(
            "openssl", "req",
            "-new", "-x509",
            "-key", str(ca_key),
            "-out", str(ca_pem),
            "-days", "3650",
            "-subj", self._CA_SUBJECT,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-addext", "authorityKeyIdentifier=keyid:always,issuer",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(cert_gen.communicate(), timeout=15)
        if cert_gen.returncode != 0:
            logger.error("[Network] CA cert generation failed: %s", err.decode(errors="replace"))
            return False

        # 3. Convert PEM → DER (.cer) for Android push
        der_gen = await asyncio.create_subprocess_exec(
            "openssl", "x509",
            "-inform", "PEM",
            "-in", str(ca_pem),
            "-outform", "DER",
            "-out", str(ca_cer),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(der_gen.communicate(), timeout=10)
        if der_gen.returncode != 0:
            logger.warning("[Network] DER conversion failed: %s", err.decode(errors="replace"))

        # 4. Create mitmproxy-ca.pem (mitmproxy needs Key + Cert concatenated)
        ca_combined = confdir / "mitmproxy-ca.pem"
        try:
            with open(ca_combined, "w") as f_out:
                with open(ca_key, "r") as f_key:
                    f_out.write(f_key.read())
                with open(ca_pem, "r") as f_cert:
                    f_out.write(f_cert.read())
            ca_combined.chmod(0o600)
        except Exception as e:
            logger.error(f"[Network] Failed to concatenate mitmproxy-ca.pem: {e}")
            return False

        # 5. Set permissions
        try:
            ca_pem.chmod(0o644)
            ca_cer.chmod(0o644)
            ca_key.chmod(0o600)
        except Exception:
            pass

        # 6. Write marker so we never regenerate on top of existing
        marker.write_text("irves_camouflaged")

        logger.info("[Network] Camouflaged CA generated: %s", ca_combined)
        return True

    async def _ensure_certificates(self):
        """
        Ensure mitmproxy certificates are generated and properly formatted.
        Generates a camouflaged CA with a legitimate-looking subject instead
        of the default O=mitmproxy which is instantly fingerprinted.
        """
        confdir = Path("/tmp/irves_mitmproxy")
        confdir.mkdir(parents=True, exist_ok=True)

        ca_pem = confdir / "mitmproxy-ca-cert.pem"
        ca_cer = confdir / "mitmproxy-ca-cert.cer"
        ca_key = confdir / "mitmproxy-ca-key.pem"

        # Generate camouflaged CA if not already present
        freshly_generated = await self._generate_camouflaged_ca(confdir)
        if freshly_generated:
            logger.info("[Network] New camouflaged CA created")
        elif ca_pem.exists() and ca_key.exists():
            logger.debug("[Network] Existing camouflaged CA found")
        else:
            # Fallback: if custom generation failed, let mitmdump generate default
            logger.warning("[Network] Camouflaged CA generation failed, falling back to mitmproxy default")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "mitmdump",
                    "--set", f"confdir={confdir}",
                    "-q",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=10)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            except Exception as e:
                logger.warning(f"[Network] Fallback cert generation failed: {e}")

        # Wait a moment for filesystem sync
        await asyncio.sleep(0.5)

        # Convert PEM to CER format if PEM exists but CER doesn't
        if ca_pem.exists() and not ca_cer.exists():
            try:
                logger.info("[Network] Converting certificate to CER format...")
                proc = await asyncio.create_subprocess_exec(
                    "openssl", "x509",
                    "-inform", "PEM",
                    "-in", str(ca_pem),
                    "-outform", "DER",
                    "-out", str(ca_cer),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0 and ca_cer.exists():
                    logger.info(f"[Network] Certificate converted to CER: {ca_cer}")
                else:
                    logger.warning(f"[Network] OpenSSL conversion failed (rc={proc.returncode}): {stderr.decode()}")
            except Exception as e:
                logger.warning(f"[Network] Certificate conversion failed: {e}")

        # Ensure proper permissions
        try:
            if ca_pem.exists():
                ca_pem.chmod(0o644)
            if ca_cer.exists():
                ca_cer.chmod(0o644)
            if ca_key.exists():
                ca_key.chmod(0o600)
        except Exception as e:
            logger.warning(f"[Network] Failed to set certificate permissions: {e}")

        # Verify certificates exist
        if ca_pem.exists() and ca_cer.exists():
            logger.info(f"[Network] CA certificates ready: {ca_pem} and {ca_cer}")
        elif ca_pem.exists():
            logger.warning(f"[Network] PEM exists but CER not found: {ca_pem}")
        else:
            logger.warning("[Network] CA certificate not generated - proxy may not intercept HTTPS")

    async def _kill_process(self):
        if self._process:
            try:
                self._process.send_signal(signal.SIGTERM)
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
        
        # Clean up any lingering mitmdump processes on the port
        try:
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-f", f"mitmdump.*:8080",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.wait()
        except Exception:
            pass


network_service = NetworkService()
