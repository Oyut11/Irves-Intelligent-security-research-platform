"""
IRVES — Network Routes: Proxy
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
import time
import uuid
from services.network_service import network_service
from services.root_wrapper import root_wrapper
from services.ebpf_service import ebpf_service
from services.frida_service import frida_service
from services.ai_service import ai_service
from services.security_analyzer import security_analyzer
from services.ct_monitor import ct_monitor
from services.fritap_capture import fritap_service

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/proxy/enable/{serial}")
async def enable_proxy(serial: str, request: Request):
    """Route Android traffic to the local mitmproxy via ADB."""
    params = dict(request.query_params)
    mode = params.get("mode", "standard")
    target_package = params.get("package", "")

    try:
        # Ensure proxy is running before binding device
        try:
            await network_service._ensure_running()
        except Exception as e:
            logger.error(f"[Network] Failed to start proxy: {e}")
            return {
                "status": "error",
                "message": f"Failed to start proxy: {str(e)}"
            }
        
        # Verify certificate exists before proceeding
        cert_path = "/tmp/irves_mitmproxy/mitmproxy-ca-cert.cer"
        import os
        
        if not os.path.exists(cert_path):
            # Try to use PEM as fallback
            pem_path = "/tmp/irves_mitmproxy/mitmproxy-ca-cert.pem"
            if os.path.exists(pem_path):
                logger.warning(f"[Network] CER not found, using PEM fallback")
                cert_path = pem_path
            else:
                return {
                    "status": "error",
                    "message": f"CA certificate not found at {cert_path}. Ensure the proxy has been started."
                }
        
        # Verify certificate file is not empty
        if os.path.getsize(cert_path) == 0:
            return {
                "status": "error",
                "message": f"CA certificate at {cert_path} is empty. Proxy may not have generated it properly."
            }

        # ADB reverse: device port 8080 → host port 8080
        proc1 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} reverse tcp:8080 tcp:8080",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, err1 = await asyncio.wait_for(proc1.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            return {"status": "error", "message": "ADB reverse command timed out. Device may be offline."}

        # Tell Android to use 127.0.0.1:8080 as its global HTTP proxy
        proc2 = await asyncio.create_subprocess_shell(
            f'adb -s {serial} shell settings put global http_proxy "127.0.0.1:8080"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, err2 = await asyncio.wait_for(proc2.communicate(), timeout=10.0)
        except asyncio.TimeoutError:
            return {"status": "error", "message": "ADB settings command timed out. Device may be offline."}

        errors = []
        if proc1.returncode != 0:
            errors.append(f"reverse: {err1.decode().strip()}")
        if proc2.returncode != 0:
            errors.append(f"set_proxy: {err2.decode().strip()}")

        if mode == "system_root":
            # ── Root / System Installation (Ghost CA) ────────────────────────
            ca_verified = False
            root_impl = "none"
            cert_msg = "CA cert not found on host"

            if os.path.exists(cert_path):
                try:
                    # 0. Detect root implementation
                    root_impl = await root_wrapper.detect(serial)
                    if root_impl == "none":
                        errors.append("No root access detected on device")
                    else:
                        # 1. Get OpenSSL subject hash. Always prefer the .pem file since
                        # openssl reads PEM natively. Fall back to DER only if PEM missing.
                        import re as _re
                        pem_file = "/tmp/irves_mitmproxy/mitmproxy-ca-cert.pem"
                        cert_hash = ""
                        
                        # Try PEM first
                        if os.path.exists(pem_file):
                            hp = await asyncio.create_subprocess_exec(
                                "openssl", "x509", "-inform", "PEM",
                                "-subject_hash_old", "-noout", "-in", pem_file,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            out, err = await hp.communicate()
                            candidate = out.decode().strip().split("\n")[0].strip() if out else ""
                            if _re.fullmatch(r"[0-9a-f]{8}", candidate):
                                cert_hash = candidate
                            else:
                                logger.warning(f"[Network] PEM hash invalid: out={candidate!r} err={err.decode()!r}")
                        
                        # Fall back to DER
                        if not cert_hash and cert_path.endswith(".cer"):
                            hp = await asyncio.create_subprocess_exec(
                                "openssl", "x509", "-inform", "DER",
                                "-subject_hash_old", "-noout", "-in", cert_path,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            out, err = await hp.communicate()
                            candidate = out.decode().strip().split("\n")[0].strip() if out else ""
                            if _re.fullmatch(r"[0-9a-f]{8}", candidate):
                                cert_hash = candidate
                            else:
                                logger.warning(f"[Network] DER hash invalid: out={candidate!r} err={err.decode()!r}")

                        if cert_hash:
                            target_name = f"{cert_hash}.0"

                            # 2. Ensure cert is in PEM format (Android cacerts store expects PEM)
                            pem_source = "/tmp/irves_mitmproxy/mitmproxy-ca-cert.pem"
                            if not os.path.exists(pem_source) and cert_path.endswith(".cer"):
                                # Convert DER → PEM
                                conv_proc = await asyncio.create_subprocess_shell(
                                    f"openssl x509 -inform DER -in {cert_path} -outform PEM -out {pem_source}",
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.PIPE,
                                )
                                await asyncio.wait_for(conv_proc.communicate(), timeout=10)

                            # 3. Push PEM cert to device staging
                            push_proc = await asyncio.create_subprocess_exec(
                                "adb", "-s", serial, "push", pem_source, f"/data/local/tmp/{target_name}",
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                            )
                            await asyncio.wait_for(push_proc.communicate(), timeout=30)

                            # 4. Build the on-device injection script.
                            # Professional self-diagnosing version that handles Android 14+ APEX
                            # conscrypt properly and reports the exact failure reason.
                            # Per-app CA injection: target only the specified
                            # package's mount namespace instead of polluting all apps.
                            inject_script = f"""
CERT=/data/local/tmp/{target_name}
STAGING=/data/local/tmp/irves-cacerts
APEX_DIR=/apex/com.android.conscrypt/cacerts
SYS_DIR=/system/etc/security/cacerts
TGT={target_name}
TARGET_PKG="{target_package}"

# Check prerequisites
if [ ! -f "$CERT" ]; then echo "IRVES_FAIL: cert push missing at $CERT"; exit 1; fi
if ! command -v mount >/dev/null 2>&1; then echo "IRVES_FAIL: no mount binary"; exit 1; fi

# Prepare staging — copy ALL existing certs so we don't lose trust
rm -rf $STAGING
mkdir -p $STAGING || {{ echo "IRVES_FAIL: mkdir $STAGING"; exit 1; }}

# Copy existing trust store (APEX is primary on Android 14+)
APEX_COUNT=$(ls $APEX_DIR 2>/dev/null | wc -l)
SYS_COUNT=$(ls $SYS_DIR 2>/dev/null | wc -l)
if [ "$APEX_COUNT" -gt 0 ]; then
  cp $APEX_DIR/* $STAGING/ 2>/dev/null
elif [ "$SYS_COUNT" -gt 0 ]; then
  cp $SYS_DIR/* $STAGING/ 2>/dev/null
fi

# Add our CA
cp $CERT $STAGING/$TGT || {{ echo "IRVES_FAIL: cp $CERT -> $STAGING"; exit 1; }}
chown -R root:root $STAGING 2>/dev/null
chmod 644 $STAGING/* 2>/dev/null
chcon -R u:object_r:system_file:s0 $STAGING 2>/dev/null

# ── Per-app injection (stealth): only target app's mount namespace ──────
INJECTED_PIDS=""
NSENTER_OK=0

# Helper to run nsenter with timeout to prevent hangs on frozen processes
nsenter_safe() {{
  if command -v timeout >/dev/null 2>&1; then
    timeout 2 nsenter "$@"
  else
    # Fallback if no timeout command: background and wait
    nsenter "$@" &
    NSPID=$!
    sleep 2
    kill -0 $NSPID 2>/dev/null && kill -9 $NSPID 2>/dev/null
  fi
}}

if [ -n "$TARGET_PKG" ]; then
  # Resolve PIDs for the target package
  for pid in $(pidof $TARGET_PKG 2>/dev/null); do
    if [ -d "/proc/$pid/ns/mnt" ]; then
      nsenter_safe --mount=/proc/$pid/ns/mnt -- /system/bin/mount --bind $STAGING $APEX_DIR 2>/dev/null
      nsenter_safe --mount=/proc/$pid/ns/mnt -- /system/bin/mount --bind $STAGING $SYS_DIR 2>/dev/null
      if [ $? -eq 0 ]; then
        INJECTED_PIDS="$INJECTED_PIDS $pid"
        NSENTER_OK=1
      fi
    fi
  done
fi

# ── Fallback: if no target PIDs found, inject into zygote (legacy) ─────
if [ -z "$INJECTED_PIDS" ]; then
  # Bind-mount over APEX cacerts (root namespace)
  umount $APEX_DIR 2>/dev/null
  APEX_MOUNT_ERR=$(mount --bind $STAGING $APEX_DIR 2>&1)
  APEX_RC=$?
  if [ $APEX_RC -ne 0 ]; then
    APEX_MOUNT_ERR=$(mount -o bind $STAGING $APEX_DIR 2>&1)
    APEX_RC=$?
  fi

  # Bind-mount over /system cacerts (for legacy apps)
  umount $SYS_DIR 2>/dev/null
  SYS_MOUNT_ERR=$(mount --bind $STAGING $SYS_DIR 2>&1)
  SYS_RC=$?
  if [ $SYS_RC -ne 0 ]; then
    SYS_MOUNT_ERR=$(mount -o bind $STAGING $SYS_DIR 2>&1)
    SYS_RC=$?
  fi

  # Propagate into zygote namespaces so forked apps inherit
  if command -v nsenter >/dev/null 2>&1; then
    for z in $(pidof zygote zygote64 2>/dev/null); do
      nsenter_safe --mount=/proc/$z/ns/mnt -- /system/bin/mount --bind $STAGING $APEX_DIR 2>/dev/null
      nsenter_safe --mount=/proc/$z/ns/mnt -- /system/bin/mount --bind $STAGING $SYS_DIR 2>/dev/null
      NSENTER_OK=1
    done
  fi
fi

# Verify result
if [ -n "$INJECTED_PIDS" ]; then
  echo "IRVES_CERT_OK: per-app injection into PIDs:$INJECTED_PIDS (pkg=$TARGET_PKG)"
elif ls $APEX_DIR/$TGT >/dev/null 2>&1; then
  echo "IRVES_CERT_OK: global apex bind succeeded, nsenter=$NSENTER_OK"
elif ls $SYS_DIR/$TGT >/dev/null 2>&1; then
  echo "IRVES_CERT_PARTIAL: only /system bind worked (apex failed: $APEX_MOUNT_ERR)"
else
  echo "IRVES_FAIL: apex_rc=$APEX_RC err='$APEX_MOUNT_ERR' | sys_rc=$SYS_RC err='$SYS_MOUNT_ERR'"
fi
"""
                            
                            # Write script to device (avoids shell-escaping multi-line content)
                            script_local = "/tmp/irves_mitmproxy/inject_ca.sh"
                            with open(script_local, "w") as f:
                                f.write(inject_script)
                            
                            push_script_proc = await asyncio.create_subprocess_exec(
                                "adb", "-s", serial, "push", script_local, "/data/local/tmp/irves-inject-ca.sh",
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                            )
                            await asyncio.wait_for(push_script_proc.communicate(), timeout=15)
                            
                            # Execute the script with root and an explicit timeout
                            try:
                                inject_out, inject_rc = await asyncio.wait_for(
                                    root_wrapper.shell(
                                        serial,
                                        "sh /data/local/tmp/irves-inject-ca.sh"
                                    ),
                                    timeout=20.0
                                )
                            except asyncio.TimeoutError:
                                inject_out = "IRVES_FAIL: CA injection script timed out after 20 seconds. (Possible frozen zygote)."
                                logger.error(f"[Network] CA injection script timed out on {serial}")
                            
                            # Cleanup script
                            await root_wrapper.shell(serial, "rm -f /data/local/tmp/irves-inject-ca.sh")
                            
                            ca_verified = "IRVES_CERT_OK" in inject_out
                            partial = "IRVES_CERT_PARTIAL" in inject_out
                            
                            # Extract the single diagnostic line
                            diag_line = ""
                            for line in inject_out.splitlines():
                                if line.startswith("IRVES_"):
                                    diag_line = line.strip()
                                    break
                            
                            if ca_verified:
                                if "per-app" in diag_line:
                                    cert_msg = f"CA cert injected as {target_name} (per-app namespace: {target_package})"
                                else:
                                    cert_msg = f"CA cert injected as {target_name} (APEX + zygote namespace fallback)"
                                logger.info(f"[Network] {diag_line}")
                            elif partial:
                                ca_verified = True  # treat as success for legacy apps
                                cert_msg = f"CA cert installed to /system store only — works for pre-Android-14 apps. {diag_line}"
                                logger.warning(f"[Network] {diag_line}")
                            else:
                                cert_msg = diag_line or f"CA injection failed: {inject_out.strip()[-250:]}"
                                logger.warning(f"[Network] CA injection failed: {inject_out}")
                        else:
                            errors.append("Could not compute OpenSSL subject hash for CA cert")
                except Exception as cert_err:
                    logger.warning(f"Ghost CA injection failed: {cert_err}")
                    errors.append(f"CA injection error: {cert_err}")

            if errors:
                return {"status": "error", "message": " | ".join(errors)}
            return {
                "status": "success",
                "message": f"Proxy bound. {cert_msg}",
                "ca_verified": ca_verified,
                "root_impl": root_impl,
            }
        else:
            # ── Standard User-Store Installation ───────────────────────────────
            if os.path.exists(cert_path):
                try:
                    proc3 = await asyncio.create_subprocess_shell(
                        f"adb -s {serial} push {cert_path} /sdcard/Download/irves-proxy-cert.cer",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await proc3.communicate()
                    
                    proc4 = await asyncio.create_subprocess_shell(
                        f"adb -s {serial} shell am start -a android.settings.SECURITY_SETTINGS",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await proc4.communicate()
                except Exception as cert_err:
                    logger.warning(f"Failed to push CA cert: {cert_err}")

            if errors:
                return {"status": "error", "message": " | ".join(errors)}
            return {
                "status": "success", 
                "message": f"Proxy bound. Please install 'irves-proxy-cert.cer' from Downloads."
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/proxy/disable/{serial}")
async def disable_proxy(serial: str):
    """Remove Android global proxy setting and ADB reverse."""
    try:
        proc1 = await asyncio.create_subprocess_shell(
            f'adb -s {serial} shell settings put global http_proxy ":0"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc1.communicate(), timeout=8.0)
        except asyncio.TimeoutError:
            logger.warning(f"[Network] disable_proxy settings timeout on {serial}")

        proc2 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} reverse --remove tcp:8080",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc2.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"[Network] disable_proxy reverse timeout on {serial}")

        return {"status": "success", "message": "Proxy disabled."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Flow inspector ────────────────────────────────────────────────────────────

@router.get("/flow/{flow_id}")
async def get_flow(flow_id: str):
    """Retrieve full request/response detail for a captured flow."""
    flow = network_service.flows.get(flow_id)
    if not flow:
        return {"status": "error", "message": "Flow not found"}

    return {
        "status": "success",
        "request": flow.get("request", {}),
        "response": flow.get("response", {}),
        "secrets": flow.get("secrets", []),
    }


# ── Repeater ──────────────────────────────────────────────────────────────────

@router.post("/replay")
async def replay_request(data: dict):
    """Replay a manually-edited request and return the live response."""
    import httpx

    try:
        url = data.get("url")
        if not url:
            return {"status": "error", "message": "URL missing"}

        method = data.get("method", "GET")
        headers = data.get("headers", {})
        content = data.get("content", "")

        # Strip headers that conflict with httpx's own logic
        filtered = {
            k: v
            for k, v in headers.items()
            if k.lower() not in ("host", "content-length", "accept-encoding")
        }

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=filtered,
                content=content.encode("utf-8") if content else None,
                timeout=15,
            )

        return {
            "status": "success",
            "response": {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.text,
            },
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── WebSocket — live traffic stream ──────────────────────────────────────────

@router.websocket("/ws")
async def network_websocket(websocket: WebSocket):
    """Push live proxy traffic to the browser in real time."""
    await websocket.accept()

    queue: asyncio.Queue = asyncio.Queue(maxsize=500)

    async def push(data: dict):
        try:
            queue.put_nowait(data)
        except asyncio.QueueFull:
            pass  # Drop oldest if browser is slow — no blocking

    network_service.add_listener(push)

    try:
        while True:
            try:
                # Wait for a flow with a short keepalive tick
                data = await asyncio.wait_for(queue.get(), timeout=15.0)
                await websocket.send_json({"type": "request", "data": data})
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception) as e:
        if not isinstance(e, WebSocketDisconnect):
            logger.debug(f"[Network WS] closed: {e}")
    finally:
        network_service.remove_listener(push)
