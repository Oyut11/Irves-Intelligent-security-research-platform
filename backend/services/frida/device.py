"""
IRVES — Frida Device Management
Device resolution, deployment, ADB helpers, and server push/start.
"""

import asyncio
import logging
import os
import lzma
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_device(frida_mod, device_id: str):
    """
    Resolve a Frida device by:
      1. Exact Frida device id (e.g. 'local', 'emulator-5554', USB serial)
      2. ADB serial match against enumerated USB/remote devices
    Raises frida.InvalidArgumentError (or RuntimeError) if nothing matches.
    """
    logger.info(f"[Frida] Resolving device: {device_id}")

    # First: try exact Frida id lookup with retries
    for attempt in range(3):
        try:
            dev = frida_mod.get_device(device_id, timeout=2.0)
            logger.info(f"[Frida] Device resolved via get_device: {dev.id} ({dev.name})")
            return dev
        except Exception as e:
            logger.debug(f"[Frida] get_device attempt {attempt + 1} failed: {e}")
            if attempt < 2:
                import time
                time.sleep(0.5)
            continue

    # Second: enumerate and match by ADB serial (USB devices expose serial as id)
    try:
        devices = frida_mod.enumerate_devices()
        logger.info(f"[Frida] Enumerated {len(devices)} devices for matching")

        for dev in devices:
            logger.debug(f"[Frida] Checking device: {dev.id} ({dev.name}, type={dev.type})")
            if dev.id == device_id or (hasattr(dev, 'id') and dev.id.startswith(device_id)):
                logger.info(f"[Frida] Device resolved via exact match: {dev.id}")
                return dev

        # If no exact match, try partial match for USB devices
        for dev in devices:
            if dev.type == 'usb' and device_id in dev.id:
                logger.info(f"[Frida] Device resolved via partial match: {dev.id}")
                return dev
    except Exception as e:
        logger.warning(f"[Frida] Device enumeration failed: {e}")

    # Third: Proactively wake up the USB daemon
    try:
        logger.info(f"[Frida] Attempting explicit get_usb_device wake-up...")
        usb_dev = frida_mod.get_usb_device(timeout=3.0)
        if usb_dev.id == device_id or (hasattr(usb_dev, 'id') and usb_dev.id.startswith(device_id)):
            logger.info(f"[Frida] Device resolved via explicit get_usb_device: {usb_dev.id}")
            return usb_dev
    except Exception as e:
        logger.debug(f"[Frida] Explicit get_usb_device failed: {e}")

    # Provide helpful error message with available devices
    try:
        devices = frida_mod.enumerate_devices()
        available = ", ".join([f"{d.id} ({d.name})" for d in devices])
        logger.error(f"[Frida] Available devices: {available}")
    except:
        pass

    raise RuntimeError(
        f"Cannot find Frida device '{device_id}'. "
        "Ensure frida-server is running on the device and the device is connected via USB."
    )


async def list_devices() -> list[dict]:
    """List all connected Frida devices (USB + emulators)."""
    from services.frida.core import get_frida
    frida = get_frida()
    devices = []
    try:
        def _refresh_and_list():
            enumerated = frida.enumerate_devices()
            logger.info(f"[Frida] Enumerated {len(enumerated)} devices")
            return enumerated

        for dev in await asyncio.get_event_loop().run_in_executor(None, _refresh_and_list):
            devices.append({
                "id": dev.id,
                "name": dev.name,
                "type": dev.type,
            })
            logger.info(f"[Frida] Device: {dev.id} ({dev.name}, type={dev.type})")
    except Exception as e:
        logger.warning(f"Could not enumerate Frida devices: {e}")
    return devices


async def deploy_server(device_id: str, adb_path: str = "adb") -> str:
    """
    Automatically deploys and starts frida-server on the device.
    Requires root access on the device (adb root).
    """
    frida_version = "17.6.1" # Zymbiote-capable (stealth spawn gating)
    
    # 1. Determine device architecture
    arch = "arm64"
    try:
        proc = await asyncio.create_subprocess_exec(
            adb_path, "-s", device_id, "shell", "getprop", "ro.product.cpu.abi",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        abi = stdout.decode().strip()
        
        if "arm64" in abi:
            arch = "arm64"
        elif "x86_64" in abi:
            arch = "x86_64"
        elif "x86" in abi:
            arch = "x86"
        elif "arm" in abi:
            arch = "arm"
            
        logger.info(f"[Frida Deployment] Detected ABI {abi}, mapped to arch {arch}")
    except Exception as e:
        logger.warning(f"[Frida Deployment] Could not detect architecture, defaulting to arm64: {e}")

    filename = f"frida-server-{frida_version}-android-{arch}.xz"
    url = f"https://github.com/frida/frida/releases/download/{frida_version}/{filename}"
    
    cache_dir = Path.home() / ".irves" / "bin" / "frida_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    xz_path = cache_dir / filename
    bin_path = cache_dir / f"frida-server-{arch}"
    
    # 2. Download if not cached
    if not bin_path.exists():
        logger.info(f"[Frida Deployment] Downloading {url}...")
        def _download_and_extract():
            urllib.request.urlretrieve(url, xz_path)
            with lzma.open(xz_path, "rb") as f_in, open(bin_path, "wb") as f_out:
                f_out.write(f_in.read())
            xz_path.unlink()
        await asyncio.get_event_loop().run_in_executor(None, _download_and_extract)
        logger.info(f"[Frida Deployment] Extracted to {bin_path}")

    # 3. Push and Execute
    remote_path = "/data/local/tmp/frida-server"
    commands = [
        [adb_path, "-s", device_id, "root"],
        [adb_path, "-s", device_id, "push", str(bin_path), remote_path],
        [adb_path, "-s", device_id, "shell", f"chmod 755 {remote_path}"],
        [adb_path, "-s", device_id, "shell", f"killall -9 frida-server 2>/dev/null || true"],
        [adb_path, "-s", device_id, "shell", f"nohup {remote_path} >/dev/null 2>&1 &"]
    ]
    
    for cmd in commands:
        logger.debug(f"[Frida Deployment] Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=10.0)

    # Allow 2 seconds for server to bind
    await asyncio.sleep(2.0)
    return f"Successfully deployed frida-server ({arch}) to {device_id}"


async def preflight_check() -> dict:
    """Check if Frida is available, USB devices reachable, and ADB state."""
    from services.frida.core import get_frida
    result = {
        "frida_installed": False,
        "frida_version": None,
        "devices": [],
        "adb_devices": [],
        "error": None,
    }
    try:
        frida = get_frida()
        result["frida_installed"] = True
        result["frida_version"] = frida.__version__
        devices = await list_devices()
        result["devices"] = devices
        logger.info(f"[Frida Preflight] Found {len(devices)} devices: {devices}")
    except RuntimeError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[Frida Preflight] Error: {e}")

    # Always check ADB independently — phones show here even without frida-server
    adb_devs = await adb_devices()
    result["adb_devices"] = adb_devs
    logger.info(f"[Frida Preflight] ADB devices: {adb_devs}")

    # Fallback: if Frida didn't see a USB device but ADB does, check ps directly
    if not any(d.get("type") == "usb" for d in result["devices"]):
        for adb_dev in adb_devs:
            serial = adb_dev["serial"]
            try:
                ps_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell", "ps -A 2>/dev/null | grep frida-server || ps 2>/dev/null | grep frida-server",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                ps_out, _ = await asyncio.wait_for(ps_proc.communicate(), timeout=8)
                if b"frida-server" in ps_out:
                    logger.info(f"[Frida Preflight] frida-server found via ADB ps on {serial} — synthesizing USB device entry")
                    result["devices"].append({
                        "id": serial,
                        "name": adb_dev.get("model", serial),
                        "type": "usb",
                    })
                    result["error"] = None
            except Exception as ps_err:
                logger.debug(f"[Frida Preflight] ADB ps fallback failed for {serial}: {ps_err}")

    return result


async def adb_devices() -> list[dict]:
    """Run `adb devices` and return connected USB devices (no frida-server needed)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "devices", "-l",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        lines = stdout.decode(errors="replace").splitlines()
        devices = []
        for line in lines[1:]:
            line = line.strip()
            if not line or "offline" in line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("device", "recovery", "sideload"):
                serial = parts[0]
                model = serial
                for tag in parts[2:]:
                    if tag.startswith("model:"):
                        model = tag.split(":", 1)[1].replace("_", " ")
                        break
                devices.append({"serial": serial, "model": model, "state": parts[1]})
        return devices
    except FileNotFoundError:
        logger.warning("[Frida] adb not found in PATH")
        return []
    except Exception as e:
        logger.warning(f"[Frida] adb devices error: {e}")
        return []


async def get_device_arch(serial: str) -> str:
    """Detect device architecture via ADB."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return stdout.decode(errors="replace").strip() or "arm64-v8a"
    except Exception as e:
        logger.warning(f"[Frida] get_device_arch error: {e}")
        return "arm64-v8a"


async def push_and_start_frida_server(serial: str):
    """
    Async generator that streams progress dicts while:
      1. Detecting device architecture
      2. Locating / downloading the matching frida-server binary
      3. Pushing it to /data/local/tmp/frida-server
      4. Setting permissions and starting it
    """
    from pathlib import Path

    try:
        import frida as frida_mod
        frida_version = frida_mod.__version__
    except ImportError:
        yield {"step": "arch", "status": "error", "message": "Frida not installed"}
        return

    yield {"step": "arch", "status": "running", "message": f"Detecting architecture for {serial}…"}
    abi = await get_device_arch(serial)
    abi_map = {
        "arm64-v8a":   "android-arm64",
        "armeabi-v7a": "android-arm",
        "armeabi":     "android-arm",
        "x86_64":      "android-x86_64",
        "x86":         "android-x86",
    }
    frida_arch = abi_map.get(abi, "android-arm64")
    yield {"step": "arch", "status": "done", "message": f"ABI: {abi}  →  frida target: {frida_arch}"}

    binary_name = f"frida-server-{frida_version}-{frida_arch}"
    cache_dir = Path.home() / ".local" / "share" / "irves" / "frida-server"
    cache_dir.mkdir(parents=True, exist_ok=True)
    local_path = cache_dir / binary_name

    if local_path.exists():
        yield {"step": "download", "status": "done",
               "message": f"Using cached binary: {local_path.name}"}
    else:
        yield {"step": "download", "status": "running",
               "message": f"Downloading frida-server {frida_version} for {frida_arch}…"}
        try:
            url = f"https://github.com/frida/frida/releases/download/{frida_version}/{binary_name}.xz"
            xz_path = cache_dir / f"{binary_name}.xz"

            def _download():
                urllib.request.urlretrieve(url, xz_path)
                with lzma.open(xz_path, "rb") as f_in, open(local_path, "wb") as f_out:
                    f_out.write(f_in.read())
                xz_path.unlink()

            await asyncio.get_event_loop().run_in_executor(None, _download)
            yield {"step": "download", "status": "done",
                   "message": f"Downloaded and extracted: {local_path.name}"}
        except Exception as e:
            yield {"step": "download", "status": "error",
                   "message": f"Download failed: {e}. You can manually download from https://github.com/frida/frida/releases"}
            return

    # Push binary
    yield {"step": "push", "status": "running",
           "message": f"Pushing frida-server to {serial}…"}
    remote_path = "/data/local/tmp/frida-server"
    try:
        push_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "push", str(local_path), remote_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(push_proc.communicate(), timeout=60)
        if push_proc.returncode != 0:
            err = stderr.decode(errors="replace").strip() or "unknown error"
            yield {"step": "push", "status": "error", "message": f"Push failed: {err}"}
            return
        yield {"step": "push", "status": "done",
               "message": f"Pushed to {remote_path}"}
    except asyncio.TimeoutError:
        yield {"step": "push", "status": "error",
               "message": "Push timed out (60s). Check USB connection."}
        return
    except Exception as e:
        yield {"step": "push", "status": "error", "message": f"Push failed: {e}"}
        return

    # Set permissions
    yield {"step": "permissions", "status": "running",
           "message": "Setting executable permissions…"}
    try:
        chmod_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", f"chmod 755 {remote_path}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(chmod_proc.communicate(), timeout=10)
        yield {"step": "permissions", "status": "done",
               "message": "Permissions set (755)"}
    except Exception as e:
        yield {"step": "permissions", "status": "error",
               "message": f"chmod failed: {e}"}
        return

    # Start frida-server
    yield {"step": "start", "status": "running",
           "message": "Starting frida-server on device…"}
    try:
        # Kill any existing instance first
        kill_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "killall -9 frida-server 2>/dev/null || true",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(kill_proc.communicate(), timeout=5)
        await asyncio.sleep(0.5)

        # Try su -c first (rooted device)
        start_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell",
            f"su -c '{remote_path} -D &'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(start_proc.communicate(), timeout=10)
        start_err = stderr.decode(errors="replace").strip()

        if "not found" in start_err.lower() or "denied" in start_err.lower() or start_proc.returncode != 0:
            # Try adb root + direct execution
            root_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "root",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(root_proc.communicate(), timeout=5)
            await asyncio.sleep(1)

            start_proc2 = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"{remote_path} -D &",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(start_proc2.communicate(), timeout=10)

        # Wait for server to bind
        await asyncio.sleep(2)

        # Verify it's running
        verify_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "ps -A 2>/dev/null || ps",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(verify_proc.communicate(), timeout=10)

        if 'frida-server' in stdout.decode(errors="replace"):
            yield {"step": "start", "status": "done",
                   "message": "frida-server is running on the device!"}
            yield {"step": "complete", "status": "done",
                   "message": "Setup complete — refreshing device status…"}
            return

        # All methods failed
        yield {"step": "start", "status": "error",
               "message": "Failed to start frida-server. Ensure root access is granted and try again."}

    except Exception as e:
        err_str = str(e).lower()
        if "su:" in err_str or "not found" in err_str or "inaccessible" in err_str or "permission denied" in err_str:
            yield {"step": "start", "status": "error",
                   "message": "Root access denied or not available. Please ensure: "
                   "1) The device is rooted (Magisk/SuperSU installed), "
                   "2) Root permission is granted to ADB/shell app, "
                   "3) For non-root devices, use 'Xposed (Non-Root)' mode instead."}
        else:
            yield {"step": "start", "status": "error", "message": f"Start failed: {e}"}
