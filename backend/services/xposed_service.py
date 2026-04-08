"""
IRVES — Xposed / LSPatch Service
Non-root instrumentation using LSPatch + TrustMeAlready module.
Provides:
  - patch_and_install_generator: full setup pipeline (SSE stream)
  - logcat_stream: async generator that tails logcat for hook output
  - preflight_check: validates Java + ADB + device state
"""

import os
import asyncio
import logging
import shutil
import uuid
from pathlib import Path
from typing import AsyncGenerator

import httpx

logger = logging.getLogger(__name__)

# ─── Asset URLs ───────────────────────────────────────────────────────────────
LSPATCH_URL = (
    "https://github.com/LSPosed/LSPatch/releases/download/v0.6/jar-v0.6-398-release.jar"
)
MODULE_TRUSTMEALREADY_URL = (
    "https://github.com/ViRb3/TrustMeAlready/releases/download/v1.11/TrustMeAlready-v1.11-release.apk"
)

# Log tag that TrustMeAlready and LSPatch module hooks write to
LOGCAT_TAGS = ["IRVES", "TrustMeAlready", "Xposed", "LSPatch"]


class XposedService:
    def __init__(self):
        self.workspace_dir = Path.home() / ".local" / "share" / "irves" / "xposed"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.lspatch_jar = self.workspace_dir / "lspatch.jar"
        self.module_apk = self.workspace_dir / "trustmealready.apk"

    # ─── Dependency management ────────────────────────────────────────────────

    async def _download_file_streaming(self, url: str, dest: Path) -> None:
        """Download a file with streaming (avoids timeout on large files)."""
        if dest.exists():
            return
        tmp = dest.with_suffix(".tmp")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=15.0, read=180.0, write=60.0, pool=15.0),
                follow_redirects=True,
            ) as client:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    with open(tmp, "wb") as f:
                        async for chunk in resp.aiter_bytes(65536):
                            f.write(chunk)
            tmp.rename(dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    async def prepare_dependencies(self):
        """Download LSPatch jar and TrustMeAlready module if not cached."""
        await asyncio.gather(
            self._download_file_streaming(LSPATCH_URL, self.lspatch_jar),
            self._download_file_streaming(MODULE_TRUSTMEALREADY_URL, self.module_apk),
        )

    # ─── Pre-flight check ─────────────────────────────────────────────────────

    async def preflight_check(self) -> dict:
        """Check Java availability, ADB connectivity, and cached assets."""
        result = {
            "java_installed": False,
            "java_version": None,
            "adb_installed": False,
            "adb_devices": [],
            "lspatch_cached": self.lspatch_jar.exists(),
            "module_cached": self.module_apk.exists(),
            "error": None,
        }
        # Java
        try:
            proc = await asyncio.create_subprocess_exec(
                "java", "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0:
                result["java_installed"] = True
                # java -version outputs to stderr
                result["java_version"] = stderr.decode(errors="replace").splitlines()[0].strip()
        except (FileNotFoundError, asyncio.TimeoutError) as e:
            result["error"] = f"Java not found: {e}"

        # ADB
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices", "-l",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            result["adb_installed"] = True
            lines = stdout.decode(errors="replace").splitlines()
            for line in lines[1:]:
                line = line.strip()
                if not line or "offline" in line or line.startswith("*"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ("device", "recovery"):
                    serial = parts[0]
                    model = serial
                    for tag in parts[2:]:
                        if tag.startswith("model:"):
                            model = tag.split(":", 1)[1].replace("_", " ")
                            break
                    result["adb_devices"].append({"serial": serial, "model": model})
        except FileNotFoundError:
            result["error"] = (result["error"] or "") + " ADB not found in PATH."
        except asyncio.TimeoutError:
            pass

        return result

    # ─── APK extraction ───────────────────────────────────────────────────────

    async def _get_apk_path_on_device(self, serial: str, package: str) -> str:
        """
        Return the base.apk path on-device for the given package.
        Handles both single-APK and split-APK installs.
        """
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", "pm", "path", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0 or not stdout.strip():
            raise RuntimeError(
                f"Package '{package}' not found on device {serial}. "
                "Is the app installed?"
            )
        lines = stdout.decode(errors="replace").strip().splitlines()
        # For split APKs, pm path returns multiple lines — pick base.apk first
        for line in lines:
            path = line.replace("package:", "").strip()
            if "base.apk" in path or "base" in path.lower():
                return path
        # Fallback: use the first path
        return lines[0].replace("package:", "").strip()

    # ─── Main setup pipeline ─────────────────────────────────────────────────

    async def patch_and_install_generator(
        self, device_id: str, package_name: str
    ) -> AsyncGenerator[dict, None]:
        """
        SSE-friendly async generator that runs the full LSPatch pipeline:
          prepare → extract → patch → install → cleanup
        Each step yields {step, status, message} dicts.
        """
        temp_dir = self.workspace_dir / f"session_{uuid.uuid4().hex[:8]}"
        temp_dir.mkdir(exist_ok=True)
        base_apk_path = temp_dir / "base.apk"
        patched_apk_dir = temp_dir / "patched"

        try:
            # ── Step 1: Download dependencies ─────────────────────────────────
            yield {"step": "prepare", "status": "running",
                   "message": "Checking / downloading LSPatch and TrustMeAlready…"}
            try:
                await self.prepare_dependencies()
            except Exception as e:
                yield {"step": "prepare", "status": "error",
                       "message": f"Download failed: {e}"}
                return
            yield {"step": "prepare", "status": "done",
                   "message": f"Dependencies ready ({self.lspatch_jar.name})."}

            # ── Step 2: Verify Java ────────────────────────────────────────────
            if not shutil.which("java"):
                yield {"step": "patch", "status": "error",
                       "message": "Java is not installed or not in PATH. "
                                  "Install Java 11+ to run LSPatch."}
                return

            # ── Step 3: Extract base APK from device ─────────────────────────
            yield {"step": "extract", "status": "running",
                   "message": f"Pulling {package_name} from device {device_id}…"}
            try:
                apk_path_on_device = await self._get_apk_path_on_device(
                    device_id, package_name
                )
            except Exception as e:
                yield {"step": "extract", "status": "error", "message": str(e)}
                return

            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "pull", apk_path_on_device, str(base_apk_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0 or not base_apk_path.exists():
                err_msg = stderr.decode(errors="replace").strip() or "adb pull failed"
                yield {"step": "extract", "status": "error",
                       "message": f"Failed to pull APK: {err_msg}"}
                return
            size_mb = base_apk_path.stat().st_size / 1_048_576
            yield {"step": "extract", "status": "done",
                   "message": f"APK pulled ({size_mb:.1f} MB) → {base_apk_path.name}"}

            # ── Step 4: Patch with LSPatch ────────────────────────────────────
            yield {"step": "patch", "status": "running",
                   "message": "Patching with LSPatch + TrustMeAlready (re-signing)…"}
            patched_apk_dir.mkdir(exist_ok=True)

            # LSPatch flags:
            #   (no -d)  — do NOT force debuggable; avoids anti-tamper triggers
            #   -m       — embed Xposed module
            #   -o       — output directory
            #   --force  — overwrite if already patched
            cmd = [
                "java", "-jar", str(self.lspatch_jar),
                str(base_apk_path),
                "-m", str(self.module_apk),
                "-o", str(patched_apk_dir),
                "--force",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=300  # 5 min for large APKs
                )
            except asyncio.TimeoutError:
                proc.kill()
                yield {"step": "patch", "status": "error",
                       "message": "LSPatch timed out after 5 minutes. Try a smaller APK."}
                return

            if proc.returncode != 0:
                err_detail = (stderr.decode(errors="replace") or
                              stdout.decode(errors="replace")).strip()[-500:]
                logger.error(f"[LSPatch] Error:\n{err_detail}")
                yield {"step": "patch", "status": "error",
                       "message": f"LSPatch failed: {err_detail}"}
                return

            patched_apks = list(patched_apk_dir.glob("*.apk"))
            if not patched_apks:
                yield {"step": "patch", "status": "error",
                       "message": "No patched APK was produced. Check LSPatch output."}
                return
            final_apk = patched_apks[0]
            patched_size_mb = final_apk.stat().st_size / 1_048_576
            yield {"step": "patch", "status": "done",
                   "message": f"Patched & signed: {final_apk.name} ({patched_size_mb:.1f} MB)"}

            # ── Step 5: Uninstall original + install patched ──────────────────
            yield {"step": "install", "status": "running",
                   "message": f"Uninstalling original {package_name}…"}
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "uninstall", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
            # Ignore uninstall failure (app may already be gone)

            yield {"step": "install", "status": "running",
                   "message": "Installing Xposed-enabled application…"}
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "install", "-r", "-t", str(final_apk),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                yield {"step": "install", "status": "error",
                       "message": "adb install timed out."}
                return

            full_output = (stdout.decode(errors="replace") +
                           stderr.decode(errors="replace")).strip()
            if proc.returncode != 0 or "Failure" in full_output:
                logger.error(f"[ADB install] {full_output}")
                yield {"step": "install", "status": "error",
                       "message": f"Install failed: {full_output[-300:]}"}
                return

            yield {"step": "install", "status": "done",
                   "message": "Xposed-patched app installed successfully!"}

            # ── Step 6: Cleanup ───────────────────────────────────────────────
            yield {"step": "cleanup", "status": "running",
                   "message": "Cleaning up temporary files…"}
            shutil.rmtree(temp_dir, ignore_errors=True)
            yield {"step": "cleanup", "status": "done",
                   "message": "Setup complete — launch the app on your device to activate hooks."}

        except Exception as e:
            logger.exception("[Xposed] Unhandled error in pipeline")
            yield {"step": "error", "status": "error", "message": str(e)}
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ─── Logcat bridge ───────────────────────────────────────────────────────

    async def logcat_stream(
        self, serial: str, package_name: str
    ) -> AsyncGenerator[str, None]:
        """
        Async generator that streams logcat lines from a running Xposed-patched
        app on the given device. Filters by relevant tags and the app's UID.
        Yields plain-text log lines.
        """
        # Build logcat tag filter string: "TAG:V *:S" format
        tag_filter = " ".join(f"{tag}:V" for tag in LOGCAT_TAGS) + " *:S"

        # Get app UID for additional filtering (optional — falls back to tag-only)
        uid_filter = ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"dumpsys package {package_name} | grep userId=",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in out.decode(errors="replace").splitlines():
                if "userId=" in line:
                    uid = line.strip().split("userId=")[1].split()[0]
                    uid_filter = f"--uid {uid}"
                    break
        except Exception:
            pass

        # Clear old logcat buffer first
        clear_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "logcat", "-c",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(clear_proc.communicate(), timeout=10)

        # Stream logcat
        cmd = ["adb", "-s", serial, "logcat", "-v", "time", tag_filter]
        if uid_filter:
            cmd += uid_filter.split()

        logger.info(f"[Xposed logcat] Starting: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            while True:
                try:
                    line_bytes = await asyncio.wait_for(
                        proc.stdout.readline(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    yield "__ping__"
                    continue

                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                if line:
                    yield line
        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# Global singleton
xposed_service = XposedService()
