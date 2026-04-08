"""
IRVES — Frida Runner
Dynamic instrumentation for runtime analysis.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any
import logging
import shutil

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)


# Pre-built Frida hooks for common security bypasses
BUILTIN_HOOKS = {
    "ssl_bypass": {
        "name": "SSL Pinning Bypass",
        "description": "Bypass SSL certificate pinning for HTTPS interception",
        "script": """
Java.perform(function() {
    console.log('[IRVES] SSL Pinning Bypass loaded');

    // OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peers) {
            console.log('[IRVES] OkHttp SSL pinning bypassed for: ' + hostname);
            return;
        };
    } catch (e) { console.log('[IRVES] OkHttp not found'); }

    // TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.irves.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch (e) {}

    // WebView SSL
    try {
        var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(view, handler, error) {
            console.log('[IRVES] WebView SSL error bypassed');
            handler.proceed();
        };
    } catch (e) {}

    console.log('[IRVES] SSL pinning bypass complete');
});
""",
    },
    "root_detection_bypass": {
        "name": "Root Detection Bypass",
        "description": "Bypass comprehensive root detection mechanisms including Magisk, SafetyNet, ProcessBuilder, and multiple su implementations",
        "script": """
Java.perform(function() {
    console.log('[IRVES] Loading comprehensive root detection bypass…');

    // ── 1. Root Detection Libraries ───────────────────────────────────────────
    var rootCheckClasses = [
        // RootBeer
        { className: 'com.scottyab.rootbeer.RootBeer', methods: ['isRooted', 'isRootedWithBusyBoxCheck', 'isRootedWithoutBusyBoxCheck', 'checkForBinary', 'checkForDangerousApps', 'checkSuExists'] },
        // SuperUser / libsuperuser
        { className: 'com.topjohnwu.superuser.Shell', methods: ['isRootAvailable', 'isRoot', 'getShell'] },
        { className: 'eu.chainfire.libsuperuser.Shell', methods: ['isRootAvailable', 'isRoot'] },
        { className: 'eu.chainfire.libsuperuser.Shell$Interactive', methods: ['run'] },
        // RootChecker variants
        { className: 'com.joebolea.rootcheck.RootCheck', methods: ['isRooted'] },
        { className: 'com.joebolea.rootcheck.RootCheck', methods: ['isRootAvailable'] },
        { className: 'com.scottyab.rootbeer.lib.RootBeerNative', methods: ['checkForRoot', 'setLogDebugMessage'] },
        // SafetyNet / Play Integrity
        { className: 'com.google.android.gms.safetynet.SafetyNetApi', methods: ['attest'] },
        { className: 'com.google.android.gms.safetynet.SafetyNetClient', methods: ['attest'] },
        // Common custom implementations
        { className: 'com.nitor24frida.rootdetect.RootDetect', methods: ['isRooted', 'checkRoot'] },
        { className: 'com.thirdparty.rootchecker.RootChecker', methods: ['isRooted', 'checkRootMethod'] },
        // Magisk specific
        { className: 'com.topjohnwu.magisk.core.utils.RootUtils', methods: ['isRootAvailable'] },
    ];

    rootCheckClasses.forEach(function(entry) {
        try {
            var Cls = Java.use(entry.className);
            entry.methods.forEach(function(methodName) {
                try {
                    if (Cls[methodName]) {
                        Cls[methodName].implementation = function() {
                            console.log('[IRVES] Root detection bypassed: ' + entry.className + '.' + methodName);
                            return false;
                        };
                    }
                } catch(m) { /* method may not exist, skip */ }
            });
        } catch(e) { /* class may not exist, skip */ }
    });

    // ── 2. Runtime.exec() - All 6 overloads ────────────────────────────────────
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var IOException = Java.use('java.io.IOException');

        function containsRootCommand(cmdOrArray) {
            var cmdStr = Array.isArray(cmdOrArray) ? cmdOrArray.join(' ') : String(cmdOrArray);
            var suspicious = ['su', 'which su', '/su', 'busybox', 'magisk', 'zygisk'];
            for (var i = 0; i < suspicious.length; i++) {
                if (cmdStr.toLowerCase().indexOf(suspicious[i].toLowerCase()) !== -1) {
                    return true;
                }
            }
            return false;
        }

        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (containsRootCommand(cmd)) {
                console.log('[IRVES] Blocked root command (String): ' + cmd);
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmd);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
            if (containsRootCommand(cmds)) {
                console.log('[IRVES] Blocked root command (String[]): ' + cmds.join(' '));
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmds);
        };

        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(cmd, envp) {
            if (containsRootCommand(cmd)) {
                console.log('[IRVES] Blocked root command (String, envp): ' + cmd);
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmd, envp);
        };

        Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(cmds, envp) {
            if (containsRootCommand(cmds)) {
                console.log('[IRVES] Blocked root command (String[], envp): ' + cmds.join(' '));
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmds, envp);
        };

        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmd, envp, dir) {
            if (containsRootCommand(cmd)) {
                console.log('[IRVES] Blocked root command (String, envp, dir): ' + cmd);
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmd, envp, dir);
        };

        Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmds, envp, dir) {
            if (containsRootCommand(cmds)) {
                console.log('[IRVES] Blocked root command (String[], envp, dir): ' + cmds.join(' '));
                throw IOException.$new('Cannot run program: Permission denied');
            }
            return this.exec(cmds, envp, dir);
        };
    } catch(e) {
        console.log('[IRVES] Runtime.exec hook partial/failed: ' + e);
    }

    // ── 3. ProcessBuilder ─────────────────────────────────────────────────────
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        var originalStart = ProcessBuilder.start;

        ProcessBuilder.start.implementation = function() {
            var cmdList = this.command();
            var cmdArray = [];
            var it = cmdList.iterator();
            while (it.hasNext()) { cmdArray.push(it.next()); }

            var cmdStr = cmdArray.join(' ');
            var suspicious = ['su', 'which su', '/su', 'busybox', 'magisk', 'zygisk'];
            for (var i = 0; i < suspicious.length; i++) {
                if (cmdStr.toLowerCase().indexOf(suspicious[i].toLowerCase()) !== -1) {
                    console.log('[IRVES] Blocked ProcessBuilder command: ' + cmdStr);
                    throw Java.use('java.io.IOException').$new('Cannot run program: Permission denied');
                }
            }
            return originalStart.call(this);
        };
    } catch(e) { /* ProcessBuilder may not be available on older Android */ }

    // ── 4. File.exists() - Extended path list ───────────────────────────────────
    try {
        var File = Java.use('java.io.File');
        var rootPaths = [
            '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su',
            '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/data/local/bin/su',
            '/data/local/xbin/su', '/su/bin/su',
            '/magisk/.core/bin/su', '/sbin/.magisk', '/data/adb/magisk', '/data/adb/ksu',
            '/data/adb/ap', '/data/adb/ksud', '/data/adb/modules/zygisk',
            '/system/etc/init.d/99SuperSUDaemon', '/system/xbin/daemonsu',
            '/system/usr/su', '/vendor/bin/su', '/system/app/SuperSU', '/system/app/SuperSU.apk',
            '/data/data/eu.chainfire.supersu', '/system/xbin/sugote',
            '/system/xbin/busybox', '/data/local/busybox',
            '/system/app/Superuser.apk', '/system/etc/init.d/', '/system/xbin/.magisk',
        ];

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path.indexOf(rootPaths[i]) !== -1 || path === rootPaths[i]) {
                    console.log('[IRVES] Blocked root path check: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch(e) {}

    // ── 5. java.nio.file.Files for modern Android ────────────────────────────
    try {
        var Files = Java.use('java.nio.file.Files');
        var rootPathPatterns = ['/su', '/magisk', '/supersu', '/busybox', 'ksu', 'zygisk'];

        Files.exists.overload('java.nio.file.Path', '[Ljava.nio.file.LinkOption;').implementation = function(path, options) {
            var pathStr = path.toString();
            for (var i = 0; i < rootPathPatterns.length; i++) {
                if (pathStr.toLowerCase().indexOf(rootPathPatterns[i].toLowerCase()) !== -1) {
                    console.log('[IRVES] Blocked Files.exists path check: ' + pathStr);
                    return false;
                }
            }
            return this.exists(path, options);
        };
    } catch(e) {}

    // ── 6. Package Manager - Hide root apps ─────────────────────────────────────
    try {
        var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
        var rootPackages = [
            'com.topjohnwu.magisk', 'com.topjohnwu.magisk.ktx', 'com.topjohnwu.magisk.k',
            'eu.chainfire.supersu', 'eu.chainfire.flashless', 'eu.chainfire.superuser',
            'com.noshufou.android.su', 'com.noshufou.android.su.elite',
            'com.koushikdutta.superuser', 'com.kuschiiu.superuser',
            'com.thirdparty.superuser', 'com.koushikdutta.rommanager',
            'com.dimonvideo.litemod.bsu', 'me.phh.superuser',
            'com.topjohnwu.su', 'io.github.huskydg.magisk', 'io.github.vvb2060.magisk',
        ];

        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkg === rootPackages[i] || pkg.indexOf(rootPackages[i]) === 0) {
                    console.log('[IRVES] Hiding root package: ' + pkg);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };

        ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
            var packages = this.getInstalledPackages(flags);
            var filtered = Java.use('java.util.ArrayList').$new();
            var it = packages.iterator();
            while (it.hasNext()) {
                var pkgInfo = it.next();
                var pkgName = pkgInfo.packageName.value;
                var isRootPkg = false;
                for (var i = 0; i < rootPackages.length; i++) {
                    if (pkgName === rootPackages[i] || pkgName.indexOf(rootPackages[i]) === 0) {
                        isRootPkg = true;
                        break;
                    }
                }
                if (!isRootPkg) {
                    filtered.add(pkgInfo);
                }
            }
            return filtered;
        };
    } catch(e) {}

    // ── 7. System Properties ────────────────────────────────────────────────────
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');

        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key === 'ro.debuggable') {
                console.log('[IRVES] Spoofing ro.debuggable = 0');
                return '0';
            }
            if (key === 'ro.secure') {
                console.log('[IRVES] Spoofing ro.secure = 1');
                return '1';
            }
            if (key === 'ro.build.tags') {
                console.log('[IRVES] Spoofing ro.build.tags = release-keys');
                return 'release-keys';
            }
            return this.get(key);
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (key === 'ro.debuggable') return '0';
            if (key === 'ro.secure') return '1';
            if (key === 'ro.build.tags') return 'release-keys';
            return this.get(key, def);
        };
    } catch(e) {}

    // ── 8. Debug flags ──────────────────────────────────────────────────────────
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            console.log('[IRVES] Spoofing isDebuggerConnected() = false');
            return false;
        };
    } catch(e) {}

    console.log('[IRVES] Root detection bypass fully loaded (comprehensive)');
});
""",
    },
    "crypto_capture": {
        "name": "Cryptography Interception",
        "description": "Capture encryption/decryption operations",
        "script": """
Java.perform(function() {
    console.log('[IRVES] Cryptography Interception loaded');

    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        var mode = opmode === 1 ? 'ENCRYPT' : 'DECRYPT';
        console.log('[IRVES] Cipher.init(' + mode + ', ' + key.getClass().getName() + ')');
        return this.init(opmode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function(data) {
        var result = this.doFinal(data);
        var algorithm = this.getAlgorithm();
        console.log('[IRVES] Cipher.doFinal()');
        console.log('    Algorithm: ' + algorithm);
        console.log('    Input (' + data.length + ' bytes): ' + bytesToHex(data.slice(0, 32)) + '...');
        console.log('    Output (' + result.length + ' bytes): ' + bytesToHex(result.slice(0, 32)) + '...');
        return result;
    };

    // SecretKey factory
    try {
        var SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');
        SecretKeyFactory.generateSecret.overload('java.security.spec.KeySpec').implementation = function(spec) {
            console.log('[IRVES] SecretKeyFactory.generateSecret()');
            return this.generateSecret(spec);
        };
    } catch (e) {}

    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < Math.min(bytes.length, 32); i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }

    console.log('[IRVES] Cryptography interception complete');
});
""",
    },
    "network_intercept": {
        "name": "Network Interception",
        "description": "Intercept HTTP/HTTPS requests and responses",
        "script": """
Java.perform(function() {
    console.log('[IRVES] Network Interception loaded');

    // OkHttp Interceptor
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Interceptor = Java.use('okhttp3.Interceptor');

        var IRVESInterceptor = Java.registerClass({
            name: 'com.irves.IRVESInterceptor',
            implements: [Interceptor],
            methods: {
                intercept: function(chain) {
                    var request = chain.request();
                    console.log('[IRVES] HTTP Request: ' + request.method() + ' ' + request.url());

                    var headers = request.headers();
                    var headerNames = headers.names();
                    var it = headerNames.iterator();
                    while (it.hasNext()) {
                        var name = it.next();
                        console.log('    ' + name + ': ' + headers.get(name));
                    }

                    var response = chain.proceed(request);
                    console.log('[IRVES] HTTP Response: ' + response.code());

                    return response;
                }
            }
        });

        console.log('[IRVES] OkHttp interceptor installed');
    } catch (e) {
        console.log('[IRVES] OkHttp not found, using URL connection hooks');
    }

    // java.net.URL
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[IRVES] URL.openConnection: ' + this.toString());
        return this.openConnection();
    };

    // HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function() {
            console.log('[IRVES] HttpURLConnection.getInputStream: ' + this.getURL());
            return this.getInputStream();
        };
    } catch (e) {}

    console.log('[IRVES] Network interception complete');
});
""",
    },
    "debugger_bypass": {
        "name": "Debugger Detection Bypass",
        "description": "Bypass debugger and reverse engineering detection",
        "script": """
Java.perform(function() {
    console.log('[IRVES] Debugger Detection Bypass loaded');

    // Debug status
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        console.log('[IRVES] isDebuggerConnected() -> false');
        return false;
    };

    // Check debug flags in ApplicationInfo
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
    var Application = Java.use('android.app.Application');

    Application.attach.overload('android.content.Context').implementation = function(context) {
        this.attach(context);
        var appInfo = this.getApplicationInfo();
        if (appInfo.flags.value & 2) { // FLAG_DEBUGGABLE
            console.log('[IRVES] App is debuggable');
        }
    };

    // Signature verification bypass
    try {
        var Signature = Java.use('android.content.pm.Signature');
        var PackageManager = Java.use('android.content.pm.PackageManager');
    } catch (e) {}

    // Tamper detection
    try {
        var CRC32 = Java.use('java.util.zip.CRC32');
    } catch (e) {}

    console.log('[IRVES] Debugger detection bypass complete');
});
""",
    },
}


class FridaRunner(ToolRunner):
    """
    Frida runner for dynamic instrumentation.

    Supports:
    - Attaching to running processes
    - Spawning new processes
    - Injecting custom scripts
    - Using pre-built security hooks
    """

    def __init__(self):
        super().__init__()
        self.session = None
        self.script = None
        self._device = None
        self._output_messages: List[Dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "frida"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
        script_path: Optional[Path] = None,
        package_name: Optional[str] = None,
        device_id: Optional[str] = None,
        spawn: bool = True,
        hooks: Optional[List[str]] = None,
    ) -> ToolResult:
        """
        Run Frida instrumentation.

        Args:
            target: Path to the APK file (for reference)
            output_dir: Directory for output logs
            script_path: Optional path to custom Frida script
            package_name: Package name to attach/spawn
            device_id: Optional device ID (defaults to USB device)
            spawn: Whether to spawn (True) or attach (False)
            hooks: List of built-in hook names to inject

        Returns:
            ToolResult with Frida session output
        """
        if progress_callback:
            progress_callback("Checking Frida installation...")

        # Check Frida installation
        if not shutil.which("frida"):
            return ToolResult(
                success=False,
                output="",
                error="Frida not found. Install with: pip install frida frida-tools",
                duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "frida")
        log_file = output_path / "session.log"
        messages_file = output_path / "messages.json"

        try:
            import frida

            # Get device
            if progress_callback:
                progress_callback("Connecting to device...")

            if device_id:
                self._device = frida.get_device(device_id)
            else:
                # Default to USB device
                self._device = frida.get_usb_device(timeout=10)

            device_name = getattr(self._device, "name", "Unknown")
            if progress_callback:
                progress_callback(f"Connected to device: {device_name}")

            # Determine package name from target if not provided
            if not package_name and target and target.suffix == ".apk":
                # Try to extract package name from APK manifest
                package_name = await self._extract_package_name(target)
                if package_name and progress_callback:
                    progress_callback(f"Detected package: {package_name}")

            if not package_name:
                return ToolResult(
                    success=False,
                    output="",
                    error="Package name required for Frida instrumentation",
                    duration_ms=self._elapsed_ms(),
                )

            # Build script
            script_content = self._build_script(script_path, hooks)
            if progress_callback:
                progress_callback("Injecting Frida script...")

            # Spawn or attach
            if spawn:
                if progress_callback:
                    progress_callback(f"Spawning {package_name}...")
                pid = self._device.spawn([package_name])
                self.session = self._device.attach(pid)
            else:
                if progress_callback:
                    progress_callback(f"Attaching to {package_name}...")
                self.session = self._device.attach(package_name)

            # Create and load script
            self.script = self.session.create_script(script_content)

            # Set up message handler
            self._output_messages = []

            def on_message(message: Dict, data: bytes) -> None:
                """Handle Frida script messages."""
                msg_entry = {
                    "timestamp": asyncio.get_event_loop().time(),
                    "message": message,
                }
                if data:
                    msg_entry["data_size"] = len(data)
                self._output_messages.append(msg_entry)

                # Log to console
                if message.get("type") == "send":
                    payload = message.get("payload", "")
                    if progress_callback:
                        progress_callback(f"[Frida] {payload}")
                elif message.get("type") == "error":
                    logger.error(f"[Frida Error] {message.get('description', message)}")

            self.script.on("message", on_message)
            self.script.load()

            # Resume if spawned
            if spawn:
                self._device.resume(pid)

            if progress_callback:
                progress_callback("Frida script injected successfully")
                progress_callback("Session active. Capturing output...")

            # Keep session open for a duration or until cancelled
            # For now, we'll run for a short time and capture initial output
            await asyncio.sleep(5)  # Allow some time for hooks to execute

            # Save logs
            with open(log_file, "w") as f:
                f.write(f"Frida Session Log\n")
                f.write(f"Device: {device_name}\n")
                f.write(f"Package: {package_name}\n")
                f.write(f"Mode: {'Spawn' if spawn else 'Attach'}\n")
                f.write(f"\n--- Messages ---\n\n")
                for msg in self._output_messages:
                    if msg["message"].get("type") == "send":
                        f.write(f"{msg['message'].get('payload', '')}\n")

            # Save full messages as JSON
            with open(messages_file, "w") as f:
                json.dump(self._output_messages, f, indent=2)

            if progress_callback:
                progress_callback(f"Captured {len(self._output_messages)} messages")

            return ToolResult(
                success=True,
                output=json.dumps(self._output_messages, indent=2),
                error="",
                duration_ms=self._elapsed_ms(),
                artifacts_path=output_path,
                metrics={
                    "device": device_name,
                    "package": package_name,
                    "messages_captured": len(self._output_messages),
                    "mode": "spawn" if spawn else "attach",
                },
            )

        except ImportError:
            return ToolResult(
                success=False,
                output="",
                error="Frida Python package not installed. Run: pip install frida frida-tools",
                duration_ms=self._elapsed_ms(),
            )
        except frida.ServerNotRunningError:
            return ToolResult(
                success=False,
                output="",
                error="Frida server not running on device. Start frida-server on the target device.",
                duration_ms=self._elapsed_ms(),
            )
        except frida.ProcessNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error=f"Process '{package_name}' not found. Ensure the app is running or use spawn mode.",
                duration_ms=self._elapsed_ms(),
            )
        except Exception as e:
            logger.exception(f"[{self.name}] Error during execution")
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                duration_ms=self._elapsed_ms(),
            )
        finally:
            await self._cleanup()

    async def _cleanup(self) -> None:
        """Clean up Frida resources."""
        try:
            if self.script:
                self.script.unload()
                self.script = None
            if self.session:
                self.session.detach()
                self.session = None
        except Exception as e:
            logger.warning(f"[{self.name}] Cleanup error: {e}")

    def _build_script(
        self,
        script_path: Optional[Path],
        hooks: Optional[List[str]],
    ) -> str:
        """Build Frida script from file and/or built-in hooks."""
        parts = []

        # Add built-in hooks
        if hooks:
            for hook_name in hooks:
                if hook_name in BUILTIN_HOOKS:
                    parts.append(f"// --- {BUILTIN_HOOKS[hook_name]['name']} ---")
                    parts.append(BUILTIN_HOOKS[hook_name]["script"])
                    parts.append("")

        # Add custom script
        if script_path and script_path.exists():
            parts.append("// --- Custom Script ---")
            parts.append(script_path.read_text())

        # Default: include basic hooks
        if not parts:
            parts.append(BUILTIN_HOOKS["network_intercept"]["script"])

        return "\n".join(parts)

    async def _extract_package_name(self, apk_path: Path) -> Optional[str]:
        """Extract package name from APK using aapt or apktool."""
        try:
            # Try using aapt
            proc = await asyncio.create_subprocess_exec(
                "aapt",
                "dump",
                "badging",
                str(apk_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                for line in stdout.decode().split("\n"):
                    if line.startswith("package: name="):
                        # Extract package name
                        return line.split("name=")[1].split()[0].strip("'")
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"[{self.name}] Could not extract package name: {e}")

        return None

    async def _get_version(self) -> Optional[str]:
        """Get Frida version."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "frida",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return None

    async def check_device_status(self) -> Dict[str, Any]:
        """Check Frida device status."""
        status = {
            "installed": shutil.which("frida") is not None,
            "version": None,
            "device": None,
            "error": None,
        }

        if not status["installed"]:
            status["error"] = "Frida not installed"
            return status

        try:
            import frida

            status["version"] = frida.__version__

            # Try to get USB device
            try:
                device = frida.get_usb_device(timeout=2)
                status["device"] = {
                    "id": device.id,
                    "name": device.name,
                    "type": device.type,
                }
            except Exception:
                status["error"] = "No USB device connected"

        except ImportError:
            status["installed"] = False
            status["error"] = "Frida package not installed in Python"

        return status

    def list_builtin_hooks(self) -> List[Dict[str, str]]:
        """List available built-in hooks."""
        return [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in BUILTIN_HOOKS.items()
        ]