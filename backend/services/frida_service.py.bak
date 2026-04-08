"""
IRVES — Frida Service
Manages Frida sessions for real-time runtime analysis of mobile apps.
"""

import asyncio
import uuid
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Pre-built hook library
BUILTIN_HOOKS: dict[str, str] = {
    "ssl_bypass": """
        Java.perform(function() {
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                    send('[IRVES] SSL pinning bypassed (OkHttp3)');
                };
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
                    send('[IRVES] SSL pinning bypassed (OkHttp3 cert variant)');
                };
            } catch(e) {}

            try {
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.verifyChain.implementation = function() {
                    send('[IRVES] SSL pinning bypassed (TrustManagerImpl)');
                    return arguments[0];
                };
            } catch(e) {}

            send('[IRVES] SSL bypass hooks loaded');
        });
    """,

    "apk_info": """
        Java.perform(function() {
            try {
                var ActivityThread = Java.use('android.app.ActivityThread');
                var app = ActivityThread.currentApplication();
                if (app != null) {
                    var context = app.getApplicationContext();
                    var pkgName = context.getPackageName();
                    var pm = context.getPackageManager();
                    var pi = pm.getPackageInfo(pkgName, 0);
                    send('[IRVES] --- App Metadata ---');
                    send('[IRVES] Package Name: ' + pkgName);
                    send('[IRVES] Version Code: ' + pi.versionCode.value);
                    send('[IRVES] Version Name: ' + pi.versionName.value);
                    send('[IRVES] Target SDK: ' + context.getApplicationInfo().targetSdkVersion.value);
                    send('[IRVES] Source Dir: ' + context.getApplicationInfo().sourceDir.value);
                    send('[IRVES] ----------------------');
                } else {
                    send('[IRVES] App context is null. App might not be fully loaded.');
                }
            } catch (e) {
                send('[IRVES] Failed to extract app info: ' + e);
            }
        });
    """,

    "root_detection_bypass": """
        Java.perform(function() {
            // ── Comprehensive Root Detection Bypass ────────────────────────────────
            // Handles: RootBeer, Magisk, SafetyNet, multiple su binaries, ProcessBuilder,
            // and various evasion techniques used by modern apps.

            send('[IRVES] Loading comprehensive root detection bypass…');

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
                                    send('[IRVES] Root detection bypassed: ' + entry.className + '.' + methodName);
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

                // Helper to check for root-related commands
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

                // exec(String)
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (containsRootCommand(cmd)) {
                        send('[IRVES] Blocked root command (String): ' + cmd);
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd);
                };

                // exec(String[])
                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
                    if (containsRootCommand(cmds)) {
                        send('[IRVES] Blocked root command (String[]): ' + cmds.join(' '));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds);
                };

                // exec(String, String[])
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(cmd, envp) {
                    if (containsRootCommand(cmd)) {
                        send('[IRVES] Blocked root command (String, envp): ' + cmd);
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd, envp);
                };

                // exec(String[], String[])
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(cmds, envp) {
                    if (containsRootCommand(cmds)) {
                        send('[IRVES] Blocked root command (String[], envp): ' + cmds.join(' '));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds, envp);
                };

                // exec(String, String[], File)
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmd, envp, dir) {
                    if (containsRootCommand(cmd)) {
                        send('[IRVES] Blocked root command (String, envp, dir): ' + cmd);
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd, envp, dir);
                };

                // exec(String[], String[], File)
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmds, envp, dir) {
                    if (containsRootCommand(cmds)) {
                        send('[IRVES] Blocked root command (String[], envp, dir): ' + cmds.join(' '));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds, envp, dir);
                };
            } catch(e) {
                send('[IRVES] Runtime.exec hook partial/failed: ' + e);
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
                            send('[IRVES] Blocked ProcessBuilder command: ' + cmdStr);
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
                    // Standard su locations
                    '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su',
                    '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/data/local/bin/su',
                    '/data/local/xbin/su', '/su/bin/su',
                    // Magisk paths
                    '/magisk/.core/bin/su', '/sbin/.magisk', '/data/adb/magisk', '/data/adb/ksu',
                    '/data/adb/ap', '/data/adb/ksud',
                    // Zygisk
                    '/data/adb/modules/zygisk',
                    // SuperSU paths
                    '/system/etc/init.d/99SuperSUDaemon', '/system/xbin/daemonsu',
                    // Additional common paths
                    '/system/usr/su', '/vendor/bin/su', '/system/app/SuperSU', '/system/app/SuperSU.apk',
                    '/data/data/eu.chainfire.supersu', '/system/xbin/sugote',
                    // BusyBox (often installed with root)
                    '/system/xbin/busybox', '/data/local/busybox',
                    // Detection files
                    '/system/app/Superuser.apk', '/system/etc/init.d/', '/system/xbin/.magisk',
                ];

                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    for (var i = 0; i < rootPaths.length; i++) {
                        if (path.indexOf(rootPaths[i]) !== -1 || path === rootPaths[i]) {
                            send('[IRVES] Blocked root path check: ' + path);
                            return false;
                        }
                    }
                    return this.exists();
                };
            } catch(e) {}

            // ── 5. java.nio.file.Files for modern Android ────────────────────────────
            try {
                var Files = Java.use('java.nio.file.Files');
                var Paths = Java.use('java.nio.file.Paths');
                var rootPathPatterns = ['/su', '/magisk', '/supersu', '/busybox', 'ksu', 'zygisk'];

                Files.exists.overload('java.nio.file.Path', '[Ljava.nio.file.LinkOption;').implementation = function(path, options) {
                    var pathStr = path.toString();
                    for (var i = 0; i < rootPathPatterns.length; i++) {
                        if (pathStr.toLowerCase().indexOf(rootPathPatterns[i].toLowerCase()) !== -1) {
                            send('[IRVES] Blocked Files.exists path check: ' + pathStr);
                            return false;
                        }
                    }
                    return this.exists(path, options);
                };
            } catch(e) { /* java.nio.file.Files may not be available on older Android */ }

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
                    'com.topjohnwu.su', 'com.android.vending.billing.InAppBillingService.COIN',
                    'com.android.vending.billing.InAppBillingService.LUCK',
                    'com.chelpus.lackypatch', 'com.dv.tls.psm', 'com.chelpus.lps',
                    'com.forp.plym.user', 'com.kingouser.com', 'com.android.vending.billing.InAppBillingService.COIN',
                    // Magisk Manager variants
                    'com.topjohnwu.magisk', 'io.github.huskydg.magisk', 'io.github.vvb2060.magisk',
                ];

                ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
                    for (var i = 0; i < rootPackages.length; i++) {
                        if (pkg === rootPackages[i] || pkg.indexOf(rootPackages[i]) === 0) {
                            send('[IRVES] Hiding root package: ' + pkg);
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
            } catch(e) { /* PackageManager may not be available in all contexts */ }

            // ── 7. System Properties ────────────────────────────────────────────────────
            try {
                var SystemProperties = Java.use('android.os.SystemProperties');
                var suspiciousProps = ['ro.debuggable', 'ro.secure', 'ro.build.tags', 'service.adb.root'];

                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    if (key === 'ro.debuggable') {
                        send('[IRVES] Spoofing ro.debuggable = 0');
                        return '0';
                    }
                    if (key === 'ro.secure') {
                        send('[IRVES] Spoofing ro.secure = 1');
                        return '1';
                    }
                    if (key === 'ro.build.tags') {
                        send('[IRVES] Spoofing ro.build.tags = release-keys');
                        return 'release-keys';
                    }
                    return this.get(key);
                };

                SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                    if (key === 'ro.debuggable') {
                        return '0';
                    }
                    if (key === 'ro.secure') {
                        return '1';
                    }
                    if (key === 'ro.build.tags') {
                        return 'release-keys';
                    }
                    return this.get(key, def);
                };
            } catch(e) {}

            // ── 8. Debug flags ──────────────────────────────────────────────────────────
            try {
                var Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function() {
                    send('[IRVES] Spoofing isDebuggerConnected() = false');
                    return false;
                };
            } catch(e) {}

            // ── 9. SELinux status hiding ───────────────────────────────────────────────
            try {
                // Hide SELinux enforcement status
                var BufferedReader = Java.use('java.io.BufferedReader');
                var InputStreamReader = Java.use('java.io.InputStreamReader');
                var Process = Java.use('java.lang.Process');

                // Hook Runtime.exec again but specifically for getenforce
                var Runtime2 = Java.use('java.lang.Runtime');
                var origExec1 = Runtime2.exec.overload('java.lang.String');
                Runtime2.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf('getenforce') !== -1 || cmd.indexOf('selinux') !== -1) {
                        send('[IRVES] Spoofing SELinux check');
                        throw Java.use('java.io.IOException').$new('Permission denied');
                    }
                    return origExec1.call(this, cmd);
                };
            } catch(e) {}

            send('[IRVES] Root detection bypass fully loaded (comprehensive)');
        });
    """,

    "crypto_capture": """
        Java.perform(function() {
            function bytesToHex(bytes) {
                if (!bytes) return 'null';
                var hex = '';
                for (var i = 0; i < bytes.length; i++) {
                    hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
                }
                return hex;
            }

            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(data) {
                var result = this.doFinal(data);
                send(JSON.stringify({
                    type: 'finding',
                    title: 'Crypto Operation Intercepted',
                    severity: 'high',
                    description: 'Algorithm: ' + this.getAlgorithm() + ' | Input: ' + bytesToHex(data).substring(0, 32) + '...'
                }));
                return result;
            };

            send('[IRVES] Crypto capture hooks loaded');
        });
    """,

    "network_intercept": """
        Java.perform(function() {
            var URL = Java.use('java.net.URL');
            URL.openConnection.overload().implementation = function() {
                send(JSON.stringify({
                    type: 'finding',
                    title: 'Network Connection Observed',
                    severity: 'info',
                    description: 'URL: ' + this.toString()
                }));
                return this.openConnection();
            };

            send('[IRVES] Network intercept hooks loaded');
        });
    """,

    "intent_monitor": """
        Java.perform(function() {
            var Intent = Java.use('android.content.Intent');
            Intent.$init.overload('android.content.Context', 'java.lang.Class').implementation = function(ctx, cls) {
                send('[IRVES] Intent -> ' + cls.getName());
                return this.$init(ctx, cls);
            };
            send('[IRVES] Intent monitor loaded');
        });
    """,
}


class FridaSession:
    """Represents an active Frida session."""

    def __init__(self, session_id: str, device_id: str, package: str):
        self.session_id = session_id
        self.device_id = device_id
        self.package = package
        self._session = None
        self._scripts: dict[str, object] = {}

    @property
    def is_attached(self) -> bool:
        return self._session is not None


class FridaService:
    """Manages Frida sessions for runtime analysis."""

    def __init__(self):
        self.sessions: dict[str, FridaSession] = {}

    def _get_frida(self):
        """Lazy import frida to avoid crash if not installed."""
        try:
            import frida
            return frida
        except ImportError:
            raise RuntimeError("frida Python package is not installed. Run: pip install frida")

    def _resolve_device(self, frida_mod, device_id: str):
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

    async def list_devices(self) -> list[dict]:
        """List all connected Frida devices (USB + emulators)."""
        frida = self._get_frida()
        devices = []
        try:
            # Force Frida's DeviceManager to refresh its USB state.
            # In long running processes, polling enumerate_devices() can return stale state
            # unless a direct hardware get_usb_device() forces a check on the ADB endpoints.
            def _refresh_and_list():
                try:
                    # Try multiple times with increasing timeout to handle slow device initialization
                    for attempt in range(3):
                        try:
                            frida.get_usb_device(timeout=1.0 + (attempt * 0.5))
                            logger.info(f"[Frida] USB device found on attempt {attempt + 1}")
                            break
                        except Exception as e:
                            logger.debug(f"[Frida] USB device check attempt {attempt + 1} failed: {e}")
                            if attempt < 2:
                                import time
                                time.sleep(0.3)
                            continue
                except Exception as e:
                    logger.warning(f"[Frida] USB device check failed: {e}")
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

    async def list_processes(self, device_id: str) -> list[dict]:
        """List running processes on a device."""
        frida = self._get_frida()

        def _list():
            device = frida.get_device(device_id, timeout=5)
            logger.info(f"[Frida] Listing processes on {device.id}")
            processes = device.enumerate_processes()
            logger.info(f"[Frida] Found {len(processes)} processes")
            return [{"pid": p.pid, "name": p.name} for p in processes]

        return await asyncio.get_event_loop().run_in_executor(None, _list)

    async def attach(self, device_id: str, package_name: str) -> str:
        """Attach to a running process by package name."""
        frida = self._get_frida()
        session_id = f"{device_id}:{package_name}"

        def _attach():
            # Resolve device with timeout
            device = self._resolve_device(frida, device_id)
            # For spawn, we might need to set timeouts differently
            try:
                return device.attach(package_name)
            except Exception as e:
                # Re-raise with a clearer message if the process was not found
                err_str = str(e).lower()
                if "unable to find" in err_str or "process not found" in err_str or "no such process" in err_str:
                    raise RuntimeError(
                        f"Process '{package_name}' is not running on the device. "
                        "Launch the app first, then click Connect."
                    ) from e
                raise

        raw_session = await asyncio.get_event_loop().run_in_executor(None, _attach)
        fs = FridaSession(session_id, device_id, package_name)
        fs._session = raw_session
        self.sessions[session_id] = fs
        logger.info(f"[Frida] Attached to {package_name} on {device_id}")
        return session_id

    async def spawn(self, device_id: str, package_name: str) -> str:
        """Spawn a new process and attach to it."""
        frida = self._get_frida()
        session_id = f"{device_id}:{package_name}"

        def _spawn():
            device = self._resolve_device(frida, device_id)
            pid = device.spawn([package_name])
            session = device.attach(pid)
            device.resume(pid)
            return session
        except Exception as e:
            logger.error(f"[Frida] Spawn failed: {e}")
            raise

        raw_session = await asyncio.get_event_loop().run_in_executor(None, _spawn)
        fs = FridaSession(session_id, device_id, package_name)
        fs._session = raw_session
        self.sessions[session_id] = fs
        logger.info(f"[Frida] Spawned {package_name} on {device_id}")
        return session_id

    async def inject_script(
        self,
        session_id: str,
        script_code: str,
        message_handler: Callable,
    ) -> str:
        """Inject a Frida script into the attached session."""
        fs = self.sessions.get(session_id)
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

    async def call_export(self, session_id: str, script_id: str, fn_name: str, args: list):
        """Call an exported function from a loaded script."""
        fs = self.sessions.get(session_id)
        if not fs:
            raise ValueError(f"Session not found: {session_id}")
        script = fs._scripts.get(script_id)
        if not script:
            raise ValueError(f"Script not found: {script_id}")

        def _call():
            return script.exports[fn_name](*args)

        return await asyncio.get_event_loop().run_in_executor(None, _call)

    async def detach(self, session_id: str) -> None:
        """Detach from an active session and clean up."""
        fs = self.sessions.pop(session_id, None)
        if fs and fs._session:
            def _detach():
                try:
                    fs._session.detach()
                except Exception:
                    pass
            await asyncio.get_event_loop().run_in_executor(None, _detach)
            logger.info(f"[Frida] Detached session {session_id}")

    async def preflight_check(self) -> dict:
        """Check if Frida is available, USB devices reachable, and ADB state."""
        result = {
            "frida_installed": False,
            "frida_version": None,
            "devices": [],
            "adb_devices": [],
            "error": None,
        }
        try:
            import frida
            result["frida_installed"] = True
            result["frida_version"] = frida.__version__
            devices = await self.list_devices()
            result["devices"] = devices
            logger.info(f"[Frida Preflight] Found {len(devices)} devices: {devices}")
        except ImportError:
            result["error"] = "frida package is not installed"
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"[Frida Preflight] Error: {e}")
        # Always check ADB independently — phones show here even without frida-server
        adb_devs = await self.adb_devices()
        result["adb_devices"] = adb_devs
        logger.info(f"[Frida Preflight] ADB devices: {adb_devs}")
        return result

    # ─── ADB helpers ──────────────────────────────────────────────────────────

    async def adb_devices(self) -> list[dict]:
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

    async def get_device_arch(self, serial: str) -> str:
        """Get the CPU ABI reported by an ADB-connected Android device."""
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

    async def push_and_start_frida_server(self, serial: str):
        """
        Async generator that streams progress dicts while:
          1. Detecting device architecture
          2. Locating / downloading the matching frida-server binary
          3. Pushing it to /data/local/tmp/frida-server
          4. Setting permissions and starting it
        """
        import os, urllib.request, lzma
        from pathlib import Path

        try:
            import frida as frida_mod
            frida_version = frida_mod.__version__
        except ImportError:
            yield {"step": "arch", "status": "error", "message": "Frida not installed"}
            return

        yield {"step": "arch", "status": "running", "message": f"Detecting architecture for {serial}…"}
        abi = await self.get_device_arch(serial)
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
            url = (
                f"https://github.com/frida/frida/releases/download/{frida_version}/"
                f"{binary_name}.xz"
            )
            yield {"step": "download", "status": "running",
                   "message": f"Downloading frida-server {frida_version} for {frida_arch}…"}
            try:
                xz_path = cache_dir / f"{binary_name}.xz"

                def _download():
                    urllib.request.urlretrieve(url, xz_path)
                    with lzma.open(xz_path) as f_in, open(local_path, "wb") as f_out:
                        f_out.write(f_in.read())
                    xz_path.unlink(missing_ok=True)
                    os.chmod(local_path, 0o755)

                await asyncio.get_event_loop().run_in_executor(None, _download)
                yield {"step": "download", "status": "done",
                       "message": f"Downloaded: {local_path.name}"}
            except Exception as e:
                yield {"step": "download", "status": "error",
                       "message": f"Download failed: {e}. Place binary at {cache_dir}/{binary_name}"}
                return

        remote_path = "/data/local/tmp/frida-server"
        yield {"step": "push", "status": "running",
               "message": f"Pushing to device {serial} → {remote_path}…"}
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "push", str(local_path), remote_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                raise RuntimeError(stderr.decode(errors="replace").strip())
            yield {"step": "push", "status": "done",
                   "message": f"Pushed → {remote_path}"}
        except Exception as e:
            yield {"step": "push", "status": "error", "message": f"Push failed: {e}"}
            return

        yield {"step": "chmod", "status": "running", "message": "Setting execute permission…"}
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, "shell", f"chmod 755 {remote_path}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=15)
        yield {"step": "chmod", "status": "done", "message": "Permission granted (755)"}

        yield {"step": "start", "status": "running", "message": "Starting frida-server as background daemon…"}
        try:
            # ── Step 1: Try multiple su implementations ─────────────────────────────────
            # Different root solutions place su in different paths
            su_paths = [
                "su",                    # Default PATH
                "/system/bin/su",        # Standard Android
                "/system/xbin/su",       # Some custom ROMs
                "/sbin/su",              # Magisk (systemless root)
                "/su/bin/su",            # Systemless root
                "/data/local/su",        # Some exploits
                "/data/local/tmp/su",    # Some temporary roots
            ]

            # First, check which su is available
            check_su_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                "which su || ls /system/bin/su /system/xbin/su /sbin/su /su/bin/su 2>/dev/null || echo 'su-not-found'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(check_su_proc.communicate(), timeout=10)
            available_su = stdout.decode(errors="replace").strip().split('\n')[0].strip()

            # Determine if device is rooted
            is_rooted = False
            if available_su and available_su != 'su-not-found' and available_su != '':
                is_rooted = True
                # Use the discovered su path
                su_cmd = available_su if available_su.startswith('/') else 'su'
            else:
                # Try direct su check
                test_root_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell",
                    "su -c 'id' 2>/dev/null || /system/bin/su -c 'id' 2>/dev/null || /sbin/su -c 'id' 2>/dev/null || echo 'no-root'",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(test_root_proc.communicate(), timeout=10)
                output = stdout.decode(errors="replace").strip()
                is_rooted = 'uid=0' in output or 'root' in output.lower()

            if not is_rooted:
                # ── Non-rooted device: Try alternative methods ───────────────────────
                # Try run-as for debuggable apps (limited but may work)
                yield {"step": "start", "status": "running",
                       "message": "No root access detected. Trying alternative startup methods…"}

                # Method 1: Try starting directly from /data/local/tmp (may work on some devices)
                start_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell",
                    f"cd /data/local/tmp && ./{remote_path.split('/')[-1]} &",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(start_proc.communicate(), timeout=15)
                await asyncio.sleep(1.5)

                # Verify if frida-server started
                verify_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell", "ps -A 2>/dev/null || ps",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(verify_proc.communicate(), timeout=10)
                if 'frida-server' in stdout.decode(errors="replace"):
                    yield {"step": "start", "status": "done",
                           "message": "frida-server started (non-root mode)"}
                    yield {"step": "complete", "status": "done",
                           "message": "Setup complete — refreshing device status…"}
                    return

                # Method 2: Check for Magisk rootless mode
                magisk_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell",
                    "ls /data/adb/magisk 2>/dev/null && echo 'magisk-found'",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(magisk_proc.communicate(), timeout=10)
                if 'magisk-found' in stdout.decode(errors="replace"):
                    yield {"step": "start", "status": "running",
                           "message": "Magisk detected, requesting root via Magisk…"}
                    # Magisk may prompt user for root access
                    start_proc = await asyncio.create_subprocess_exec(
                        "adb", "-s", serial, "shell",
                        "/data/adb/magisk/busybox sh -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &' 2>/dev/null || "
                        "/data/adb/ksu/bin/su -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(start_proc.communicate(), timeout=15)
                    await asyncio.sleep(2)

                    verify_proc = await asyncio.create_subprocess_exec(
                        "adb", "-s", serial, "shell", "ps -A 2>/dev/null || ps",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(verify_proc.communicate(), timeout=10)
                    if 'frida-server' in stdout.decode(errors="replace"):
                        yield {"step": "start", "status": "done",
                               "message": "frida-server started via Magisk"}
                        yield {"step": "complete", "status": "done",
                               "message": "Setup complete — refreshing device status…"}
                        return

                # All non-root methods failed
                yield {"step": "start", "status": "error",
                       "message": "This device is not rooted. Frida requires root access OR use the 'Xposed (Non-Root)' mode for this device. "
                       "To use root mode: ensure Magisk/SuperSU is installed and grant root permission when prompted."}
                return

            # ── Rooted device: Kill old frida-server instances ─────────────────────────
            # Try different su paths for killing
            for su_path in [su_cmd] + su_paths:
                if su_path.startswith('/') or su_path == 'su':
                    kill_proc = await asyncio.create_subprocess_exec(
                        "adb", "-s", serial, "shell",
                        f"{su_path} -c 'pkill -f frida-server 2>/dev/null; killall frida-server 2>/dev/null; sleep 0.5; true'",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(kill_proc.communicate(), timeout=10)
                    await asyncio.sleep(0.5)
                    break

            # ── Step 2: Handle SELinux (important for Magisk devices) ────────────────
            # Check and temporarily set SELinux to permissive if needed
            check_selinux_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"{su_cmd} -c 'getenforce 2>/dev/null || echo unknown'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(check_selinux_proc.communicate(), timeout=10)
            selinux_mode = stdout.decode(errors="replace").strip().upper()

            if selinux_mode == 'ENFORCING':
                yield {"step": "start", "status": "running",
                       "message": "SELinux is Enforcing, temporarily setting to Permissive…"}
                set_selinux_proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell",
                    f"{su_cmd} -c 'setenforce 0 2>/dev/null || true'",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(set_selinux_proc.communicate(), timeout=10)
                await asyncio.sleep(0.5)

            # ── Step 3: Start frida-server with proper handling ─────────────────────────
            # Use different startup methods based on available su

            # Method 1: Standard su -c with proper quoting
            start_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"{su_cmd} -c 'nohup {remote_path} > /dev/null 2>&1 &'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(start_proc.communicate(), timeout=15)
            await asyncio.sleep(1.5)

            # Verify frida-server is running
            verify_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell", "ps -A 2>/dev/null || ps",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(verify_proc.communicate(), timeout=10)

            if 'frida-server' in stdout.decode(errors="replace"):
                yield {"step": "start", "status": "done",
                       "message": "frida-server is running on the device!"}
                # Additional verification: try to actually connect via Frida
                yield {"step": "verify", "status": "running",
                       "message": "Verifying Frida connection..."}
                await asyncio.sleep(2)  # Give it more time to stabilize

                # Try to verify Frida can actually connect
                try:
                    import frida as frida_mod
                    # Force a device enumeration to verify Frida can see the device
                    def _verify_frida():
                        try:
                            devices = frida_mod.enumerate_devices()
                            usb_devices = [d for d in devices if d.type == 'usb']
                            if usb_devices:
                                # Try to get the device to ensure it's responsive
                                dev = frida_mod.get_device(usb_devices[0].id, timeout=3)
                                return True, f"Verified: {dev.name}"
                            return False, "No USB devices found"
                        except Exception as e:
                            return False, str(e)

                    success, msg = await asyncio.get_event_loop().run_in_executor(None, _verify_frida)
                    if success:
                        yield {"step": "verify", "status": "done",
                               "message": msg}
                    else:
                        yield {"step": "verify", "status": "error",
                               "message": f"Frida verification failed: {msg}"}
                except Exception as e:
                    yield {"step": "verify", "status": "error",
                           "message": f"Verification error: {e}"}

                yield {"step": "complete", "status": "done",
                       "message": "Setup complete — refreshing device status…"}
                return

            # Method 2: Try with explicit shell for devices where su -c doesn't work
            yield {"step": "start", "status": "running",
                   "message": "Trying alternative startup method…"}
            start_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"{su_cmd} -c 'sh -c \"{remote_path} &\"'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(start_proc.communicate(), timeout=15)
            await asyncio.sleep(2)

            # Verify again
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

            # Method 3: Try with daemonize for older devices
            yield {"step": "start", "status": "running",
                   "message": "Trying daemon startup method…"}
            start_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", serial, "shell",
                f"{su_cmd} -c 'cd /data/local/tmp && ./frida-server -D &'",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(start_proc.communicate(), timeout=15)
            await asyncio.sleep(2)

            # Final verification
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
                   "message": "Failed to start frida-server. Try running 'adb shell su -c /data/local/tmp/frida-server &' manually on the device. "
                   "If SELinux is Enforcing, run: adb shell su -c setenforce 0"}

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


# Global singleton
frida_service = FridaService()

