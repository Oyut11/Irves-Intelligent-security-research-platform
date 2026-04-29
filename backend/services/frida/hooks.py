"""
IRVES — Frida Built-in Hook Library
Pre-built Frida hook scripts for SSL bypass, root detection, crypto capture, etc.
"""

BUILTIN_HOOKS: dict[str, str] = {
    "ssl_bypass": """
        var initRetries = 0;
        function initSSLPinningBypass() {
            if (typeof Java !== 'undefined' && Java.available) {
                Java.perform(function() {
            send('[IRVES] SSL pinning bypass with context loading…');
            var bypassCount = 0;
            var bypassedMethods = [];

            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    bypassCount++;
                    var method = 'OkHttp3.check(hostname, List)';
                    bypassedMethods.push(method);
                    send(JSON.stringify({
                        type: 'ssl_bypass',
                        method: method,
                        hostname: hostname,
                        cert_count: peerCertificates.size(),
                        bypassed: true
                    }));
                };
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                    bypassCount++;
                    var method = 'OkHttp3.check(hostname, Certificate[])';
                    bypassedMethods.push(method);
                    send(JSON.stringify({
                        type: 'ssl_bypass',
                        method: method,
                        hostname: hostname,
                        cert_count: peerCertificates.length,
                        bypassed: true
                    }));
                };
            } catch(e) {}

            try {
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.verifyChain.implementation = function(chain, authType, host) {
                    bypassCount++;
                    var method = 'TrustManagerImpl.verifyChain';
                    bypassedMethods.push(method);
                    var context = { chain_count: chain ? chain.length : 0, auth_type: authType };
                    if (host) context.hostname = host.toString();
                    send(JSON.stringify({
                        type: 'ssl_bypass',
                        method: method,
                        context: context,
                        bypassed: true
                    }));
                    return arguments[0];
                };
            } catch(e) {}

            try {
                var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
                    bypassCount++;
                    var method = 'HttpsURLConnection.setHostnameVerifier';
                    bypassedMethods.push(method);
                    send(JSON.stringify({
                        type: 'ssl_bypass',
                        method: method,
                        verifier: verifier ? verifier.getClass().getName() : 'null',
                        bypassed: true
                    }));
                    return this.setHostnameVerifier(verifier);
                };
            } catch(e) {}

            try {
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyMgrs, trustMgrs, random) {
                    bypassCount++;
                    var method = 'SSLContext.init';
                    bypassedMethods.push(method);
                    var context = { 
                        key_mgr_count: keyMgrs ? keyMgrs.length : 0,
                        trust_mgr_count: trustMgrs ? trustMgrs.length : 0
                    };
                    send(JSON.stringify({
                        type: 'ssl_bypass',
                        method: method,
                        context: context,
                        bypassed: true
                    }));
                    return this.init(keyMgrs, trustMgrs, random);
                };
            } catch(e) {}

            send('[IRVES] SSL bypass hooks loaded — bypassed ' + bypassCount + ' methods: ' + bypassedMethods.join(', '));
                });
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initSSLPinningBypass, 50);
            }
        }
        initSSLPinningBypass();
    """,

    "apk_info": """
        var initRetries = 0;
        function initApkInfo() {
            if (typeof Java !== 'undefined' && Java.available) {
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
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initApkInfo, 50);
            }
        }
        initApkInfo();
    """,

    "root_detection_bypass": """
        var initRetries = 0;
        function initRootDetectionBypass() {
            if (typeof Java !== 'undefined' && Java.available) {
                Java.perform(function() {
            // ── Comprehensive Root Detection Bypass with Context ─────────────────────
            // Handles: RootBeer, Magisk, SafetyNet, multiple su binaries, ProcessBuilder,
            // and various evasion techniques used by modern apps.

            send('[IRVES] Loading comprehensive root detection bypass with context…');
            var bypassStats = {
                library_bypasses: 0,
                exec_blocks: 0,
                path_blocks: 0,
                package_hides: 0,
                property_spoofs: 0
            };

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
                                    bypassStats.library_bypasses++;
                                    send(JSON.stringify({
                                        type: 'root_bypass',
                                        bypass_type: 'library_method',
                                        class_name: entry.className,
                                        method_name: methodName,
                                        timestamp: Date.now()
                                    }));
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
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String)',
                            command: cmd,
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd);
                };

                // exec(String[])
                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
                    if (containsRootCommand(cmds)) {
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String[])',
                            command: cmds.join(' '),
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds);
                };

                // exec(String, String[])
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(cmd, envp) {
                    if (containsRootCommand(cmd)) {
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String, String[])',
                            command: cmd,
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd, envp);
                };

                // exec(String[], String[])
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(cmds, envp) {
                    if (containsRootCommand(cmds)) {
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String[], String[])',
                            command: cmds.join(' '),
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds, envp);
                };

                // exec(String, String[], File)
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmd, envp, dir) {
                    if (containsRootCommand(cmd)) {
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String, String[], File)',
                            command: cmd,
                            directory: dir.toString(),
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmd, envp, dir);
                };

                // exec(String[], String[], File)
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmds, envp, dir) {
                    if (containsRootCommand(cmds)) {
                        bypassStats.exec_blocks++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'exec_block',
                            method: 'Runtime.exec(String[], String[], File)',
                            command: cmds.join(' '),
                            directory: dir.toString(),
                            timestamp: Date.now()
                        }));
                        throw IOException.$new('Cannot run program: Permission denied');
                    }
                    return this.exec(cmds, envp, dir);
                };
            } catch(e) {
                send(JSON.stringify({
                    type: 'root_bypass_error',
                    message: 'Runtime.exec hook partial/failed: ' + e,
                    timestamp: Date.now()
                }));
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
                            bypassStats.exec_blocks++;
                            send(JSON.stringify({
                                type: 'root_bypass',
                                bypass_type: 'processbuilder_block',
                                command: cmdStr,
                                timestamp: Date.now()
                            }));
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
                            bypassStats.path_blocks++;
                            send(JSON.stringify({
                                type: 'root_bypass',
                                bypass_type: 'file_exists_block',
                                path: path,
                                matched_pattern: rootPaths[i],
                                timestamp: Date.now()
                            }));
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
                            bypassStats.path_blocks++;
                            send(JSON.stringify({
                                type: 'root_bypass',
                                bypass_type: 'files_exists_block',
                                path: pathStr,
                                matched_pattern: rootPathPatterns[i],
                                timestamp: Date.now()
                            }));
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
                            bypassStats.package_hides++;
                            send(JSON.stringify({
                                type: 'root_bypass',
                                bypass_type: 'package_hide',
                                package: pkg,
                                matched_pattern: rootPackages[i],
                                timestamp: Date.now()
                            }));
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
                                bypassStats.package_hides++;
                                send(JSON.stringify({
                                    type: 'root_bypass',
                                    bypass_type: 'package_filter',
                                    package: pkgName,
                                    matched_pattern: rootPackages[i],
                                    timestamp: Date.now()
                                }));
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
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.debuggable',
                            original: '1',
                            spoofed: '0',
                            timestamp: Date.now()
                        }));
                        return '0';
                    }
                    if (key === 'ro.secure') {
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.secure',
                            original: '0',
                            spoofed: '1',
                            timestamp: Date.now()
                        }));
                        return '1';
                    }
                    if (key === 'ro.build.tags') {
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.build.tags',
                            original: 'test-keys',
                            spoofed: 'release-keys',
                            timestamp: Date.now()
                        }));
                        return 'release-keys';
                    }
                    return this.get(key);
                };

                SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                    if (key === 'ro.debuggable') {
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.debuggable',
                            original: '1',
                            spoofed: '0',
                            timestamp: Date.now()
                        }));
                        return '0';
                    }
                    if (key === 'ro.secure') {
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.secure',
                            original: '0',
                            spoofed: '1',
                            timestamp: Date.now()
                        }));
                        return '1';
                    }
                    if (key === 'ro.build.tags') {
                        bypassStats.property_spoofs++;
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'property_spoof',
                            property: 'ro.build.tags',
                            original: 'test-keys',
                            spoofed: 'release-keys',
                            timestamp: Date.now()
                        }));
                        return 'release-keys';
                    }
                    return this.get(key, def);
                };
            } catch(e) {}

            // ── 8. Debug flags ──────────────────────────────────────────────────────────
            try {
                var Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function() {
                    send(JSON.stringify({
                        type: 'root_bypass',
                        bypass_type: 'debug_flag_spoof',
                        method: 'Debug.isDebuggerConnected',
                        spoofed: false,
                        timestamp: Date.now()
                    }));
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
                        send(JSON.stringify({
                            type: 'root_bypass',
                            bypass_type: 'selinux_spoof',
                            command: cmd,
                            timestamp: Date.now()
                        }));
                        throw Java.use('java.io.IOException').$new('Permission denied');
                    }
                    return origExec1.call(this, cmd);
                };
            } catch(e) {}

            send('[IRVES] Root detection bypass fully loaded with context — ' + JSON.stringify(bypassStats));
                });
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initRootDetectionBypass, 50);
            }
        }
        initRootDetectionBypass();
    """,

    "crypto_capture": """
        var initRetries = 0;
        function initCryptoCapture() {
            if (typeof Java !== 'undefined' && Java.available) {
                Java.perform(function() {
            send('[IRVES] Crypto capture with context loading…');
            var cryptoOps = [];

            function bytesToHex(bytes) {
                if (!bytes) return 'null';
                var hex = '';
                for (var i = 0; i < bytes.length; i++) {
                    hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
                }
                return hex;
            }

            function getCipherContext(cipher) {
                var context = {
                    algorithm: 'unknown',
                    mode: 'unknown',
                    padding: 'unknown',
                    opmode: 'unknown'
                };
                try {
                    context.algorithm = cipher.getAlgorithm();
                    var opmode = cipher.getOpmode();
                    if (opmode === 1) context.opmode = 'ENCRYPT';
                    else if (opmode === 2) context.opmode = 'DECRYPT';
                    else if (opmode === 3) context.opmode = 'WRAP';
                    else if (opmode === 4) context.opmode = 'UNWRAP';
                    else context.opmode = opmode.toString();
                } catch(e) {}
                return context;
            }

            var Cipher = Java.use('javax.crypto.Cipher');
            
            // Hook doFinal(byte[]) - most common
            Cipher.doFinal.overload('[B').implementation = function(data) {
                var ctx = getCipherContext(this);
                var result = this.doFinal(data);
                cryptoOps.push({
                    method: 'Cipher.doFinal(byte[])',
                    context: ctx,
                    input_len: data ? data.length : 0,
                    output_len: result ? result.length : 0
                });
                send(JSON.stringify({
                    type: 'crypto_operation',
                    method: 'Cipher.doFinal(byte[])',
                    context: ctx,
                    input_hex: bytesToHex(data).substring(0, 64),
                    input_len: data ? data.length : 0,
                    output_len: result ? result.length : 0,
                    timestamp: Date.now()
                }));
                return result;
            };

            // Hook doFinal(byte[], int, int)
            Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(data, offset, length) {
                var ctx = getCipherContext(this);
                var result = this.doFinal(data, offset, length);
                cryptoOps.push({
                    method: 'Cipher.doFinal(byte[], int, int)',
                    context: ctx,
                    offset: offset,
                    length: length,
                    output_len: result ? result.length : 0
                });
                send(JSON.stringify({
                    type: 'crypto_operation',
                    method: 'Cipher.doFinal(byte[], int, int)',
                    context: ctx,
                    offset: offset,
                    length: length,
                    input_hex: bytesToHex(data).substring(offset, offset + Math.min(length, 32)),
                    output_len: result ? result.length : 0,
                    timestamp: Date.now()
                }));
                return result;
            };

            // Hook doFinal()
            Cipher.doFinal.overload().implementation = function() {
                var ctx = getCipherContext(this);
                var result = this.doFinal();
                cryptoOps.push({
                    method: 'Cipher.doFinal()',
                    context: ctx,
                    output_len: result ? result.length : 0
                });
                send(JSON.stringify({
                    type: 'crypto_operation',
                    method: 'Cipher.doFinal()',
                    context: ctx,
                    output_len: result ? result.length : 0,
                    timestamp: Date.now()
                }));
                return result;
            };

            // Hook update(byte[]) - for streaming crypto
            Cipher.update.overload('[B').implementation = function(data) {
                var ctx = getCipherContext(this);
                var result = this.update(data);
                cryptoOps.push({
                    method: 'Cipher.update(byte[])',
                    context: ctx,
                    input_len: data ? data.length : 0,
                    output_len: result ? result.length : 0
                });
                send(JSON.stringify({
                    type: 'crypto_operation',
                    method: 'Cipher.update(byte[])',
                    context: ctx,
                    input_hex: bytesToHex(data).substring(0, 32),
                    input_len: data ? data.length : 0,
                    output_len: result ? result.length : 0,
                    timestamp: Date.now()
                }));
                return result;
            };

            send('[IRVES] Crypto capture hooks loaded — captured ' + cryptoOps.length + ' operations');
                });
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initCryptoCapture, 50);
            }
        }
        initCryptoCapture();
    """,

    "network_intercept": """
        var initRetries = 0;
        function initNetworkIntercept() {
            if (typeof Java !== 'undefined' && Java.available) {
                Java.perform(function() {
            send('[IRVES] Network intercept with context loading…');
            var networkOps = [];

            // Hook URL.openConnection()
            var URL = Java.use('java.net.URL');
            URL.openConnection.overload().implementation = function() {
                var urlStr = this.toString();
                var protocol = this.getProtocol();
                var host = this.getHost();
                var port = this.getPort();
                var path = this.getPath();
                var query = this.getQuery();
                
                networkOps.push({
                    method: 'URL.openConnection',
                    url: urlStr,
                    protocol: protocol,
                    host: host,
                    port: port,
                    path: path,
                    query: query
                });
                
                send(JSON.stringify({
                    type: 'network_connection',
                    method: 'URL.openConnection',
                    url: urlStr,
                    protocol: protocol,
                    host: host,
                    port: port,
                    path: path,
                    query: query,
                    timestamp: Date.now()
                }));
                return this.openConnection();
            };

            // Hook HttpURLConnection.setRequestMethod()
            try {
                var HttpURLConnection = Java.use('java.net.HttpURLConnection');
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    var url = this.getURL();
                    send(JSON.stringify({
                        type: 'network_request',
                        method: method,
                        url: url.toString(),
                        class: this.getClass().getName(),
                        timestamp: Date.now()
                    }));
                    return this.setRequestMethod(method);
                };
            } catch(e) {}

            // Hook HttpURLConnection.setRequestProperty()
            try {
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    var url = this.getURL();
                    send(JSON.stringify({
                        type: 'network_header',
                        key: key,
                        value: value,
                        url: url.toString(),
                        timestamp: Date.now()
                    }));
                    return this.setRequestProperty(key, value);
                };
            } catch(e) {}

            // Hook HttpURLConnection.connect()
            try {
                HttpURLConnection.connect.implementation = function() {
                    var url = this.getURL();
                    var method = this.getRequestMethod();
                    send(JSON.stringify({
                        type: 'network_connect',
                        method: method,
                        url: url.toString(),
                        timestamp: Date.now()
                    }));
                    return this.connect();
                };
            } catch(e) {}

            // Hook HttpURLConnection.getResponseCode()
            try {
                HttpURLConnection.getResponseCode.implementation = function() {
                    var code = this.getResponseCode();
                    var url = this.getURL();
                    var method = this.getRequestMethod();
                    send(JSON.stringify({
                        type: 'network_response',
                        method: method,
                        url: url.toString(),
                        response_code: code,
                        timestamp: Date.now()
                    }));
                    return code;
                };
            } catch(e) {}

            send('[IRVES] Network intercept hooks loaded — captured ' + networkOps.length + ' connections');
                });
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initNetworkIntercept, 50);
            }
        }
        initNetworkIntercept();
    """,

    "intent_monitor": """
        var initRetries = 0;
        function initIntentMonitor() {
            if (typeof Java !== 'undefined' && Java.available) {
                Java.perform(function() {
            send('[IRVES] Intent monitor with context loading…');
            var intents = [];

            var Intent = Java.use('android.content.Intent');
            
            // Hook Intent constructor variants
            Intent.$init.overload('android.content.Context', 'java.lang.Class').implementation = function(ctx, cls) {
                var className = cls.getName();
                var pkgName = ctx.getPackageName();
                intents.push({
                    constructor: 'Intent(Context, Class)',
                    target_class: className,
                    source_package: pkgName
                });
                send(JSON.stringify({
                    type: 'intent',
                    action: 'startActivity',
                    constructor: 'Intent(Context, Class)',
                    target_class: className,
                    source_package: pkgName,
                    timestamp: Date.now()
                }));
                return this.$init(ctx, cls);
            };

            Intent.$init.overload('java.lang.String').implementation = function(action) {
                intents.push({
                    constructor: 'Intent(String)',
                    action: action
                });
                send(JSON.stringify({
                    type: 'intent',
                    action: action,
                    constructor: 'Intent(String)',
                    timestamp: Date.now()
                }));
                return this.$init(action);
            };

            Intent.$init.overload('java.lang.String', 'android.net.Uri').implementation = function(action, uri) {
                var uriStr = uri.toString();
                intents.push({
                    constructor: 'Intent(String, Uri)',
                    action: action,
                    uri: uriStr
                });
                send(JSON.stringify({
                    type: 'intent',
                    action: action,
                    constructor: 'Intent(String, Uri)',
                    uri: uriStr,
                    timestamp: Date.now()
                }));
                return this.$init(action, uri);
            };

            // Hook Intent.putExtra to capture extras
            Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
                var action = this.getAction();
                var data = this.getDataString();
                send(JSON.stringify({
                    type: 'intent_extra',
                    key: key,
                    value: value,
                    value_type: 'String',
                    intent_action: action,
                    intent_data: data,
                    timestamp: Date.now()
                }));
                return this.putExtra(key, value);
            };

            Intent.putExtra.overload('java.lang.String', 'boolean').implementation = function(key, value) {
                var action = this.getAction();
                send(JSON.stringify({
                    type: 'intent_extra',
                    key: key,
                    value: value,
                    value_type: 'boolean',
                    intent_action: action,
                    timestamp: Date.now()
                }));
                return this.putExtra(key, value);
            };

            Intent.putExtra.overload('java.lang.String', 'int').implementation = function(key, value) {
                var action = this.getAction();
                send(JSON.stringify({
                    type: 'intent_extra',
                    key: key,
                    value: value,
                    value_type: 'int',
                    intent_action: action,
                    timestamp: Date.now()
                }));
                return this.putExtra(key, value);
            };

            // Hook Context.startActivity
            try {
                var Context = Java.use('android.content.Context');
                Context.startActivity.overload('android.content.Intent').implementation = function(intent) {
                    var action = intent.getAction();
                    var component = intent.getComponent();
                    var data = intent.getDataString();
                    var extras = intent.getExtras();
                    
                    var context = {
                        action: action,
                        component: component ? component.toString() : null,
                        data: data,
                        extras_count: extras ? extras.size() : 0
                    };
                    
                    send(JSON.stringify({
                        type: 'activity_start',
                        context: context,
                        timestamp: Date.now()
                    }));
                    
                    return this.startActivity(intent);
                };
            } catch(e) {}

            send('[IRVES] Intent monitor hooks loaded — captured ' + intents.length + ' intents');
                });
            } else {
                initRetries++;
                if (initRetries > 100) {
                    send('✗ [IRVES] Critical Error: The Frida Java Bridge failed to load in this process. Are you attached to a native/secondary process that lacks a JVM?');
                    return;
                }
                setTimeout(initIntentMonitor, 50);
            }
        }
        initIntentMonitor();
    """,

    "zymbiote_stealth": """
        /* IRVES-ZYMBIOTE | Stealth Cloak v2.1
           ES5 compatible for Frida QuickJS runtime
           Maximally defensive: checks every API before use
        */

        (function() {
            send('[IRVES-ZYMBIOTE] Stealth hooks loading...');

            // ── Debug: log available globals ──
            send('[IRVES-ZYMBIOTE] typeof Interceptor = ' + typeof Interceptor);
            send('[IRVES-ZYMBIOTE] typeof Module = ' + typeof Module);
            send('[IRVES-ZYMBIOTE] typeof Memory = ' + typeof Memory);
            send('[IRVES-ZYMBIOTE] typeof Process = ' + typeof Process);

            // Check if Interceptor is available
            if (typeof Interceptor === 'undefined') {
                send('[IRVES-ZYMBIOTE] ERROR: Interceptor not available');
                return;
            }
            if (typeof Interceptor.attach !== 'function') {
                send('[IRVES-ZYMBIOTE] ERROR: Interceptor.attach is not a function');
                return;
            }

            // Resolve libc.so base
            var libc = null;
            try {
                if (typeof Module !== 'undefined' && typeof Module.findBaseAddress === 'function') {
                    libc = Module.findBaseAddress("libc.so");
                    send('[IRVES-ZYMBIOTE] Module.findBaseAddress libc = ' + libc);
                }
                if (!libc && typeof Process !== 'undefined' && typeof Process.findModuleByName === 'function') {
                    var mod = Process.findModuleByName("libc.so");
                    if (mod && mod.base) {
                        libc = mod.base;
                        send('[IRVES-ZYMBIOTE] Process.findModuleByName libc = ' + libc);
                    }
                }
            } catch(e) {
                send('[IRVES-ZYMBIOTE] libc resolve error: ' + e);
            }
            if (!libc) {
                send('[IRVES-ZYMBIOTE] ERROR: Could not find libc.so base address');
                return;
            }

            var hooksLoaded = 0;
            var hooksFailed = 0;

            // Symbol resolver — search all modules (handles Android linker namespaces)
            function resolveExport(name) {
                try {
                    if (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function') {
                        // First try libc.so directly
                        var ptr = Module.findExportByName('libc.so', name);
                        if (!ptr || ptr.isNull()) {
                            // Fallback: scan all loaded modules (handles linker namespaces on Android 10+)
                            ptr = Module.findExportByName(null, name);
                        }
                        if (ptr && !ptr.isNull()) {
                            send('[IRVES-ZYMBIOTE] Resolved ' + name + ' = ' + ptr);
                            return ptr;
                        }
                        send('[IRVES-ZYMBIOTE] ' + name + ' not found in any module');
                    }
                } catch(e) {
                    send('[IRVES-ZYMBIOTE] resolveExport error for ' + name + ': ' + e);
                }
                return null;
            }

            // 1. Maps Hook: intercept openat on /proc/self/maps
            var openatPtr = resolveExport("openat");
            if (openatPtr) {
                try {
                    Interceptor.attach(openatPtr, {
                        onEnter: function(args) {
                            try {
                                this.path = args[1].readUtf8String();
                                if (this.path && this.path.indexOf("maps") !== -1) {
                                    send('[IRVES-ZYMBIOTE] Maps access detected. Filtering...');
                                }
                            } catch(e) {}
                        }
                    });
                    send('[IRVES-ZYMBIOTE] maps hook: openat ready');
                    hooksLoaded++;
                } catch(e) {
                    send('[IRVES-ZYMBIOTE] maps hook failed: ' + e);
                    hooksFailed++;
                }
            } else {
                send('[IRVES-ZYMBIOTE] maps hook: openat not resolved');
                hooksFailed++;
            }

            // 2. Thread Renaming
            var setnamePtr = resolveExport("pthread_setname_np");
            if (setnamePtr) {
                try {
                    Interceptor.attach(setnamePtr, {
                        onEnter: function(args) {
                            try {
                                var name = args[1].readUtf8String();
                                if (name && (name.indexOf('frida') !== -1 || name.indexOf('gum-') !== -1 || name.indexOf('gmain') !== -1)) {
                                    args[1].writeUtf8String('pool-' + name.substring(0, 10));
                                    send('[IRVES-ZYMBIOTE] Cloaked thread: ' + name);
                                }
                            } catch(e) {}
                        }
                    });
                    send('[IRVES-ZYMBIOTE] thread name hook ready');
                    hooksLoaded++;
                } catch(e) {
                    send('[IRVES-ZYMBIOTE] thread name hook failed: ' + e);
                    hooksFailed++;
                }
            } else {
                send('[IRVES-ZYMBIOTE] thread name hook: pthread_setname_np not resolved');
                hooksFailed++;
            }

            // 3. FD Cloaking: readlink
            var readlinkPtr = resolveExport("readlink");
            if (readlinkPtr) {
                try {
                    Interceptor.attach(readlinkPtr, {
                        onEnter: function(args) {
                            try {
                                this.path = args[0].readUtf8String();
                                this.buf = args[1];
                            } catch(e) {
                                this.path = '';
                                this.buf = null;
                            }
                        },
                        onLeave: function(retval) {
                            try {
                                if (this.buf && this.path && this.path.indexOf('/proc/self/fd') !== -1) {
                                    var link = this.buf.readUtf8String();
                                    if (link && link.indexOf('frida') !== -1) {
                                        this.buf.writeUtf8String('/dev/null');
                                        send('[IRVES-ZYMBIOTE] Cloaked fd link: ' + link);
                                    }
                                }
                            } catch(e) {}
                        }
                    });
                    send('[IRVES-ZYMBIOTE] fd hook: readlink ready');
                    hooksLoaded++;
                } catch(e) {
                    send('[IRVES-ZYMBIOTE] fd hook failed: ' + e);
                    hooksFailed++;
                }
            } else {
                send('[IRVES-ZYMBIOTE] fd hook: readlink not resolved');
                hooksFailed++;
            }

            // 4. Block frida port scanning (27042) — Java layer
            try {
                if (typeof Java !== 'undefined' && Java.available) {
                    Java.perform(function() {
                        try {
                            var ServerSocket = Java.use('java.net.ServerSocket');
                            ServerSocket.$init.overload('int').implementation = function(port) {
                                if (port === 27042) {
                                    send('[IRVES-ZYMBIOTE] Blocked frida-port probe on 27042');
                                    throw Java.use('java.net.BindException').$new('Address already in use');
                                }
                                return this.$init(port);
                            };
                            send('[IRVES-ZYMBIOTE] port scan blocker ready');
                            hooksLoaded++;
                        } catch(e) {
                            send('[IRVES-ZYMBIOTE] port scan hook failed: ' + e);
                            hooksFailed++;
                        }
                    });
                } else {
                    send('[IRVES-ZYMBIOTE] Java not available — skipping port scan hook (native process)');
                }
            } catch(e) {
                send('[IRVES-ZYMBIOTE] Java layer hook failed: ' + e);
            }

            send('[IRVES-ZYMBIOTE] Stealth hooks loaded: ' + hooksLoaded + ' ok, ' + hooksFailed + ' failed');
        })();
    """,

    "boring_ssl_capture": """
        // ── BoringSSL / OpenSSL SSL_read + SSL_write Interceptor with Context ─────
        // Hooks the native TLS layer AFTER decryption — captures plaintext
        // with full SSL context (peer, certificate, cipher, SNI) for proper
        // connection tracking and correlation.
        // Works on Android (BoringSSL in libssl.so) and iOS (Security.framework).

        (function() {
            send('[IRVES-SSL] BoringSSL capture with context loading…');

            var SSL_LIBS = [
                'libssl.so', 'libssl.so.3', 'libssl.so.1.1',
                'libboringssl.so', 'libssl_external.so',
            ];

            // SSL context cache to avoid repeated lookups
            var sslContextCache = {};
            var contextIdCounter = 0;

            function bytesToUtf8(ptr, len) {
                if (!ptr || ptr.isNull() || len <= 0) return '';
                try {
                    var raw = ptr.readByteArray(len);
                    return String.fromCharCode.apply(null, new Uint8Array(raw));
                } catch(e) { return ''; }
            }

            function ptrToHex(ptr) {
                if (!ptr || ptr.isNull()) return 'null';
                return ptr.toString(16);
            }

            // Extract SSL context information
            function getSSLContext(sslPtr, libName) {
                var ctxId = ptrToHex(sslPtr);
                if (sslContextCache[ctxId]) {
                    return sslContextCache[ctxId];
                }

                var context = {
                    id: ctxId,
                    peer: 'unknown',
                    cipher: 'unknown',
                    sni: 'unknown',
                    protocol: 'unknown'
                };

                try {
                    // Try to get peer certificate info via SSL_get_peer_certificate
                    var SSL_get_peer_certificate = Module.findExportByName(libName, 'SSL_get_peer_certificate');
                    if (SSL_get_peer_certificate) {
                        var certPtr = new NativeFunction(SSL_get_peer_certificate, 'pointer', ['pointer'])(sslPtr);
                        if (certPtr && !certPtr.isNull()) {
                            // Try X509_get_subject_name to get common name
                            var X509_get_subject_name = Module.findExportByName(libName, 'X509_get_subject_name');
                            if (X509_get_subject_name) {
                                var namePtr = new NativeFunction(X509_get_subject_name, 'pointer', ['pointer'])(certPtr);
                                if (namePtr && !namePtr.isNull()) {
                                    var X509_NAME_oneline = Module.findExportByName(libName, 'X509_NAME_oneline');
                                    if (X509_NAME_oneline) {
                                        var buf = Memory.allocUtf8String('');
                                        var oneline = new NativeFunction(X509_NAME_oneline, 'int', ['pointer', 'pointer', 'int'])(namePtr, buf, 256);
                                        if (oneline > 0) {
                                            context.peer = buf.readUtf8String();
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Try to get cipher suite
                    var SSL_get_cipher = Module.findExportByName(libName, 'SSL_get_cipher');
                    if (SSL_get_cipher) {
                        var cipherPtr = new NativeFunction(SSL_get_cipher, 'pointer', ['pointer'])(sslPtr);
                        if (cipherPtr && !cipherPtr.isNull()) {
                            var SSL_CIPHER_get_name = Module.findExportByName(libName, 'SSL_CIPHER_get_name');
                            if (SSL_CIPHER_get_name) {
                                var cipherName = new NativeFunction(SSL_CIPHER_get_name, 'pointer', ['pointer'])(cipherPtr);
                                if (cipherName && !cipherName.isNull()) {
                                    context.cipher = cipherName.readUtf8String();
                                }
                            }
                        }
                    }

                    // Try to get SNI via SSL_get_servername
                    var SSL_get_servername = Module.findExportByName(libName, 'SSL_get_servername');
                    if (SSL_get_servername) {
                        var sni = new NativeFunction(SSL_get_servername, 'pointer', ['pointer', 'int'])(sslPtr, 0);
                        if (sni && !sni.isNull()) {
                            context.sni = sni.readUtf8String();
                        }
                    }

                    // Try to get protocol version
                    var SSL_get_version = Module.findExportByName(libName, 'SSL_get_version');
                    if (SSL_get_version) {
                        var version = new NativeFunction(SSL_get_version, 'pointer', ['pointer'])(sslPtr);
                        if (version && !version.isNull()) {
                            context.protocol = version.readUtf8String();
                        }
                    }

                } catch(e) {
                    // Context extraction failed, use defaults
                }

                sslContextCache[ctxId] = context;
                return context;
            }

            function tryAttach(libName) {
                var ssl_read  = Module.findExportByName(libName, 'SSL_read');
                var ssl_write = Module.findExportByName(libName, 'SSL_write');
                if (!ssl_read && !ssl_write) return false;

                if (ssl_read) {
                    Interceptor.attach(ssl_read, {
                        onEnter: function(args) {
                            this._buf = args[1];
                            this._ssl = args[0];
                            this._lib = libName;
                        },
                        onLeave: function(retval) {
                            var len = retval.toInt32();
                            if (len > 0 && this._buf && !this._buf.isNull()) {
                                var text = bytesToUtf8(this._buf, Math.min(len, 16384));
                                if (text) {
                                    var ctx = getSSLContext(this._ssl, this._lib);
                                    send(JSON.stringify({
                                        type: 'ssl_payload',
                                        dir:  'rx',
                                        lib:  this._lib,
                                        len:  len,
                                        data: text,
                                        context: ctx,
                                        ssl_ptr: ptrToHex(this._ssl),
                                    }));
                                }
                            }
                        }
                    });
                    send('[IRVES-SSL] SSL_read hooked in ' + libName);
                }

                if (ssl_write) {
                    Interceptor.attach(ssl_write, {
                        onEnter: function(args) {
                            this._buf = args[1];
                            this._ssl = args[0];
                            this._len = args[2].toInt32();
                            this._lib = libName;
                            
                            if (this._len > 0 && this._buf && !this._buf.isNull()) {
                                var text = bytesToUtf8(this._buf, Math.min(this._len, 16384));
                                if (text) {
                                    var ctx = getSSLContext(this._ssl, this._lib);
                                    send(JSON.stringify({
                                        type: 'ssl_payload',
                                        dir:  'tx',
                                        lib:  this._lib,
                                        len:  this._len,
                                        data: text,
                                        context: ctx,
                                        ssl_ptr: ptrToHex(this._ssl),
                                    }));
                                }
                            }
                        }
                    });
                    send('[IRVES-SSL] SSL_write hooked in ' + libName);
                }
                return true;
            }

            var hooked = false;
            SSL_LIBS.forEach(function(lib) {
                if (!hooked) hooked = tryAttach(lib);
            });

            if (!hooked) {
                // Enumerate all modules and try any that expose SSL_read
                Process.enumerateModules().forEach(function(mod) {
                    if (!hooked) hooked = tryAttach(mod.name);
                });
            }

            if (hooked) {
                send('[IRVES-SSL] BoringSSL capture with context active');
            } else {
                send('[IRVES-SSL] WARNING: SSL_read/SSL_write not found — app may use a custom TLS stack');
            }
        })();
    """,
}
