"""
IRVES — Python-native APK Static Analyzer
Performs comprehensive static analysis using androguard + apktool.
No external Java tools required beyond apktool (which is installed).
"""

import asyncio
import re
import json
import shutil
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Callable, List, Dict
import logging

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Security pattern library: (pattern, title, severity, category, owasp, cwe)
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_PATTERNS = [
    # Crypto
    (r'(?i)(des|rc2|rc4)\.getinstance', "Weak Cipher Algorithm", "high", "Cryptography", "M5", "CWE-327"),
    (r'(?i)ecb.*mode|nopaddding', "ECB Mode / No Padding", "high", "Cryptography", "M5", "CWE-327"),
    (r'(?i)md5|sha1', "Weak Hash Algorithm", "medium", "Cryptography", "M5", "CWE-326"),
    (r'(?i)securerandom.*setalgorithm\s*\(\s*"sha1prng"', "Insecure SecureRandom Seed", "high", "Cryptography", "M5", "CWE-338"),
    (r'(?i)privatekey.*hardcode|"-----begin\s+rsa\s+private', "Hardcoded Private Key", "critical", "Secrets", "M1", "CWE-321"),
    # Secrets / keys
    (r'(?i)(api_key|apikey|api\.key)\s*=\s*"[A-Za-z0-9_\-]{8,}"', "Hardcoded API Key", "critical", "Secrets", "M1", "CWE-798"),
    (r'(?i)(password|passwd|secret)\s*=\s*"[^"]{4,}"', "Hardcoded Password", "critical", "Secrets", "M1", "CWE-798"),
    (r'(?i)(aws_access_key|aws_secret)\s*=\s*"[^"]{8,}"', "Hardcoded AWS Credential", "critical", "Secrets", "M1", "CWE-798"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Hardcoded Google API Key", "high", "Secrets", "M1", "CWE-798"),
    # Network
    (r'http://[A-Za-z0-9\.\-_]+(/|$)', "Cleartext HTTP Traffic", "high", "Network", "M3", "CWE-319"),
    (r'(?i)allowallhostnameverifier|onReceivedSslError|setHostnameVerifier\(.*ALLOW_ALL', "SSL Hostname Verification Disabled", "critical", "Network", "M3", "CWE-297"),
    (r'(?i)trustAllCerts|X509TrustManager.*checkserver|checkClientTrusted.*\{\s*\}', "SSL Certificate Validation Disabled", "critical", "Network", "M3", "CWE-295"),
    (r'(?i)setAllowUniversalAccessFromFileURLs.*true|setAllowFileAccessFromFileURL.*true', "WebView Universal File Access", "high", "WebView", "M1", "CWE-264"),
    # Storage
    (r'(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', "World-Readable/Writable File", "high", "Storage", "M2", "CWE-732"),
    (r'(?i)getExternalStorage|Environment\.getExternalStorage', "External Storage Usage", "medium", "Storage", "M2", "CWE-312"),
    (r'(?i)openFileOutput\(.*MODE_PRIVATE\).*password|sharedpreferences.*password', "Sensitive Data in Storage", "high", "Storage", "M2", "CWE-312"),
    # Logging
    (r'(?i)Log\.(d|v|i|e|w)\s*\(.*(?:password|token|key|secret|auth|credential)', "Sensitive Data Logged", "high", "Logging", "M2", "CWE-532"),
    (r'(?i)System\.out\.println.*(?:password|token|key|secret)', "Sensitive Data to stdout", "medium", "Logging", "M2", "CWE-532"),
    # Code execution
    (r'(?i)Runtime\.getRuntime\(\)\.exec|ProcessBuilder', "Dynamic Code Execution", "high", "Code", "M7", "CWE-78"),
    (r'(?i)DexClassLoader|PathClassLoader|loadClass', "Dynamic Class Loading", "medium", "Code", "M7", "CWE-470"),
    (r'(?i)Reflection\..*invoke|Method\.invoke', "Reflection Usage", "low", "Code", "M7", "CWE-470"),
    # Root / debug
    (r'(?i)isDeviceRooted|checkRoot|/system/bin/su|/system/xbin/su', "Root Detection Bypass Risk", "medium", "Anti-Tampering", "M8", "CWE-693"),
    (r'(?i)android:debuggable\s*=\s*"true"', "Debuggable Flag Set", "high", "Configuration", "M8", "CWE-489"),
    (r'(?i)android:allowBackup\s*=\s*"true"', "Backup Allowed", "medium", "Configuration", "M2", "CWE-530"),
    # SQL
    (r'(?i)rawQuery\s*\(.*\+|execSQL\s*\(.*\+', "SQL Injection Risk", "high", "SQL", "M1", "CWE-89"),
    # Intent
    (r'(?i)getStringExtra|getIntExtra.*Bundle.*putExtra', "Unvalidated Intent Extra Usage", "low", "IPC", "M1", "CWE-20"),
    (r'(?i)sendBroadcast.*Intent.*permission.*null', "Implicit Broadcast Without Permission", "medium", "IPC", "M1", "CWE-284"),
]

# Dangerous manifest permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": ("high", "M2", "CWE-276"),
    "android.permission.WRITE_CONTACTS": ("high", "M2", "CWE-276"),
    "android.permission.READ_SMS": ("high", "M2", "CWE-276"),
    "android.permission.SEND_SMS": ("high", "M2", "CWE-276"),
    "android.permission.RECEIVE_SMS": ("high", "M2", "CWE-276"),
    "android.permission.RECORD_AUDIO": ("medium", "M2", "CWE-276"),
    "android.permission.CAMERA": ("medium", "M2", "CWE-276"),
    "android.permission.READ_CALL_LOG": ("high", "M2", "CWE-276"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("high", "M2", "CWE-276"),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "M2", "CWE-276"),
    "android.permission.ACCESS_COARSE_LOCATION": ("low", "M2", "CWE-276"),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "M2", "CWE-276"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "M2", "CWE-276"),
    "android.permission.GET_ACCOUNTS": ("medium", "M2", "CWE-276"),
    "android.permission.USE_CREDENTIALS": ("high", "M2", "CWE-276"),
    "android.permission.INSTALL_PACKAGES": ("critical", "M7", "CWE-276"),
    "android.permission.DELETE_PACKAGES": ("critical", "M7", "CWE-276"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("medium", "M8", "CWE-276"),
}


class APKAnalyzerRunner(ToolRunner):
    """
    Python-native APK static analyzer.
    Uses androguard for deep bytecode analysis + apktool for decompilation.
    Works without jadx, mobsf, or any external Java tools.
    """

    @property
    def name(self) -> str:
        return "apk_analyzer"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        if not target or not target.exists():
            return ToolResult(
                success=False, output="", error="Target file not found", duration_ms=0
            )
        if target.suffix.lower() not in (".apk",):
            return ToolResult(
                success=True,
                output=json.dumps({"findings": [], "skipped": f"{target.suffix} not an APK"}),
                error="",
                duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "apk_analyzer")
        findings: List[Dict] = []

        def progress(msg: str):
            if progress_callback:
                progress_callback(msg)
            logger.info(f"[apk_analyzer] {msg}")

        progress(f"Starting analysis of {target.name}")

        # ── 1. Decompile with apktool (is installed) ─────────────────────────
        decompile_dir = output_path / "decompiled"
        try:
            apktool_findings = await self._run_apktool(target, decompile_dir, progress)
            findings.extend(apktool_findings)
        except Exception as e:
            progress(f"apktool error (non-fatal): {e}")

        # ── 2. Parse AndroidManifest.xml ──────────────────────────────────────
        manifest_path = decompile_dir / "AndroidManifest.xml"
        try:
            manifest_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._analyze_manifest, manifest_path
            )
            findings.extend(manifest_findings)
            progress(f"Manifest analysis: {len(manifest_findings)} issues found")
        except Exception as e:
            progress(f"Manifest parse error (non-fatal): {e}")

        # ── 3. Androguard deep analysis ───────────────────────────────────────
        try:
            progress("Running androguard static analysis...")
            ag_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._run_androguard, target, progress
            )
            findings.extend(ag_findings)
            progress(f"Androguard: {len(ag_findings)} findings")
        except Exception as e:
            progress(f"Androguard error (non-fatal): {e}")
            logger.exception("[apk_analyzer] Androguard failed")

        # ── 4. Source-level pattern scan (smali / strings) ───────────────────
        try:
            progress("Scanning source patterns...")
            pattern_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._scan_patterns, decompile_dir, target
            )
            findings.extend(pattern_findings)
            progress(f"Pattern scan: {len(pattern_findings)} potential issues")
        except Exception as e:
            progress(f"Pattern scan error (non-fatal): {e}")

        # Deduplicate by title+location
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("title", ""), f.get("location", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        progress(f"Analysis complete: {len(unique)} total findings")

        return ToolResult(
            success=True,
            output=json.dumps({"findings": unique}),
            error="",
            duration_ms=self._elapsed_ms(),
            artifacts_path=output_path,
            findings_count=len(unique),
        )

    # ── apktool decompilation ─────────────────────────────────────────────────

    async def _run_apktool(
        self, target: Path, out: Path, progress: Callable
    ) -> List[Dict]:
        progress("Running apktool decompilation...")
        cmd = [
            settings.APKTOOL_PATH, "d", str(target),
            "-o", str(out), "-f", "--no-debug-info",
        ]
        stdout, stderr, rc = await self._run_command(cmd, target.parent, timeout=300)
        if rc == 0:
            progress(f"apktool: decompiled successfully")
        else:
            progress(f"apktool: exited {rc} (may be partial)")
        return []

    # ── Manifest analysis ─────────────────────────────────────────────────────

    def _analyze_manifest(self, manifest_path: Path) -> List[Dict]:
        if not manifest_path.exists():
            return []
        findings = []
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = "http://schemas.android.com/apk/res/android"

            def attr(el, name: str) -> str:
                return el.get(f"{{{ns}}}{name}") or el.get(name) or ""

            # Package info
            pkg = root.get("package", "unknown")

            # Application-level checks
            app = root.find("application")
            if app is not None:
                if attr(app, "debuggable") == "true":
                    findings.append(self._finding(
                        "Debuggable Application",
                        "high", "Configuration",
                        "The application has android:debuggable=\"true\". This allows remote debugging in production.",
                        "AndroidManifest.xml", "M8", "CWE-489",
                    ))
                if attr(app, "allowBackup") == "true":
                    findings.append(self._finding(
                        "Backup Allowed",
                        "medium", "Configuration",
                        "android:allowBackup=\"true\" allows data extraction via ADB backup without root.",
                        "AndroidManifest.xml", "M2", "CWE-530",
                    ))
                if attr(app, "usesCleartextTraffic") == "true":
                    findings.append(self._finding(
                        "Cleartext Traffic Permitted",
                        "high", "Network",
                        "android:usesCleartextTraffic=\"true\" permits HTTP connections.",
                        "AndroidManifest.xml", "M3", "CWE-319",
                    ))
                # Exported components
                for tag in ("activity", "service", "receiver", "provider"):
                    for comp in app.findall(tag):
                        comp_name = attr(comp, "name")
                        exported = attr(comp, "exported")
                        permission = attr(comp, "permission")
                        if exported == "true" and not permission:
                            findings.append(self._finding(
                                f"Exported {tag.capitalize()} Without Permission",
                                "high", "IPC",
                                f"Component '{comp_name}' is exported without a permission guard, allowing any app to interact with it.",
                                f"AndroidManifest.xml#{comp_name}", "M1", "CWE-926",
                                snippet=f'<{tag} android:name="{comp_name}" android:exported="true">'
                            ))

            # Permissions
            for perm_el in root.findall("uses-permission"):
                perm = attr(perm_el, "name")
                if perm in DANGEROUS_PERMISSIONS:
                    sev, owasp, cwe = DANGEROUS_PERMISSIONS[perm]
                    short = perm.replace("android.permission.", "")
                    findings.append(self._finding(
                        f"Dangerous Permission: {short}",
                        sev, "Permissions",
                        f"App requests the dangerous permission '{perm}'. Ensure this is strictly required.",
                        "AndroidManifest.xml", owasp, cwe,
                        snippet=f'<uses-permission android:name="{perm}"/>'
                    ))

        except ET.ParseError as e:
            logger.warning(f"[apk_analyzer] Manifest parse error: {e}")
        return findings

    # ── Androguard deep analysis ──────────────────────────────────────────────

    def _run_androguard(self, target: Path, progress: Callable) -> List[Dict]:
        findings = []
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(str(target))

            # Certificate analysis
            try:
                certs = a.get_certificates()
                for cert in certs:
                    # Check signature algorithm
                    sig_alg = str(cert.signature_hash_algorithm).upper() if hasattr(cert, 'signature_hash_algorithm') else ""
                    if "MD5" in sig_alg or "SHA1" in sig_alg:
                        findings.append(self._finding(
                            f"Weak Certificate Signature: {sig_alg}",
                            "high", "Cryptography",
                            f"APK is signed with weak hash algorithm {sig_alg}. Use SHA-256 or stronger.",
                            "META-INF/", "M5", "CWE-327",
                        ))
            except Exception:
                pass

            # Minimum SDK check
            try:
                min_sdk = a.get_min_sdk_version()
                if min_sdk and int(min_sdk) < 21:
                    findings.append(self._finding(
                        f"Low Minimum SDK Version: API {min_sdk}",
                        "medium", "Configuration",
                        f"minSdkVersion={min_sdk} supports Android versions with known vulnerabilities. Set to at least 21 (Android 5.0).",
                        "AndroidManifest.xml", "M8", "CWE-693",
                    ))
            except Exception:
                pass

            # Method-level bytecode analysis
            dangerous_calls = {
                "Ljavax/crypto/Cipher;": ("getInstance", "Potential Insecure Cipher Usage", "medium", "Cryptography", "M5", "CWE-327"),
                "Ljava/security/MessageDigest;": ("getInstance", "Potential Weak Hash Usage", "medium", "Cryptography", "M5", "CWE-328"),
                "Landroid/webkit/WebSettings;": ("setJavaScriptEnabled", "JavaScript Enabled in WebView", "medium", "WebView", "M1", "CWE-749"),
                "Landroid/webkit/WebSettings;": ("setAllowUniversalAccessFromFileURLs", "Universal File Access in WebView", "high", "WebView", "M1", "CWE-264"),
                "Landroid/util/Log;": ("d", "Debug Logging in Production", "low", "Logging", "M2", "CWE-532"),
                "Ljava/lang/Runtime;": ("exec", "Dynamic Code Execution via Runtime.exec", "high", "Code", "M7", "CWE-78"),
                "Ldalvik/system/DexClassLoader;": ("<init>", "Dynamic Class Loading Detected", "medium", "Code", "M7", "CWE-470"),
                "Landroid/content/SharedPreferences;": ("edit", "SharedPreferences Usage (may store sensitive data)", "low", "Storage", "M2", "CWE-312"),
                "Ljavax/net/ssl/SSLContext;": ("init", "SSL Context Initialization (verify TrustManager)", "medium", "Network", "M3", "CWE-295"),
                "Landroid/telephony/SmsManager;": ("sendTextMessage", "SMS Sending Capability", "high", "Telephony", "M2", "CWE-306"),
            }

            reported_classes = set()
            for cls in dx.get_classes():
                cls_name = cls.get_vm_class().get_name()
                if cls_name in reported_classes:
                    continue
                for method in cls.get_methods():
                    for _, call, _ in method.get_xref_to():
                        callee_class = call.get_class_name()
                        callee_method = call.get_name()
                        if callee_class in dangerous_calls:
                            meth_name, title, sev, cat, owasp, cwe = dangerous_calls[callee_class]
                            if meth_name in callee_method or meth_name == "*":
                                caller = f"{cls_name}->{method.get_name()}"
                                findings.append(self._finding(
                                    title, sev, cat,
                                    f"Detected call to {callee_class}.{callee_method}() from {caller}.",
                                    caller.replace("/", ".").replace(";", ""), owasp, cwe,
                                ))
                                reported_classes.add(cls_name)
                                break

        except ImportError:
            logger.warning("[apk_analyzer] androguard not available; skipping bytecode analysis")
        except Exception as e:
            logger.error(f"[apk_analyzer] androguard analysis error: {e}")
        return findings[:40]  # Cap to top 40

    # ── Source pattern scan ───────────────────────────────────────────────────

    def _scan_patterns(self, decompile_dir: Path, apk_path: Path) -> List[Dict]:
        findings = []

        # Scan smali files (from apktool) + raw strings from the APK
        source_dirs = []
        if decompile_dir.exists():
            source_dirs.append(decompile_dir)

        files_checked = 0
        for src_dir in source_dirs:
            for file in src_dir.rglob("*.smali"):
                try:
                    text = file.read_text(errors="ignore")
                    for pattern, title, sev, cat, owasp, cwe in SECURITY_PATTERNS:
                        match = re.search(pattern, text)
                        if match:
                            # Grab surrounding context line
                            lines = text.splitlines()
                            match_line = next(
                                (l for l in lines if re.search(pattern, l)), ""
                            ).strip()[:200]
                            rel = str(file.relative_to(decompile_dir))
                            findings.append(self._finding(
                                title, sev, cat,
                                f"Pattern match in {rel}: {match_line}",
                                rel, owasp, cwe,
                                snippet=match_line,
                            ))
                    files_checked += 1
                except Exception:
                    pass

        # Also scan raw APK strings (unzip, search assets/res)
        try:
            with zipfile.ZipFile(str(apk_path), "r") as z:
                for name in z.namelist():
                    if name.startswith(("assets/", "res/")) and name.endswith((".xml", ".json", ".properties", ".txt")):
                        try:
                            text = z.read(name).decode("utf-8", errors="ignore")
                            for pattern, title, sev, cat, owasp, cwe in SECURITY_PATTERNS:
                                if re.search(pattern, text):
                                    match_line = next(
                                        (l.strip() for l in text.splitlines() if re.search(pattern, l)), ""
                                    )[:200]
                                    findings.append(self._finding(
                                        title, sev, cat,
                                        f"Pattern match in {name}: {match_line}",
                                        name, owasp, cwe,
                                        snippet=match_line,
                                    ))
                        except Exception:
                            pass
        except Exception:
            pass

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _finding(
        self, title: str, severity: str, category: str, description: str,
        location: str, owasp: str = "", cwe: str = "", snippet: str = "",
    ) -> Dict:
        return {
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "location": location,
            "owasp_mapping": owasp,
            "cwe_mapping": cwe,
            "code_snippet": snippet,
            "tool": "apk_analyzer",
        }
