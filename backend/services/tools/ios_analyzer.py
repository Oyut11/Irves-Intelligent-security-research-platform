"""
IRVES — iOS IPA Static Analyzer
Parses .ipa archives, inspects Info.plist, inspects embedded binaries
using 'strings', and flags security issues aligned with OWASP MASVS.
"""

import asyncio
import re
import json
import zipfile
import hashlib
import plistlib
import shutil
from pathlib import Path
from typing import Optional, Callable, List, Dict
import logging

from services.tool_runner import ToolRunner, ToolResult

logger = logging.getLogger(__name__)

# Known-safe URL patterns (exclude from HTTP URL findings)
SAFE_URL_PATTERNS = [
    r'http://schemas\.android\.com/.*',
    r'http://schemas\.xmlsoap\.org/.*',
    r'http://www\.w3\.org/.*',
]

# Known vulnerable iOS/third-party SDK signatures
# Format: library_identifier -> [(version, CVE, severity, description), ...]
IOS_LIBRARY_VULNERABILITIES = {
    "AFNetworking": [
        ("2.5.1", "CVE-2015-3994", "critical", "AFNetworking 2.5.1 SSL MiTM due to invalid cert chain handling"),
        ("2.6.0", "CVE-2015-6995", "high", "AFNetworking domain validation bypass in < 2.6.3"),
    ],
    "Alamofire": [
        ("4.0.0", "CVE-2016-0886", "medium", "Alamofire cookie handling vulnerability in < 4.3"),
    ],
    "SDWebImage": [
        ("4.0.0", "CVE-2018-4314", "high", "SDWebImage remote code execution via malicious image"),
    ],
    "Firebase": [
        ("6.0", "CVE-2020-10551", "medium", "Firebase iOS SDK insecure logging of config data"),
    ],
    "OneSignal": [
        ("2.0", "CVE-2020-26895", "medium", "OneSignal SDK insecure WebView JavaScript bridge"),
    ],
    "FBSDK": [
        ("4.0", "CVE-2016-1000337", "high", "Facebook SDK insecure WebView cookie handling"),
    ],
}

# iOS-specific security patterns (applied to binary strings output)
IOS_SECURITY_PATTERNS = [
    (r'(?i)NSAllowsArbitraryLoads.*true', "ATS Arbitrary Loads Enabled", "high", "Network", "MASVS-NETWORK", "CWE-319"),
    (r'(?i)NSExceptionAllowsInsecureHTTPLoads', "ATS Exception Allows HTTP", "medium", "Network", "MASVS-NETWORK", "CWE-319"),
    (r'(?i)kSecAttrAccessibleAlways(?!WhenUnlocked)', "Keychain Always Accessible", "high", "Storage", "MASVS-STORAGE", "CWE-312"),
    (r'(?i)sqlite_open|sqlite3_open', "SQLite Usage (Check for sensitive data)", "low", "Storage", "MASVS-STORAGE", "CWE-312"),
    (r'(?i)NSLog\s*\(@?".*?(password|token|key|secret)', "Sensitive Data in NSLog", "high", "Logging", "MASVS-CODE", "CWE-532"),
    (r'UIPasteboard|generalPasteboard', "Clipboard Usage (May Expose Sensitive Data)", "medium", "IPC", "MASVS-PLATFORM", "CWE-200"),
    (r'(?i)(password|passwd|secret|api_key)\s*=\s*@?"[^"]{4,}"', "Hardcoded Credential in Source", "critical", "Secrets", "MASVS-CODE", "CWE-798"),
    (r'http://[A-Za-z0-9.\-_]+(/|$)', "Cleartext HTTP URL Found", "high", "Network", "MASVS-NETWORK", "CWE-319"),
    (r'(?i)allowsBackgroundLocationUpdates.*YES', "Background Location Access", "medium", "Privacy", "MASVS-PLATFORM", "CWE-200"),
    (r'(?i)CFBundleURLTypes|openURL:', "Custom URL Scheme Registered", "low", "IPC", "MASVS-PLATFORM", "CWE-939"),
    (r'(?i)UIWebView', "Deprecated UIWebView Usage", "medium", "WebView", "MASVS-PLATFORM", "CWE-749"),
    (r'(?i)jailbreak|jailbroken|isJailbroken|SFAntiPiracy', "Jailbreak Detection Present (Verify Effectiveness)", "info", "Anti-Tampering", "MASVS-RESILIENCE", "CWE-693"),
]

# Dangerous Info.plist keys
PLIST_PERMISSION_KEYS = {
    "NSCameraUsageDescription": ("medium", "MASVS-PLATFORM", "CWE-200"),
    "NSMicrophoneUsageDescription": ("medium", "MASVS-PLATFORM", "CWE-200"),
    "NSLocationWhenInUseUsageDescription": ("medium", "MASVS-PLATFORM", "CWE-200"),
    "NSLocationAlwaysUsageDescription": ("high", "MASVS-PLATFORM", "CWE-200"),
    "NSContactsUsageDescription": ("high", "MASVS-PLATFORM", "CWE-200"),
    "NSPhotoLibraryUsageDescription": ("medium", "MASVS-PLATFORM", "CWE-200"),
    "NSFaceIDUsageDescription": ("low", "MASVS-AUTH", "CWE-200"),
}


class IPAAnalyzerRunner(ToolRunner):
    """Static analyzer for iOS .ipa files."""

    @property
    def name(self) -> str:
        return "ios_analyzer"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        if not target or not target.exists():
            return ToolResult(success=False, output="", error="Target file not found", duration_ms=0)
        if target.suffix.lower() not in (".ipa",):
            return ToolResult(
                success=True,
                output=json.dumps({"findings": [], "skipped": f"{target.suffix} not an IPA"}),
                error="", duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "ios_analyzer")
        findings: List[Dict] = []

        def progress(msg: str):
            if progress_callback:
                progress_callback(msg)
            logger.info(f"[ios_analyzer] {msg}")

        progress(f"Starting iOS analysis of {target.name}")

        # 1. Extract IPA (it's a zip)
        extract_dir = output_path / "extracted"
        try:
            progress("Extracting IPA archive...")
            await asyncio.get_event_loop().run_in_executor(
                None, self._extract_ipa, target, extract_dir
            )
        except Exception as e:
            progress(f"IPA extraction failed: {e}")
            return ToolResult(success=False, output="", error=str(e), duration_ms=self._elapsed_ms())

        # 2. Parse Info.plist
        try:
            plist_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._analyze_plist, extract_dir
            )
            findings.extend(plist_findings)
            progress(f"Plist analysis: {len(plist_findings)} issues found")
        except Exception as e:
            progress(f"Plist analysis failed (non-fatal): {e}")

        # 3. Binary strings analysis
        try:
            progress("Scanning binary strings for security patterns...")
            binary_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._analyze_binary_strings, extract_dir
            )
            findings.extend(binary_findings)
            progress(f"Binary analysis: {len(binary_findings)} issues found")
        except Exception as e:
            progress(f"Binary analysis failed (non-fatal): {e}")

        # 4. Source-file scan (swift/objc/plist files)
        try:
            source_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._scan_source_patterns, extract_dir
            )
            findings.extend(source_findings)
            progress(f"Source scan: {len(source_findings)} potential issues")
        except Exception as e:
            progress(f"Source scan failed (non-fatal): {e}")

        # Deduplicate by rule_id + title + category
        from collections import defaultdict
        grouped = defaultdict(lambda: {"locations": [], "snippets": [], "severities": set()})
        
        for f in findings:
            rule_id = f.get("rule_id", f.get("title", ""))
            key = (rule_id, f.get("title", ""), f.get("category", ""))
            grouped[key]["locations"].append(f.get("location", ""))
            grouped[key]["snippets"].append(f.get("code_snippet", ""))
            grouped[key]["severities"].add(f.get("severity", "medium"))
            # Keep the first finding's metadata
            if "metadata" not in grouped[key]:
                grouped[key]["metadata"] = {k: v for k, v in f.items() if k not in ["location", "code_snippet"]}
        
        unique = []
        for (rule_id, title, category), group in grouped.items():
            metadata = group["metadata"]
            # Use the highest severity
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            highest_sev = max(group["severities"], key=lambda s: severity_order.get(s, 0))
            
            # Collapse locations into a comma-separated list
            locations_str = ", ".join(set(group["locations"]))[:3]  # Show up to 3 unique locations
            if len(set(group["locations"])) > 3:
                locations_str += f" (+{len(set(group['locations'])) - 3} more)"
            
            metadata["severity"] = highest_sev
            metadata["location"] = locations_str
            metadata["description"] = f"{metadata.get('description', '')} Affected files: {len(set(group['locations']))}"
            metadata["code_snippet"] = group["snippets"][0][:200] if group["snippets"] else ""
            unique.append(metadata)

        # ── 5. Third-party library CVE detection ──────────────────────────────
        try:
            progress("Detecting third-party libraries and known CVEs...")
            lib_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._detect_ios_library_cves, extract_dir
            )
            unique.extend(lib_findings)
            progress(f"Library CVE scan: {len(lib_findings)} issues")
        except Exception as e:
            progress(f"Library CVE scan error (non-fatal): {e}")

        # ── 6. Calculate malware risk score ──────────────────────────────────
        malware_score = self._calculate_malware_score(unique)
        progress(f"Malware risk score: {malware_score}/100")

        progress(f"iOS analysis complete: {len(unique)} total findings")

        return ToolResult(
            success=True,
            output=json.dumps({
                "findings": unique,
                "malware_score": malware_score,
                "score_label": self._score_label(malware_score),
            }),
            error="", duration_ms=self._elapsed_ms(),
            artifacts_path=output_path,
            findings_count=len(unique),
        )

    def _extract_ipa(self, ipa_path: Path, extract_dir: Path):
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            # Validate all paths before extraction to prevent Zip Slip
            for member in z.infolist():
                member_path = Path(extract_dir) / member.filename
                # Ensure path is within extract_dir (no directory traversal)
                if not member_path.resolve().is_relative_to(extract_dir.resolve()):
                    raise ValueError(f"Zip Slip attempt: {member.filename}")
            z.extractall(str(extract_dir))

    def _find_app_bundle(self, extract_dir: Path) -> Optional[Path]:
        """Find the .app bundle inside Payload/"""
        payload = extract_dir / "Payload"
        if payload.exists():
            for item in payload.iterdir():
                if item.suffix == ".app":
                    return item
        return None

    def _analyze_plist(self, extract_dir: Path) -> List[Dict]:
        findings = []
        app_bundle = self._find_app_bundle(extract_dir)
        if not app_bundle:
            return []

        plist_path = app_bundle / "Info.plist"
        if not plist_path.exists():
            return []

        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)

            # Check ATS
            ats = plist.get("NSAppTransportSecurity", {})
            if ats.get("NSAllowsArbitraryLoads", False):
                findings.append(self._finding(
                    "App Transport Security: Arbitrary Loads Allowed",
                    "high", "Network",
                    "NSAllowsArbitraryLoads=YES disables ATS, allowing all cleartext HTTP traffic.",
                    "Info.plist", "MASVS-NETWORK", "CWE-319",
                    rule_id="plist_ats_arbitrary"
                ))

            # Check MinimumOSVersion
            min_os = plist.get("MinimumOSVersion", "")
            if min_os and float(min_os.split(".")[0]) < 13:
                findings.append(self._finding(
                    f"Low Minimum OS Version: iOS {min_os}",
                    "medium", "Configuration",
                    f"MinimumOSVersion={min_os} allows installation on iOS versions with known vulnerabilities.",
                    "Info.plist", "MASVS-CODE", "CWE-693",
                    rule_id="plist_min_os"
                ))

            # Check dangerous permissions
            for key, (sev, owasp, cwe) in PLIST_PERMISSION_KEYS.items():
                if key in plist:
                    findings.append(self._finding(
                        f"Sensitive Permission: {key.replace('NSUsageDescription', '').replace('NS', '')}",
                        sev, "Permissions",
                        f"App declares permission key '{key}' with description: {str(plist[key])[:100]}",
                        "Info.plist", owasp, cwe,
                        rule_id=f"plist_permission_{key}"
                    ))

        except Exception as e:
            logger.warning(f"[ios_analyzer] Plist parse error: {e}")
        return findings

    def _analyze_binary_strings(self, extract_dir: Path) -> List[Dict]:
        findings = []
        app_bundle = self._find_app_bundle(extract_dir)
        if not app_bundle:
            return []

        # Find the main binary (same name as .app bundle)
        binary_name = app_bundle.stem
        binary_path = app_bundle / binary_name
        if not binary_path.exists():
            # Try to find any Mach-O binary
            for f in app_bundle.iterdir():
                if f.is_file() and not f.suffix:
                    binary_path = f
                    break

        if not binary_path.exists():
            return []

        # Use 'strings' command if available, otherwise do binary read
        strings_bin = shutil.which("strings")
        if strings_bin:
            try:
                import subprocess
                result = subprocess.run(
                    [strings_bin, str(binary_path)],
                    capture_output=True, text=True, timeout=30
                )
                text = result.stdout
            except Exception:
                text = binary_path.read_bytes().decode("utf-8", errors="ignore")
        else:
            text = binary_path.read_bytes().decode("utf-8", errors="ignore")

        for idx, (pattern, title, sev, cat, owasp, cwe) in enumerate(IOS_SECURITY_PATTERNS):
            match = re.search(pattern, text)
            if match:
                context_line = match.group(0)[:200]
                findings.append(self._finding(
                    title, sev, cat,
                    f"Found in binary strings: {context_line}",
                    f"Binary/{binary_name}", owasp, cwe,
                    snippet=context_line,
                    rule_id=f"binary_pattern_{idx}"
                ))

        return findings

    def _scan_source_patterns(self, extract_dir: Path) -> List[Dict]:
        """Scan any embedded source/config files in the bundle."""
        findings = []
        for ext in (".plist", ".json", ".xml", ".strings"):
            for f in extract_dir.rglob(f"*{ext}"):
                try:
                    text = f.read_text(errors="ignore")
                    rel = str(f.relative_to(extract_dir))
                    for idx, (pattern, title, sev, cat, owasp, cwe) in enumerate(IOS_SECURITY_PATTERNS):
                        match = re.search(pattern, text)
                        if match:
                            context = match.group(0)[:200]
                            # Downgrade HTTP URLs in resource XML files to INFO
                            actual_sev = sev
                            if title == "Cleartext HTTP URL Found" and self._is_resource_xml_file(rel):
                                actual_sev = "info"
                            findings.append(self._finding(
                                title, actual_sev, cat,
                                f"Pattern match in {rel}: {context}",
                                rel, owasp, cwe, snippet=context,
                                rule_id=f"source_pattern_{idx}"
                            ))
                except Exception:
                    pass
        return findings

    def _is_resource_xml_file(self, file_path: str) -> bool:
        """Check if file is a resource XML/plist file (not code or main config)."""
        # iOS resource file patterns
        resource_patterns = [
            r'.*\.plist$',
            r'.*\.xml$',
            r'.*\.strings$',
        ]
        
        # Exclude important config files
        excluded = [
            'Info.plist',
        ]
        
        for excluded_file in excluded:
            if excluded_file in file_path:
                return False
        
        for pattern in resource_patterns:
            if re.search(pattern, file_path):
                return True
        
        return False

    # ── Library CVE Detection ─────────────────────────────────────────────────

    def _detect_ios_library_cves(self, extract_dir: Path) -> List[Dict]:
        """Detect known vulnerable third-party libraries from binary strings and source files."""
        findings = []
        detected_libs = set()

        # Search for library identifiers in all text files
        for ext in (".plist", ".strings", ".json", ".xml", ".txt"):
            for f in extract_dir.rglob(f"*{ext}"):
                try:
                    text = f.read_text(errors="ignore")
                    for lib_name, vulns in IOS_LIBRARY_VULNERABILITIES.items():
                        if lib_name.lower() in text.lower() and lib_name not in detected_libs:
                            detected_libs.add(lib_name)
                            # Try to extract version from nearby text
                            version = self._guess_ios_library_version(text, lib_name)
                            for v_ver, cve, sev, desc in vulns:
                                if version:
                                    try:
                                        if self._version_cmp(version, v_ver) <= 0:
                                            findings.append(self._finding(
                                                f"Vulnerable Library: {lib_name} {version} — {cve}",
                                                sev, "Dependencies",
                                                f"Detected {lib_name} v{version}. {desc}. "
                                                f"Upgrade to a patched version. "
                                                f"(Known vulnerable: <= {v_ver})",
                                                str(f.relative_to(extract_dir)), "MASVS-CODE", "CWE-1104",
                                                snippet=f"{lib_name}:{version}",
                                                rule_id=f"lib_cve_{lib_name}_{cve}"
                                            ))
                                        continue
                                    except Exception:
                                        pass
                                findings.append(self._finding(
                                    f"Potentially Vulnerable Library: {lib_name} — {cve}",
                                    "info" if not version else sev, "Dependencies",
                                    f"Detected {lib_name} library. {desc}. "
                                    f"Verify version is > {v_ver}. "
                                    f"(Version detection: {version or 'failed'})",
                                    str(f.relative_to(extract_dir)), "MASVS-CODE", "CWE-1104",
                                    snippet=f"{lib_name}:{version or 'unknown'}",
                                    rule_id=f"lib_cve_{lib_name}_{cve}"
                                ))
                except Exception:
                    pass

        return findings

    def _guess_ios_library_version(self, text: str, lib_name: str) -> str:
        """Attempt to extract version string near library name mention."""
        # Look for version near library mention
        match = re.search(
            rf'{re.escape(lib_name)}[^0-9.]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            text, re.IGNORECASE
        )
        if match:
            return match.group(1)
        # Check plist-style version keys
        match = re.search(
            rf'{re.escape(lib_name)}.*?CFBundleShortVersionString[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            text, re.IGNORECASE | re.DOTALL
        )
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _version_cmp(v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        def normalize(v):
            return [int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x][:4]
        a, b = normalize(v1), normalize(v2)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return -1
            if av > bv:
                return 1
        return 0

    # ── Malware Risk Scoring ──────────────────────────────────────────────────

    def _calculate_malware_score(self, findings: List[Dict]) -> int:
        """Calculate a 0-100 malware risk score based on findings."""
        score = 0
        severity_weights = {"critical": 25, "high": 10, "medium": 5, "low": 2, "info": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            score += severity_weights.get(sev, 2)
        return min(score, 100)

    @staticmethod
    def _score_label(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 10:
            return "low"
        return "safe"

    def _finding(self, title, severity, category, description, location,
                 owasp="", cwe="", snippet="", rule_id="") -> Dict:
        return {
            "title": title, "severity": severity, "category": category,
            "description": description, "location": location,
            "owasp_mapping": owasp, "cwe_mapping": cwe,
            "code_snippet": snippet, "tool": "ios_analyzer",
            "rule_id": rule_id,
        }
