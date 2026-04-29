"""
IRVES — Source Code Analyzer
Snyk-style SAST pipeline for cloned repositories.

Engines used (same stack as Snyk's open-source tooling):
  1. Semgrep    — SAST pattern matching (Snyk Code uses Semgrep rules internally)
  2. Secrets    — Regex-based secret detection (modeled after Snyk's secret scanner)
  3. Dep-audit  — Dependency vulnerability scanning via pip-audit / npm-audit
"""

import asyncio
import json
import re
import shutil
import subprocess
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any

logger = logging.getLogger(__name__)


# ── Secret Detection Patterns (Snyk-style) ────────────────────────────────────
# Each entry: (pattern, name, severity, cwe)
SECRET_PATTERNS: List[tuple] = [
    # Generic hardcoded secrets
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Hardcoded Password", "critical", "CWE-798"),
    (r'(?i)(secret|api_?key|access_?key|auth_?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']', "Hardcoded Secret / API Key", "critical", "CWE-798"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "Hardcoded AWS Access Key ID", "critical", "CWE-798"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "Hardcoded AWS Secret Access Key", "critical", "CWE-798"),
    # GitHub / GitLab tokens
    (r'ghp_[A-Za-z0-9]{36}', "Hardcoded GitHub Personal Access Token", "critical", "CWE-798"),
    (r'ghs_[A-Za-z0-9]{36}', "Hardcoded GitHub App Secret", "critical", "CWE-798"),
    (r'glpat-[A-Za-z0-9\-]{20}', "Hardcoded GitLab Personal Access Token", "critical", "CWE-798"),
    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Hardcoded Google API Key", "high", "CWE-798"),
    (r'ya29\.[0-9A-Za-z\-_]+', "Hardcoded Google OAuth Access Token", "critical", "CWE-798"),
    # Firebase
    (r'(?i)firebase.*["\']AIza[0-9A-Za-z\-_]{35}', "Hardcoded Firebase API Key", "critical", "CWE-798"),
    # Private keys
    (r'-----BEGIN\s+(RSA|EC|OPENSSH|PGP)\s+PRIVATE KEY', "Embedded Private Key", "critical", "CWE-321"),
    # Connection strings / DSNs
    (r'(?i)(mongodb|postgresql|mysql|redis):\/\/[^:]+:[^@]+@', "Hardcoded Database Credential", "critical", "CWE-798"),
    # JWT secrets
    (r'(?i)jwt_?secret\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']', "Hardcoded JWT Secret", "high", "CWE-798"),
    # Slack / Stripe / Twilio / Sendgrid
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Hardcoded Slack Token", "high", "CWE-798"),
    (r'sk_live_[0-9A-Za-z]{24}', "Hardcoded Stripe Secret Key", "critical", "CWE-798"),
    (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', "Hardcoded SendGrid API Key", "high", "CWE-798"),
    # Azure
    (r'(?i)AccountKey=[A-Za-z0-9+/=]{44}', "Hardcoded Azure Storage Account Key", "critical", "CWE-798"),
    # OpenAI / Anthropic / HuggingFace
    (r'sk-[A-Za-z0-9]{32,}', "Hardcoded OpenAI / LLM API Key", "critical", "CWE-798"),
    (r'sk-ant-[A-Za-z0-9\-]{40,}', "Hardcoded Anthropic API Key", "critical", "CWE-798"),
    (r'hf_[A-Za-z0-9]{16,}', "Hardcoded HuggingFace Token", "high", "CWE-798"),
    # Discord
    (r'(?:discord|bot).*["\'][A-Za-z0-9_\-\.]{59}["\']', "Possible Hardcoded Discord Bot Token", "high", "CWE-798"),
]

# ── Source Code SAST Patterns (no Semgrep) — Python ──────────────────────────
PYTHON_SAST_PATTERNS: List[tuple] = [
    (r'(?i)exec\s*\(|eval\s*\(', "Python eval/exec Code Injection", "high", "Commands", "CWE-78"),
    (r'(?i)subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', "Shell Injection via subprocess", "high", "Commands", "CWE-78"),
    (r'(?i)os\.system\s*\(', "Shell Injection via os.system", "high", "Commands", "CWE-78"),
    (r'(?i)pickle\.loads?\s*\(', "Insecure Deserialization (pickle)", "high", "Deserialization", "CWE-502"),
    (r'(?i)yaml\.load\s*\([^)]*\)', "Unsafe YAML load (use yaml.safe_load)", "medium", "Deserialization", "CWE-502"),
    (r'(?i)hashlib\.(md5|sha1)\s*\(', "Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'(?i)random\.random|random\.randint', "Insecure Random (use secrets module)", "low", "Cryptography", "CWE-338"),
    (r'(?i)DEBUG\s*=\s*True', "Debug Mode Enabled", "medium", "Configuration", "CWE-489"),
    (r'(?i)verify\s*=\s*False', "SSL Certificate Verification Disabled", "high", "Network", "CWE-295"),
    (r'(?i)cursor\.execute\s*\(.*%[sd%]|\.format\s*\(', "SQL Injection Risk", "high", "SQL", "CWE-89"),
]

# ── JS/TS SAST Patterns ────────────────────────────────────────────────────────
JS_SAST_PATTERNS: List[tuple] = [
    (r'(?i)eval\s*\(', "JavaScript eval() Code Injection", "high", "Commands", "CWE-78"),
    (r'(?i)innerHTML\s*=', "XSS via innerHTML assignment", "high", "XSS", "CWE-79"),
    (r'(?i)document\.write\s*\(', "XSS via document.write", "high", "XSS", "CWE-79"),
    (r'(?i)Math\.random\s*\(', "Insecure Random (use crypto.getRandomValues)", "low", "Cryptography", "CWE-338"),
    (r'(?i)http:\/\/', "Cleartext HTTP Usage", "medium", "Network", "CWE-319"),
    (r'(?i)localStorage\.setItem\s*\(.*(?:password|token|secret)', "Sensitive Data in LocalStorage", "high", "Storage", "CWE-312"),
    (r'(?i)dangerouslySetInnerHTML', "React XSS via dangerouslySetInnerHTML", "high", "XSS", "CWE-79"),
    (r'(?i)child_process', "Child Process Execution (potential command injection)", "medium", "Commands", "CWE-78"),
]

# ── Java / Kotlin SAST Patterns ───────────────────────────────────────────────
JAVA_SAST_PATTERNS: List[tuple] = [
    (r'(?i)Runtime\.getRuntime\(\)\.exec\s*\(', "OS Command Injection via Runtime.exec", "high", "Commands", "CWE-78"),
    (r'(?i)ProcessBuilder', "Potential OS Command via ProcessBuilder", "medium", "Commands", "CWE-78"),
    (r'(?i)MessageFormat\.format|String\.format.*%[sd]', "Possible Format String Injection", "medium", "Injection", "CWE-134"),
    (r'(?i)createStatement\(\)|prepareCall\(|executeQuery\([^?]', "SQL Injection Risk (non-parameterized query)", "high", "SQL", "CWE-89"),
    (r'(?i)ObjectInputStream|readObject\(', "Insecure Java Deserialization", "critical", "Deserialization", "CWE-502"),
    (r'(?i)MessageDigest.getInstance\(["\']MD5["\']|MessageDigest.getInstance\(["\']SHA-1["\']', "Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'(?i)Log\.[dvwie]\s*\(.*(?:password|token|secret|key)', "Sensitive Data Logged to Logcat", "high", "Logging", "CWE-532"),
    (r'(?i)android:debuggable\s*=\s*["\']true["\']', "Android Debuggable Flag Enabled", "high", "Configuration", "CWE-489"),
    (r'(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true', "WebView Universal Access from File URLs", "critical", "WebView", "CWE-285"),
    (r'(?i)setJavaScriptEnabled\s*\(\s*true', "WebView JavaScript Enabled", "medium", "WebView", "CWE-79"),
    (r'(?i)addJavascriptInterface\s*\(', "WebView addJavascriptInterface (Remote Code Execution)", "critical", "WebView", "CWE-749"),
    (r'(?i)checkSelfPermission|requestPermissions.*WRITE_EXTERNAL_STORAGE', "Overly Broad Permissions Requested", "low", "Permissions", "CWE-250"),
    (r'(?i)TrustAllCerts|X509TrustManager|allowAllHostnames|ALLOW_ALL_HOSTNAME_VERIFIER', "SSL Certificate Validation Disabled", "critical", "Network", "CWE-295"),
    (r'(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', "World-Readable/Writable File Mode", "high", "Storage", "CWE-732"),
    (r'(?i)SharedPreferences.*(?:password|token|secret)', "Sensitive Data in SharedPreferences", "high", "Storage", "CWE-312"),
    (r'(?i)new\s+Random\s*\(\)', "Insecure Random (use SecureRandom)", "low", "Cryptography", "CWE-330"),
    (r'(?i)Cipher\.getInstance\(["\'](?:DES|RC2|RC4|Blowfish)', "Weak Cipher Algorithm", "high", "Cryptography", "CWE-327"),
    (r'(?i)IvParameterSpec\s*\(\s*new\s+byte', "Static IV in Cipher (breaks encryption)", "high", "Cryptography", "CWE-329"),
    (r'(?i)SQLiteDatabase.*rawQuery|openOrCreateDatabase', "Raw SQL Query (SQLite Injection Risk)", "medium", "SQL", "CWE-89"),
]

# ── Swift / Objective-C SAST Patterns ─────────────────────────────────────────
SWIFT_SAST_PATTERNS: List[tuple] = [
    (r'(?i)NSLog\s*\(.*(?:password|token|secret)', "Sensitive Data in NSLog", "high", "Logging", "CWE-532"),
    (r'(?i)print\s*\(.*(?:password|token|secret)', "Sensitive Data in print()", "high", "Logging", "CWE-532"),
    (r'(?i)UserDefaults.*(?:password|token|secret)', "Sensitive Data in UserDefaults", "high", "Storage", "CWE-312"),
    (r'(?i)kSecAttrAccessibleAlways', "Keychain Item Always Accessible (insecure)", "high", "Storage", "CWE-311"),
    (r'(?i)allowsAnyHTTPSCertificate|NSAllowsArbitraryLoads', "ATS Disabled (arbitrary HTTP traffic allowed)", "medium", "Network", "CWE-319"),
    (r'(?i)WKWebView.*evaluateJavaScript|UIWebView', "WebView JavaScript Execution Risk", "medium", "WebView", "CWE-79"),
    (r'(?i)CC_MD5|CC_SHA1\s*\(', "Deprecated / Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'(?i)SecRandom|arc4random', "Potentially Insecure Random (prefer SecRandomCopyBytes)", "low", "Cryptography", "CWE-338"),
    (r'(?i)UnsafePointer|withUnsafeMutableBytes|bitPattern', "Unsafe Memory Operation", "medium", "Memory", "CWE-119"),
    (r'(?i)String\(format:.*%[^@]', "Potential Format String Vulnerability", "medium", "Injection", "CWE-134"),
]

# ── Go SAST Patterns ───────────────────────────────────────────────────────────
GO_SAST_PATTERNS: List[tuple] = [
    (r'(?i)exec\.Command', "OS Command Execution", "medium", "Commands", "CWE-78"),
    (r'(?i)os/exec', "OS Exec Package Import", "low", "Commands", "CWE-78"),
    (r'(?i)crypto/md5|crypto/sha1', "Weak Hash Algorithm (md5/sha1)", "medium", "Cryptography", "CWE-327"),
    (r'(?i)math/rand', "Insecure Random (use crypto/rand)", "low", "Cryptography", "CWE-338"),
    (r'(?i)InsecureSkipVerify\s*:\s*true', "TLS Certificate Verification Disabled", "critical", "Network", "CWE-295"),
    (r'(?i)sql\.Query\s*\(.*\+|db\.Exec\s*\(.*\+', "SQL Injection via String Concatenation", "high", "SQL", "CWE-89"),
    (r'(?i)fmt\.Sprintf.*(?:SELECT|INSERT|UPDATE|DELETE)', "SQL Formatting via fmt.Sprintf (Injection Risk)", "high", "SQL", "CWE-89"),
    (r'(?i)log\.Print.*(?:password|token|secret)', "Sensitive Data Logged", "high", "Logging", "CWE-532"),
]

# ── Ruby SAST Patterns ─────────────────────────────────────────────────────────
RUBY_SAST_PATTERNS: List[tuple] = [
    (r'(?i)eval\s*\(', "Ruby eval() Code Injection", "high", "Commands", "CWE-78"),
    (r'(?i)system\s*\(|exec\s*\(|`[^`]+`', "OS Command Execution", "high", "Commands", "CWE-78"),
    (r'(?i)Marshal\.load\s*\(', "Insecure Deserialization via Marshal.load", "critical", "Deserialization", "CWE-502"),
    (r'(?i)Digest::MD5|Digest::SHA1', "Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'".*#\{.*params\[', "Possible XSS/Injection via String Interpolation", "medium", "Injection", "CWE-79"),
    (r'(?i)puts.*(?:password|token|secret)', "Sensitive Data Printed to STDOUT", "high", "Logging", "CWE-532"),
]

# ── PHP SAST Patterns ──────────────────────────────────────────────────────────
PHP_SAST_PATTERNS: List[tuple] = [
    (r'(?i)\$_GET\[|\$_POST\[|\$_REQUEST\[', "Unvalidated User Input", "medium", "Injection", "CWE-20"),
    (r'(?i)eval\s*\(', "PHP eval() Code Injection", "critical", "Commands", "CWE-78"),
    (r'(?i)system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(', "OS Command Injection", "critical", "Commands", "CWE-78"),
    (r'(?i)mysql_query|mysqli_query.*\$_', "SQL Injection Risk", "high", "SQL", "CWE-89"),
    (r'(?i)serialize\s*\(|unserialize\s*\(', "PHP Object Injection via unserialize", "high", "Deserialization", "CWE-502"),
    (r'(?i)md5\s*\(|sha1\s*\(', "Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'(?i)echo\s+\$_GET|echo\s+\$_POST|echo\s+\$_REQUEST', "Reflected XSS via echo", "critical", "XSS", "CWE-79"),
    (r'(?i)header\s*\(\s*["\']Location.*\$_', "Open Redirect via header()", "medium", "Redirect", "CWE-601"),
]

# ── C / C++ SAST Patterns ──────────────────────────────────────────────────────
C_SAST_PATTERNS: List[tuple] = [
    (r'(?i)\bgets\s*\(', "Dangerous gets() Usage (Buffer Overflow)", "critical", "Memory", "CWE-120"),
    (r'(?i)\bstrcpy\s*\(|\bstrcat\s*\(', "Unsafe String Function (use strlcpy/strncat)", "high", "Memory", "CWE-120"),
    (r'(?i)\bsprintf\s*\(', "Unsafe sprintf (use snprintf)", "medium", "Memory", "CWE-134"),
    (r'(?i)\bsystem\s*\(|\bpopen\s*\(', "OS Command Execution", "high", "Commands", "CWE-78"),
    (r'(?i)\bprintf\s*\([^,"]+\)', "Format String Vulnerability (non-literal format)", "high", "Injection", "CWE-134"),
    (r'(?i)malloc\s*\(|calloc\s*\(|realloc\s*\(', "Manual Memory Allocation (check for null/free)", "low", "Memory", "CWE-401"),
    (r'(?i)rand\s*\(\)|srand\s*\(', "Insecure Random (use /dev/urandom or getrandom)", "low", "Cryptography", "CWE-338"),
]

# ── Android XML Patterns (AndroidManifest.xml) ───────────────────────────────
XML_ANDROID_PATTERNS: List[tuple] = [
    (r'android:allowBackup\s*=\s*["\']true["\']', "Android Backup Enabled (data leak risk)", "medium", "Configuration", "CWE-312"),
    (r'android:debuggable\s*=\s*["\']true["\']', "Android Debuggable Mode Enabled", "high", "Configuration", "CWE-489"),
    (r'android:exported\s*=\s*["\']true["\']', "Component Exported Without Permission", "medium", "Access Control", "CWE-284"),
    (r'android:usesCleartextTraffic\s*=\s*["\']true["\']', "Cleartext Traffic Allowed", "high", "Network", "CWE-319"),
    (r'android:networkSecurityConfig', "Custom Network Security Config (review carefully)", "info", "Network", "CWE-319"),
    (r'android:sharedUserId', "Shared User ID (privilege escalation risk)", "medium", "Permissions", "CWE-250"),
    (r'android:permission\s*=\s*["\']android.permission.READ_EXTERNAL_STORAGE', "READ_EXTERNAL_STORAGE Permission", "low", "Permissions", "CWE-250"),
    (r'android:permission\s*=\s*["\']android.permission.WRITE_EXTERNAL_STORAGE', "WRITE_EXTERNAL_STORAGE Permission", "medium", "Permissions", "CWE-250"),
]

# ── Dart / Flutter SAST Patterns ──────────────────────────────────────────
DART_SAST_PATTERNS: List[tuple] = [
    (r'(?i)SharedPreferences.*(?:password|token|secret|key)', "Sensitive Data in SharedPreferences", "high", "Storage", "CWE-312"),
    (r'(?i)print\s*\(.*(?:password|token|secret|key)', "Sensitive Data in print()", "high", "Logging", "CWE-532"),
    (r'(?i)debugPrint\s*\(.*(?:password|token|secret)', "Sensitive Data in debugPrint", "high", "Logging", "CWE-532"),
    (r'(?i)http\.get\s*\(.*http://', "Cleartext HTTP Usage", "medium", "Network", "CWE-319"),
    (r'(?i)badCertificateCallback.*true|onBadCertificate.*true', "SSL Certificate Validation Disabled", "critical", "Network", "CWE-295"),
    (r'(?i)Platform\.environment\[', "Sensitive Environment Variable Access", "low", "Configuration", "CWE-526"),
    (r'(?i)dart:io.*Process\.run|Process\.start', "OS Process Execution", "high", "Commands", "CWE-78"),
    (r'(?i)dart:mirrors', "Reflection API Usage (potential security risk)", "low", "Access Control", "CWE-470"),
    (r'(?i)kDebugMode|assert\s*\(', "Debug/Assert in Production Code", "low", "Configuration", "CWE-489"),
    (r'(?i)FlutterSecureStorage.*(?:password|token|key)', "Direct Secure Storage Access (verify encryption)", "info", "Storage", "CWE-312"),
    (r'(?i)md5\.convert|sha1\.convert', "Weak Hash Algorithm", "medium", "Cryptography", "CWE-327"),
    (r'(?i)Random\(\)', "Insecure Random (use Random.secure())", "low", "Cryptography", "CWE-338"),
    (r'(?i)WebView.*javascriptMode.*JavascriptMode\.unrestricted', "WebView JavaScript Unrestricted", "medium", "WebView", "CWE-79"),
]

# ── Rust SAST Patterns ─────────────────────────────────────────────────────────
RUST_SAST_PATTERNS: List[tuple] = [
    (r'(?i)unsafe\s*\{', "Unsafe Rust Block", "medium", "Memory", "CWE-119"),
    (r'(?i)std::process::Command', "OS Command Execution", "medium", "Commands", "CWE-78"),
    (r'(?i)unwrap\s*\(\)|expect\s*\(', "Panic on None/Err (unwrap/expect) in production", "low", "Error Handling", "CWE-390"),
    (r'(?i)println!.*(?:password|token|secret)', "Sensitive Data in println!", "high", "Logging", "CWE-532"),
    (r'(?i)eprintln!.*(?:password|token|secret)', "Sensitive Data in eprintln!", "high", "Logging", "CWE-532"),
    (r'(?i)std::env::var\s*\(', "Environment Variable Access", "low", "Configuration", "CWE-526"),
    (r'(?i)from_utf8_unchecked', "Unchecked UTF-8 Conversion (memory safety risk)", "medium", "Memory", "CWE-125"),
    (r'(?i)transmute\s*::<', "mem::transmute Usage (type safety bypass)", "high", "Memory", "CWE-119"),
    (r'(?i)use\s+md5|extern\s+crate\s+md5', "Weak Hash (md5 crate)", "medium", "Cryptography", "CWE-327"),
    (r'(?i)rand::thread_rng(?!.*(?:fill_bytes|gen_range))', "Non-cryptographic RNG Usage", "low", "Cryptography", "CWE-338"),
    (r'(?i)TlsConnector::builder.*danger_accept_invalid_certs\s*\(\s*true', "TLS Cert Validation Disabled", "critical", "Network", "CWE-295"),
    (r'(?i)format!.*(?:SELECT|INSERT|UPDATE|DELETE).*\{', "SQL Injection via format! macro", "high", "SQL", "CWE-89"),
]

# ── React Native–specific patterns (augments JS/TS) ────────────────────────
REACT_NATIVE_EXTRA_PATTERNS: List[tuple] = [
    (r'(?i)AsyncStorage\.setItem\s*\(.*(?:password|token|secret)', "Sensitive Data in AsyncStorage", "high", "Storage", "CWE-312"),
    (r'(?i)Keychain\.setGenericPassword.*(?:password|token)', "Keychain setGenericPassword (verify encryption)", "info", "Storage", "CWE-312"),
    (r'(?i)NetInfo|fetch\s*\(["\']http://', "Cleartext HTTP in Fetch Call", "medium", "Network", "CWE-319"),
    (r'(?i)react-native-webview.*originWhitelist.*\*', "WebView with Wildcard Origin", "medium", "WebView", "CWE-284"),
    (r'(?i)\.env.*(?:API_KEY|SECRET|TOKEN|PASSWORD)', "Sensitive Value in .env File", "high", "Secrets", "CWE-798"),
    (r'(?i)__DEV__\s*\|\||if\s*\(__DEV__\)', "Debug Code Path Detected", "low", "Configuration", "CWE-489"),
    (r'(?i)SecureStore\.setItemAsync|expo-secure-store', "Expo SecureStore Usage (good — verify key handling)", "info", "Storage", "CWE-312"),
]

# Merge React Native extras into JS patterns for .jsx/.tsx
JS_REACT_NATIVE_PATTERNS = JS_SAST_PATTERNS + REACT_NATIVE_EXTRA_PATTERNS

# ── TypeScript-specific additions ───────────────────────────────────────────────
TS_EXTRA_PATTERNS: List[tuple] = [
    (r'(?i)as\s+any', "TypeScript `as any` Type Assertion (disables type safety)", "low", "Type Safety", "CWE-704"),
    (r'(?i)@ts-ignore|@ts-nocheck', "TypeScript Type Check Suppressed", "low", "Type Safety", "CWE-704"),
    (r'(?i)process\.env\.(?:SECRET|API_KEY|TOKEN|PASSWORD)', "Sensitive ENV Var Access in TypeScript", "medium", "Secrets", "CWE-526"),
    (r'(?i)JSON\.parse\s*\(.*req\.body|JSON\.parse\s*\(.*req\.query', "Unsafe JSON.parse from User Input", "high", "Injection", "CWE-20"),
]

TS_PATTERNS = JS_SAST_PATTERNS + TS_EXTRA_PATTERNS

FILE_EXTENSION_PATTERNS = {
    ".py":   PYTHON_SAST_PATTERNS,
    ".js":   JS_SAST_PATTERNS,
    ".ts":   TS_PATTERNS,
    ".jsx":  JS_REACT_NATIVE_PATTERNS,
    ".tsx":  JS_REACT_NATIVE_PATTERNS,
    ".java": JAVA_SAST_PATTERNS,
    ".kt":   JAVA_SAST_PATTERNS,
    ".kts":  JAVA_SAST_PATTERNS,
    ".swift": SWIFT_SAST_PATTERNS,
    ".m":    SWIFT_SAST_PATTERNS,
    ".go":   GO_SAST_PATTERNS,
    ".rb":   RUBY_SAST_PATTERNS,
    ".php":  PHP_SAST_PATTERNS,
    ".c":    C_SAST_PATTERNS,
    ".cpp":  C_SAST_PATTERNS,
    ".cc":   C_SAST_PATTERNS,
    ".h":    C_SAST_PATTERNS,
    ".xml":  XML_ANDROID_PATTERNS,
    ".dart": DART_SAST_PATTERNS,
    ".rs":   RUST_SAST_PATTERNS,
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".dart_tool", ".flutter",
    "target",   # Rust build dir
    "Pods",     # iOS CocoaPods
    ".gradle",  # Android Gradle
    "DerivedData",  # Xcode
}
SKIP_EXTS = {".pyc", ".pyo", ".min.js", ".map", ".lock", ".g.dart", ".freezed.dart"}

MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB


@dataclass
class SourceFinding:
    title: str
    severity: str
    category: str
    location: str
    code_snippet: str
    cwe_mapping: str
    owasp_mapping: str
    tool: str
    description: str = ""


@dataclass
class SourceScanResult:
    findings: List[SourceFinding] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[str] = field(default_factory=list)


class SourceAnalyzer:
    """
    Run the full source-code security analysis pipeline on a cloned repo.
    Pipeline: Secrets → SAST Patterns → Dependency Audit → Semgrep (if available).
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        backend_dir = Path(__file__).parent.parent.parent
        semgrep_path = shutil.which("semgrep") or str(backend_dir / ".venv/bin/semgrep")
        pip_audit_path = shutil.which("pip-audit") or str(backend_dir / ".venv/bin/pip-audit")
        self._semgrep = semgrep_path if Path(semgrep_path).exists() else None
        self._pip_audit = pip_audit_path if Path(pip_audit_path).exists() else None

    async def run(self, progress_callback: Optional[Callable[[str], None]] = None) -> SourceScanResult:
        result = SourceScanResult()
        cb = progress_callback or (lambda _: None)

        # 1. Secrets detection
        cb("Scanning for hardcoded secrets…")
        secret_findings = await asyncio.to_thread(self._scan_secrets, result)
        result.findings.extend(secret_findings)
        cb(f"Secrets scan complete — {len(secret_findings)} issue(s) found.")

        # 2. SAST pattern scan
        cb("Running SAST pattern analysis…")
        sast_findings, files_scanned = await asyncio.to_thread(self._scan_sast_patterns)
        result.findings.extend(sast_findings)
        result.files_scanned = files_scanned
        cb(f"SAST scan complete — {len(sast_findings)} issue(s) in {files_scanned} file(s).")

        # 3. Dependency audit
        cb("Auditing dependencies for known vulnerabilities…")
        dep_findings = await self._scan_dependencies()
        result.findings.extend(dep_findings)
        cb(f"Dependency audit complete — {len(dep_findings)} vulnerable package(s).")

        # 4. Semgrep (optional — uses community ruleset identical to Snyk's OSS rules)
        if self._semgrep:
            cb("Running Semgrep (Snyk-compatible ruleset)…")
            sg_findings = await self._scan_semgrep()
            result.findings.extend(sg_findings)
            cb(f"Semgrep complete — {len(sg_findings)} issue(s).")
        else:
            cb("Semgrep not available — skipping (pip install semgrep to enable).")

        return result

    # ── Secret Detection ──────────────────────────────────────────────────────

    def _scan_secrets(self, result: SourceScanResult) -> List[SourceFinding]:
        findings: List[SourceFinding] = []

        for file_path in self._iter_files():
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for pattern, title, severity, cwe in SECRET_PATTERNS:
                for match in re.finditer(pattern, text):
                    line_no = text[: match.start()].count("\n") + 1
                    snippet = match.group(0)[:120]
                    # Redact matched secret value in snippet
                    snippet = re.sub(r'["\']([A-Za-z0-9_\-\.+/=]{6,})["\']',
                                     lambda m: f'"{m.group(1)[:3]}***"', snippet)
                    rel = str(file_path.relative_to(self.repo_path))
                    findings.append(SourceFinding(
                        title=title,
                        severity=severity,
                        category="Secrets",
                        location=f"{rel}:{line_no}",
                        code_snippet=snippet,
                        cwe_mapping=cwe,
                        owasp_mapping="A07:2021",
                        tool="secrets_scanner",
                        description=f"Potential secret detected at {rel} line {line_no}. "
                                    "Remove from source code and rotate the credential immediately.",
                    ))
        return findings

    # ── SAST Pattern Scan ─────────────────────────────────────────────────────

    def _scan_sast_patterns(self) -> tuple:
        findings: List[SourceFinding] = []
        files_scanned = 0

        for file_path in self._iter_files():
            ext = file_path.suffix.lower()
            patterns = FILE_EXTENSION_PATTERNS.get(ext) or []
            if not patterns:
                continue

            files_scanned += 1
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for pattern, title, severity, category, cwe in patterns:
                for match in re.finditer(pattern, text):
                    line_no = text[: match.start()].count("\n") + 1
                    lines = text.splitlines()
                    line = lines[line_no - 1][:200] if lines else ""
                    rel = str(file_path.relative_to(self.repo_path))
                    findings.append(SourceFinding(
                        title=title,
                        severity=severity,
                        category=category,
                        location=f"{rel}:{line_no}",
                        code_snippet=line.strip(),
                        cwe_mapping=cwe,
                        owasp_mapping="A03:2021",
                        tool="sast_scanner",
                    ))

        return findings, files_scanned

    # ── Dependency Audit ──────────────────────────────────────────────────────

    async def _scan_dependencies(self) -> List[SourceFinding]:
        findings: List[SourceFinding] = []

        # Python: requirements.txt / pyproject.toml
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists() and self._pip_audit:
            try:
                proc = await asyncio.create_subprocess_exec(
                    self._pip_audit, "-r", str(req_file), "--format", "json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                data = json.loads(stdout_b.decode())
                for vuln, details in ((d.get("name", "?"), d.get("vulns", [])) for d in data.get("dependencies", [])):
                    for v in details:
                        findings.append(SourceFinding(
                            title=f"Vulnerable Dependency: {vuln}",
                            severity=self._cvss_to_severity(v.get("fix_versions", [])),
                            category="Dependencies",
                            location="requirements.txt",
                            code_snippet=f"{vuln} — {v.get('id', '')}",
                            cwe_mapping="CWE-1035",
                            owasp_mapping="A06:2021",
                            tool="pip_audit",
                            description=f"{v.get('description', '')[:300]}",
                        ))
            except Exception as e:
                logger.debug(f"[pip-audit] {e}")

        # Node.js: package.json
        pkg_file = self.repo_path / "package.json"
        if pkg_file.exists() and shutil.which("npm"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "npm", "audit", "--json",
                    cwd=str(self.repo_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                data = json.loads(stdout_b.decode(errors="replace"))
                for name, info in data.get("vulnerabilities", {}).items():
                    findings.append(SourceFinding(
                        title=f"Vulnerable npm Package: {name}",
                        severity=info.get("severity", "medium"),
                        category="Dependencies",
                        location="package.json",
                        code_snippet=f"{name} ({info.get('range', 'unknown version')})",
                        cwe_mapping="CWE-1035",
                        owasp_mapping="A06:2021",
                        tool="npm_audit",
                        description=info.get("url", "")[:300],
                    ))
            except Exception as e:
                logger.debug(f"[npm-audit] {e}")

        return findings

    # ── Semgrep ───────────────────────────────────────────────────────────────

    async def _scan_semgrep(self) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self._semgrep, "scan",
                "--config", "p/owasp-top-ten",  # Snyk uses OWASP rulesets
                "--config", "p/secrets",
                "--json",
                "--no-git-ignore",
                "--timeout", "60",
                str(self.repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=120)
            data = json.loads(stdout_b.decode(errors="replace"))
            for r in data.get("results", []):
                severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
                sev = severity_map.get(r.get("extra", {}).get("severity", "INFO"), "info")
                meta = r.get("extra", {}).get("metadata", {})
                findings.append(SourceFinding(
                    title=r.get("check_id", "Unknown Rule").split(".")[-1].replace("-", " ").title(),
                    severity=sev,
                    category=meta.get("category", "SAST"),
                    location=f"{r['path']}:{r['start']['line']}",
                    code_snippet=r.get("extra", {}).get("lines", "")[:200],
                    cwe_mapping=", ".join(meta.get("cwe", [])) or "CWE-0",
                    owasp_mapping=", ".join(meta.get("owasp", [])) or "A00:2021",
                    tool="semgrep",
                    description=r.get("extra", {}).get("message", "")[:300],
                ))
        except Exception as e:
            logger.warning(f"[Semgrep] {e}")
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _iter_files(self):
        """Walk the repo skipping build artifacts."""
        for path in self.repo_path.rglob("*"):
            if not path.is_file():
                continue
            if any(d in path.parts for d in SKIP_DIRS):
                continue
            if any(path.name.endswith(e) for e in SKIP_EXTS):
                continue
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            yield path

    @staticmethod
    def _cvss_to_severity(fix_versions: list) -> str:
        return "high" if fix_versions else "medium"
