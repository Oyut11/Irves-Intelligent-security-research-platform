"""IRVES — Retrieval-Augmented Generation (RAG) Module

Retrieves relevant security knowledge, Frida techniques, and vulnerability patterns
to provide the AI with contextual evidence before generating responses.
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# Knowledge base chunks for retrieval
# These are structured snippets that can be retrieved based on query similarity
KNOWLEDGE_CHUNKS = {
    "frida_ssl_bypass": {
        "text": "SSL Pinning Bypass: Many Android apps use certificate pinning to prevent MITM. Frida can bypass this by hooking TrustManager implementations (Java layer) or SSL_read/SSL_write functions (native BoringSSL layer). Java-layer bypass works for OkHttp3, HttpsURLConnection. Native-layer bypass is required for apps using Cronet, custom TLS, or anti-Frida detection.",
        "tags": ["ssl", "pinning", "mitm", "network", "bypass"],
        "category": "network_security",
    },
    "frida_root_detection": {
        "text": "Root Detection Bypass: Apps check for root using SuperUser binaries, Magisk, or SafetyNet. Frida can hook RootBeer, SafetyNet APIs, and block su binary execution. For stronger bypasses, use Zymbiote stealth cloak to hide Frida from /proc/self/maps and abstract socket detection.",
        "tags": ["root", "detection", "bypass", "stealth", "anti-tamper"],
        "category": "anti_tamper",
    },
    "frida_crypto_capture": {
        "text": "Crypto Operation Capture: Hook javax.crypto.Cipher to log algorithm names, input/output bytes. Useful for analyzing encryption schemes, key derivation, and identifying weak crypto implementations. For native crypto, hook OpenSSL EVP_* functions or BoringSSL equivalents.",
        "tags": ["crypto", "encryption", "aes", "keys", "cipher"],
        "category": "cryptography",
    },
    "frida_native_hooks": {
        "text": "Native Interceptor Hooks: When Java Bridge fails, use native Interceptor.attach() to target shared libraries (.so files). Common targets: libssl.so (SSL functions), libc.so (openat, read, write), libart.so (Android runtime). Use Module.enumerateExports() to find available symbols.",
        "tags": ["native", "interceptor", "so", "libssl", "libc"],
        "category": "runtime_analysis",
    },
    "frida_stealth": {
        "text": "Zymbiote Stealth Cloak: Hides Frida from detection by masking /proc/self/maps, hiding frida-agent thread names, and removing abstract socket traces. Essential for apps with RASP (Runtime Application Self-Protection). Verify stealth by checking TracerPid=0 and absence of frida-named sockets.",
        "tags": ["stealth", "anti-detection", "rasp", "zymbiote"],
        "category": "anti_detection",
    },
    "frida_intent_monitoring": {
        "text": "Intent Monitoring: Hook Intent constructor and ActivityManager to track IPC (Inter-Process Communication). Useful for identifying exported components, intent redirection vulnerabilities, and data leakage through implicit intents. Monitor both explicit and implicit intent creation.",
        "tags": ["intent", "ipc", "components", "exported", "redirection"],
        "category": "ipc_security",
    },
    "frida_network_monitoring": {
        "text": "Network Connection Monitoring: Hook java.net.URL.openConnection and related classes to log outbound network requests. Captures full URLs, headers, and request bodies. Useful for API endpoint discovery, data exfiltration tracking, and identifying insecure HTTP usage.",
        "tags": ["network", "http", "urls", "api", "monitoring"],
        "category": "network_security",
    },
    "android_m3_insecure_communication": {
        "text": "OWASP M3 - Insecure Communication: Apps using HTTP instead of HTTPS, weak TLS configurations, or improper certificate validation are vulnerable to MITM attacks. Remediation: Enable network security config, use certificate pinning, enforce TLS 1.2+, and validate certificates properly.",
        "tags": ["owasp", "m3", "insecure", "communication", "mitm"],
        "category": "owasp_m3",
    },
    "android_m2_insecure_storage": {
        "text": "OWASP M2 - Insecure Data Storage: Storing sensitive data in SharedPreferences, SQLite, or external storage without encryption. Remediation: Use Android Keystore for keys, EncryptedSharedPreferences, SQLCipher for databases, and avoid storing PII in external storage.",
        "tags": ["owasp", "m2", "storage", "encryption", "keystore"],
        "category": "owasp_m2",
    },
    "android_m1_improper_platform_usage": {
        "text": "OWASP M1 - Improper Platform Usage: Misusing Android features like custom permissions, exported components, or insecure IPC. Remediation: Minimize exported components, use custom permissions with protection levels, and validate all incoming intents.",
        "tags": ["owasp", "m1", "platform", "permissions", "exported"],
        "category": "owasp_m1",
    },
    "android_m7_poor_code_quality": {
        "text": "OWASP M7 - Client Code Quality: Buffer overflows in JNI, format string vulnerabilities, or unsafe native code. Remediation: Use bounds checking, validate input lengths, use safe string functions, and enable compiler hardening flags.",
        "tags": ["owasp", "m7", "jni", "buffer", "overflow"],
        "category": "owasp_m7",
    },
    "android_m8_code_tampering": {
        "text": "OWASP M8 - Code Tampering: Apps vulnerable to reverse engineering, repackaging, or modification. Remediation: Use code obfuscation (ProGuard/R8), anti-debugging, integrity checks, and tamper detection at runtime.",
        "tags": ["owasp", "m8", "tampering", "obfuscation", "anti-debug"],
        "category": "owasp_m8",
    },
    "android_m9_reverse_engineering": {
        "text": "OWASP M9 - Reverse Engineering: APK can be decompiled to extract source code, strings, and logic. Remediation: Use code obfuscation, string encryption, native code for sensitive logic, and packers to hide DEX files.",
        "tags": ["owasp", "m9", "reverse", "decompile", "packer"],
        "category": "owasp_m9",
    },
    "common_errors_timeout": {
        "text": "Timeout Errors: Frida attach/spawn timeout usually means the app is protected, crashed, or frida-server is not running. Check: 1) frida-server is running with root, 2) App is actually running, 3) Try spawn mode instead of attach, 4) Check for anti-debug protection.",
        "tags": ["error", "timeout", "attach", "spawn", "debug"],
        "category": "troubleshooting",
    },
    "common_errors_java_bridge": {
        "text": "Java Bridge Failed: The app's Java runtime cannot be hooked. Causes: 1) App is native-only (no Java), 2) Anti-Frida protection, 3) Wrong class/method names. Solutions: Use native Interceptor hooks, verify class names with JADX, or target native libraries directly.",
        "tags": ["error", "java", "bridge", "native", "jadx"],
        "category": "troubleshooting",
    },
    "common_errors_symbol_not_found": {
        "text": "Symbol Not Found: Native symbol or module doesn't exist in the target process. Solutions: 1) Use Module.enumerateModules() to list available libraries, 2) Use Module.enumerateExports() to find available symbols, 3) Target the correct library name (e.g., libssl.so vs libssl.so.1.1).",
        "tags": ["error", "symbol", "module", "native", "exports"],
        "category": "troubleshooting",
    },
}


def retrieve_relevant_knowledge(
    query: str,
    max_results: int = 3,
    categories: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve relevant knowledge chunks based on query similarity.

    Uses simple keyword matching for now. Can be upgraded to vector similarity later.

    Args:
        query: The user's question or context
        max_results: Maximum number of chunks to return
        categories: Optional filter for specific categories (e.g., ['owasp_m3', 'network_security'])

    Returns:
        List of relevant knowledge chunks with text, tags, and category
    """
    query_lower = query.lower()
    scored_chunks = []

    for chunk_id, chunk in KNOWLEDGE_CHUNKS.items():
        # Filter by category if specified
        if categories and chunk.get("category") not in categories:
            continue

        # Simple scoring: count matching keywords
        score = 0
        for tag in chunk.get("tags", []):
            if tag.lower() in query_lower:
                score += 2
        # Also check for partial matches in text
        for word in query_lower.split():
            if len(word) > 3 and word in chunk["text"].lower():
                score += 1

        if score > 0:
            scored_chunks.append({
                "id": chunk_id,
                "text": chunk["text"],
                "tags": chunk["tags"],
                "category": chunk["category"],
                "score": score,
            })

    # Sort by score and return top results
    scored_chunks.sort(key=lambda x: x["score"], reverse=True)
    return scored_chunks[:max_results]


def build_rag_context(
    query: str,
    logs: str = "",
    finding_context: Optional[dict] = None,
    max_results: int = 3,
) -> str:
    """
    Build RAG context string to inject into AI prompt.

    Args:
        query: User's question
        logs: Runtime logs (for error-specific retrieval)
        finding_context: Finding context for OWASP-specific retrieval
        max_results: Max chunks to retrieve

    Returns:
        Formatted context string with retrieved knowledge
    """
    parts = ["## Retrieved Knowledge (RAG)\n"]

    # Determine categories based on context
    categories = []
    if finding_context:
        owasp = finding_context.get("owasp_mapping", "")
        if "M1" in owasp:
            categories.append("owasp_m1")
        elif "M2" in owasp:
            categories.append("owasp_m2")
        elif "M3" in owasp:
            categories.append("owasp_m3")
        elif "M7" in owasp:
            categories.append("owasp_m7")
        elif "M8" in owasp:
            categories.append("owasp_m8")
        elif "M9" in owasp:
            categories.append("owasp_m9")

    # Add troubleshooting category if logs contain errors
    if logs and any(kw in logs.lower() for kw in ["error", "failed", "timeout", "crash"]):
        categories.append("troubleshooting")

    # Retrieve knowledge
    combined_query = f"{query} {logs} {finding_context.get('description', '') if finding_context else ''}"
    chunks = retrieve_relevant_knowledge(combined_query, max_results, categories or None)

    if not chunks:
        parts.append("No specific knowledge retrieved for this query.\n")
        return "\n".join(parts)

    parts.append(f"Found {len(chunks)} relevant knowledge chunks:\n")
    for i, chunk in enumerate(chunks, 1):
        parts.append(f"### {i}. {chunk['category'].replace('_', ' ').title()}")
        parts.append(chunk["text"])
        parts.append(f"Tags: {', '.join(chunk['tags'])}\n")

    return "\n".join(parts)
