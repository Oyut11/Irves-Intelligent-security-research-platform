"""
IRVES — Domain Knowledge & Semantic Analysis
Initializes domain knowledge bases, response templates, and semantic analysis.
"""

import logging
from typing import Dict, Any, List

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    np = None

logger = logging.getLogger(__name__)


def initialize_domain_knowledge() -> Dict[str, Any]:
    """Initialize comprehensive domain-specific knowledge base for iOS, Android, Web, and Desktop security analysis."""
    return {
        "vulnerability_patterns": {
            "ios_security": {
                "patterns": ["jailbreak detection bypass", "keychain vulnerabilities", "app transport security bypass", "code signing bypass", "sandbox escape"],
                "indicators": ["cydia", "substrate", "hooking frameworks", "unsigned code", "entitlements abuse", "url schemes"],
                "impact": "Device compromise, data exfiltration, malware installation, privacy violations",
                "platform": "iOS"
            },
            "android_security": {
                "patterns": ["root detection bypass", "certificate pinning bypass", "anti-debugging bypass", "intent redirection", "broadcast receiver flaws"],
                "indicators": ["su binary", "magisk", "xposed", "frida-server", "exported components", "intent filters"],
                "impact": "Device compromise, app hijacking, data leakage, cross-app attacks",
                "platform": "Android"
            },
            "web_security": {
                "patterns": ["xss", "csrf", "sql injection", "authentication bypass", "session management flaws", "cors misconfiguration"],
                "indicators": ["user input reflection", "missing csrf tokens", "dynamic queries", "weak session tokens", "overly permissive cors"],
                "impact": "Account takeover, data breach, malicious script execution, unauthorized actions",
                "platform": "Web"
            },
            "desktop_security": {
                "patterns": ["buffer overflow", "dll hijacking", "privilege escalation", "code injection", "memory corruption"],
                "indicators": ["unsafe functions", "dll search order", "elevated privileges", "process injection", "heap corruption"],
                "impact": "System compromise, arbitrary code execution, privilege escalation, data theft",
                "platform": "Desktop"
            },
            "cross_platform": {
                "patterns": ["weak encryption", "hardcoded secrets", "insecure communication", "input validation flaws", "business logic errors"],
                "indicators": ["des", "md5", "sha1", "hardcoded keys", "http usage", "missing validation"],
                "impact": "Data decryption, credential exposure, man-in-the-middle attacks, data manipulation",
                "platform": "All"
            },
            "api_security": {
                "patterns": ["broken authentication", "excessive data exposure", "lack of rate limiting", "injection flaws", "security misconfiguration"],
                "indicators": ["missing auth", "verbose responses", "no rate limits", "dynamic queries", "default configs"],
                "impact": "Unauthorized access, data leakage, service abuse, system compromise",
                "platform": "Web/Mobile"
            },
            "runtime_analysis": {
                "patterns": [
                    "dynamic dex loading", "in-memory dex decryption", "packer unpacking",
                    "mte tag mismatch", "heap buffer overflow", "use-after-free",
                    "frida evasion", "ptrace anti-debug", "anti-emulation",
                    "ebpf mmap anomaly", "memfd_create packer signature",
                    "ssl pinning bypass detection", "certificate validation bypass",
                ],
                "indicators": [
                    # eBPF indicators
                    "dex_dump event", "memfd_create syscall", "mmap file_backed=false",
                    "PROT_EXEC|PROT_WRITE", "anonymous mapping", "dex magic 64 65 78 0a",
                    # MTE indicators
                    "SEGV_MTESERR", "tag check fault", "fault addr", "pc address",
                    "register dump", "backtrace depth",
                    # Packer families
                    "qihoo 360", "secshell", "bangcle", "jiagu", "liapp", "dexprotector",
                    # Stealth indicators
                    "TracerPid=0", "abstract socket", "frida-agent", "frida-server",
                ],
                "packer_signatures": {
                    "qihoo_360": ["libjiagu", "libshella", "360packer"],
                    "secshell": ["libSecShell", "secshell"],
                    "bangcle": ["libsecexe", "libdexenc"],
                    "jiagu": ["libjiagu.so", "jiagu_protect"],
                    "dexprotector": ["dexprotector", "looksery"],
                },
                "mte_fault_patterns": {
                    "heap_oob": "fault_addr outside heap allocation bounds",
                    "use_after_free": "tag mismatch after dealloc — access to freed memory",
                    "stack_oob": "fault_addr in stack region beyond frame",
                    "double_free": "second tag_mismatch on already-freed pointer",
                },
                "impact": "Hidden code execution, memory corruption, anti-analysis bypass, data exfiltration",
                "platform": "Android (root required)",
            }
        },
        "exploitation_techniques": {
            "ios_analysis": {
                "static": ["ipa analysis", "class-dump", "otool inspection", "plist analysis", "entitlements review"],
                "dynamic": ["frida hooking", "cycript", "lldb debugging", "network monitoring", "keychain dumping"],
                "tools": ["hopper", "ida pro", "ghidra", "objection", "needle"]
            },
            "android_analysis": {
                "static": ["apk analysis", "jadx decompilation", "manifest inspection", "smali analysis", "resource extraction"],
                "dynamic": ["frida hooking", "xposed modules", "adb debugging", "network interception", "memory dumping"],
                "tools": ["apktool", "dex2jar", "apk_analyzer", "drozer", "qark"]
            },
            "web_analysis": {
                "static": ["source code review", "dependency analysis", "configuration review", "template analysis"],
                "dynamic": ["proxy interception", "fuzzing", "crawler analysis", "authentication testing", "session analysis"],
                "tools": ["burp suite", "owasp zap", "nikto", "sqlmap", "nmap"]
            },
            "desktop_analysis": {
                "static": ["binary analysis", "pe inspection", "dependency analysis", "configuration review"],
                "dynamic": ["debugger attachment", "api monitoring", "memory analysis", "network monitoring"],
                "tools": ["ida pro", "ghidra", "x64dbg", "process monitor", "wireshark"]
            }
        },
        "remediation_strategies": {
            "ios_hardening": {
                "app_transport_security": "Enable ATS with certificate pinning and disable arbitrary loads",
                "keychain_security": "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly and biometric protection",
                "jailbreak_detection": "Implement multi-layered jailbreak detection with server-side validation",
                "code_obfuscation": "Use Swift obfuscation and anti-debugging techniques",
                "entitlements": "Minimize entitlements and use proper sandboxing"
            },
            "android_hardening": {
                "certificate_pinning": "Implement certificate and public key pinning with backup mechanisms",
                "root_detection": "Multi-layered root detection with SafetyNet attestation",
                "anti_tampering": "Runtime application self-protection (RASP) and integrity checks",
                "secure_storage": "Use Android Keystore and EncryptedSharedPreferences",
                "network_security": "Implement network security config and disable cleartext traffic"
            },
            "web_hardening": {
                "input_validation": "Comprehensive input sanitization with allowlists and proper encoding",
                "authentication": "Multi-factor authentication with secure session management",
                "csrf_protection": "Implement CSRF tokens and SameSite cookie attributes",
                "content_security_policy": "Strict CSP headers to prevent XSS attacks",
                "https_enforcement": "HSTS headers and secure cookie flags"
            },
            "desktop_hardening": {
                "aslr_dep": "Enable ASLR and DEP/NX bit protection",
                "code_signing": "Implement proper code signing and certificate validation",
                "privilege_separation": "Run with minimal privileges and proper user account separation",
                "secure_coding": "Use safe functions and bounds checking",
                "update_mechanisms": "Secure automatic update mechanisms with signature verification"
            },
            "cross_platform": {
                "encryption": "AES-256 with secure key derivation (PBKDF2/Argon2) and proper IV generation",
                "secure_communication": "TLS 1.3 with certificate pinning and proper validation",
                "error_handling": "Secure error handling without information disclosure",
                "logging_security": "Secure logging without sensitive data exposure",
                "dependency_management": "Regular dependency updates and vulnerability scanning"
            }
        },
        "attack_vectors": {
            "ios_attacks": ["jailbreak exploitation", "keychain attacks", "url scheme hijacking", "pasteboard attacks", "backup analysis"],
            "android_attacks": ["root exploitation", "intent fuzzing", "broadcast hijacking", "content provider attacks", "webview exploitation"],
            "web_attacks": ["xss exploitation", "csrf attacks", "sql injection", "authentication bypass", "session hijacking"],
            "desktop_attacks": ["buffer overflow", "dll injection", "registry manipulation", "file system attacks", "process injection"],
            "network_attacks": ["mitm attacks", "ssl stripping", "dns poisoning", "traffic analysis", "protocol downgrade"],
            "api_attacks": ["broken authentication", "excessive data exposure", "injection flaws", "rate limiting bypass", "bola/bfla"]
        },
        "learning_resources": {
            "beginner": {
                "ios": ["iOS Security Guide", "OWASP Mobile Top 10", "Swift Security Basics", "Xcode Security Features"],
                "android": ["Android Security Fundamentals", "OWASP Mobile Top 10", "Java/Kotlin Security", "Android Studio Security"],
                "web": ["OWASP Top 10", "Web Security Fundamentals", "Secure Coding Practices", "Browser Security Basics"],
                "desktop": ["Desktop Security Basics", "OS Security Features", "Secure Development Lifecycle", "Common Vulnerabilities"],
                "tools": ["Burp Suite Basics", "OWASP ZAP Tutorial", "Frida Introduction", "Static Analysis Tools"]
            },
            "intermediate": {
                "ios": ["Advanced iOS Pentesting", "Objective-C/Swift Reverse Engineering", "iOS Malware Analysis", "Jailbreak Detection"],
                "android": ["Advanced Android Pentesting", "APK Analysis Techniques", "Android Malware Analysis", "Root Detection Bypass"],
                "web": ["Advanced Web Pentesting", "API Security Testing", "Modern Web Frameworks Security", "Client-Side Security"],
                "desktop": ["Binary Analysis", "Reverse Engineering Techniques", "Exploit Development", "Memory Corruption Bugs"],
                "tools": ["IDA Pro/Ghidra", "Frida Scripting", "Custom Tool Development", "Automation Frameworks"]
            },
            "advanced": {
                "research": ["0-day Discovery", "Vulnerability Research Methodologies", "Bug Bounty Advanced Techniques", "CVE Analysis"],
                "evasion": ["Anti-Analysis Techniques", "Advanced Obfuscation", "Sandbox Evasion", "Detection Bypass"],
                "forensics": ["Mobile Forensics", "Web Application Forensics", "Memory Analysis", "Network Forensics"],
                "platforms": ["Cross-Platform Security", "Hybrid App Security", "Cloud Security", "IoT Security"]
            },
            "expert": {
                "architecture": ["Secure Architecture Design", "Threat Modeling", "Security by Design", "Zero Trust Architecture"],
                "compliance": ["GDPR/Privacy Security", "PCI DSS", "SOC 2", "Industry-Specific Standards"],
                "leadership": ["Security Program Management", "Risk Assessment", "Incident Response", "Security Strategy"],
                "research": ["Security Research Leadership", "Vulnerability Disclosure", "Security Conference Speaking", "Open Source Security"]
            }
        },
        "context_indicators": {
            "urgency_high": ["production", "critical", "urgent", "emergency", "breach", "exploit in wild", "0-day"],
            "learning_mode": ["explain", "understand", "learn", "tutorial", "guide", "teach me", "how does", "what is"],
            "debugging_mode": ["not working", "error", "failed", "broken", "debug", "troubleshoot", "fix", "solve"],
            "research_mode": ["analyze", "investigate", "research", "deep dive", "comprehensive", "detailed analysis"],
            "platform_ios": ["ios", "iphone", "ipad", "swift", "objective-c", "xcode", "app store", "jailbreak"],
            "platform_android": ["android", "apk", "java", "kotlin", "gradle", "play store", "root", "adb"],
            "platform_web": ["web", "html", "javascript", "css", "browser", "http", "api", "rest", "graphql"],
            "platform_desktop": ["desktop", "windows", "macos", "linux", "exe", "dll", "binary", "native"]
        }
    }


def initialize_response_templates() -> Dict[str, str]:
    """Initialize adaptive response templates for different contexts, moods, and expertise levels."""
    return {
        # Emotional state adaptations
        "frustrated_user": "I understand this can be frustrating. Let's work through this systematically and get you back on track.",
        "excited_user": "That's excellent! I can see you're engaged with this. Let's dive deeper and explore the possibilities.",
        "confused_user": "No worries at all - this is complex stuff. Let me break this down into clearer, digestible pieces.",
        "focused_user": "I can see you're in problem-solving mode. Let's tackle this methodically.",
        
        # Expertise level adaptations
        "expert_user": "Given your advanced expertise, let's examine the technical nuances and edge cases here.",
        "beginner_user": "Let me walk you through this concept step-by-step, starting with the fundamentals.",
        "intermediate_user": "You have a solid foundation, so let's build on that and explore the deeper implications.",
        
        # Context-specific responses
        "urgent_security": "This appears to be a critical security issue. Let me prioritize the immediate remediation steps.",
        "discovery_mode": "Interesting finding! Let's explore the implications and potential attack vectors.",
        "verification_mode": "Let's verify this systematically — I want to make sure we're not chasing a false positive.",
        "remediation_mode": "Let's focus on the fix. I'll give you the most effective remediation with code examples.",
        
        # Platform-specific responses
        "ios_context": "Given this is an iOS target, I'll focus on platform-specific attack surfaces and Swift/ObjC remediation.",
        "android_context": "For this Android target, I'll address Java/Kotlin patterns and Android-specific hardening.",
        "web_context": "For this web application, I'll focus on OWASP patterns and modern web security practices.",
        "desktop_context": "For this desktop application, I'll address binary-level security and OS-specific hardening.",
        
        # Runtime-specific responses
        "runtime_error": "I see a runtime error. Let me analyze the failure and suggest an immediate pivot strategy.",
        "runtime_success": "The hook is working. Let's build on this — what's the next vulnerability to test?",
        "runtime_pivot": "The current approach isn't working. Let me suggest an alternative strategy based on the error.",
        
        # Learning resources
        "beginner_resource": "Here are some resources to build your foundation in this area.",
        "advanced_resource": "For deeper exploration, I'd recommend these advanced resources and techniques.",
    }


def initialize_semantic_analysis(
    domain_knowledge: Dict[str, Any],
) -> Dict[str, Any]:
    """Initialize TF-IDF semantic analysis for intent and platform detection.
    
    Returns dict with keys: tfidf_vectorizer, intent_vectors, platform_vectors
    """
    if not SKLEARN_AVAILABLE:
        return {
            "tfidf_vectorizer": None,
            "intent_vectors": None,
            "platform_vectors": None,
        }
    
    try:
        # Build training corpus from domain knowledge
        intent_corpus = {
            'casual_conversation': ["hi hey hello what's up greetings thanks cool nice ok"],
            'quick_question': ["what is how does can I should I where is when does why is quick question"],
            'problem_solving': ["error broken fix debug fail not working troubleshoot solve issue problem"],
            'learning_inquiry': ["explain understand learn tutorial guide teach me how does what is"],
            'deep_analysis': ["analyze investigate research deep dive comprehensive detailed analysis review assess evaluate"],
        }
        
        platform_corpus = {
            'ios': ["ios iphone ipad swift objective-c xcode jailbreak keychain ats app store"],
            'android': ["android apk java kotlin gradle root magisk xposed frida adb play store"],
            'web': ["web html javascript css browser http api rest graphql xss csrf sql injection"],
            'desktop': ["desktop windows macos linux exe dll binary native buffer overflow pe"],
            'general': ["security vulnerability finding risk assessment code analysis"]
        }
        
        # Build combined corpus for fitting — flatten each 1-element list to a string
        all_documents = [v[0] if isinstance(v, list) else v for v in intent_corpus.values()] + \
                        [v[0] if isinstance(v, list) else v for v in platform_corpus.values()]
        
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=500)
        vectors = vectorizer.fit_transform(all_documents)
        
        # Split back into intent and platform vectors
        n_intent = len(intent_corpus)
        intent_vectors = {}
        for i, intent in enumerate(intent_corpus.keys()):
            intent_vectors[intent] = vectors[i].toarray()[0]
        
        platform_vectors = {}
        for i, platform in enumerate(platform_corpus.keys()):
            platform_vectors[platform] = vectors[n_intent + i].toarray()[0]
        
        return {
            "tfidf_vectorizer": vectorizer,
            "intent_vectors": intent_vectors,
            "platform_vectors": platform_vectors,
        }
    except Exception as e:
        logger.error(f"Semantic analysis initialization failed: {e}")
        return {
            "tfidf_vectorizer": None,
            "intent_vectors": None,
            "platform_vectors": None,
        }


def semantic_context_analysis(
    message: str,
    conversation_history: List[Dict],
    tfidf_vectorizer,
    intent_vectors: Dict,
    platform_vectors: Dict,
) -> Dict[str, Any]:
    """Professional semantic context analysis using conversation flow and content understanding."""
    if not tfidf_vectorizer or not SKLEARN_AVAILABLE:
        return fallback_context_analysis(message, conversation_history)
    
    try:
        # Vectorize the current message
        message_vector = tfidf_vectorizer.transform([message]).toarray()[0]
        
        # Analyze intent using semantic similarity
        intent_scores = {}
        for intent, intent_vector in intent_vectors.items():
            similarity = cosine_similarity([message_vector], [intent_vector])[0][0]
            intent_scores[intent] = float(similarity)
        
        # Analyze platform context
        platform_scores = {}
        for platform, platform_vector in platform_vectors.items():
            similarity = cosine_similarity([message_vector], [platform_vector])[0][0]
            platform_scores[platform] = float(similarity)
        
        # Determine primary intent and platform
        primary_intent = max(intent_scores, key=intent_scores.get)
        detected_platform = max(platform_scores, key=platform_scores.get)
        
        return {
            'primary_intent': primary_intent,
            'confidence': intent_scores[primary_intent],
            'all_scores': intent_scores,
            'platform': detected_platform,
            'platform_confidence': platform_scores[detected_platform],
            'semantic_analysis': True
        }
        
    except Exception as e:
        logger.error(f"Semantic context analysis failed: {e}")
        return fallback_context_analysis(message, conversation_history)


def fallback_context_analysis(message: str, conversation_history: List[Dict]) -> Dict[str, Any]:
    """Fallback context analysis when semantic models are unavailable."""
    import re
    message_lower = message.lower().strip()
    
    _CASUAL_PATTERNS = re.compile(
        r"^(hi|hey|hello|yo|sup|what'?s up|howdy|greetings)[\s!?.]*$"
        r"|^(talk|chat|let'?s talk|tell me about yourself|who are you|what can you do)"
        r"|^(thanks|thank you|thx|ok|okay|got it|nice|cool|great|awesome|sounds good)"
        r"|^(good (morning|afternoon|evening|night))",
        re.IGNORECASE
    )
    _QUICK_QUESTION_PATTERNS = re.compile(
        r"^(what is|what's|what are|how (do|does|to|can)|is it|can (i|we|you)|should i|where (is|are|do)|when (is|does|should)|why (is|does|do))"
        r"|^(quick question|simple question|just wondering|curious)",
        re.IGNORECASE
    )
    _ANALYSIS_PATTERNS = re.compile(
        r"(analy[zs]e|analysis|review|assess|evaluate|investigate|explain|summarize|summary)"
        r"|((list|tell me|show me|give me|what are).{0,30}(finding|vulnerabilit|critical|issue|risk|flaw|weakness|problem))"
        r"|(attack (path|vector|surface)|exploit|remediat|mitigat|fix (this|the|it))"
        r"|(full (report|analysis|breakdown)|deep dive|comprehensive)"
        r"|(what should I (do|fix|patch|address)|how (serious|bad|critical) (is|are))"
        r"|(triage|auto.triage|priorit)",
        re.IGNORECASE
    )
    
    # Basic intent classification
    intent_scores = {
        'casual_conversation': 0.1,
        'learning_inquiry': 0.1,
        'problem_solving': 0.1,
        'deep_analysis': 0.1,
        'quick_question': 0.1
    }
    
    if _CASUAL_PATTERNS.search(message):
        intent_scores['casual_conversation'] = 0.9
    elif _QUICK_QUESTION_PATTERNS.search(message):
        intent_scores['quick_question'] = 0.8
    elif _ANALYSIS_PATTERNS.search(message):
        intent_scores['deep_analysis'] = 0.8
    elif any(word in message_lower for word in ['error', 'broken', 'fix', 'debug', 'fail']):
        intent_scores['problem_solving'] = 0.8
    elif any(word in message_lower for word in ['explain', 'what is', 'how does', 'teach']):
        intent_scores['learning_inquiry'] = 0.8
    
    primary_intent = max(intent_scores, key=intent_scores.get)
    confidence = intent_scores[primary_intent]
    
    return {
        'primary_intent': primary_intent,
        'confidence': confidence,
        'all_scores': intent_scores,
        'platform': 'general',
        'platform_confidence': 0.0,
        'semantic_analysis': False
    }
