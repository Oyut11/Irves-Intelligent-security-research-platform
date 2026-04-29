"""
IRVES — AST Platform Templates
Pre-defined task templates for Android, iOS, and Repository analysis.

Each template defines the complete task tree with dependencies for a platform.
"""

from typing import List

from ast_engine.models import AnalysisTask, AnalysisPhase, PlatformType, Priority, TaskStatus


def get_template_for_platform(platform: PlatformType) -> List[AnalysisTask]:
    """
    Get the default AST template for a platform.

    Args:
        platform: Target platform type

    Returns:
        List of tasks with dependencies configured
    """
    templates = {
        PlatformType.ANDROID: get_android_template,
        PlatformType.IOS: get_ios_template,
        PlatformType.REPOSITORY: get_repository_template,
        PlatformType.DESKTOP: get_desktop_template,
        PlatformType.WEB: get_web_template,
    }

    template_fn = templates.get(platform, get_android_template)
    return template_fn()


def get_android_template() -> List[AnalysisTask]:
    """
    Android analysis template.

    Phases:
    1. Static Analysis - Manifest, code, resources
    2. Dynamic Analysis - Runtime behavior, hooking
    3. Network Analysis - Traffic capture, API testing
    4. Exploit Development - PoC generation
    """
    tasks = []

    # ========== PHASE 1: STATIC ANALYSIS ==========
    phase = AnalysisPhase.STATIC

    # 1.1 Manifest Analysis
    tasks.append(AnalysisTask(
        task_id="1.1.1",
        name="Permissions Review",
        description="Analyze requested permissions for dangerous combinations",
        phase=phase,
        priority=Priority.HIGH,
        tool_name="apk_analyzer",
        tool_config={"analysis_type": "manifest"},
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.2",
        name="Exported Components",
        description="Identify exported activities, services, and receivers",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["1.1.1"],
        tool_name="apk_analyzer",
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.3",
        name="Intent Filters",
        description="Review intent filters for implicit intent vulnerabilities",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["1.1.1"],
    ))

    # 1.2 Code Analysis
    tasks.append(AnalysisTask(
        task_id="1.2.1",
        name="Hardcoded Secrets",
        description="Search for API keys, passwords, and tokens in code",
        phase=phase,
        priority=Priority.CRITICAL,
        tool_name="apk_analyzer",
        tool_config={"analysis_type": "code"},
    ))
    tasks.append(AnalysisTask(
        task_id="1.2.2",
        name="Cryptographic Implementation",
        description="Analyze crypto usage for weak algorithms or improper implementation",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.2.1"],
        tool_name="apk_analyzer",
    ))
    tasks.append(AnalysisTask(
        task_id="1.2.3",
        name="WebView Configuration",
        description="Check WebView settings for JavaScript injection risks",
        phase=phase,
        priority=Priority.HIGH,
        tool_name="apk_analyzer",
    ))

    # 1.3 Resource Analysis
    tasks.append(AnalysisTask(
        task_id="1.3.1",
        name="String Resources",
        description="Extract and analyze string resources for sensitive data",
        phase=phase,
        priority=Priority.MEDIUM,
        tool_name="apktool",
    ))
    tasks.append(AnalysisTask(
        task_id="1.3.2",
        name="Asset Files",
        description="Review bundled assets for configuration files or secrets",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["1.3.1"],
    ))

    # ========== PHASE 2: DYNAMIC ANALYSIS ==========
    phase = AnalysisPhase.DYNAMIC

    # 2.1 Runtime Behavior
    tasks.append(AnalysisTask(
        task_id="2.1.1",
        name="App Startup",
        description="Monitor application startup behavior and initialization",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.2.2"],  # Need crypto analysis first
        tool_name="frida",
        tool_config={"hook_type": "startup"},
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.2",
        name="Key Extraction",
        description="Extract cryptographic keys from runtime memory",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["2.1.1"],
        tool_name="frida",
        tool_config={"hook_type": "crypto"},
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.3",
        name="Storage Access",
        description="Monitor file system and SharedPreferences access",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
        tool_name="frida",
        tool_config={"hook_type": "storage"},
    ))

    # 2.2 Method Hooking
    tasks.append(AnalysisTask(
        task_id="2.2.1",
        name="Network Method Hooking",
        description="Hook network-related methods to intercept URLs and data",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.1.3"],
        tool_name="frida",
    ))
    tasks.append(AnalysisTask(
        task_id="2.2.2",
        name="SSL Pinning Bypass",
        description="Attempt to bypass certificate pinning",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.2.1"],
        tool_name="frida",
        tool_config={"hook_type": "ssl_bypass"},
    ))

    # 2.3 Memory Analysis
    tasks.append(AnalysisTask(
        task_id="2.3.1",
        name="Memory Dump Analysis",
        description="Search memory for passwords, tokens, and sensitive data",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["2.1.2"],
    ))

    # ========== PHASE 3: NETWORK ANALYSIS ==========
    phase = AnalysisPhase.NETWORK

    # 3.1 Traffic Capture
    tasks.append(AnalysisTask(
        task_id="3.1.1",
        name="HTTPS Traffic Interception",
        description="Capture HTTPS traffic with SSL pinning bypassed",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["2.2.2"],  # Need SSL bypass first
        tool_name="mitmproxy",
        tool_config={"mode": "transparent"},
    ))
    tasks.append(AnalysisTask(
        task_id="3.1.2",
        name="API Endpoint Discovery",
        description="Identify and catalog all API endpoints",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["3.1.1"],
    ))
    tasks.append(AnalysisTask(
        task_id="3.1.3",
        name="Sensitive Data Transmission",
        description="Detect sensitive data in network traffic",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["3.1.1"],
    ))

    # 3.2 API Analysis
    tasks.append(AnalysisTask(
        task_id="3.2.1",
        name="Authentication Testing",
        description="Test API authentication mechanisms",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["3.1.2"],
    ))
    tasks.append(AnalysisTask(
        task_id="3.2.2",
        name="Input Validation",
        description="Test API inputs for injection vulnerabilities",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["3.1.2"],
    ))

    # 3.3 SSL/TLS Analysis
    tasks.append(AnalysisTask(
        task_id="3.3.1",
        name="Certificate Validation",
        description="Verify proper certificate chain validation",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["2.2.2"],
    ))

    # ========== PHASE 4: EXPLOIT DEVELOPMENT ==========
    phase = AnalysisPhase.EXPLOIT

    # 4.1 PoC Generation
    tasks.append(AnalysisTask(
        task_id="4.1.1",
        name="Exported Component Exploit",
        description="Generate PoC for exported component vulnerabilities",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.1.2", "3.1.1"],
    ))
    tasks.append(AnalysisTask(
        task_id="4.1.2",
        name="Intent Injection PoC",
        description="Create proof of concept for intent injection attacks",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["4.1.1"],
    ))

    # 4.2 Verification
    tasks.append(AnalysisTask(
        task_id="4.2.1",
        name="Static-Dynamic Correlation",
        description="Verify static findings with dynamic behavior",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["1.2.1", "2.1.2"],
    ))
    tasks.append(AnalysisTask(
        task_id="4.2.2",
        name="Attack Chain Validation",
        description="Validate complete attack chains from finding to exploit",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["4.1.2", "4.2.1"],
    ))

    return tasks


def get_ios_template() -> List[AnalysisTask]:
    """
    iOS analysis template.

    Similar structure to Android but with iOS-specific tasks.
    """
    tasks = []

    # ========== PHASE 1: STATIC ANALYSIS ==========
    phase = AnalysisPhase.STATIC

    # 1.1 Info.plist Analysis
    tasks.append(AnalysisTask(
        task_id="1.1.1",
        name="Info.plist Review",
        description="Analyze Info.plist for sensitive configurations",
        phase=phase,
        priority=Priority.HIGH,
        tool_name="ios_analyzer",
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.2",
        name="URL Schemes",
        description="Identify custom URL schemes and handlers",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.1.1"],
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.3",
        name="ATS Configuration",
        description="Review App Transport Security exceptions",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["1.1.1"],
    ))

    # 1.2 Binary Analysis
    tasks.append(AnalysisTask(
        task_id="1.2.1",
        name="Class Dump",
        description="Extract Objective-C class information",
        phase=phase,
        priority=Priority.MEDIUM,
        tool_name="class_dump",
    ))
    tasks.append(AnalysisTask(
        task_id="1.2.2",
        name="String Analysis",
        description="Search binary for hardcoded secrets and URLs",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.2.1"],
        tool_name="strings",
    ))

    # 1.3 Code Analysis
    tasks.append(AnalysisTask(
        task_id="1.3.1",
        name="Hardcoded Secrets",
        description="Find API keys and tokens in source",
        phase=phase,
        priority=Priority.CRITICAL,
        tool_name="ios_analyzer",
    ))
    tasks.append(AnalysisTask(
        task_id="1.3.2",
        name="Keychain Usage",
        description="Analyze Keychain access patterns",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.3.1"],
    ))

    # ========== PHASE 2: DYNAMIC ANALYSIS ==========
    phase = AnalysisPhase.DYNAMIC

    # 2.1 Runtime
    tasks.append(AnalysisTask(
        task_id="2.1.1",
        name="Jailbreak Detection Bypass",
        description="Attempt to bypass jailbreak detection",
        phase=phase,
        priority=Priority.HIGH,
        tool_name="frida",
        tool_config={"hook_type": "jailbreak"},
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.2",
        name="Keychain Extraction",
        description="Extract data from iOS Keychain",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["2.1.1"],
        tool_name="frida",
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.3",
        name="Crypto Operations",
        description="Hook CommonCrypto and CryptoKit functions",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
        tool_name="frida",
    ))

    # 2.2 Method Swizzling Detection
    tasks.append(AnalysisTask(
        task_id="2.2.1",
        name="Method Swizzle Hooks",
        description="Detect method swizzling in runtime",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["2.1.1"],
    ))

    # ========== PHASE 3: NETWORK ANALYSIS ==========
    phase = AnalysisPhase.NETWORK

    tasks.append(AnalysisTask(
        task_id="3.1.1",
        name="Traffic Capture",
        description="Intercept HTTPS traffic",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
        tool_name="mitmproxy",
    ))
    tasks.append(AnalysisTask(
        task_id="3.1.2",
        name="Certificate Pinning Test",
        description="Test SSL pinning implementation",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["3.1.1"],
    ))

    # ========== PHASE 4: EXPLOIT ==========
    phase = AnalysisPhase.EXPLOIT

    tasks.append(AnalysisTask(
        task_id="4.1.1",
        name="URL Scheme Hijacking PoC",
        description="Create PoC for URL scheme hijacking",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.1.2", "3.1.1"],
    ))

    return tasks


def get_repository_template() -> List[AnalysisTask]:
    """
    Repository (source code) analysis template.

    Focuses on SAST, secrets scanning, and dependency analysis.
    """
    tasks = []

    # ========== PHASE 1: SECRET SCANNING ==========
    phase = AnalysisPhase.STATIC

    tasks.append(AnalysisTask(
        task_id="1.1.1",
        name="Git History Scan",
        description="Scan git history for committed secrets",
        phase=phase,
        priority=Priority.CRITICAL,
        tool_name="gitleaks",
        tool_config={"scan_type": "history"},
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.2",
        name="Current Code Secrets",
        description="Scan current codebase for secrets",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["1.1.1"],
        tool_name="gitleaks",
    ))
    tasks.append(AnalysisTask(
        task_id="1.1.3",
        name="Config File Analysis",
        description="Analyze config files for credentials",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["1.1.2"],
    ))

    # ========== PHASE 2: SAST ==========
    phase = AnalysisPhase.STATIC  # Repository uses static for all

    tasks.append(AnalysisTask(
        task_id="2.1.1",
        name="Injection Flaws",
        description="Scan for SQL, NoSQL, Command injection",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["1.1.2"],
        tool_name="semgrep",
        tool_config={"rules": "owasp-top-ten"},
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.2",
        name="Authentication Issues",
        description="Find auth bypass and session issues",
        phase=phase,
        priority=Priority.CRITICAL,
        dependencies=["2.1.1"],
        tool_name="semgrep",
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.3",
        name="Cryptography Problems",
        description="Detect weak crypto implementations",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
        tool_name="semgrep",
    ))
    tasks.append(AnalysisTask(
        task_id="2.1.4",
        name="Input Validation",
        description="Check input validation patterns",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
    ))

    # 2.2 Dependency Analysis
    tasks.append(AnalysisTask(
        task_id="2.2.1",
        name="Vulnerable Dependencies",
        description="Scan dependencies for known CVEs",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
    ))
    tasks.append(AnalysisTask(
        task_id="2.2.2",
        name="License Compliance",
        description="Check license compatibility",
        phase=phase,
        priority=Priority.LOW,
        dependencies=["2.2.1"],
    ))

    # ========== PHASE 3: IaC ANALYSIS ==========
    phase = AnalysisPhase.STATIC

    tasks.append(AnalysisTask(
        task_id="3.1.1",
        name="Docker Security",
        description="Analyze Dockerfile for security issues",
        phase=phase,
        priority=Priority.MEDIUM,
        tool_name="semgrep",
    ))
    tasks.append(AnalysisTask(
        task_id="3.1.2",
        name="Kubernetes Configs",
        description="Scan Kubernetes YAML for misconfigurations",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["3.1.1"],
    ))

    # ========== PHASE 4: CORRELATION ==========
    phase = AnalysisPhase.EXPLOIT

    tasks.append(AnalysisTask(
        task_id="4.1.1",
        name="Attack Path Analysis",
        description="Map exploitable paths from findings",
        phase=phase,
        priority=Priority.HIGH,
        dependencies=["2.1.1", "2.1.2"],
    ))
    tasks.append(AnalysisTask(
        task_id="4.1.2",
        name="Fix Prioritization",
        description="Prioritize fixes by risk and effort",
        phase=phase,
        priority=Priority.MEDIUM,
        dependencies=["4.1.1"],
    ))

    return tasks


def get_desktop_template() -> List[AnalysisTask]:
    """Desktop application template (Windows/macOS/Linux)."""
    # Simplified version - can be expanded
    return get_android_template()[:10]  # Use subset of Android tasks as base


def get_web_template() -> List[AnalysisTask]:
    """Web application template."""
    # Similar to repository but with runtime components
    tasks = get_repository_template()

    # Add network testing tasks
    tasks.append(AnalysisTask(
        task_id="3.1.1",
        name="Live Endpoint Testing",
        description="Test discovered endpoints live",
        phase=AnalysisPhase.NETWORK,
        priority=Priority.HIGH,
        dependencies=["2.1.1"],
    ))

    return tasks
