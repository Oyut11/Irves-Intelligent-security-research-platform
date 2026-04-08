"""
IRVES — Tool Registry
Central registry for security tools and scan profiles.
"""

from typing import Dict, List, Type, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

from services.tool_runner import ToolRunner

logger = logging.getLogger(__name__)


class ScanProfile(str, Enum):
    """Predefined scan profiles."""
    QUICK = "quick"       # Fast static analysis only
    FULL = "full"         # Comprehensive static + dynamic analysis
    RUNTIME = "runtime"   # Dynamic analysis with Frida/mitmproxy
    CUSTOM = "custom"     # User-selected tools


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    runner_class: Type[ToolRunner]
    description: str
    category: str
    platforms: List[str]  # Supported platforms: android, ios, web, desktop
    requires_server: bool = False
    requires_device: bool = False
    estimated_duration_seconds: int = 60


# Tool information registry
TOOL_INFO: Dict[str, ToolInfo] = {}


def register_tool(
    name: str,
    runner_class: Type[ToolRunner],
    description: str,
    category: str,
    platforms: List[str],
    requires_server: bool = False,
    requires_device: bool = False,
    estimated_duration_seconds: int = 60,
) -> None:
    """Register a security tool in the registry."""
    TOOL_INFO[name] = ToolInfo(
        name=name,
        runner_class=runner_class,
        description=description,
        category=category,
        platforms=platforms,
        requires_server=requires_server,
        requires_device=requires_device,
        estimated_duration_seconds=estimated_duration_seconds,
    )
    logger.debug(f"Registered tool: {name}")


# Import and register all available tools
def _initialize_registry() -> None:
    """Initialize the tool registry with all available tools."""

    # APKTool - APK decompilation
    from services.tools.apktool import APKToolRunner
    register_tool(
        name="apktool",
        runner_class=APKToolRunner,
        description="Decompile APK to smali and extract manifest",
        category="static",
        platforms=["android"],
        estimated_duration_seconds=30,
    )

    # JADX - Java decompilation
    from services.tools.jadx import JADXRunner
    register_tool(
        name="jadx",
        runner_class=JADXRunner,
        description="Decompile APK to readable Java source code",
        category="static",
        platforms=["android"],
        estimated_duration_seconds=60,
    )

    # MobSF - Comprehensive mobile security analysis
    from services.tools.mobsf import MobSFRunner
    register_tool(
        name="mobsf",
        runner_class=MobSFRunner,
        description="Comprehensive mobile security framework analysis",
        category="static",
        platforms=["android", "ios"],
        requires_server=True,
        estimated_duration_seconds=180,
    )

    # Frida - Dynamic instrumentation
    from services.tools.frida import FridaRunner
    register_tool(
        name="frida",
        runner_class=FridaRunner,
        description="Dynamic instrumentation toolkit for runtime analysis",
        category="dynamic",
        platforms=["android", "ios"],
        requires_device=True,
        estimated_duration_seconds=300,
    )

    # mitmproxy - Traffic interception
    from services.tools.mitmproxy import MitmproxyRunner
    register_tool(
        name="mitmproxy",
        runner_class=MitmproxyRunner,
        description="HTTPS traffic interception and analysis",
        category="dynamic",
        platforms=["android", "ios", "web"],
        estimated_duration_seconds=120,
    )


# Initialize on module load
_initialize_registry()


# Scan profile definitions - which tools to run for each profile
SCAN_PROFILE_TOOLS: Dict[str, List[str]] = {
    ScanProfile.QUICK: ["apktool", "jadx"],
    ScanProfile.FULL: ["apktool", "jadx", "mobsf"],
    ScanProfile.RUNTIME: ["frida", "mitmproxy"],
    ScanProfile.CUSTOM: [],  # User-specified
}

# Estimated duration for each profile (sum of tool durations)
SCAN_PROFILE_DURATION: Dict[str, int] = {
    ScanProfile.QUICK: 90,      # ~1.5 minutes
    ScanProfile.FULL: 270,      # ~4.5 minutes
    ScanProfile.RUNTIME: 420,  # ~7 minutes
}


def get_tools_for_profile(
    profile: str,
    custom_tools: Optional[List[str]] = None,
    platform: str = "android",
) -> List[Type[ToolRunner]]:
    """
    Get tool runner classes for a scan profile.

    Args:
        profile: Scan profile name (quick, full, runtime, custom)
        custom_tools: List of tool names for custom profile
        platform: Target platform (android, ios, web, desktop)

    Returns:
        List of ToolRunner classes to execute
    """
    if profile == ScanProfile.CUSTOM and custom_tools:
        tool_names = custom_tools
    else:
        tool_names = SCAN_PROFILE_TOOLS.get(profile, [])

    runners: List[Type[ToolRunner]] = []

    for name in tool_names:
        if name not in TOOL_INFO:
            logger.warning(f"Unknown tool: {name}")
            continue

        info = TOOL_INFO[name]

        # Check platform compatibility
        if platform not in info.platforms:
            logger.warning(f"Tool {name} does not support platform {platform}")
            continue

        runners.append(info.runner_class)

    return runners


def get_tool_info(name: str) -> Optional[ToolInfo]:
    """Get information about a specific tool."""
    return TOOL_INFO.get(name)


def get_all_tools() -> Dict[str, ToolInfo]:
    """Get information about all registered tools."""
    return TOOL_INFO.copy()


def get_tools_by_category(category: str) -> List[ToolInfo]:
    """Get all tools in a specific category."""
    return [info for info in TOOL_INFO.values() if info.category == category]


def get_tools_for_platform(platform: str) -> List[ToolInfo]:
    """Get all tools that support a specific platform."""
    return [info for info in TOOL_INFO.values() if platform in info.platforms]


def validate_scan_config(
    profile: str,
    custom_tools: Optional[List[str]] = None,
    platform: str = "android",
) -> Dict[str, List[str]]:
    """
    Validate a scan configuration and return any issues.

    Returns:
        Dictionary with 'errors' and 'warnings' lists
    """
    errors: List[str] = []
    warnings: List[str] = []

    # Validate profile
    valid_profiles = [p.value for p in ScanProfile]
    if profile not in valid_profiles:
        errors.append(f"Invalid profile: {profile}. Must be one of: {valid_profiles}")
        return {"errors": errors, "warnings": warnings}

    # Validate custom tools
    if profile == ScanProfile.CUSTOM:
        if not custom_tools:
            errors.append("Custom profile requires tool selection")
        else:
            for tool in custom_tools:
                if tool not in TOOL_INFO:
                    errors.append(f"Unknown tool: {tool}")

    # Check platform compatibility
    tools = get_tools_for_profile(profile, custom_tools, platform)
    if not tools:
        if profile != ScanProfile.CUSTOM:
            warnings.append(f"No compatible tools for {platform} platform with {profile} profile")

    # Check requirements
    for runner_class in tools:
        info = TOOL_INFO.get(runner_class().name)
        if info:
            if info.requires_server:
                warnings.append(f"Tool '{info.name}' requires a running server")
            if info.requires_device:
                warnings.append(f"Tool '{info.name}' requires a connected device")

    return {"errors": errors, "warnings": warnings}


def estimate_scan_duration(
    profile: str,
    custom_tools: Optional[List[str]] = None,
) -> int:
    """
    Estimate scan duration in seconds.

    Returns:
        Estimated duration in seconds
    """
    if profile == ScanProfile.CUSTOM and custom_tools:
        total = 0
        for name in custom_tools:
            info = TOOL_INFO.get(name)
            if info:
                total += info.estimated_duration_seconds
        return total

    return SCAN_PROFILE_DURATION.get(profile, 60)


# Convenience exports
__all__ = [
    "ScanProfile",
    "ToolInfo",
    "TOOL_INFO",
    "SCAN_PROFILE_TOOLS",
    "SCAN_PROFILE_DURATION",
    "get_tools_for_profile",
    "get_tool_info",
    "get_all_tools",
    "get_tools_by_category",
    "get_tools_for_platform",
    "validate_scan_config",
    "estimate_scan_duration",
    "register_tool",
]