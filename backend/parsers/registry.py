"""
IRVES — Parser Registry
Auto-discovery and registration system for tool output parsers.

Usage:
    # Using decorator (recommended)
    from parsers import register_parser, ToolOutputParser

    @register_parser
    class MyParser(ToolOutputParser):
        @property
        def tool_name(self) -> str:
            return "my_tool"
        ...

    # Using registry directly
    from parsers.registry import ParserRegistry
    registry = ParserRegistry()
    registry.register(MyParser)

    # Getting a parser
    parser = get_parser("frida")
    findings = parser.parse(raw_output)
"""

import logging
from typing import Any, Callable, List, Optional, Type, Union
from pathlib import Path

from parsers.base import ToolOutputParser, ParserRegistry, ParsedOutput

logger = logging.getLogger(__name__)


# Global registry singleton
_registry = ParserRegistry()


def register_parser(parser_class: Type[ToolOutputParser]) -> Type[ToolOutputParser]:
    """
    Decorator to register a parser class.

    Usage:
        @register_parser
        class FridaParser(ToolOutputParser):
            ...

    This makes the parser available via get_parser("frida")
    """
    _registry.register(parser_class)
    return parser_class


def get_parser(tool_name: str) -> Optional[ToolOutputParser]:
    """
    Get a parser instance by tool name.

    Args:
        tool_name: Tool name (e.g., "frida", "semgrep")

    Returns:
        Parser instance or None if not found

    Example:
        parser = get_parser("frida")
        if parser:
            output = parser.parse_file("/path/to/report.json")
    """
    return _registry.get(tool_name)


def list_parsers() -> List[str]:
    """
    List all registered parser tool names.

    Returns:
        List of registered tool names
    """
    return _registry.list_parsers()


def auto_detect_parser(raw_output: Union[str, dict, Path]) -> Optional[ToolOutputParser]:
    """
    Auto-detect the appropriate parser for given content.

    Tries each registered parser's can_parse() method.

    Args:
        raw_output: Tool output to analyze

    Returns:
        Suitable parser or None
    """
    return _registry.auto_detect(raw_output)


def parse_with(tool_name: str, raw_output: Union[str, dict, Path]) -> Optional[ParsedOutput]:
    """
    Convenience function: Get parser and parse in one call.

    Args:
        tool_name: Tool name
        raw_output: Raw tool output

    Returns:
        ParsedOutput or None if parser not found
    """
    parser = get_parser(tool_name)
    if not parser:
        logger.warning(f"[Registry] No parser found for tool: {tool_name}")
        return None

    try:
        return parser.parse(raw_output)
    except Exception as e:
        logger.error(f"[Registry] Parse error for {tool_name}: {e}")
        return None


def discover_parsers():
    """
    Auto-discover and register all parsers in the parsers package.
    Call this on application startup.
    """
    import importlib
    import pkgutil
    from parsers import mobile, repository

    modules = [
        ("parsers.mobile", mobile),
        ("parsers.repository", repository),
    ]

    registered = []

    for package_name, package in modules:
        for _, name, is_pkg in pkgutil.iter_modules(package.__path__):
            if not is_pkg:
                try:
                    module = importlib.import_module(f"{package_name}.{name}")
                    # Parsers decorated with @register_parser are auto-registered
                    # when the module is imported
                    registered.append(name)
                except Exception as e:
                    logger.warning(f"[Discovery] Failed to load {package_name}.{name}: {e}")

    logger.info(f"[Discovery] Loaded {len(registered)} parser modules: {registered}")
    return registered


# Import all parsers to trigger registration
# This happens when registry is imported
logger.debug("[Registry] Initializing parser registry...")
