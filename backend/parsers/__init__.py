"""
IRVES — Parser Infrastructure (Phase 1)
Tool output parsing framework for condensing verbose tool output before AI processing.

This module provides:
- ToolOutputParser: Abstract base class for all parsers
- ParserRegistry: Auto-discovery and registration of parsers
- ParsedFinding: Standardized output structure

Usage:
    from parsers import get_parser, ParsedFinding
    from parsers.mobile import FridaParser

    # Using registry
    parser = get_parser("frida")
    findings = parser.parse(raw_output)

    # Direct instantiation
    parser = FridaParser()
    findings = parser.parse_file("/path/to/frida_output.json")
"""

from parsers.base import (
    ToolOutputParser,
    ParsedFinding,
    ParserMetadata,
    ParserRegistry,
    Severity,
    Confidence,
    ParsedOutput,
)
from parsers.registry import get_parser, list_parsers, register_parser, parse_with

# Import parsers to trigger @register_parser decorator
# This must happen after registry imports
try:
    from parsers.mobile.frida import FridaParser
    from parsers.repository.semgrep import SemgrepParser
    from parsers.repository.gitleaks import GitLeaksParser
except ImportError as e:
    import logging
    logging.getLogger(__name__).debug(f"[Parsers] Import error: {e}")

__all__ = [
    # Base classes
    "ToolOutputParser",
    "ParsedFinding",
    "ParsedOutput",
    "ParserMetadata",
    "ParserRegistry",
    # Enums
    "Severity",
    "Confidence",
    # Registry functions
    "get_parser",
    "list_parsers",
    "register_parser",
    "parse_with",
    # Parser classes
    "FridaParser",
    "SemgrepParser",
    "GitLeaksParser",
]
