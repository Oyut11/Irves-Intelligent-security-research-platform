"""
IRVES — Parser Integration Adapter
Connects new Phase 1 parsers to existing scanner without breaking functionality.

This adapter provides:
- Backward compatibility with existing finding_parser.py
- Seamless migration path to new parser infrastructure
- Optional use of new parsers via feature flag

Usage:
    # Existing code continues to work (backward compatible)
    from services.finding_parser import parse_tool_output
    findings = await parse_tool_output("frida", result)

    # New code can use enhanced parsers
    from parsers.adapter import parse_with_new_parsers
    parsed = parse_with_new_parsers("frida", result.output)
"""

import logging
from typing import List, Optional, Union
from pathlib import Path

from database.models import FindingSeverity
from models.finding import FindingCreate
from services.tool_runner import ToolResult

# Import new parser infrastructure
from parsers import get_parser, parse_with
from parsers.base import ParsedOutput, Severity

logger = logging.getLogger(__name__)

# Feature flag: Use new parsers when available
USE_NEW_PARSERS = True


def _convert_severity(severity: Severity) -> FindingSeverity:
    """Convert new parser severity to existing FindingSeverity."""
    mapping = {
        Severity.CRITICAL: FindingSeverity.CRITICAL,
        Severity.HIGH: FindingSeverity.HIGH,
        Severity.MEDIUM: FindingSeverity.MEDIUM,
        Severity.LOW: FindingSeverity.LOW,
        Severity.INFO: FindingSeverity.INFO,
    }
    return mapping.get(severity, FindingSeverity.MEDIUM)


def _convert_parsed_finding(parsed_finding) -> FindingCreate:
    """Convert new ParsedFinding to existing FindingCreate."""
    # Build location string
    location = parsed_finding.file_path or ""
    if parsed_finding.line_number:
        location += f":{parsed_finding.line_number}"

    # Build description with context if available
    description = parsed_finding.description
    if parsed_finding.context:
        description += f"\n\nContext: {parsed_finding.context}"

    # Add evidence to description
    if parsed_finding.evidence:
        description += f"\n\nEvidence: {parsed_finding.evidence}"

    return FindingCreate(
        scan_id="tmp",  # Will be replaced by caller
        title=parsed_finding.title,
        severity=_convert_severity(parsed_finding.severity),
        category=parsed_finding.category,
        description=description,
        location=location,
        code_snippet=parsed_finding.evidence,
        tool=parsed_finding.tool,
        owasp_mapping=parsed_finding.owasp_category or "",
        cwe_mapping=parsed_finding.cwe_id or "",
    )


async def parse_with_new_parsers(tool_name: str, raw_output: Union[str, dict, Path]) -> Optional[ParsedOutput]:
    """
    Parse using new Phase 1 parser infrastructure.

    Args:
        tool_name: Tool name (e.g., "frida", "semgrep")
        raw_output: Raw tool output

    Returns:
        ParsedOutput or None if parser not available
    """
    if not USE_NEW_PARSERS:
        return None

    try:
        return parse_with(tool_name, raw_output)
    except Exception as e:
        logger.warning(f"[ParserAdapter] New parser failed for {tool_name}: {e}")
        return None


async def parse_tool_output_enhanced(tool_name: str, result: ToolResult) -> List[FindingCreate]:
    """
    Enhanced version of parse_tool_output that uses new parsers when available.

    Falls back to legacy parser if new parser fails or isn't available.

    Args:
        tool_name: Tool name
        result: ToolResult from tool execution

    Returns:
        List of FindingCreate (existing format)
    """
    # Try new parser first
    if USE_NEW_PARSERS:
        try:
            parsed_output = await parse_with_new_parsers(tool_name, result.output)
            if parsed_output and parsed_output.findings:
                logger.info(f"[ParserAdapter] Using new parser for {tool_name}: {len(parsed_output.findings)} findings")
                return [_convert_parsed_finding(f) for f in parsed_output.findings]
        except Exception as e:
            logger.debug(f"[ParserAdapter] New parser failed for {tool_name}, using legacy: {e}")

    # Fall back to legacy parser
    from services.finding_parser import parse_tool_output as legacy_parse
    return await legacy_parse(tool_name, result)


def get_condensed_summary(tool_name: str, raw_output: Union[str, dict, Path]) -> Optional[str]:
    """
    Get condensed summary for AI processing (< 500 words).

    This is the key value-add of Phase 1 parsers - condensing verbose
    tool output before sending to AI.

    Args:
        tool_name: Tool name
        raw_output: Raw tool output

    Returns:
        Condensed summary string or None
    """
    try:
        parsed = parse_with(tool_name, raw_output)
        if parsed:
            return parsed.to_ai_condensed(max_findings=20)
    except Exception as e:
        logger.debug(f"[ParserAdapter] Could not get summary for {tool_name}: {e}")

    return None


class ParserBridge:
    """
    Bridge class for gradual migration to new parser infrastructure.

    Can be used as a drop-in replacement in scanner.py:

    OLD:
        from services.finding_parser import parse_tool_output
        findings = await parse_tool_output(tool_name, result)

    NEW:
        from parsers.adapter import ParserBridge
        bridge = ParserBridge()
        findings = await bridge.parse(tool_name, result)
    """

    def __init__(self, prefer_new_parsers: bool = True):
        self.prefer_new = prefer_new_parsers
        self.stats = {
            "new_parser_hits": 0,
            "legacy_parser_hits": 0,
            "failures": 0,
        }

    async def parse(self, tool_name: str, result: ToolResult) -> List[FindingCreate]:
        """Parse tool output using best available parser."""
        findings = await parse_tool_output_enhanced(tool_name, result)

        # Update stats
        if self.prefer_new_parsers:
            # We can't easily know which parser was used, but we can infer
            # from whether new parsers are registered
            parser = get_parser(tool_name)
            if parser and findings:
                self.stats["new_parser_hits"] += 1
            else:
                self.stats["legacy_parser_hits"] += 1

        return findings

    def get_summary(self, tool_name: str, raw_output: str) -> Optional[str]:
        """Get AI-condensed summary."""
        return get_condensed_summary(tool_name, raw_output)

    def get_stats(self) -> dict:
        """Get parser usage statistics."""
        return self.stats.copy()


# Backward-compatible alias for existing code
# This allows existing imports to work without changes
parse_tool_output = parse_tool_output_enhanced
