"""
IRVES — Parser Base Classes
Abstract foundation for all tool output parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
import logging

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Standardized severity levels across all parsers."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Confidence level in the finding."""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


@dataclass
class ParsedFinding:
    """
    Standardized finding structure across all parsers.

    This is the universal output format that all parsers must return.
    It condenses verbose tool output into actionable intelligence.
    """
    title: str
    severity: Severity
    category: str
    description: str

    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None

    # Evidence (limited to keep output < 500 words)
    evidence: str = ""  # Code snippet or key evidence
    context: str = ""     # Additional context (truncated)

    # Classification
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None  # e.g., "M1: Improper Platform Usage"
    cvss_score: Optional[float] = None

    # Metadata
    tool: str = ""        # Tool that generated this finding
    confidence: Confidence = Confidence.MEDIUM
    remediation: str = ""

    # For AI context (key-value pairs for LLM understanding)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Raw reference (for deep dives)
    raw_reference: str = ""  # Pointer to full output location

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "evidence": self.evidence,
            "context": self.context,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "cvss_score": self.cvss_score,
            "tool": self.tool,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }

    def to_ai_summary(self, max_words: int = 100) -> str:
        """
        Generate a condensed summary for AI processing.
        Keeps output under specified word count.
        """
        words = [
            f"[{self.severity.value.upper()}]",
            self.title,
            "-",
            self.description[:150],
        ]

        if self.file_path:
            words.extend(["Location:", self.file_path])
            if self.line_number:
                words.append(f"line {self.line_number}")

        if self.evidence:
            words.extend(["Evidence:", self.evidence[:100]])

        if self.cwe_id:
            words.extend([f"CWE-{self.cwe_id}"])

        summary = " ".join(str(w) for w in words if w)
        words_list = summary.split()

        if len(words_list) > max_words:
            return " ".join(words_list[:max_words]) + "..."

        return summary


@dataclass
class ParserMetadata:
    """Metadata about a parser."""
    name: str
    version: str
    supported_tools: List[str]
    description: str
    platforms: List[str]  # android, ios, repository, web, desktop
    output_formats: List[str]  # json, xml, sarif, txt


@dataclass
class ParsedOutput:
    """
    Complete parsed output from a tool.
    Contains findings + summary statistics.
    """
    findings: List[ParsedFinding]
    tool_name: str
    summary: str = ""  # Executive summary (< 500 words)
    raw_output_path: Optional[Path] = None

    # Statistics
    stats: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        if not self.stats:
            self.stats = {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            }

    def get_summary_text(self) -> str:
        """Generate a human-readable summary."""
        if self.summary:
            return self.summary

        lines = [
            f"Tool: {self.tool_name}",
            f"Total Findings: {self.stats['total']}",
            f"  Critical: {self.stats['critical']}",
            f"  High: {self.stats['high']}",
            f"  Medium: {self.stats['medium']}",
            f"  Low: {self.stats['low']}",
            f"  Info: {self.stats['info']}",
        ]
        return "\n".join(lines)

    def to_ai_condensed(self, max_findings: int = 20) -> str:
        """
        Generate condensed output for AI consumption.
        Limits to top N findings by severity to prevent context overflow.
        """
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity, 5)
        )

        # Take top N
        top_findings = sorted_findings[:max_findings]

        lines = [
            f"=== {self.tool_name} Analysis Summary ===",
            self.get_summary_text(),
            "",
            "=== Key Findings ===",
        ]

        for i, finding in enumerate(top_findings, 1):
            lines.append(f"\n{i}. {finding.to_ai_summary()}")

        if len(self.findings) > max_findings:
            lines.append(f"\n... and {len(self.findings) - max_findings} more findings")

        return "\n".join(lines)


class ToolOutputParser(ABC):
    """
    Abstract base class for all tool output parsers.

    All parsers must implement:
    - parse(): Parse raw tool output (string or dict)
    - parse_file(): Parse from file path
    - can_parse(): Check if this parser can handle given input

    Example:
        class FridaParser(ToolOutputParser):
            @property
            def tool_name(self) -> str:
                return "frida"

            def parse(self, raw_output: Union[str, Dict]) -> ParsedOutput:
                # Implementation
                pass
    """

    def __init__(self):
        self._metadata: Optional[ParserMetadata] = None

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the tool this parser handles."""
        pass

    @property
    def metadata(self) -> ParserMetadata:
        """Parser metadata. Override in subclass."""
        if not self._metadata:
            self._metadata = ParserMetadata(
                name=self.__class__.__name__,
                version="1.0.0",
                supported_tools=[self.tool_name],
                description=f"Parser for {self.tool_name} output",
                platforms=[],
                output_formats=["json"],
            )
        return self._metadata

    @abstractmethod
    def parse(self, raw_output: Union[str, Dict, Path]) -> ParsedOutput:
        """
        Parse raw tool output into structured findings.

        Args:
            raw_output: Tool output as string, dict, or Path to file

        Returns:
            ParsedOutput with findings and summary
        """
        pass

    def parse_file(self, file_path: Union[str, Path]) -> ParsedOutput:
        """
        Parse output from a file.

        Default implementation reads file and calls parse().
        Override for binary or special formats.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = path.read_text(encoding="utf-8", errors="replace")
        result = self.parse(content)
        result.raw_output_path = path
        return result

    @abstractmethod
    def can_parse(self, raw_output: Union[str, Dict, Path]) -> bool:
        """
        Check if this parser can handle the given input.

        Used for auto-detection in parser registry.
        """
        pass

    def _extract_severity(self, severity_str: str) -> Severity:
        """Helper: Normalize severity string to Severity enum."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "warning": Severity.HIGH,
            "error": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
            "secure": Severity.LOW,  # legacy: "secure" treated as low severity
        }
        return severity_map.get(severity_str.lower(), Severity.MEDIUM)

    def _truncate(self, text: str, max_length: int = 500) -> str:
        """Helper: Truncate text to max length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."


class ParserRegistry:
    """
    Global registry for tool output parsers.

    Provides:
    - Parser auto-discovery
    - Tool-to-parser mapping
    - Parser selection by content detection
    """

    _instance = None
    _parsers: Dict[str, type] = {}
    _instances: Dict[str, ToolOutputParser] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._parsers = {}
            cls._instance._instances = {}
        return cls._instance

    def register(self, parser_class: type):
        """Register a parser class."""
        if not issubclass(parser_class, ToolOutputParser):
            raise ValueError("Parser must inherit from ToolOutputParser")

        # Create temporary instance to get tool name
        temp = parser_class()
        tool_name = temp.tool_name

        self._parsers[tool_name] = parser_class
        logger.info(f"[ParserRegistry] Registered '{tool_name}' parser: {parser_class.__name__}")

    def get(self, tool_name: str) -> Optional[ToolOutputParser]:
        """Get parser instance by tool name."""
        tool_name = tool_name.lower()

        # Return cached instance if available
        if tool_name in self._instances:
            return self._instances[tool_name]

        # Create new instance
        parser_class = self._parsers.get(tool_name)
        if not parser_class:
            return None

        instance = parser_class()
        self._instances[tool_name] = instance
        return instance

    def list_parsers(self) -> List[str]:
        """List all registered parser tool names."""
        return list(self._parsers.keys())

    def auto_detect(self, raw_output: Union[str, Dict, Path]) -> Optional[ToolOutputParser]:
        """Auto-detect parser based on content."""
        for tool_name, parser_class in self._parsers.items():
            parser = self.get(tool_name)
            if parser and parser.can_parse(raw_output):
                return parser
        return None


# Global registry instance
_registry = ParserRegistry()
