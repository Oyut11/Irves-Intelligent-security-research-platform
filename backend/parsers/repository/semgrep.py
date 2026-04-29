"""
IRVES — Semgrep Parser
Parses Semgrep SAST output (SARIF format) into standardized findings.

Supports:
- SARIF JSON format (standard)
- Semgrep JSON format (native)
- Multiple programming languages
- CWE mapping
- OWASP mapping
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

from parsers.base import (
    ToolOutputParser,
    ParsedFinding,
    ParsedOutput,
    Severity,
    Confidence,
    ParserMetadata,
)
from parsers.registry import register_parser

logger = logging.getLogger(__name__)


@register_parser
class SemgrepParser(ToolOutputParser):
    """
    Parser for Semgrep SAST tool output.

    Parses SARIF and Semgrep JSON formats to extract:
    - Security vulnerabilities (injection, auth, crypto)
    - Code quality issues
    - CWE-classified findings
    - Multi-language support

    Output is condensed to < 500 words for AI processing.
    """

    # CWE to Severity mapping
    CWE_SEVERITY = {
        # Injection flaws
        "CWE-89": Severity.CRITICAL,   # SQL Injection
        "CWE-79": Severity.HIGH,       # XSS
        "CWE-94": Severity.CRITICAL,   # Code Injection
        "CWE-78": Severity.CRITICAL,   # OS Command Injection
        "CWE-77": Severity.HIGH,       # Command Injection

        # Authentication
        "CWE-287": Severity.CRITICAL,  # Improper Authentication
        "CWE-306": Severity.CRITICAL,  # Missing Authentication
        "CWE-798": Severity.CRITICAL,  # Hardcoded Credentials
        "CWE-259": Severity.CRITICAL,  # Hardcoded Password

        # Cryptography
        "CWE-327": Severity.HIGH,      # Broken Crypto
        "CWE-326": Severity.MEDIUM,    # Inadequate Encryption
        "CWE-310": Severity.MEDIUM,    # Cryptographic Issues
        "CWE-759": Severity.MEDIUM,    # Use of Hardcoded Salt

        # Data protection
        "CWE-312": Severity.HIGH,      # Cleartext Storage
        "CWE-315": Severity.HIGH,       # Cleartext in Cookie
        "CWE-532": Severity.MEDIUM,     # Log Injection

        # Communication
        "CWE-319": Severity.HIGH,       # Cleartext Transmission
        "CWE-295": Severity.HIGH,       # Certificate Validation

        # Input validation
        "CWE-20": Severity.MEDIUM,      # Input Validation
        "CWE-22": Severity.HIGH,        # Path Traversal
    }

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="SemgrepParser",
            version="1.0.0",
            supported_tools=["semgrep"],
            description="Parses Semgrep SAST output (SARIF and native JSON)",
            platforms=["repository"],
            output_formats=["sarif", "json"],
        )

    def can_parse(self, raw_output: Union[str, Dict, Path]) -> bool:
        """Check if input looks like Semgrep/SARIF JSON."""
        try:
            if isinstance(raw_output, Path):
                content = Path(raw_output).read_text(errors="replace")[:1000]
                data = json.loads(content)
            elif isinstance(raw_output, str):
                data = json.loads(raw_output[:1000])
            else:
                data = raw_output

            # Check for SARIF format
            if "$schema" in data and "sarif" in str(data.get("$schema", "")).lower():
                return True
            if "version" in data and "sarifVersion" in data:
                return True

            # Check for Semgrep native format
            if "results" in data and "errors" in data:
                return True
            if "version" in data and isinstance(data.get("results"), list):
                return True

            return False
        except Exception:
            return False

    def parse(self, raw_output: Union[str, Dict, Path]) -> ParsedOutput:
        """
        Parse Semgrep/SARIF output.

        Args:
            raw_output: JSON string, dict, or file path

        Returns:
            ParsedOutput with findings
        """
        # Load JSON
        if isinstance(raw_output, Path):
            data = json.loads(Path(raw_output).read_text(encoding="utf-8", errors="replace"))
        elif isinstance(raw_output, str):
            data = json.loads(raw_output)
        else:
            data = raw_output

        # Detect format and parse
        if self._is_sarif(data):
            findings = self._parse_sarif(data)
        else:
            findings = self._parse_semgrep_native(data)

        summary = self._generate_summary(findings, data)

        return ParsedOutput(
            findings=findings,
            tool_name=self.tool_name,
            summary=summary,
        )

    def _is_sarif(self, data: Dict) -> bool:
        """Check if data is SARIF format."""
        schema = str(data.get("$schema", "")).lower()
        return "sarif" in schema or "sarifVersion" in data

    def _parse_sarif(self, data: Dict) -> List[ParsedFinding]:
        """Parse SARIF format output."""
        findings = []

        # Get runs
        runs = data.get("runs", [])
        if not runs:
            return findings

        for run in runs:
            # Get rules mapping
            rules = {}
            tool_info = run.get("tool", {})
            driver = tool_info.get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                rules[rule_id] = rule

            # Parse results
            for result in run.get("results", []):
                finding = self._convert_sarif_result(result, rules)
                if finding:
                    findings.append(finding)

        return findings

    def _convert_sarif_result(
        self, result: Dict, rules: Dict[str, Dict]
    ) -> Optional[ParsedFinding]:
        """Convert SARIF result to ParsedFinding."""
        rule_id = result.get("ruleId", "")
        rule = rules.get(rule_id, {})

        # Get message
        message = result.get("message", {})
        text = message.get("text", message.get("markdown", "No description"))

        # Get locations
        locations = result.get("locations", [])
        if not locations:
            return None

        location = locations[0]
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})

        file_path = artifact.get("uri", "")
        line = region.get("startLine", 0)
        column = region.get("startColumn", 0)

        # Get snippet
        snippet = ""
        context_region = physical.get("contextRegion", {})
        if context_region:
            snippet = context_region.get("snippet", {}).get("text", "")
        if not snippet:
            snippet = region.get("snippet", {}).get("text", "")

        # Get severity
        rule_props = rule.get("properties", {})
        cwe = self._extract_cwe_from_tags(rule.get("properties", {}).get("tags", []))
        severity = self._map_sarif_severity(
            result.get("level", rule_props.get("security-severity", "warning")),
            cwe,
        )

        # Get remediation
        remediation = rule.get("help", {}).get("text", "")
        if not remediation:
            remediation = rule.get("fullDescription", {}).get("text", "")

        return ParsedFinding(
            title=rule.get("name", rule_id),
            severity=severity,
            category=rule_props.get("category", "SAST"),
            description=text,
            file_path=file_path,
            line_number=line,
            column=column,
            evidence=self._truncate(snippet, 200),
            cwe_id=cwe,
            owasp_category=self._get_owasp_from_cwe(cwe),
            tool=self.tool_name,
            confidence=Confidence.HIGH,
            remediation=self._truncate(remediation, 300),
            metadata={"rule_id": rule_id, "semgrep_severity": result.get("level", "unknown")},
        )

    def _parse_semgrep_native(self, data: Dict) -> List[ParsedFinding]:
        """Parse Semgrep native JSON format."""
        findings = []

        results = data.get("results", [])
        for result in results:
            finding = self._convert_semgrep_result(result)
            if finding:
                findings.append(finding)

        return findings

    def _convert_semgrep_result(self, result: Dict) -> Optional[ParsedFinding]:
        """Convert Semgrep native result to ParsedFinding."""
        check_id = result.get("check_id", "")
        path = result.get("path", "")
        start = result.get("start", {})
        line = start.get("line", 0)
        column = start.get("col", 0)

        # Extract message and metadata
        extra = result.get("extra", {})
        message = extra.get("message", "No description")
        severity_str = extra.get("severity", "WARNING")
        lines = extra.get("lines", "")
        metadata = extra.get("metadata", {})

        # Get CWE
        cwe = None
        cwe_list = metadata.get("cwe", [])
        if cwe_list:
            cwe = self._extract_cwe_from_string(cwe_list[0])

        # Map severity
        severity = self._map_semgrep_severity(severity_str, cwe)

        # Get remediation if available
        fix = extra.get("fix", "")
        remediation = f"Suggested fix: {fix}" if fix else ""

        return ParsedFinding(
            title=check_id.split(".")[-1] if "." in check_id else check_id,
            severity=severity,
            category=metadata.get("category", "SAST"),
            description=message,
            file_path=path,
            line_number=line,
            column=column,
            evidence=self._truncate(lines, 200),
            cwe_id=cwe,
            owasp_category=self._get_owasp_from_cwe(cwe),
            tool=self.tool_name,
            confidence=Confidence.HIGH,
            remediation=remediation,
            metadata={"rule_id": check_id, "technology": metadata.get("technology", [])},
        )

    def _extract_cwe_from_tags(self, tags: List[str]) -> Optional[str]:
        """Extract CWE ID from SARIF tags."""
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                return tag.upper().split()[0]  # Handle "CWE-89: SQL Injection"
        return None

    def _extract_cwe_from_string(self, text: str) -> Optional[str]:
        """Extract CWE ID from string."""
        import re
        match = re.search(r"CWE-\d+", text, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        return None

    def _map_sarif_severity(self, level: str, cwe: Optional[str]) -> Severity:
        """Map SARIF severity level to IRVES severity."""
        # First check CWE mapping
        if cwe and cwe in self.CWE_SEVERITY:
            return self.CWE_SEVERITY[cwe]

        level_map = {
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
            "none": Severity.INFO,
        }
        return level_map.get(level.lower(), Severity.MEDIUM)

    def _map_semgrep_severity(self, severity: str, cwe: Optional[str]) -> Severity:
        """Map Semgrep severity to IRVES severity."""
        # First check CWE mapping
        if cwe and cwe in self.CWE_SEVERITY:
            return self.CWE_SEVERITY[cwe]

        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return severity_map.get(severity.upper(), Severity.MEDIUM)

    def _get_owasp_from_cwe(self, cwe: Optional[str]) -> Optional[str]:
        """Map CWE to OWASP category."""
        if not cwe:
            return None

        cwe_to_owasp = {
            "CWE-89": "A03:2021 – Injection",
            "CWE-79": "A03:2021 – Injection",
            "CWE-94": "A03:2021 – Injection",
            "CWE-78": "A03:2021 – Injection",
            "CWE-287": "A07:2021 – Identification and Authentication Failures",
            "CWE-306": "A07:2021 – Identification and Authentication Failures",
            "CWE-798": "A07:2021 – Identification and Authentication Failures",
            "CWE-259": "A07:2021 – Identification and Authentication Failures",
            "CWE-327": "A02:2021 – Cryptographic Failures",
            "CWE-326": "A02:2021 – Cryptographic Failures",
            "CWE-312": "A02:2021 – Cryptographic Failures",
            "CWE-319": "A02:2021 – Cryptographic Failures",
            "CWE-22": "A01:2021 – Broken Access Control",
            "CWE-532": "A09:2021 – Security Logging and Monitoring Failures",
        }
        return cwe_to_owasp.get(cwe)

    def _generate_summary(self, findings: List[ParsedFinding], data: Dict) -> str:
        """Generate executive summary."""
        if not findings:
            return "Semgrep Analysis: No security issues detected."

        stats = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        }

        # Count errors
        errors = data.get("errors", [])
        error_count = len(errors)

        lines = [
            "Semgrep SAST Analysis Summary",
            f"Total Findings: {stats['total']}",
            f"  Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}",
        ]

        if error_count > 0:
            lines.append(f"Parse Errors: {error_count}")

        # Top files with issues
        file_counts: Dict[str, int] = {}
        for f in findings:
            path = f.file_path or "unknown"
            file_counts[path] = file_counts.get(path, 0) + 1

        top_files = sorted(file_counts.items(), key=lambda x: -x[1])[:5]
        if top_files:
            lines.extend(["", "Files with Most Issues:"])
            for path, count in top_files:
                lines.append(f"  • {path}: {count} findings")

        # Top CWEs
        cwe_counts: Dict[str, int] = {}
        for f in findings:
            if f.cwe_id:
                cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1

        top_cwes = sorted(cwe_counts.items(), key=lambda x: -x[1])[:3]
        if top_cwes:
            lines.extend(["", "Top CWEs:"])
            for cwe, count in top_cwes:
                lines.append(f"  • {cwe}: {count} findings")

        return "\n".join(lines)
