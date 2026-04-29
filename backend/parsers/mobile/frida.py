"""
IRVES — Frida Parser
Parses Frida runtime hook output into standardized findings.

Extracts:
- Cryptographic keys (AES, DES, RSA)
- API keys and tokens
- JWT tokens
- Sensitive data (credit cards, emails)
- SSL/TLS certificates
- Runtime method traces
"""

import json
import re
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
class FridaParser(ToolOutputParser):
    """
    Parser for Frida runtime hook output.

    Extracts runtime findings from Frida scripts including:
    - Cryptographic operations and keys
    - API credentials in transit
    - JWT tokens
    - Sensitive data exposure
    - SSL/TLS certificate details

    Designed to condense verbose Frida logs into structured findings.
    """

    # Regex patterns for finding extraction
    PATTERNS = {
        # Crypto keys
        "aes_key": re.compile(r"AES[_\s]?[Kk]ey[:\s=]+([A-Fa-f0-9]{16,64})", re.IGNORECASE),
        "des_key": re.compile(r"DES[_\s]?[Kk]ey[:\s=]+([A-Fa-f0-9]{16})", re.IGNORECASE),
        "rsa_key": re.compile(r"RSA[_\s]?(?:Private|Public)[_\s]?[Kk]ey", re.IGNORECASE),
        "crypto_key": re.compile(r"(?:Secret)?[Kk]ey[:\s=]+['\"]?([A-Za-z0-9+/=]{16,})", re.IGNORECASE),

        # API Keys
        "api_key_generic": re.compile(r"(?i)(?:api[_\-]?key|apikey)[:\s=]+['\"]?([A-Za-z0-9_\-]{16,})"),
        "aws_key": re.compile(r"(?i)(AKIA[0-9A-Z]{16})"),
        "google_api": re.compile(r"(?i)(AIza[0-9A-Za-z_\-]{35})"),
        "firebase": re.compile(r"(?i)(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})"),
        "slack_token": re.compile(r"(?i)(xox[baprs]-[0-9a-zA-Z]{10,48})"),
        "github_token": re.compile(r"(?i)(ghp_[0-9a-zA-Z]{36})"),
        "stripe_key": re.compile(r"(?i)(sk_live_[0-9a-zA-Z]{24,})"),

        # JWT Tokens
        "jwt": re.compile(r"eyJ[A-Za-z0-9_/+-]*\.eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9._/+-]*"),

        # Bearer tokens
        "bearer_token": re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})"),

        # Sensitive data
        "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b"),

        # Passwords
        "password": re.compile(r"(?i)(?:password|passwd|pwd)[:\s=]+['\"]?([^'\"\s]{4,})"),

        # Certificate pins
        "certificate_pin": re.compile(r"(?i)Certificate[_\s]?[Pp]in[:\s=]+([A-Fa-f0-9]{64})"),
    }

    @property
    def tool_name(self) -> str:
        return "frida"

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="FridaParser",
            version="1.0.0",
            supported_tools=["frida"],
            description="Parses Frida runtime hook output for crypto keys, API keys, and sensitive data",
            platforms=["android", "ios"],
            output_formats=["json", "txt"],
        )

    def can_parse(self, raw_output: Union[str, Dict, Path]) -> bool:
        """Check if input looks like Frida output."""
        try:
            if isinstance(raw_output, Path):
                content = Path(raw_output).read_text(errors="replace")[:2000]
            elif isinstance(raw_output, str):
                content = raw_output[:2000]
            else:
                # Check if it's a Frida JSON structure
                return isinstance(raw_output, dict) and "type" in raw_output

            # Check for Frida-specific markers
            frida_markers = [
                "[+]",
                "[-]",
                "[*]",
                "Frida",
                "Java.perform",
                "Interceptor.attach",
            ]
            return any(marker in content for marker in frida_markers)
        except Exception:
            return False

    def parse(self, raw_output: Union[str, Dict, Path]) -> ParsedOutput:
        """
        Parse Frida output into standardized findings.

        Args:
            raw_output: Frida log string, JSON dict, or file path

        Returns:
            ParsedOutput with extracted findings
        """
        # Load content
        if isinstance(raw_output, Path):
            content = Path(raw_output).read_text(encoding="utf-8", errors="replace")
            data = None
        elif isinstance(raw_output, str):
            content = raw_output
            data = None
        else:
            content = json.dumps(raw_output)
            data = raw_output

        findings: List[ParsedFinding] = []

        # Parse JSON format (structured Frida output)
        if data:
            json_findings = self._parse_json_output(data)
            findings.extend(json_findings)
        elif self._looks_like_json(content):
            try:
                json_data = json.loads(content)
                json_findings = self._parse_json_output(json_data)
                findings.extend(json_findings)
            except json.JSONDecodeError:
                # Not valid JSON, continue to text parsing
                pass

        # Parse text format (console output)
        text_findings = self._parse_text_output(content)
        findings.extend(text_findings)

        # Deduplicate findings (same key/extracted value)
        findings = self._deduplicate(findings)

        # Generate summary
        summary = self._generate_summary(findings)

        return ParsedOutput(
            findings=findings,
            tool_name=self.tool_name,
            summary=summary,
        )

    def _looks_like_json(self, content: str) -> bool:
        """Check if content appears to be JSON."""
        stripped = content.strip()
        return stripped.startswith("{") or stripped.startswith("[")

    def _parse_json_output(self, data: Union[Dict, List]) -> List[ParsedFinding]:
        """Parse structured JSON output from Frida scripts."""
        findings = []

        if isinstance(data, dict):
            # Single finding
            if data.get("type") == "finding":
                findings.append(self._convert_json_finding(data))
            # Nested findings
            elif "findings" in data:
                for item in data["findings"]:
                    if isinstance(item, dict):
                        findings.append(self._convert_json_finding(item))
            # Crypto key extraction
            elif "algorithm" in data and "key" in data:
                findings.append(self._convert_crypto_finding(data))

        elif isinstance(data, list):
            # Array of findings
            for item in data:
                if isinstance(item, dict):
                    findings.extend(self._parse_json_output(item))

        return findings

    def _convert_json_finding(self, data: Dict) -> ParsedFinding:
        """Convert JSON finding to ParsedFinding."""
        return ParsedFinding(
            title=data.get("title", "Runtime Finding"),
            severity=self._extract_severity(data.get("severity", "medium")),
            category=data.get("category", "Runtime Analysis"),
            description=data.get("description", ""),
            file_path=data.get("file"),
            line_number=data.get("line"),
            evidence=json.dumps(data.get("data", {}))[:200],
            tool=self.tool_name,
            confidence=Confidence.HIGH,
            metadata={"hook_type": data.get("type", "unknown")},
        )

    def _convert_crypto_finding(self, data: Dict) -> ParsedFinding:
        """Convert crypto extraction finding."""
        algorithm = data.get("algorithm", "Unknown")
        key = data.get("key", "")
        operation = data.get("operation", "used")

        # Mask the key for display (security)
        masked_key = key[:4] + "****" + key[-4:] if len(key) > 8 else "****"

        return ParsedFinding(
            title=f"Runtime: {algorithm} Key {operation.title()}",
            severity=Severity.CRITICAL,
            category="Cryptography",
            description=f"{algorithm} cryptographic key was {operation} at runtime. Key (masked): {masked_key}",
            evidence=f"Algorithm: {algorithm}\nKey: {masked_key}",
            tool=self.tool_name,
            confidence=Confidence.CERTAIN,
            remediation="Ensure keys are generated securely and not exposed in logs or memory.",
            metadata={"algorithm": algorithm, "operation": operation},
        )

    def _parse_text_output(self, content: str) -> List[ParsedFinding]:
        """Parse text-based Frida console output."""
        findings = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Extract findings from each line
            for finding in self._extract_from_line(line):
                if finding:
                    findings.append(finding)

        return findings

    def _extract_from_line(self, line: str) -> List[ParsedFinding]:
        """Extract findings from a single log line."""
        findings = []

        # Check each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            for match in pattern.finditer(line):
                finding = self._create_finding_from_match(pattern_name, match, line)
                if finding:
                    findings.append(finding)

        return findings

    def _create_finding_from_match(
        self, pattern_name: str, match: re.Match, context: str
    ) -> Optional[ParsedFinding]:
        """Create a ParsedFinding from a regex match."""
        matched_value = match.group(0)

        # Skip if it's a common false positive
        if self._is_false_positive(pattern_name, matched_value):
            return None

        # Determine severity and category based on pattern
        severity, category, title, description = self._classify_finding(
            pattern_name, matched_value, context
        )

        return ParsedFinding(
            title=title,
            severity=severity,
            category=category,
            description=description,
            evidence=self._truncate(matched_value, 100),
            context=self._truncate(context, 200),
            tool=self.tool_name,
            confidence=Confidence.HIGH,
            metadata={"pattern": pattern_name, "match": matched_value[:50]},
        )

    def _is_false_positive(self, pattern_name: str, value: str) -> bool:
        """Check if a match is likely a false positive."""
        # Skip example/placeholder values
        placeholders = [
            "example", "sample", "test", "dummy", "placeholder",
            "your_key_here", "xxx", "***", "null", "undefined",
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)

    def _classify_finding(
        self, pattern_name: str, value: str, context: str
    ) -> tuple[Severity, str, str, str]:
        """Classify finding based on pattern type."""
        classifications = {
            "aes_key": (
                Severity.CRITICAL,
                "Cryptography",
                "Runtime: AES Key Extracted",
                "AES encryption key was extracted from memory during runtime execution.",
            ),
            "des_key": (
                Severity.CRITICAL,
                "Cryptography",
                "Runtime: DES Key Extracted",
                "DES encryption key was extracted from memory. DES is considered weak cryptography.",
            ),
            "rsa_key": (
                Severity.CRITICAL,
                "Cryptography",
                "Runtime: RSA Key Operation",
                "RSA key operation detected in runtime.",
            ),
            "aws_key": (
                Severity.CRITICAL,
                "Secrets",
                "Runtime: AWS Access Key Detected",
                "AWS access key was observed in runtime memory/network traffic.",
            ),
            "google_api": (
                Severity.HIGH,
                "Secrets",
                "Runtime: Google API Key Detected",
                "Google API key was extracted from memory or network requests.",
            ),
            "firebase": (
                Severity.HIGH,
                "Secrets",
                "Runtime: Firebase Token Detected",
                "Firebase authentication token was extracted.",
            ),
            "slack_token": (
                Severity.CRITICAL,
                "Secrets",
                "Runtime: Slack Token Detected",
                "Slack API token was observed in runtime.",
            ),
            "github_token": (
                Severity.CRITICAL,
                "Secrets",
                "Runtime: GitHub Token Detected",
                "GitHub personal access token was extracted.",
            ),
            "stripe_key": (
                Severity.CRITICAL,
                "Secrets",
                "Runtime: Stripe API Key Detected",
                "Stripe API key was detected in runtime memory. This is a critical financial secret.",
            ),
            "jwt": (
                Severity.HIGH,
                "Authentication",
                "Runtime: JWT Token Detected",
                "JSON Web Token was extracted from runtime. Token may contain claims and signatures.",
            ),
            "bearer_token": (
                Severity.HIGH,
                "Authentication",
                "Runtime: Bearer Token Detected",
                "Bearer authentication token was observed in runtime.",
            ),
            "password": (
                Severity.CRITICAL,
                "Secrets",
                "Runtime: Password Detected",
                "Plaintext password was observed in runtime memory or network traffic.",
            ),
            "credit_card": (
                Severity.CRITICAL,
                "Sensitive Data",
                "Runtime: Credit Card Number Detected",
                "Credit card number pattern detected in runtime data. PCI-DSS violation.",
            ),
            "email": (
                Severity.MEDIUM,
                "Sensitive Data",
                "Runtime: Email Address Detected",
                "Email address pattern found in runtime data.",
            ),
            "certificate_pin": (
                Severity.HIGH,
                "Cryptography",
                "Runtime: Certificate Pin Observed",
                "SSL/TLS certificate pinning hash was observed in runtime.",
            ),
        }

        return classifications.get(
            pattern_name,
            (
                Severity.MEDIUM,
                "Runtime Analysis",
                f"Runtime: {pattern_name.replace('_', ' ').title()}",
                f"Pattern '{pattern_name}' matched in runtime output.",
            ),
        )

    def _deduplicate(self, findings: List[ParsedFinding]) -> List[ParsedFinding]:
        """Remove duplicate findings based on evidence content."""
        seen = set()
        unique = []

        for finding in findings:
            # Create deduplication key
            key = f"{finding.title}:{finding.evidence[:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _generate_summary(self, findings: List[ParsedFinding]) -> str:
        """Generate executive summary."""
        if not findings:
            return "Frida Analysis: No runtime findings detected."

        stats = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        }

        # Group by category
        categories: Dict[str, int] = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1

        lines = [
            "Frida Runtime Analysis Summary",
            f"Total Findings: {stats['total']}",
            f"  Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']}",
            "",
            "Findings by Category:",
        ]

        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"  • {cat}: {count}")

        # Add top critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            lines.extend(["", "Critical Findings:"])
            for f in critical_findings[:3]:
                lines.append(f"  • {f.title}")

        return "\n".join(lines)
