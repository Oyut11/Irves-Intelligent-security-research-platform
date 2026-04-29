"""
IRVES — GitLeaks Parser
Parses GitLeaks secrets scanning output into standardized findings.

Supports:
- GitLeaks JSON format
- Secrets detection in code
- Git history scanning
- Multiple secret types (API keys, tokens, passwords)
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
class GitLeaksParser(ToolOutputParser):
    """
    Parser for GitLeaks secrets scanner output.

    Extracts secrets from:
    - Source code files
    - Git commit history
    - Configuration files

    Detects:
    - API keys (AWS, Google, GitHub, Slack, etc.)
    - Database connection strings
    - Private keys
    - Passwords and tokens
    - High-entropy strings

    All secrets are marked as CRITICAL severity.
    """

    # Secret type classifications
    SECRET_TYPES = {
        # Cloud providers
        "aws": "AWS Credential",
        "azure": "Azure Credential",
        "gcp": "Google Cloud Credential",
        "firebase": "Firebase Token",

        # Version control
        "github": "GitHub Token",
        "gitlab": "GitLab Token",
        "bitbucket": "Bitbucket Token",

        # Communication
        "slack": "Slack Token",
        "discord": "Discord Token",
        "telegram": "Telegram Bot Token",

        # Payment
        "stripe": "Stripe API Key",
        "paypal": "PayPal Credential",
        "square": "Square Access Token",

        # Database
        "postgres": "PostgreSQL Connection String",
        "mysql": "MySQL Connection String",
        "mongodb": "MongoDB Connection String",
        "redis": "Redis Connection String",
        "jdbc": "JDBC Connection String",

        # Authentication
        "jwt": "JWT Token",
        "oauth": "OAuth Token",
        "bearer": "Bearer Token",
        "api_key": "API Key",
        "private_key": "Private Key",
        "secret_key": "Secret Key",

        # Generic
        "generic": "Generic Secret",
        "password": "Hardcoded Password",
        "secret": "Hardcoded Secret",
    }

    @property
    def tool_name(self) -> str:
        return "gitleaks"

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="GitLeaksParser",
            version="1.0.0",
            supported_tools=["gitleaks"],
            description="Parses GitLeaks secrets scanning output",
            platforms=["repository"],
            output_formats=["json"],
        )

    def can_parse(self, raw_output: Union[str, Dict, Path]) -> bool:
        """Check if input looks like GitLeaks JSON."""
        try:
            if isinstance(raw_output, Path):
                content = Path(raw_output).read_text(errors="replace")[:1000]
                data = json.loads(content)
            elif isinstance(raw_output, str):
                data = json.loads(raw_output[:1000])
            else:
                data = raw_output

            # Check for GitLeaks-specific structure
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                gitleaks_keys = ["Description", "Match", "Secret", "File", "RuleID"]
                return any(key in first for key in gitleaks_keys)

            return False
        except Exception:
            return False

    def parse(self, raw_output: Union[str, Dict, Path]) -> ParsedOutput:
        """
        Parse GitLeaks JSON output.

        Args:
            raw_output: JSON string, dict, or file path

        Returns:
            ParsedOutput with extracted secrets
        """
        # Load JSON
        if isinstance(raw_output, Path):
            data = json.loads(Path(raw_output).read_text(encoding="utf-8", errors="replace"))
        elif isinstance(raw_output, str):
            data = json.loads(raw_output)
        else:
            data = raw_output

        findings = []

        # GitLeaks returns an array of findings
        if isinstance(data, list):
            for item in data:
                finding = self._convert_finding(item)
                if finding:
                    findings.append(finding)
        elif isinstance(data, dict):
            # Single finding
            finding = self._convert_finding(data)
            if finding:
                findings.append(finding)

        # Deduplicate secrets (same secret value found in multiple places)
        findings = self._deduplicate(findings)

        summary = self._generate_summary(findings)

        return ParsedOutput(
            findings=findings,
            tool_name=self.tool_name,
            summary=summary,
        )

    def _convert_finding(self, data: Dict) -> Optional[ParsedFinding]:
        """Convert GitLeaks finding to ParsedFinding."""
        # Extract fields (GitLeaks uses various field names)
        description = data.get("Description", data.get("description", "Unknown Secret"))
        match = data.get("Match", data.get("match", ""))
        secret = data.get("Secret", data.get("secret", match))
        file_path = data.get("File", data.get("file", ""))
        rule_id = data.get("RuleID", data.get("ruleId", data.get("rule_id", "unknown")))

        # Location info
        line = data.get("StartLine", data.get("startLine", data.get("line", 0)))
        column = data.get("StartColumn", data.get("startColumn", 0))

        # Git commit info (if scanning history)
        commit = data.get("Commit", data.get("commit", ""))
        author = data.get("Author", data.get("author", ""))
        email = data.get("Email", data.get("email", ""))
        date = data.get("Date", data.get("date", ""))

        # Fingerprint for deduplication
        fingerprint = data.get("Fingerprint", "")

        # Mask the secret for display (security)
        masked_secret = self._mask_secret(secret)

        # Classify secret type
        secret_type = self._classify_secret_type(rule_id, description)

        # Build context
        context_parts = []
        if commit:
            context_parts.append(f"Commit: {commit[:8]}")
        if author:
            context_parts.append(f"Author: {author}")
        if email:
            context_parts.append(f"Email: {email}")
        if date:
            context_parts.append(f"Date: {date}")

        context = " | ".join(context_parts) if context_parts else ""

        # Determine if it's from git history or current code
        is_historical = bool(commit)
        location_type = "Git History" if is_historical else "Source Code"

        return ParsedFinding(
            title=f"Secret: {secret_type}",
            severity=Severity.CRITICAL,  # All secrets are critical
            category="Secrets",
            description=f"{description} detected in {location_type}. This is a critical security issue as the secret may be exposed to anyone with access to the repository.",
            file_path=file_path,
            line_number=line if isinstance(line, int) else 0,
            column=column if isinstance(column, int) else 0,
            evidence=f"Masked: {masked_secret}",
            context=context,
            cwe_id="798",  # Use of Hard-coded Credentials
            owasp_category="A07:2021 – Identification and Authentication Failures",
            tool=self.tool_name,
            confidence=Confidence.CERTAIN,
            remediation=self._get_remediation(rule_id, is_historical),
            metadata={
                "rule_id": rule_id,
                "secret_type": secret_type,
                "is_historical": is_historical,
                "fingerprint": fingerprint,
                "commit": commit,
                "match_length": len(match) if match else 0,
            },
        )

    def _mask_secret(self, secret: str) -> str:
        """Mask secret for safe display."""
        if len(secret) <= 8:
            return "****"
        return secret[:4] + "****" + secret[-4:]

    def _classify_secret_type(self, rule_id: str, description: str) -> str:
        """Classify the type of secret."""
        text = f"{rule_id} {description}".lower()

        for key, name in self.SECRET_TYPES.items():
            if key in text:
                return name

        # Default classification based on description
        if "api" in text and "key" in text:
            return "API Key"
        if "token" in text:
            return "Access Token"
        if "password" in text:
            return "Password"
        if "private" in text and "key" in text:
            return "Private Key"
        if "secret" in text:
            return "Generic Secret"

        return "Unknown Secret"

    def _get_remediation(self, rule_id: str, is_historical: bool) -> str:
        """Get remediation guidance."""
        base_remediation = (
            "1. Immediately revoke/rotate the exposed credential\n"
            "2. Remove the secret from the codebase\n"
            "3. Use environment variables or secure vaults for secrets\n"
            "4. Add the secret pattern to .gitignore or use git-secrets\n"
            "5. Scan git history and remove with BFG Repo-Cleaner or git-filter-repo"
        )

        if is_historical:
            return (
                "CRITICAL: Secret found in git history!\n"
                f"{base_remediation}\n"
                "Note: Even after removing from current code, the secret exists in git history. "
                "Use 'git filter-repo' or BFG Repo-Cleaner to permanently remove from history."
            )

        return base_remediation

    def _deduplicate(self, findings: List[ParsedFinding]) -> List[ParsedFinding]:
        """Deduplicate findings based on secret fingerprint or evidence."""
        seen_secrets = set()
        unique = []

        for finding in findings:
            # Use evidence (masked secret) as dedup key
            key = finding.evidence
            if key not in seen_secrets:
                seen_secrets.add(key)
                unique.append(finding)

        return unique

    def _generate_summary(self, findings: List[ParsedFinding]) -> str:
        """Generate executive summary."""
        if not findings:
            return "GitLeaks Analysis: No secrets detected."

        # Count by type
        type_counts: Dict[str, int] = {}
        historical_count = 0
        current_count = 0

        for f in findings:
            secret_type = f.metadata.get("secret_type", "Unknown")
            type_counts[secret_type] = type_counts.get(secret_type, 0) + 1

            if f.metadata.get("is_historical"):
                historical_count += 1
            else:
                current_count += 1

        lines = [
            "GitLeaks Secrets Analysis Summary",
            f"Total Secrets Found: {len(findings)} (CRITICAL)",
            f"  In Current Code: {current_count}",
            f"  In Git History: {historical_count}",
            "",
            "Secrets by Type:",
        ]

        for secret_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  • {secret_type}: {count}")

        # Add urgent notice for historical secrets
        if historical_count > 0:
            lines.extend([
                "",
                "⚠️  URGENT: Secrets found in git history!",
                "These secrets remain accessible in repository history even if removed from current code.",
                "Action required: Use 'git filter-repo' to permanently remove.",
            ])

        return "\n".join(lines)
