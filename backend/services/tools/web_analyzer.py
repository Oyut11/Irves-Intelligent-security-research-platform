"""
IRVES — Web Target Analyzer
Integrates Nuclei (preferred) with a graceful fallback to basic header analysis.
Nuclei enriches results with template-based CVE/misconfiguration detection.
"""

import asyncio
import json
import shutil
import re
import urllib.request
from pathlib import Path
from typing import Optional, Callable, List, Dict
import logging

from services.tool_runner import ToolRunner, ToolResult

logger = logging.getLogger(__name__)

# Passive header checks done on every web target regardless of external tools
HEADER_CHECKS = [
    ("Strict-Transport-Security", "missing", "HSTS Header Missing", "medium", "Network", "CWE-319"),
    ("X-Frame-Options", "missing", "X-Frame-Options Missing (Clickjacking)", "medium", "Web", "CWE-1021"),
    ("X-Content-Type-Options", "missing", "X-Content-Type-Options Missing", "low", "Web", "CWE-693"),
    ("Content-Security-Policy", "missing", "Content Security Policy Missing", "medium", "Web", "CWE-693"),
    ("X-XSS-Protection", "missing", "XSS Protection Header Missing", "low", "Web", "CWE-79"),
    ("Referrer-Policy", "missing", "Referrer-Policy Missing", "low", "Web", "CWE-200"),
    ("Permissions-Policy", "missing", "Permissions-Policy Missing", "info", "Web", "CWE-200"),
]


class WebAnalyzerRunner(ToolRunner):
    """Web target analyzer using Nuclei + passive header analysis."""

    @property
    def name(self) -> str:
        return "web_analyzer"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        # Web targets store URL as the target_path string
        url = str(target) if target else None
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            return ToolResult(
                success=True,
                output=json.dumps({"findings": [], "skipped": "Not a web URL target"}),
                error="", duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "web_analyzer")
        findings: List[Dict] = []

        def progress(msg: str):
            if progress_callback:
                progress_callback(msg)
            logger.info(f"[web_analyzer] {msg}")

        progress(f"Starting web analysis of {url}")

        # 1. Passive header analysis (always runs)
        try:
            progress("Checking HTTP response headers...")
            header_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._check_headers, url
            )
            findings.extend(header_findings)
            progress(f"Header checks: {len(header_findings)} issues")
        except Exception as e:
            progress(f"Header check failed (non-fatal): {e}")

        # 2. Nuclei scan (if installed)
        nuclei_path = shutil.which("nuclei")
        if nuclei_path:
            try:
                progress("Running Nuclei template scan...")
                nuclei_findings = await self._run_nuclei(nuclei_path, url, output_path, progress)
                findings.extend(nuclei_findings)
                progress(f"Nuclei: {len(nuclei_findings)} findings")
            except asyncio.TimeoutError:
                progress("Nuclei scan timed out (non-fatal)")
            except Exception as e:
                progress(f"Nuclei scan failed (non-fatal): {e}")
        else:
            progress("Nuclei not installed — only passive checks performed. Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("title", ""), f.get("location", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        progress(f"Web analysis complete: {len(unique)} findings")
        return ToolResult(
            success=True,
            output=json.dumps({"findings": unique}),
            error="", duration_ms=self._elapsed_ms(),
            artifacts_path=output_path,
            findings_count=len(unique),
        )

    def _check_headers(self, url: str) -> List[Dict]:
        findings = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IRVES Security Scanner"})
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}

                for header, check, title, sev, cat, cwe in HEADER_CHECKS:
                    if header.lower() not in headers:
                        findings.append(self._finding(
                            title, sev, cat,
                            f"Response header '{header}' is not present. This may weaken security posture.",
                            url, cwe=cwe
                        ))

                # Check for server version disclosure
                server = headers.get("server", "")
                if re.search(r"[0-9]+\.[0-9]+", server):
                    findings.append(self._finding(
                        "Server Version Disclosure",
                        "low", "Configuration",
                        f"Server header reveals version information: '{server}'",
                        url, cwe="CWE-200", snippet=server
                    ))

                # HTTP-only check
                if url.startswith("http://"):
                    findings.append(self._finding(
                        "Insecure HTTP Protocol",
                        "high", "Network",
                        f"Target is served over HTTP without TLS.",
                        url, cwe="CWE-319"
                    ))

        except Exception as e:
            findings.append(self._finding(
                "Header Check Failed",
                "info", "Connectivity",
                f"Could not connect to {url}: {e}",
                url
            ))
        return findings

    async def _run_nuclei(self, nuclei_path: str, url: str, output_path: Path, progress) -> List[Dict]:
        findings = []
        results_file = output_path / "nuclei_results.jsonl"

        cmd = [
            nuclei_path,
            "-u", url,
            "-t", "http/exposures/,http/misconfiguration/,http/vulnerabilities/",
            "-severity", "critical,high,medium,low",
            "-o", str(results_file),
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "5",
            "-rate-limit", "30",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            progress(f"Nuclei finished")
        except asyncio.TimeoutError:
            proc.kill()
            raise

        # Parse JSONL output
        if results_file.exists():
            for line in results_file.read_text().splitlines():
                try:
                    result = json.loads(line)
                    sev = result.get("info", {}).get("severity", "info").lower()
                    name = result.get("info", {}).get("name", "Unknown")
                    desc = result.get("info", {}).get("description", "")
                    matched = result.get("matched-at", url)
                    owasp_tags = result.get("info", {}).get("classification", {}).get("owasp-id", [])
                    findings.append(self._finding(
                        name, sev, "Web",
                        desc or f"Nuclei template matched at: {matched}",
                        matched,
                        owasp=", ".join(owasp_tags) if owasp_tags else "",
                        cwe=(result.get("info", {}).get("classification", {}).get("cwe-id", [""]) or [""])[0]
                    ))
                except Exception:
                    pass

        return findings

    def _finding(self, title, severity, category, description, location,
                 owasp="", cwe="", snippet="") -> Dict:
        return {
            "title": title, "severity": severity, "category": category,
            "description": description, "location": location,
            "owasp_mapping": owasp, "cwe_mapping": cwe,
            "code_snippet": snippet, "tool": "web_analyzer",
        }
