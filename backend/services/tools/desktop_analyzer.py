"""
IRVES — Desktop Binary Analyzer
Static analysis of Windows/macOS/Linux executables.
Uses: SHA-256 hashing, strings extraction, PE/ELF header inspection.
Optionally invokes Ghidra headless if available.
"""

import asyncio
import hashlib
import json
import re
import shutil
import struct
from pathlib import Path
from typing import Optional, Callable, List, Dict
import logging

from services.tool_runner import ToolRunner, ToolResult

logger = logging.getLogger(__name__)

# String patterns to look for in extracted strings
BINARY_SECURITY_PATTERNS = [
    (r'(?i)(password|passwd|secret|api_key|api-key)\s*[=:]\s*\S{4,}', "Possible Hardcoded Credential", "high", "Secrets", "CWE-798"),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Hardcoded IP Address", "medium", "Network", "CWE-284"),
    (r'http://[A-Za-z0-9.\-_]+(/|$)', "Cleartext HTTP URL", "medium", "Network", "CWE-319"),
    (r'(?i)(sqlite|mysql|postgresql)://.+', "Hardcoded Database Connection String", "critical", "Secrets", "CWE-798"),
    (r'(?i)eval\(|exec\(|os\.system\(|subprocess\.', "Dynamic Code Execution String", "high", "Code", "CWE-78"),
    (r'(?i)BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY', "Embedded Private Key", "critical", "Secrets", "CWE-321"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Embedded Google API Key", "high", "Secrets", "CWE-798"),
    (r'(?i)(AKIA|AGPA|AROA|ASCA)[A-Z0-9]{16}', "Embedded AWS Access Key", "critical", "Secrets", "CWE-798"),
    (r'(?i)cmd\.exe|powershell\.exe|/bin/sh|/bin/bash', "Shell Invocation Strings", "medium", "Code", "CWE-78"),
    (r'(?i)WinExec|CreateProcess|ShellExecute', "Windows Process Creation API", "medium", "Code", "CWE-78"),
    (r'(?i)VirtualAlloc|VirtualProtect', "Memory Protection Manipulation", "high", "Anti-Tamper", "CWE-693"),
    (r'(?i)IsDebuggerPresent|CheckRemoteDebuggerPresent', "Anti-Debug Detection", "info", "Anti-Tamper", "CWE-693"),
]

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGIC_LE = 0xFEEDFACE
MACHO_MAGIC_64_LE = 0xFEEDFACF
MACHO_MAGIC_BE = 0xCEFAEDFE


def _detect_format(data: bytes) -> str:
    if data[:2] == PE_MAGIC:
        return "PE (Windows)"
    if data[:4] == ELF_MAGIC:
        return "ELF (Linux)"
    if len(data) >= 4:
        magic = struct.unpack("<I", data[:4])[0]
        if magic in (MACHO_MAGIC_LE, MACHO_MAGIC_64_LE, MACHO_MAGIC_BE):
            return "Mach-O (macOS)"
    return "Unknown Binary"


class DesktopAnalyzerRunner(ToolRunner):
    """Static analyzer for desktop executables."""

    @property
    def name(self) -> str:
        return "desktop_analyzer"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        if not target or not target.exists():
            return ToolResult(success=False, output="", error="Target not found", duration_ms=0)

        desktop_exts = {".exe", ".msi", ".dmg", ".deb", ".rpm", ".appimage", ".elf", ".bin", ".out"}
        if target.suffix.lower() not in desktop_exts:
            return ToolResult(
                success=True,
                output=json.dumps({"findings": [], "skipped": f"{target.suffix} not a desktop binary"}),
                error="", duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "desktop_analyzer")
        findings: List[Dict] = []

        def progress(msg: str):
            if progress_callback:
                progress_callback(msg)
            logger.info(f"[desktop_analyzer] {msg}")

        progress(f"Starting desktop binary analysis of {target.name}")

        # 1. File hash & format detection
        try:
            hash_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._analyze_metadata, target, output_path
            )
            findings.extend(hash_findings)
        except Exception as e:
            progress(f"Metadata analysis failed (non-fatal): {e}")

        # 2. Strings extraction + pattern scan
        try:
            progress("Extracting binary strings...")
            string_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._scan_strings, target
            )
            findings.extend(string_findings)
            progress(f"Strings scan: {len(string_findings)} patterns found")
        except Exception as e:
            progress(f"Strings scan failed (non-fatal): {e}")

        # 3. Optional: Ghidra headless analysis
        ghidra_path = shutil.which("analyzeHeadless")
        if ghidra_path:
            try:
                progress("Ghidra headless analysis starting...")
                ghidra_findings = await self._run_ghidra(target, output_path, progress)
                findings.extend(ghidra_findings)
            except Exception as e:
                progress(f"Ghidra analysis skipped: {e}")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("title", ""), f.get("description", "")[:60])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        progress(f"Desktop analysis complete: {len(unique)} findings")
        return ToolResult(
            success=True,
            output=json.dumps({"findings": unique}),
            error="", duration_ms=self._elapsed_ms(),
            artifacts_path=output_path,
            findings_count=len(unique),
        )

    def _analyze_metadata(self, target: Path, output_path: Path) -> List[Dict]:
        findings = []
        data = target.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        file_format = _detect_format(data)
        size_mb = target.stat().st_size / (1024 * 1024)

        # Write metadata file
        meta = {
            "filename": target.name,
            "sha256": sha256,
            "size_bytes": target.stat().st_size,
            "format": file_format,
        }
        (output_path / "metadata.json").write_text(json.dumps(meta, indent=2))

        findings.append(self._finding(
            f"Binary Metadata: {target.name}",
            "info", "Identification",
            f"Format: {file_format} | SHA-256: {sha256[:32]}... | Size: {size_mb:.2f} MB",
            target.name, snippet=sha256,
        ))

        # Flag unusually large binaries
        if size_mb > 50:
            findings.append(self._finding(
                "Oversized Binary",
                "low", "Code",
                f"Binary is {size_mb:.1f} MB which may indicate packed/obfuscated code or embedded resources.",
                target.name,
            ))
        return findings

    def _scan_strings(self, target: Path) -> List[Dict]:
        findings = []
        strings_bin = shutil.which("strings")

        if strings_bin:
            import subprocess
            try:
                result = subprocess.run(
                    [strings_bin, "-n", "8", str(target)],
                    capture_output=True, text=True, timeout=60
                )
                text = result.stdout
            except Exception:
                text = target.read_bytes().decode("utf-8", errors="ignore")
        else:
            text = target.read_bytes().decode("utf-8", errors="ignore")

        for pattern, title, sev, cat, cwe in BINARY_SECURITY_PATTERNS:
            for match in re.finditer(pattern, text):
                context = match.group(0)[:200]
                findings.append(self._finding(
                    title, sev, cat,
                    f"Detected in binary strings: {context}",
                    target.name, cwe=cwe, snippet=context,
                ))

        # Cap at 30 findings per binary
        return findings[:30]

    async def _run_ghidra(self, target: Path, output_path: Path, progress) -> List[Dict]:
        """Run Ghidra headless analyzer if available."""
        ghidra_path = shutil.which("analyzeHeadless")
        if not ghidra_path:
            return []

        project_dir = output_path / "ghidra_project"
        project_dir.mkdir(exist_ok=True)
        cmd = [
            ghidra_path, str(project_dir), "IRVESProject",
            "-import", str(target),
            "-deleteProject",
            "-analysisTimeoutPerFile", "60",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode(errors="ignore")
            progress(f"Ghidra completed: {len(output)} chars output")
            return []  # Could parse Ghidra CSV exports here in future
        except asyncio.TimeoutError:
            proc.kill()
            progress("Ghidra timed out after 120s")
            return []

    def _finding(self, title, severity, category, description,
                 location, owasp="", cwe="", snippet="") -> Dict:
        return {
            "title": title, "severity": severity, "category": category,
            "description": description, "location": location,
            "owasp_mapping": owasp, "cwe_mapping": cwe,
            "code_snippet": snippet, "tool": "desktop_analyzer",
        }
