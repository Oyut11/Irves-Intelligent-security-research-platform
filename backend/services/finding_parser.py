import json
from typing import List
from database.models import FindingSeverity
from models.finding import FindingCreate
from services.tool_runner import ToolResult

async def parse_tool_output(tool_name: str, result: ToolResult) -> List[FindingCreate]:
    """Parse tool output into standardized findings."""
    parsers = {
        "mobsf": parse_mobsf,
        "jadx": parse_jadx,
        "apktool": parse_apktool,
        "frida": parse_frida,
        "mitmproxy": parse_mitmproxy,
    }
    
    parser = parsers.get(tool_name)
    if not parser:
        return []
    
    return await parser(result)


async def parse_mobsf(result: ToolResult) -> List[FindingCreate]:
    """Parse MobSF JSON report."""
    findings = []
    
    try:
        if not result.output:
            return findings
            
        report = json.loads(result.output)
        
        # Security findings
        for issue in report.get("security", []):
            findings.append(FindingCreate(
                scan_id="tmp",  # This will be replaced during creation
                title=issue.get("title", "Unknown issue"),
                severity=map_mobsf_severity(issue.get("severity", "info")),
                category=issue.get("category", "General"),
                location=issue.get("file", ""),
                description=issue.get("description", ""),
                tool="mobsf",
                owasp_mapping=issue.get("owasp", "")
            ))
        
        # Manifest issues
        for issue in report.get("manifest_analysis", []):
            findings.append(FindingCreate(
                scan_id="tmp",
                title=issue.get("title", "Manifest issue"),
                severity=map_mobsf_severity(issue.get("severity", "medium")),
                category="Android Manifest",
                location="AndroidManifest.xml",
                description=issue.get("description", ""),
                tool="mobsf"
            ))
    
    except json.JSONDecodeError:
        pass
    except Exception:
        pass
    
    return findings


def map_mobsf_severity(severity: str) -> FindingSeverity:
    """Map MobSF severity to IRVES severity."""
    severity = str(severity).lower()
    mapping = {
        "high": FindingSeverity.CRITICAL,
        "critical": FindingSeverity.CRITICAL,
        "warning": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "secure": FindingSeverity.LOW,
        "info": FindingSeverity.INFO
    }
    return mapping.get(severity, FindingSeverity.MEDIUM)


async def parse_jadx(result: ToolResult) -> List[FindingCreate]:
    """Parse JADX findings (e.g., bad code errors during decompilation)."""
    findings = []
    if result.error:
        for line in result.error.splitlines():
            line_upper = line.upper()
            if "ERROR" in line_upper or "WARN" in line_upper:
                findings.append(FindingCreate(
                    scan_id="tmp",
                    title="Decompilation Issue",
                    severity=FindingSeverity.INFO,
                    tool="jadx",
                    category="Decompilation",
                    description=line.strip()
                ))
    return findings[:10]  # Limit to avoid spam


async def parse_apktool(result: ToolResult) -> List[FindingCreate]:
    """Parse APKTool issues."""
    findings = []
    if result.error:
        for line in result.error.splitlines():
            line_lower = line.lower()
            if "warning" in line_lower or "error" in line_lower:
                findings.append(FindingCreate(
                    scan_id="tmp",
                    title="APKTool Notice",
                    severity=FindingSeverity.INFO,
                    tool="apktool",
                    category="Unpack",
                    description=line.strip()
                ))
    return findings[:10]


async def parse_frida(result: ToolResult) -> List[FindingCreate]:
    """Parse runtime findings from Frida."""
    findings = []
    try:
        if result.output:
            for line in result.output.splitlines():
                if line.startswith("{") and line.endswith("}"):
                    try:
                        data = json.loads(line)
                        if data.get("type") == "finding":
                            findings.append(FindingCreate(
                                scan_id="tmp",
                                title=data.get("title", "Runtime Finding"),
                                severity=FindingSeverity.HIGH,
                                tool="frida",
                                description=data.get("description", ""),
                                category="Runtime Hook",
                            ))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return findings


async def parse_mitmproxy(result: ToolResult) -> List[FindingCreate]:
    """Parse runtime findings from mitmproxy flows."""
    findings = []
    try:
        if result.output:
            for line in result.output.splitlines():
                if "[IRVES] SENSITIVE" in line:
                    findings.append(FindingCreate(
                        scan_id="tmp",
                        title="Sensitive Data in Traffic",
                        severity=FindingSeverity.HIGH,
                        tool="mitmproxy",
                        category="Network",
                        description=line.strip()
                    ))
    except Exception:
        pass
    return findings
