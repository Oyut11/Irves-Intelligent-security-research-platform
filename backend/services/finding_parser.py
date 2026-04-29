import json
from typing import List
from collections import defaultdict
from database.models import FindingSeverity
from models.finding import FindingCreate
from services.tool_runner import ToolResult

def deduplicate_findings(findings: List[FindingCreate]) -> List[FindingCreate]:
    """Deduplicate findings by title + category, collapsing affected files."""
    if not findings:
        return []
    
    grouped = defaultdict(lambda: {"locations": [], "severities": set(), "first": None})
    
    for f in findings:
        key = (f.title, f.category)
        grouped[key]["locations"].append(f.location or "")
        grouped[key]["severities"].add(f.severity)
        # Keep the first finding as the base
        if grouped[key]["first"] is None:
            grouped[key]["first"] = f
    
    unique = []
    for (title, category), group in grouped.items():
        base = group["first"]
        # Use the highest severity
        severity_order = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        highest_sev = max(group["severities"], key=lambda s: severity_order.get(s, 0))
        
        # Collapse locations into a comma-separated list
        unique_locations = list(set(group["locations"]))
        locations_str = ", ".join(unique_locations[:3])
        if len(unique_locations) > 3:
            locations_str += f" (+{len(unique_locations) - 3} more)"
        
        # Create a new finding with collapsed data
        base.location = locations_str
        base.severity = highest_sev
        base.description = f"{base.description or ''} Affected files: {len(unique_locations)}"
        unique.append(base)
    
    return unique

async def parse_tool_output(tool_name: str, result: ToolResult) -> List[FindingCreate]:
    """Parse tool output into standardized findings."""
    parsers = {
        "jadx": parse_jadx,
        "apktool": parse_apktool,
        "frida": parse_frida,
        "mitmproxy": parse_mitmproxy,
    }
    
    parser = parsers.get(tool_name)
    if not parser:
        return []
    
    findings = await parser(result)
    
    # Deduplicate findings at parser level
    return deduplicate_findings(findings)


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
