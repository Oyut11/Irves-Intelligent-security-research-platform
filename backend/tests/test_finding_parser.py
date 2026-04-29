"""
IRVES — Unit Tests for Finding Parser
Tests severity mapping and tool output parsing (pure logic, no DB required).
"""

import pytest
from pathlib import Path

from database.models import FindingSeverity
from models.finding import FindingCreate
from services.tool_runner import ToolResult
from services.finding_parser import (
    parse_jadx,
    parse_apktool,
    parse_frida,
    parse_mitmproxy,
    parse_tool_output,
)


# ── JADX Parser ──────────────────────────────────────────────────────────────

class TestParseJadx:
    @pytest.mark.asyncio
    async def test_no_errors(self):
        result = ToolResult(success=True, output="ok", error="", duration_ms=0)
        findings = await parse_jadx(result)
        assert findings == []

    @pytest.mark.asyncio
    async def test_error_lines(self):
        result = ToolResult(success=True, output="", error="ERROR: bad code\nWARN: something\ninfo: normal", duration_ms=0)
        findings = await parse_jadx(result)
        assert len(findings) == 2  # ERROR + WARN
        assert all(f.tool == "jadx" for f in findings)

    @pytest.mark.asyncio
    async def test_limit_10(self):
        lines = "\n".join([f"ERROR: issue {i}" for i in range(20)])
        result = ToolResult(success=True, output="", error=lines, duration_ms=0)
        findings = await parse_jadx(result)
        assert len(findings) == 10


# ── APKTool Parser ───────────────────────────────────────────────────────────

class TestParseApktool:
    @pytest.mark.asyncio
    async def test_warning_and_error_lines(self):
        result = ToolResult(success=True, output="", error="warning: bad resource\nerror: missing file\ninfo: normal", duration_ms=0)
        findings = await parse_apktool(result)
        assert len(findings) == 2  # warning + error
        assert all(f.tool == "apktool" for f in findings)

    @pytest.mark.asyncio
    async def test_limit_10(self):
        lines = "\n".join([f"warning: issue {i}" for i in range(20)])
        result = ToolResult(success=True, output="", error=lines, duration_ms=0)
        findings = await parse_apktool(result)
        assert len(findings) == 10


# ── Frida Parser ─────────────────────────────────────────────────────────────

class TestParseFrida:
    @pytest.mark.asyncio
    async def test_finding_json_lines(self):
        import json
        line = json.dumps({"type": "finding", "title": "Root Detection Bypassed", "description": "App detected root"})
        result = ToolResult(success=True, output=line, error="", duration_ms=0)
        findings = await parse_frida(result)
        assert len(findings) == 1
        assert findings[0].title == "Root Detection Bypassed"
        assert findings[0].severity == FindingSeverity.HIGH

    @pytest.mark.asyncio
    async def test_non_finding_json_ignored(self):
        import json
        line = json.dumps({"type": "message", "payload": "hello"})
        result = ToolResult(success=True, output=line, error="", duration_ms=0)
        findings = await parse_frida(result)
        assert findings == []

    @pytest.mark.asyncio
    async def test_non_json_lines_ignored(self):
        result = ToolResult(success=True, output="plain text line", error="", duration_ms=0)
        findings = await parse_frida(result)
        assert findings == []


# ── Mitmproxy Parser ─────────────────────────────────────────────────────────

class TestParseMitmproxy:
    @pytest.mark.asyncio
    async def test_sensitive_data(self):
        result = ToolResult(success=True, output="[IRVES] SENSITIVE: API key found in request", error="", duration_ms=0)
        findings = await parse_mitmproxy(result)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[0].tool == "mitmproxy"

    @pytest.mark.asyncio
    async def test_normal_traffic_ignored(self):
        result = ToolResult(success=True, output="GET /api/data 200 OK", error="", duration_ms=0)
        findings = await parse_mitmproxy(result)
        assert findings == []


# ── Dispatch ─────────────────────────────────────────────────────────────────

class TestParseToolOutput:
    @pytest.mark.asyncio
    async def test_unknown_tool_returns_empty(self):
        result = ToolResult(success=True, output="", error="", duration_ms=0)
        findings = await parse_tool_output("unknown_tool", result)
        assert findings == []

