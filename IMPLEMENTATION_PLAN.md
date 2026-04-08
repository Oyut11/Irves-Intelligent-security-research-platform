# IRVES — Professional Tool Implementation Plan

> Making the security tools run for real.

---

## Current State

| Component | Status |
|-----------|--------|
| 10 Screen Templates | ✅ Complete |
| App Shell (Tauri + FastAPI) | ✅ Complete |
| Design System | ✅ Complete |
| API Endpoint Stubs | ✅ Complete |
| Tool Orchestration | ✅ Complete |
| Real-time Progress | ✅ Complete |
| Finding Storage | ✅ Complete |
| AI Analysis | ✅ Complete |
| Report Generation | ✅ Complete |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Tauri Desktop Shell                      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Routes     │  │   Services   │  │      Models          │   │
│  │  (API层)     │  │  (Business)  │  │   (Data structures)  │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Tool Runner    │  │   Database     │  │   AI Service    │
│  (Subprocess)   │  │   (SQLite)     │  │   (LLM API)     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
        │
        ├──────────┬──────────┬──────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ APKTool │ │  JADX   │ │  MobSF  │ │  Frida  │ │mitmproxy│
   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

---

## Phase 1: Core Infrastructure

**Goal:** Establish the foundation for tool orchestration, data persistence, and real-time communication.

### 1.1 Project Structure Refactor

```
backend/
├── main.py                    # FastAPI app entry (keep minimal)
├── config.py                  # Environment & tool paths config
├── database/
│   ├── __init__.py
│   ├── connection.py          # SQLite async connection
│   ├── models.py              # SQLAlchemy models
│   └── crud.py                # Database operations
├── services/
│   ├── __init__.py
│   ├── scanner.py             # Scan orchestration service
│   ├── tool_runner.py         # Subprocess management
│   ├── finding_parser.py      # Parse tool outputs to findings
│   └── ai_service.py          # LLM integration
├── models/
│   ├── __init__.py
│   ├── scan.py                # Scan Pydantic models
│   ├── finding.py             # Finding Pydantic models
│   └── report.py              # Report Pydantic models
├── routes/
│   ├── scan.py                # Scan endpoints (rewrite)
│   ├── analysis.py            # AI analysis endpoints
│   └── reports.py             # Report endpoints
├── workers/
│   ├── __init__.py
│   └── scan_worker.py         # Background scan execution
├── static/
└── templates/
```

### 1.2 Database Schema (SQLite)

```sql
-- Projects
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,           -- android, ios, desktop, web
    target_path TEXT,                  -- File path or URL
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scans
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(id),
    profile TEXT NOT NULL,             -- full, quick, runtime, custom
    status TEXT DEFAULT 'pending',     -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT
);

-- Findings
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,            -- critical, high, medium, low, info
    category TEXT,                     -- OWASP category
    location TEXT,                     -- File:line reference
    code_snippet TEXT,
    description TEXT,
    tool TEXT,                         -- Which tool found it
    owasp_mapping TEXT,
    status TEXT DEFAULT 'open',        -- open, resolved, ignored
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tool Executions (pipeline tracking)
CREATE TABLE tool_executions (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id),
    tool_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',     -- pending, running, completed, failed
    started_at DATETIME,
    completed_at DATETIME,
    output_path TEXT,
    error_message TEXT,
    metrics JSON                       -- Tool-specific metrics
);

-- Reports
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(id),
    scan_id TEXT REFERENCES scans(id),
    template TEXT NOT NULL,            -- masvs, owasp_top10, sbom, privacy
    format TEXT NOT NULL,              -- pdf, markdown, json, html
    file_path TEXT,
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 1.3 Configuration System

```python
# config.py
from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    # App
    APP_NAME: str = "IRVES"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./irves.db"
    
    # Tool Paths (auto-detect or override)
    APKTOOL_PATH: str = "apktool"
    JADX_PATH: str = "jadx"
    MOBSF_URL: str = "http://127.0.0.1:8000"
    MOBSF_API_KEY: str = ""
    FRIDA_PATH: str = "frida"
    MITMPROXY_PATH: str = "mitmproxy"
    
    # AI
    ANTHROPIC_API_KEY: str = ""
    AI_MODEL: str = "claude-sonnet-4-6"
    
    # Storage
    PROJECTS_DIR: Path = Path.home() / ".irves" / "projects"
    REPORTS_DIR: Path = Path.home() / ".irves" / "reports"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
```

### 1.4 Deliverables

- [x] Create database layer with SQLAlchemy async
- [x] Implement config with environment variables
- [x] Create project/scan/finding Pydantic models
- [x] Add database initialization on startup
- [x] Create `.env.example` template

---

## Phase 2: Tool Runner Architecture

**Goal:** Reliable subprocess management for security tools.

### 2.1 Tool Runner Base Class

```python
# services/tool_runner.py
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Callable
from pathlib import Path
import uuid

@dataclass
class ToolResult:
    success: bool
    output: str
    error: str
    duration_ms: int
    artifacts_path: Optional[Path] = None

class ToolRunner(ABC):
    """Base class for all security tool runners."""
    
    def __init__(self):
        self.process: Optional[asyncio.subprocess.Process] = None
        self.cancelled = False
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name for logging."""
        pass
    
    @abstractmethod
    async def run(self, target: Path, output_dir: Path, 
                  progress_callback: Optional[Callable[[str], None]] = None) -> ToolResult:
        """Execute the tool."""
        pass
    
    async def cancel(self):
        """Gracefully cancel the running process."""
        self.cancelled = True
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
    
    async def _run_command(self, cmd: list[str], cwd: Path, 
                           progress_callback: Optional[Callable[[str], None]] = None) -> tuple[str, str]:
        """Execute command and capture output."""
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout_chunks = []
        stderr_chunks = []
        
        async def read_stream(stream, chunks, callback):
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                chunks.append(decoded)
                if callback:
                    callback(decoded)
        
        await asyncio.gather(
            read_stream(self.process.stdout, stdout_chunks, progress_callback),
            read_stream(self.process.stderr, stderr_chunks, progress_callback)
        )
        
        await self.process.wait()
        return '\n'.join(stdout_chunks), '\n'.join(stderr_chunks)
```

### 2.2 Individual Tool Implementations

```python
# services/tools/apktool.py
from services.tool_runner import ToolRunner, ToolResult
from pathlib import Path
import time

class APKToolRunner(ToolRunner):
    """APKTool: Decompile APK to smali + manifest."""
    
    @property
    def name(self) -> str:
        return "APKTool"
    
    async def run(self, target: Path, output_dir: Path, 
                  progress_callback=None) -> ToolResult:
        start = time.time()
        
        cmd = [
            settings.APKTOOL_PATH,
            "d", str(target),
            "-o", str(output_dir / "apktool"),
            "-f",  # Force overwrite
            "-r"   # Don't decode resources (faster)
        ]
        
        stdout, stderr = await self._run_command(cmd, output_dir, progress_callback)
        
        return ToolResult(
            success=self.process.returncode == 0,
            output=stdout,
            error=stderr,
            duration_ms=int((time.time() - start) * 1000),
            artifacts_path=output_dir / "apktool"
        )


# services/tools/jadx.py
class JADXRunner(ToolRunner):
    """JADX: Decompile APK to readable Java."""
    
    @property
    def name(self) -> str:
        return "JADX"
    
    async def run(self, target: Path, output_dir: Path,
                  progress_callback=None) -> ToolResult:
        start = time.time()
        
        cmd = [
            settings.JADX_PATH,
            "-d", str(output_dir / "jadx"),
            "--show-bad-code",
            "--no-res",  # Skip resources (faster)
            str(target)
        ]
        
        stdout, stderr = await self._run_command(cmd, output_dir, progress_callback)
        
        return ToolResult(
            success=self.process.returncode == 0,
            output=stdout,
            error=stderr,
            duration_ms=int((time.time() - start) * 1000),
            artifacts_path=output_dir / "jadx"
        )


# services/tools/mobsf.py
class MobSFRunner(ToolRunner):
    """MobSF: Static analysis via API."""
    
    @property
    def name(self) -> str:
        return "MobSF"
    
    async def run(self, target: Path, output_dir: Path,
                  progress_callback=None) -> ToolResult:
        import httpx
        start = time.time()
        
        async with httpx.AsyncClient() as client:
            # Upload APK
            if progress_callback:
                progress_callback("Uploading to MobSF...")
            
            with open(target, 'rb') as f:
                upload_resp = await client.post(
                    f"{settings.MOBSF_URL}/api/v1/upload",
                    files={'file': f},
                    headers={'Authorization': settings.MOBSF_API_KEY}
                )
            
            if upload_resp.status_code != 200:
                return ToolResult(success=False, output="", error="Upload failed", duration_ms=0)
            
            scan_hash = upload_resp.json()['hash']
            
            # Trigger scan
            if progress_callback:
                progress_callback("Running MobSF scan...")
            
            scan_resp = await client.post(
                f"{settings.MOBSF_URL}/api/v1/scan",
                json={'hash': scan_hash},
                headers={'Authorization': settings.MOBSF_API_KEY}
            )
            
            # Get results
            report_resp = await client.get(
                f"{settings.MOBSF_URL}/api/v1/report_json",
                params={'hash': scan_hash},
                headers={'Authorization': settings.MOBSF_API_KEY}
            )
            
            # Save results
            report_path = output_dir / "mobsf" / "report.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report_resp.text)
            
        return ToolResult(
            success=True,
            output=report_resp.text,
            error="",
            duration_ms=int((time.time() - start) * 1000),
            artifacts_path=report_path.parent
        )
```

### 2.3 Tool Registry

```python
# services/tool_registry.py
from typing import Type, Dict
from services.tool_runner import ToolRunner
from services.tools.apktool import APKToolRunner
from services.tools.jadx import JADXRunner
from services.tools.mobsf import MobSFRunner
from services.tools.frida import FridaRunner
from services.tools.mitmproxy import MitmproxyRunner

TOOL_REGISTRY: Dict[str, Type[ToolRunner]] = {
    "apktool": APKToolRunner,
    "jadx": JADXRunner,
    "mobsf": MobSFRunner,
    "frida": FridaRunner,
    "mitmproxy": MitmproxyRunner,
}

SCAN_PROFILES = {
    "quick": ["apktool", "jadx"],
    "full": ["apktool", "jadx", "mobsf"],
    "runtime": ["frida", "mitmproxy"],
}

def get_tools_for_profile(profile: str, custom_tools: list[str] = None) -> list[Type[ToolRunner]]:
    """Get tool runners for a scan profile."""
    if profile == "custom" and custom_tools:
        return [TOOL_REGISTRY[t] for t in custom_tools if t in TOOL_REGISTRY]
    return [TOOL_REGISTRY[t] for t in SCAN_PROFILES.get(profile, [])]
```

### 2.4 Deliverables

- [x] Implement base ToolRunner class
- [x] APKTool runner
- [x] JADX runner
- [x] MobSF API client
- [x] Frida runner (script injection)
- [x] mitmproxy runner (traffic capture)
- [x] Tool health check endpoint (`GET /api/tools/status`)

---

## Phase 3: Scan Orchestration Service

**Goal:** Coordinate multiple tools and track progress in real-time.

### 3.1 Scanner Service

```python
# services/scanner.py
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime
import uuid

from database import crud
from models.scan import ScanCreate, ScanStatus
from services.tool_registry import get_tools_for_profile
from services.finding_parser import parse_tool_output

class ScannerService:
    """Orchestrates security scans across multiple tools."""
    
    def __init__(self):
        self.active_scans: dict[str, asyncio.Task] = {}
    
    async def start_scan(self, project_id: str, target: Path, 
                         profile: str, custom_tools: list[str] = None) -> str:
        """Start a new scan."""
        scan_id = str(uuid.uuid4())[:8]
        
        # Create scan record
        scan = await crud.create_scan(ScanCreate(
            id=scan_id,
            project_id=project_id,
            profile=profile,
            status=ScanStatus.PENDING
        ))
        
        # Create output directory
        output_dir = settings.PROJECTS_DIR / project_id / "scans" / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Start background task
        task = asyncio.create_task(
            self._run_scan_pipeline(scan_id, target, output_dir, profile, custom_tools)
        )
        self.active_scans[scan_id] = task
        
        return scan_id
    
    async def _run_scan_pipeline(self, scan_id: str, target: Path, 
                                  output_dir: Path, profile: str,
                                  custom_tools: list[str] = None):
        """Execute the scan pipeline."""
        await crud.update_scan_status(scan_id, ScanStatus.RUNNING, started_at=datetime.utcnow())
        
        tools = get_tools_for_profile(profile, custom_tools)
        total_tools = len(tools)
        completed = 0
        all_findings = []
        
        for i, ToolClass in enumerate(tools):
            tool_name = ToolClass.__name__.replace("Runner", "").lower()
            
            # Create tool execution record
            tool_exec_id = await crud.create_tool_execution(scan_id, tool_name)
            await crud.update_tool_execution(tool_exec_id, "running", started_at=datetime.utcnow())
            
            # Progress callback
            async def progress_callback(msg: str):
                await self._broadcast_progress(scan_id, tool_name, msg)
            
            try:
                # Run tool
                runner = ToolClass()
                result = await runner.run(target, output_dir, progress_callback)
                
                # Parse findings
                findings = await parse_tool_output(tool_name, result)
                all_findings.extend(findings)
                
                # Save findings
                for finding in findings:
                    await crud.create_finding(scan_id, finding)
                
                # Update tool execution
                await crud.update_tool_execution(
                    tool_exec_id, 
                    "completed" if result.success else "failed",
                    completed_at=datetime.utcnow(),
                    metrics={"duration_ms": result.duration_ms, "findings": len(findings)}
                )
                
                completed += 1
                progress = int((completed / total_tools) * 100)
                await crud.update_scan_progress(scan_id, progress)
                await self._broadcast_progress(scan_id, "_overall", f"Progress: {progress}%")
                
            except asyncio.CancelledError:
                await crud.update_scan_status(scan_id, ScanStatus.CANCELLED)
                return
            except Exception as e:
                await crud.update_tool_execution(tool_exec_id, "failed", error_message=str(e))
        
        # Mark scan complete
        await crud.update_scan_status(
            scan_id, 
            ScanStatus.COMPLETED,
            completed_at=datetime.utcnow()
        )
        
        await self._broadcast_complete(scan_id, all_findings)
    
    async def cancel_scan(self, scan_id: str):
        """Cancel an active scan."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].cancel()
    
    async def _broadcast_progress(self, scan_id: str, tool: str, message: str):
        """Broadcast progress via SSE."""
        # Implementation in Phase 4
        pass
    
    async def _broadcast_complete(self, scan_id: str, findings: list):
        """Broadcast completion via SSE."""
        pass
```

### 3.2 Finding Parser

```python
# services/finding_parser.py
import json
from typing import List
from models.finding import FindingCreate

async def parse_tool_output(tool_name: str, result) -> List[FindingCreate]:
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


async def parse_mobsf(result) -> List[FindingCreate]:
    """Parse MobSF JSON report."""
    findings = []
    
    try:
        report = json.loads(result.output)
        
        # Security findings
        for issue in report.get("security", []):
            findings.append(FindingCreate(
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
                title=issue.get("title", "Manifest issue"),
                severity=map_mobsf_severity(issue.get("severity", "medium")),
                category="Android Manifest",
                location="AndroidManifest.xml",
                description=issue.get("description", ""),
                tool="mobsf"
            ))
    
    except json.JSONDecodeError:
        pass
    
    return findings


def map_mobsf_severity(severity: str) -> str:
    """Map MobSF severity to IRVES severity."""
    mapping = {
        "high": "critical",
        "warning": "high",
        "info": "info",
        "secure": "low"
    }
    return mapping.get(severity.lower(), "medium")
```

### 3.3 Deliverables

- [x] Scanner service implementation
- [x] Finding parser for each tool
- [x] Background task management
- [x] Scan cancellation
- [x] Error handling and recovery

---

## Phase 4: Real-Time Communication

**Goal:** Stream live progress and findings to the frontend.

### 4.1 Server-Sent Events (SSE)

```python
# routes/events.py
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import asyncio
import json

router = APIRouter()

# Connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[asyncio.Queue]] = {}
    
    def connect(self, scan_id: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(queue)
        return queue
    
    def disconnect(self, scan_id: str, queue: asyncio.Queue):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(queue)
    
    async def broadcast(self, scan_id: str, event: dict):
        if scan_id in self.active_connections:
            for queue in self.active_connections[scan_id]:
                await queue.put(event)

manager = ConnectionManager()

@router.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    """SSE endpoint for live scan updates."""
    
    async def event_generator():
        queue = manager.connect(scan_id)
        try:
            # Send initial state
            scan = await crud.get_scan(scan_id)
            yield f"data: {json.dumps({'type': 'init', 'data': scan.dict()})}\n\n"
            
            # Stream updates
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(event)}\n\n"
                    
                    if event.get("type") == "complete":
                        break
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield f": keepalive\n\n"
        finally:
            manager.disconnect(scan_id, queue)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )
```

### 4.2 HTMX Integration

```html
<!-- screens/live_scan.html -->
<div class="pipeline-section">
    <div hx-ext="sse" sse-connect="/api/events/scan/{{ scan_id }}/stream">
        <!-- Progress bar -->
        <div class="progress-bar">
            <div class="progress-bar__fill" 
                 sse-swap="progress"
                 style="width: 0%"></div>
        </div>
        
        <!-- Pipeline steps -->
        <div id="pipeline-steps" sse-swap="pipeline">
            {% include "components/pipeline_steps.html" %}
        </div>
        
        <!-- Live findings -->
        <div id="live-findings" sse-swap="finding">
            {% include "components/findings_list.html" %}
        </div>
    </div>
</div>
```

### 4.3 Deliverables

- [x] SSE connection manager
- [x] Scan progress streaming endpoint
- [x] HTMX SSE integration
- [x] Live finding updates
- [x] Keepalive and reconnection handling

---

## Phase 5: Runtime Workspace (Frida)

**Goal:** Interactive Frida session management.

### 5.1 Frida Service

```python
# services/f Frida_service.py
import frida
from typing import Optional, Callable
import asyncio

class FridaService:
    """Manage Frida sessions for runtime analysis."""
    
    def __init__(self):
        self.sessions: dict[str, frida.core.Session] = {}
        self.scripts: dict[str, frida.core.Script] = {}
    
    async def attach(self, device_id: str, package_name: str) -> str:
        """Attach to a running process."""
        session_id = f"{device_id}:{package_name}"
        
        device = frida.get_device(device_id)
        session = device.attach(package_name)
        
        self.sessions[session_id] = session
        return session_id
    
    async def spawn(self, device_id: str, package_name: str) -> str:
        """Spawn and attach to a process."""
        session_id = f"{device_id}:{package_name}"
        
        device = frida.get_device(device_id)
        pid = device.spawn([package_name])
        session = device.attach(pid)
        device.resume(pid)
        
        self.sessions[session_id] = session
        return session_id
    
    async def inject_script(self, session_id: str, script_code: str,
                            message_handler: Callable) -> str:
        """Inject a Frida script."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        script = session.create_script(script_code)
        script.on("message", message_handler)
        script.load()
        
        script_id = str(uuid.uuid4())[:8]
        self.scripts[script_id] = script
        return script_id
    
    async def call_function(self, script_id: str, function_name: str, args: list):
        """Call a function in an injected script."""
        script = self.scripts.get(script_id)
        if not script:
            raise ValueError(f"Script {script_id} not found")
        
        return script.exports[function_name](*args)
    
    async def detach(self, session_id: str):
        """Detach from a session."""
        if session_id in self.sessions:
            self.sessions[session_id].detach()
            del self.sessions[session_id]

# Pre-built hooks library
BUILTIN_HOOKS = {
    "ssl_bypass": """
        Java.perform(function() {
            // SSL pinning bypass
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log('[+] SSL pinning bypassed');
                return;
            };
        });
    """,
    
    "root_detection_bypass": """
        Java.perform(function() {
            var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            RootBeer.isRooted.implementation = function() {
                console.log('[+] Root detection bypassed');
                return false;
            };
        });
    """,
    
    "crypto_capture": """
        Java.perform(function() {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(data) {
                var result = this.doFinal(data);
                console.log('[+] Cipher.doFinal called');
                console.log('    Algorithm: ' + this.getAlgorithm());
                console.log('    Input: ' + bytesToHex(data));
                console.log('    Output: ' + bytesToHex(result));
                return result;
            };
            
            function bytesToHex(bytes) {
                var hex = '';
                for (var i = 0; i < bytes.length; i++) {
                    hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
                }
                return hex;
            }
        });
    """,
    
    "network_intercept": """
        Java.perform(function() {
            var URL = Java.use('java.net.URL');
            URL.openConnection.overload().implementation = function() {
                console.log('[+] HTTP Request: ' + this.toString());
                return this.openConnection();
            };
        });
    """
}
```

### 5.2 Runtime WebSocket Endpoint

```python
# routes/runtime.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()
frida_service = FridaService()

@router.websocket("/ws/runtime/{device_id}/{package}")
async def runtime_websocket(websocket: WebSocket, device_id: str, package: str):
    """WebSocket for runtime Frida sessions."""
    await websocket.accept()
    
    session_id = None
    
    async def message_handler(message, data):
        """Forward Frida messages to WebSocket."""
        if message["type"] == "send":
            await websocket.send_json({
                "type": "output",
                "payload": message["payload"]
            })
        elif message["type"] == "error":
            await websocket.send_json({
                "type": "error",
                "payload": message["description"]
            })
    
    try:
        # Attach to process
        session_id = await frida_service.attach(device_id, package)
        await websocket.send_json({"type": "attached", "session_id": session_id})
        
        while True:
            data = await websocket.receive_json()
            
            if data["type"] == "inject":
                # Inject script
                script_code = data.get("script") or BUILTIN_HOOKS.get(data.get("hook_name"))
                if script_code:
                    script_id = await frida_service.inject_script(
                        session_id, script_code, message_handler
                    )
                    await websocket.send_json({
                        "type": "injected",
                        "script_id": script_id
                    })
            
            elif data["type"] == "call":
                # Call script function
                result = await frida_service.call_function(
                    data["script_id"], data["function"], data.get("args", [])
                )
                await websocket.send_json({
                    "type": "result",
                    "payload": result
                })
            
            elif data["type"] == "detach":
                break
                
    except WebSocketDisconnect:
        pass
    finally:
        if session_id:
            await frida_service.detach(session_id)
```

### 5.3 Deliverables

- [x] Frida service implementation
- [x] WebSocket endpoint for runtime
- [x] Pre-built hooks library
- [x] Device discovery endpoint
- [x] Process listing endpoint
- [x] Runtime pre-flight checks

---

## Phase 6: AI Analysis Layer

**Goal:** Per-finding intelligent explanations.

### 6.1 AI Service

```python
# services/ai_service.py
from anthropic import Anthropic
from models.finding import FindingCreate

class AIService:
    """AI-powered finding analysis."""
    
    def __init__(self):
        self.client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    
    async def analyze_finding(self, finding: FindingCreate) -> dict:
        """Generate per-finding analysis."""
        
        prompt = f"""You are a security analyst. Analyze this vulnerability finding and provide a clear, actionable explanation.

**Finding:**
- Title: {finding.title}
- Severity: {finding.severity}
- Location: {finding.location}
- Description: {finding.description}
- OWASP Mapping: {finding.owasp_mapping}

**Code Snippet:**
```
{finding.code_snippet or 'Not available'}
```

Provide your response in this exact JSON format:
{{
    "explanation": "Plain-language explanation of what this vulnerability is",
    "attack_path": ["Step 1", "Step 2", "Step 3"],
    "fix": "Specific, actionable fix guidance",
    "references": ["Link 1", "Link 2"]
}}

Keep explanations technical but accessible to a senior developer. Be specific, not generic."""

        response = self.client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        
        import json
        return json.loads(response.content[0].text)
    
    async def chat(self, finding_id: str, question: str, context: dict) -> str:
        """Contextual chat about a specific finding."""
        
        prompt = f"""You are helping a developer understand a security vulnerability.

**Finding Context:**
{json.dumps(context, indent=2)}

**Developer Question:**
{question}

Provide a helpful, specific answer. Reference the code if relevant."""

        response = self.client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
```

### 6.2 Deliverables

- [x] AI service with Claude integration
- [x] Finding analysis endpoint
- [x] Contextual chat endpoint
- [x] Streaming response support
- [ ] Rate limiting

---

## Phase 7: Report Generation

**Goal:** Enterprise-grade compliance reports.

### 7.1 Report Templates

```python
# services/report_generator.py
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import json

class ReportGenerator:
    """Generate compliance reports."""
    
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader("templates/reports"))
    
    async def generate(self, project_id: str, scan_id: str, 
                       template: str, format: str) -> Path:
        """Generate a report."""
        
        # Gather data
        project = await crud.get_project(project_id)
        findings = await crud.get_findings_by_scan(scan_id)
        
        # Render template
        if template == "masvs":
            return await self._generate_masvs(project, findings, format)
        elif template == "sbom":
            return await self._generate_sbom(project, findings, format)
        elif template == "privacy":
            return await self._generate_privacy(project, findings, format)
    
    async def _generate_masvs(self, project, findings, format: str) -> Path:
        """Generate OWASP MASVS report."""
        
        # Group findings by MASVS category
        masvs_findings = {}
        for finding in findings:
            category = finding.owasp_mapping or "Uncategorized"
            if category not in masvs_findings:
                masvs_findings[category] = []
            masvs_findings[category].append(finding)
        
        # Determine pass/fail
        results = {}
        for category, cats in masvs_findings.items():
            critical_count = sum(1 for f in cats if f.severity in ["critical", "high"])
            results[category] = "PASS" if critical_count == 0 else "FAIL"
        
        template = self.env.get_template("masvs.html")
        html_content = template.render(
            project=project,
            findings=findings,
            masvs_results=results,
            generated_at=datetime.utcnow()
        )
        
        # Generate output
        output_path = settings.REPORTS_DIR / f"{project.id}_masvs.{format}"
        
        if format == "pdf":
            HTML(string=html_content).write_pdf(output_path)
        elif format == "html":
            output_path.write_text(html_content)
        elif format == "json":
            output_path.write_text(json.dumps({
                "project": project.dict(),
                "masvs_results": results,
                "findings": [f.dict() for f in findings]
            }, indent=2))
        
        return output_path
```

### 7.2 Deliverables

- [x] Report template engine
- [x] OWASP MASVS report template
- [x] SBOM report template
- [x] Privacy audit template
- [x] PDF/Markdown/JSON/HTML export

---

## Phase 8: Tool Health & Settings

**Goal:** Tool management and configuration UI.

### 8.1 Tool Health Check

```python
# routes/settings.py
from fastapi import APIRouter
import shutil
import asyncio

router = APIRouter()

@router.get("/tools/status")
async def get_tools_status():
    """Check all tools' installation status."""
    
    tools = ["apktool", "jadx", "frida", "mitmproxy"]
    status = {}
    
    for tool in tools:
        path = shutil.which(tool)
        status[tool] = {
            "installed": path is not None,
            "path": path,
            "version": await get_tool_version(tool) if path else None
        }
    
    # Check MobSF separately
    status["mobsf"] = await check_mobsf_status()
    
    return status

async def get_tool_version(tool: str) -> str:
    """Get tool version."""
    version_flags = {
        "apktool": "--version",
        "jadx": "--version",
        "frida": "--version",
        "mitmproxy": "--version"
    }
    
    try:
        proc = await asyncio.create_subprocess_exec(
            tool, version_flags.get(tool, "--version"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip().split('\n')[0]
    except:
        return "unknown"

async def check_mobsf_status() -> dict:
    """Check MobSF server status."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{settings.MOBSF_URL}/api/v1/version", timeout=5.0)
            return {
                "installed": True,
                "running": resp.status_code == 200,
                "url": settings.MOBSF_URL
            }
    except:
        return {
            "installed": False,
            "running": False,
            "url": settings.MOBSF_URL
        }
```

### 8.2 Deliverables

- [x] Tool status endpoint
- [x] Tool version detection
- [x] MobSF connection check
- [x] Device management (ADB)
- [x] Settings persistence

---

## Implementation Timeline

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Infrastructure | Database, config, models |
| 2 | Tool Runners | APKTool, JADX, MobSF runners |
| 3 | Scan Service | Orchestration, parsers, background tasks |
| 4 | Real-time | SSE streaming, live scan view |
| 5 | Runtime | Frida service, WebSocket, pre-flight |
| 6 | AI Layer | Claude integration, finding analysis |
| 7 | Reports | Templates, PDF generation |
| 8 | Polish | Settings UI, error handling, testing |

---

## Dependencies to Add

```txt
# backend/requirements.txt (additions)
sqlalchemy[asyncio]==2.0.25
aiosqlite==0.20.0
pydantic-settings==2.2.1
python-dotenv==1.0.1
anthropic==0.27.0
frida==16.5.9
frida-tools==13.4.0
weasyprint==60.2
jinja2==3.1.6  # already present
```

---

## Testing Strategy

### Unit Tests
- Tool runner execution (mocked subprocess)
- Finding parsers
- AI service (mocked API)

### Integration Tests
- Full scan pipeline (with sample APK)
- Database operations
- SSE streaming

### End-to-End Tests
- Complete scan workflow
- Runtime session lifecycle
- Report generation

---

## Security Considerations

1. **Sandbox tool execution** - Run tools in isolated environment
2. **Path validation** - Prevent directory traversal
3. **Rate limiting** - API and AI endpoints
4. **Input sanitization** - File names, URLs
5. **Credential storage** - Secure API key handling
6. **CORS** - Restrict to Tauri origin

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Scan completion rate | > 95% |
| Average scan time (Android) | < 5 minutes |
| Finding accuracy | > 90% (validated) |
| AI response time | < 3 seconds |
| Report generation | < 10 seconds |

---

## Next Steps

1. Review and approve this plan
2. Set up development environment (install tools)
3. Begin Phase 1 implementation
4. Create sample test APKs for validation