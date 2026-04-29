"""
IRVES — Intelligent Security Tool
FastAPI Core — Entry Point

A desktop-native security analysis platform for mobile, desktop, and web applications.
Integrates static analysis, dynamic instrumentation (Frida), and AI-powered reasoning.
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Depends, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import logging

# Database
from sqlalchemy.ext.asyncio import AsyncSession
from database import init_db, close_db, get_db_session
from database.models import AnalysisCategory

# Configuration
from config import settings

# Routes
from routes import scan, analysis, reports, events, runtime, settings_api, network, auth, docs
from routes import ast_routes  # Phase 2: AST
from routes import ai_module_routes  # Phase 3: Three-Module AI
from routes import repository_routes  # Phase 4: Repository Analysis
from routes import correlation_routes  # Phase E: Cross-Phase Correlation
from routes import session_routes  # Phase F: Session Persistence
from routes import source_analysis_routes  # Source Code Analysis

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).parent


# ── Lifespan Management ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(f"[IRVES] Starting {settings.APP_NAME} v{settings.ENVIRONMENT}")
    logger.info(f"[IRVES] Debug mode: {settings.DEBUG}")

    # Initialize database
    try:
        await init_db()
        logger.info("[IRVES] Database initialized")
    except Exception as e:
        logger.error(f"[IRVES] Database initialization failed: {e}")
        raise

    # Apply persisted user settings
    try:
        from services.settings_service import settings_service
        user_settings = settings_service.load()
        
        # AI Config
        ai = user_settings.get("ai", {})
        if ai.get("api_key"): settings.AI_API_KEY = ai.get("api_key")
        if ai.get("model"): settings.AI_MODEL = ai.get("model")
        if ai.get("api_base"): settings.AI_API_BASE = ai.get("api_base")
        if ai.get("provider"): settings.AI_PROVIDER = ai.get("provider")

        # Also set provider-specific key so LiteLLM can route natively
        _PROVIDER_KEY_MAP = {
            "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY", "xai": "XAI_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY", "together": "TOGETHER_AI_API_KEY",
            "huggingface": "HUGGINGFACE_API_KEY",
        }
        _prov = ai.get("provider", "")
        _key = ai.get("api_key", "")
        if _prov in _PROVIDER_KEY_MAP and _key:
            setattr(settings, _PROVIDER_KEY_MAP[_prov], _key)

        logger.info("[IRVES] Loaded persisted user settings")
    except Exception as e:
        logger.warning(f"[IRVES] Could not load persisted settings: {e}")

    # Ensure storage directories
    try:
        settings.ensure_directories()
        logger.info(f"[IRVES] Storage directories created")
    except Exception as e:
        logger.warning(f"[IRVES] Could not create storage directories: {e}")

    # Log configuration
    logger.info(f"[IRVES] Projects directory: {settings.projects_path}")
    logger.info(f"[IRVES] Reports directory: {settings.reports_path}")

    # Start network proxy service (mitmdump subprocess)
    try:
        from services.network_service import network_service
        await network_service.start(fastapi_port=settings.PORT)
    except Exception as e:
        logger.warning(f"[IRVES] Network proxy failed to start: {e}")

    yield

    # Shutdown
    logger.info("[IRVES] Shutting down...")
    from services.network_service import network_service
    await network_service.stop()
    await close_db()
    logger.info("[IRVES] Shutdown complete")


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="IRVES",
    description="Intelligent Security Tool — API Core",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

# CORS middleware (for Tauri)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["tauri://localhost", "http://localhost:8765", "https://tauri.localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if not settings.SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required. Set a secure random string in .env before starting the server.")

# Session middleware (for OAuth)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=3600 * 24 * 7  # 1 week
)


# ── Static Assets ──────────────────────────────────────────────────────────────

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)


# ── Templates ───────────────────────────────────────────────────────────────────

templates = Jinja2Templates(directory=BASE_DIR / "templates")


# ── API Routes ─────────────────────────────────────────────────────────────────

app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
app.include_router(reports.router, prefix="/api/report", tags=["reports"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(runtime.router, prefix="/api/runtime", tags=["runtime"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["settings"])
app.include_router(network.router, prefix="/api/network", tags=["network"])
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(docs.router, prefix="/docs", tags=["docs"])
app.include_router(ast_routes.router)  # Phase 2: AST routes
app.include_router(ai_module_routes.router)  # Phase 3: AI Module routes
app.include_router(repository_routes.router)  # Phase 4: Repository routes
app.include_router(correlation_routes.router)  # Phase E: Correlation routes
app.include_router(session_routes.router)  # Phase F: Session routes
app.include_router(source_analysis_routes.router)  # Source Code Analysis routes


# ── Health Check ───────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["system"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/tools/status", tags=["system"])
async def tools_status():
    """Check status of all security tools."""
    from services.tools import APKToolRunner, JADXRunner, FridaRunner, MitmproxyRunner

    tools = []

    # Check APKTool
    apktool = APKToolRunner()
    tools.append(await apktool.check_installed())

    # Check JADX
    jadx = JADXRunner()
    tools.append(await jadx.check_installed())

    # Check Frida
    frida = FridaRunner()
    tools.append(await frida.check_installed())

    # Check Mitmproxy
    mitmproxy = MitmproxyRunner()
    tools.append(await mitmproxy.check_installed())

    return {"tools": tools}


# ── UI Routes (HTMX / Jinja2) ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Projects screen — application entry point."""
    projects = await scan.list_projects(db=db)
    return templates.TemplateResponse(
        "screens/projects.html",
        {"request": request, "projects": projects, "active_nav": "projects"},
    )


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """New scan configuration screen."""
    return templates.TemplateResponse(
        "screens/new_scan.html",
        {"request": request, "active_nav": "scan"},
    )

@app.get("/auth_success", response_class=HTMLResponse)
async def auth_success_page(request: Request):
    """Callback target for OAuth popups."""
    return HTMLResponse(
        content="""
        <html><body>
        <script>
            window.close();
        </script>
        <div style="font-family:sans-serif; padding: 2rem; text-align: center;">
            <h2>Authentication Successful</h2>
            <p>You can safely close this window.</p>
        </div>
        </body></html>
        """,
        status_code=200
    )


@app.get("/live-scan", response_class=HTMLResponse)
async def live_scan_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Live scan progress screen."""
    scan_id = request.query_params.get("scan_id")
    project_id = request.query_params.get("project_id")

    if not scan_id:
        from sqlalchemy import select
        from database.models import Scan, ScanStatus
        # 1. Try to find an actively running scan
        result = await db.execute(select(Scan).where(Scan.status == ScanStatus.RUNNING).order_by(Scan.created_at.desc()).limit(1))
        latest = result.scalar_one_or_none()
        if not latest:
            # 2. Fall back to the most recent scan of any status
            result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(1))
            latest = result.scalar_one_or_none()
        
        if latest:
            scan_id = latest.id
            project_id = latest.project_id

    project = None
    if project_id:
        from database.crud import get_project
        project = await get_project(db, project_id)

    return templates.TemplateResponse(
        "screens/live_scan.html",
        {
            "request": request, 
            "active_nav": "live_scan",
            "scan_id": scan_id,
            "project_id": project_id,
            "project": project
        },
    )


@app.get("/runtime", response_class=HTMLResponse)
async def runtime_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Runtime workspace for Frida sessions."""
    project_id = request.query_params.get("project")
    project = None
    if project_id:
        from database.crud import get_project
        project = await get_project(db, project_id)

    return templates.TemplateResponse(
        "screens/runtime_workspace.html",
        {"request": request, "active_nav": "runtime", "project": project},
    )


@app.get("/network", response_class=HTMLResponse)
async def network_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Network proxy and intercept workspace."""
    project_id = request.query_params.get("project")
    project = None
    if project_id:
        from database.crud import get_project
        project = await get_project(db, project_id)

    return templates.TemplateResponse(
        "screens/network_intercept.html",
        {"request": request, "active_nav": "network", "project": project},
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Findings dashboard. Auto-selects the most recent project+scan when no ?project= given."""
    project_id = request.query_params.get("project")
    from database.crud import get_project, get_scan, get_scans_by_project, get_findings_by_scan, count_findings_by_severity, count_findings_by_category
    from database.models import Scan, ScanStatus
    from sqlalchemy import select

    project = None
    projects = []
    scan = None
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}
    malware_score = None
    score_label = None

    # ── Resolve Project ───────────────────────────────────────────────────────
    if project_id:
        project = await get_project(db, project_id)
    else:
        # Fetch all projects to allow selection on the dashboard
        from routes.scan import list_projects
        projects = await list_projects(db=db)



    # ── Resolve Scan & Findings ───────────────────────────────────────────────
    if project:
        # Get the most recent scan for this project (preferring completed)
        from database.models import Scan, ScanStatus
        # Try completed first
        result = await db.execute(
            select(Scan)
            .where(Scan.project_id == project.id)
            .where(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            # Fall back to any scan
            result = await db.execute(
                select(Scan)
                .where(Scan.project_id == project.id)
                .order_by(Scan.created_at.desc())
                .limit(1)
            )
            scan = result.scalar_one_or_none()

        if scan:
            findings = await get_findings_by_scan(db, scan.id, limit=5000)
            raw = await count_findings_by_severity(db, scan.id)
            severity_counts = {
                "critical": raw.get("critical", 0),
                "high": raw.get("high", 0),
                "medium": raw.get("medium", 0),
                "low": raw.get("low", 0),
            }
            category_counts = await count_findings_by_category(db, scan.id)

            # Extract malware score from tool execution metrics
            from database.crud import get_tool_executions_by_scan
            tool_execs = await get_tool_executions_by_scan(db, scan.id)
            for te in tool_execs:
                if te.metrics:
                    ms = te.metrics.get("malware_score")
                    sl = te.metrics.get("score_label")
                    if ms is not None:
                        malware_score = ms
                        score_label = sl
                        break

    return templates.TemplateResponse(
        "screens/dashboard.html",
        {
            "request": request,
            "active_nav": "dashboard",
            "project": project,
            "projects": projects,
            "scan": scan,
            "findings": findings,
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "malware_score": malware_score,
            "score_label": score_label,
        },
    )


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail_page(request: Request, finding_id: str, db: AsyncSession = Depends(get_db_session)):
    """Finding detail with AI analysis."""
    from database.crud import get_finding, get_scan, get_project
    
    finding = await get_finding(db, finding_id)
    scan = None
    project = None
    if finding:
        scan = await get_scan(db, finding.scan_id)
        if scan:
            project = await get_project(db, scan.project_id)

        ai_analysis_dict = {}
        if finding.ai_analysis and isinstance(finding.ai_analysis, str):
            import json
            try:
                ai_analysis_dict = json.loads(finding.ai_analysis)
            except json.JSONDecodeError:
                pass

    return templates.TemplateResponse(
        "screens/finding_detail.html",
        {
            "request": request, 
            "finding_id": finding_id, 
            "finding": finding,
            "ai_analysis": ai_analysis_dict,
            "scan": scan,
            "project": project,
            "active_nav": "dashboard"
        },
    )


@app.get("/malware-report", response_class=HTMLResponse)
async def malware_report_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Malware risk score detailed report."""
    project_id = request.query_params.get("project")
    from database.crud import get_project, get_scan, get_findings_by_scan, count_findings_by_severity
    from database.models import Scan, ScanStatus
    from sqlalchemy import select

    project = None
    scan = None
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    malware_score = None
    score_label = None

    if project_id:
        project = await get_project(db, project_id)
        if project:
            result = await db.execute(
                select(Scan)
                .where(Scan.project_id == project.id)
                .where(Scan.status == ScanStatus.COMPLETED)
                .order_by(Scan.created_at.desc())
                .limit(1)
            )
            scan = result.scalar_one_or_none()

            if not scan:
                result = await db.execute(
                    select(Scan)
                    .where(Scan.project_id == project.id)
                    .order_by(Scan.created_at.desc())
                    .limit(1)
                )
                scan = result.scalar_one_or_none()

            if scan:
                findings = await get_findings_by_scan(db, scan.id, limit=5000)
                raw = await count_findings_by_severity(db, scan.id)
                severity_counts = {
                    "critical": raw.get("critical", 0),
                    "high": raw.get("high", 0),
                    "medium": raw.get("medium", 0),
                    "low": raw.get("low", 0),
                }
                from database.crud import get_tool_executions_by_scan
                tool_execs = await get_tool_executions_by_scan(db, scan.id)
                for te in tool_execs:
                    if te.metrics:
                        ms = te.metrics.get("malware_score")
                        sl = te.metrics.get("score_label")
                        if ms is not None:
                            malware_score = ms
                            score_label = sl
                            break

    score_color = (score_label if score_label in ["critical", "high", "medium", "low", "info"] else "info")

    return templates.TemplateResponse(
        "screens/malware_report.html",
        {
            "request": request,
            "active_nav": "dashboard",
            "project": project,
            "scan": scan,
            "findings": findings,
            "severity_counts": severity_counts,
            "malware_score": malware_score,
            "score_label": score_label,
            "score_color": score_color,
        },
    )


@app.get("/cve-report", response_class=HTMLResponse)
async def cve_report_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """CVE findings detailed report."""
    project_id = request.query_params.get("project")
    from database.crud import get_project, get_scan, get_findings_by_scan
    from database.models import Scan, ScanStatus, Finding
    from sqlalchemy import select
    import re

    project = None
    scan = None
    cve_findings = []
    cve_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    if project_id:
        project = await get_project(db, project_id)
        if project:
            result = await db.execute(
                select(Scan)
                .where(Scan.project_id == project.id)
                .where(Scan.status == ScanStatus.COMPLETED)
                .order_by(Scan.created_at.desc())
                .limit(1)
            )
            scan = result.scalar_one_or_none()

            if not scan:
                result = await db.execute(
                    select(Scan)
                    .where(Scan.project_id == project.id)
                    .order_by(Scan.created_at.desc())
                    .limit(1)
                )
                scan = result.scalar_one_or_none()

            if scan:
                all_findings = await get_findings_by_scan(db, scan.id, limit=5000)
                for f in all_findings:
                    title = (f.title or "").lower()
                    if "vulnerable library" in title or "library" in title and "cve" in title:
                        m = re.search(r'vulnerable library:\s*([^\s]+)\s*(v?([\d.]+))?\s*[-–]\s*(cve-\d+-\d+)', f.title, re.I)
                        if not m:
                            m = re.search(r'potentially vulnerable library:\s*([^\s]+)\s*[-–]\s*(cve-\d+-\d+)', f.title, re.I)
                        library_name = m.group(1) if m else "Unknown"
                        library_version = m.group(3) if m and m.group(3) else ""
                        cve_id = m.group(4) if m else ""

                        cve_entry = {
                            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                            "library_name": library_name,
                            "library_version": library_version,
                            "cve_id": cve_id,
                            "description": f.description or "",
                            "location": f.location or "",
                        }
                        cve_findings.append(cve_entry)
                        sev = cve_entry["severity"].lower()
                        cve_counts[sev] = cve_counts.get(sev, 0) + 1

    return templates.TemplateResponse(
        "screens/cve_report.html",
        {
            "request": request,
            "active_nav": "dashboard",
            "project": project,
            "scan": scan,
            "cve_findings": cve_findings,
            "cve_counts": cve_counts,
        },
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Report generation screen."""
    project_id = request.query_params.get("project")
    from database.crud import get_project, get_reports_by_project
    
    project = None
    reports_list = []
    if project_id:
        project = await get_project(db, project_id)
        if project:
            reports_list = await get_reports_by_project(db, project.id, limit=20)

    return templates.TemplateResponse(
        "screens/reports.html",
        {
            "request": request,
            "active_nav": "reports",
            "project": project,
            "reports_list": reports_list,
        },
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings and tool configuration."""
    return templates.TemplateResponse(
        "screens/settings.html",
        {"request": request, "active_nav": "settings"},
    )


@app.get("/source-analysis", response_class=HTMLResponse)
async def source_analysis_page(
    request: Request,
    project_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Source Code Analysis screen.
    Displays comprehensive analysis across 8 categories for repository projects.
    """
    project = None
    if project_id:
        from database.crud import get_project
        project = await get_project(db, project_id)

    # If no project specified and there's a repository project, use the latest one
    if not project:
        from database.crud import get_projects
        projects = await get_projects(db, platform="repository", limit=1)
        if projects:
            project = projects[0]

    return templates.TemplateResponse(
        "screens/source_analysis.html",
        {
            "request": request,
            "active_nav": "source-analysis",
            "project": project,
        },
    )


@app.get("/source-analysis/report/{project_id}/{category}")
async def source_analysis_report(
    request: Request,
    project_id: str,
    category: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Dedicated full-screen report view for a specific analysis category.
    """
    from database.crud import get_project
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate category
    try:
        category_enum = AnalysisCategory(category)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid category: {category}")

    return templates.TemplateResponse(
        "screens/report_detail.html",
        {
            "request": request,
            "active_nav": "source-analysis",
            "project": project,
            "category": category,
            "category_label": category.replace("_", " ").title(),
        },
    )



# ── Development Server ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )