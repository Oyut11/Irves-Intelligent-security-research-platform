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

from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

# Database
from sqlalchemy.ext.asyncio import AsyncSession
from database import init_db, close_db, get_db_session

# Configuration
from config import settings

# Routes
from routes import scan, analysis, reports, events, runtime, settings_api, network

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

    # Ensure storage directories
    try:
        settings.ensure_directories()
        logger.info(f"[IRVES] Storage directories created")
    except Exception as e:
        logger.warning(f"[IRVES] Could not create storage directories: {e}")

    # Log configuration
    logger.info(f"[IRVES] Projects directory: {settings.projects_path}")
    logger.info(f"[IRVES] Reports directory: {settings.reports_path}")

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
    from services.tools import APKToolRunner, JADXRunner, MobSFRunner, FridaRunner, MitmproxyRunner

    tools = []

    # Check APKTool
    apktool = APKToolRunner()
    tools.append(await apktool.check_installed())

    # Check JADX
    jadx = JADXRunner()
    tools.append(await jadx.check_installed())

    # Check MobSF
    mobsf = MobSFRunner()
    mobsf_status = await mobsf.check_server_status()
    tools.append({
        "name": "mobsf",
        "installed": True,
        "running": mobsf_status.get("running", False),
        "version": mobsf_status.get("version"),
        "url": mobsf_status.get("url"),
        "error": mobsf_status.get("error"),
    })

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

    return templates.TemplateResponse(
        "screens/live_scan.html",
        {
            "request": request, 
            "active_nav": "live_scan",
            "scan_id": scan_id,
            "project_id": project_id
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
    """Findings dashboard."""
    project_id = request.query_params.get("project")
    from database.crud import get_project, get_scans_by_project, get_findings_by_scan, count_findings_by_severity

    project = None
    scan = None
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    if project_id:
        project = await get_project(db, project_id)
        if project:
            scans = await get_scans_by_project(db, project.id, limit=1)
            if scans:
                scan = scans[0]
                findings = await get_findings_by_scan(db, scan.id)
                raw = await count_findings_by_severity(db, scan.id)
                severity_counts = {
                    "critical": raw.get("critical", 0),
                    "high": raw.get("high", 0),
                    "medium": raw.get("medium", 0),
                    "low": raw.get("low", 0),
                }

    return templates.TemplateResponse(
        "screens/dashboard.html",
        {
            "request": request,
            "active_nav": "dashboard",
            "project": project,
            "scan": scan,
            "findings": findings,
            "severity_counts": severity_counts,
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

    return templates.TemplateResponse(
        "screens/finding_detail.html",
        {
            "request": request, 
            "finding_id": finding_id, 
            "finding": finding,
            "scan": scan,
            "project": project,
            "active_nav": "dashboard"
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