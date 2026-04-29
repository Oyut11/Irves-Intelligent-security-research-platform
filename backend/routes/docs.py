"""
IRVES — Documentation Routes
Serves user-facing documentation pages for Runtime Workspace and Network Intercept.
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import markdown
from typing import Optional

router = APIRouter()

# Path to docs directory
DOCS_DIR = Path(__file__).parent.parent.parent / "docs"
# Templates directory
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)


@router.get("/runtime-workspace", response_class=HTMLResponse)
async def runtime_workspace_docs(request: Request):
    """Serve Runtime Workspace documentation."""
    doc_file = DOCS_DIR / "runtime-workspace.md"
    
    if not doc_file.exists():
        return HTMLResponse(content="<h1>Documentation not found</h1>", status_code=404)
    
    with open(doc_file, "r", encoding="utf-8") as f:
        md_content = f.read()
    
    html_content = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "codehilite", "toc"]
    )
    
    return templates.TemplateResponse(
        "docs_view.html",
        {
            "request": request,
            "title": "Runtime Workspace Documentation",
            "content": html_content,
            "breadcrumb": "Runtime Workspace"
        }
    )


@router.get("/network-intercept", response_class=HTMLResponse)
async def network_intercept_docs(request: Request):
    """Serve Network Intercept documentation."""
    doc_file = DOCS_DIR / "network-intercept.md"
    
    if not doc_file.exists():
        return HTMLResponse(content="<h1>Documentation not found</h1>", status_code=404)
    
    with open(doc_file, "r", encoding="utf-8") as f:
        md_content = f.read()
    
    html_content = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "codehilite", "toc"]
    )
    
    return templates.TemplateResponse(
        "docs_view.html",
        {
            "request": request,
            "title": "Network Intercept Documentation",
            "content": html_content,
            "breadcrumb": "Network Intercept"
        }
    )
