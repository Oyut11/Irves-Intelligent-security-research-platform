"""
IRVES — Report Generator Service (Phase 7)
Renders OWASP MASVS, SBOM, and Privacy Audit reports as PDF / HTML / JSON / Markdown.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import settings
from database import crud
from database.connection import get_db
from database.models import FindingSeverity

logger = logging.getLogger(__name__)

# Severity ordering for sorting
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ReportGenerator:
    """Generates compliance and audit reports from scan data."""

    def __init__(self):
        templates_dir = Path(__file__).parent.parent / "templates" / "reports"
        templates_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters["severity_class"] = lambda s: s.lower() if s else "info"
        self.env.filters["to_json"] = lambda v: json.dumps(v, indent=2)

    # ── Public interface ─────────────────────────────────────────────────────

    async def generate(
        self,
        project_id: str,
        scan_id: Optional[str],
        template: str,
        fmt: str,
        selected_finding_ids: Optional[list[str]] = None,
    ) -> Path:
        """
        Generate a report and return the file path.

        template: "masvs" | "sbom" | "privacy"
        fmt:      "pdf" | "html" | "json" | "markdown"
        """
        async with get_db() as db:
            project = await crud.get_project(db, project_id)
            if not project:
                raise ValueError(f"Project not found: {project_id}")

            findings = []
            severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            if scan_id:
                findings = await crud.get_findings_by_scan(db, scan_id)
                if selected_finding_ids:
                    findings = [f for f in findings if f.id in set(selected_finding_ids)]
                severity_counts = await crud.count_findings_by_severity(db, scan_id)

        # Sort by severity
        findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower(), 4)
        )

        generated_at = datetime.utcnow()
        report_name = f"{project_id}_{template}_{generated_at.strftime('%Y%m%d_%H%M%S')}"
        output_dir = settings.reports_path
        output_dir.mkdir(parents=True, exist_ok=True)

        if template == "masvs":
            return await self._generate_masvs(project, scan_id, findings, severity_counts, fmt, report_name, generated_at)
        elif template == "sbom":
            return await self._generate_sbom(project, scan_id, findings, fmt, report_name, generated_at)
        elif template == "privacy":
            return await self._generate_privacy(project, scan_id, findings, fmt, report_name, generated_at)
        else:
            raise ValueError(f"Unknown template: {template}")

    # ── MASVS ────────────────────────────────────────────────────────────────

    async def _generate_masvs(self, project, scan_id, findings, severity_counts, fmt, report_name, generated_at) -> Path:
        """OWASP Mobile Application Security Verification Standard report."""
        masvs_categories = {
            "MASVS-STORAGE": [],
            "MASVS-CRYPTO": [],
            "MASVS-AUTH": [],
            "MASVS-NETWORK": [],
            "MASVS-PLATFORM": [],
            "MASVS-CODE": [],
            "MASVS-RESILIENCE": [],
            "Uncategorised": [],
        }

        for f in findings:
            owasp = f.owasp_mapping or ""
            placed = False
            for cat in masvs_categories:
                if cat.lower() in owasp.lower():
                    masvs_categories[cat].append(f)
                    placed = True
                    break
            if not placed:
                masvs_categories["Uncategorised"].append(f)

        results = {
            cat: "PASS" if not any(
                str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower() in ("critical", "high")
                for f in cats
            ) else "FAIL"
            for cat, cats in masvs_categories.items()
        }

        overall = "PASS" if all(v == "PASS" for v in results.values()) else "FAIL"

        ctx = dict(
            project=project,
            scan_id=scan_id,
            findings=findings,
            masvs_categories=masvs_categories,
            masvs_results=results,
            overall=overall,
            severity_counts=severity_counts,
            generated_at=generated_at,
            total_findings=len(findings),
        )

        return self._render(ctx, "masvs.html", fmt, report_name)

    # ── SBOM ─────────────────────────────────────────────────────────────────

    async def _generate_sbom(self, project, scan_id, findings, fmt, report_name, generated_at) -> Path:
        """Software Bill of Materials security report."""
        code_findings = [f for f in findings if f.tool in ("jadx", "apktool")]
        runtime_findings = [f for f in findings if f.tool in ("frida", "mitmproxy")]
        static_findings = [f for f in findings if f.tool == "mobsf"]

        ctx = dict(
            project=project,
            scan_id=scan_id,
            code_findings=code_findings,
            runtime_findings=runtime_findings,
            static_findings=static_findings,
            all_findings=findings,
            total_findings=len(findings),
            generated_at=generated_at,
        )
        return self._render(ctx, "sbom.html", fmt, report_name)

    # ── Privacy Audit ─────────────────────────────────────────────────────────

    async def _generate_privacy(self, project, scan_id, findings, fmt, report_name, generated_at) -> Path:
        """Privacy / data-protection audit report."""
        PRIVACY_KEYWORDS = {"api key", "token", "password", "credential", "pii", "cleartext", "sensitive", "tracking", "location"}

        privacy_findings = [
            f for f in findings
            if any(kw in (f.title or "").lower() or kw in (f.description or "").lower() for kw in PRIVACY_KEYWORDS)
        ]

        ctx = dict(
            project=project,
            scan_id=scan_id,
            privacy_findings=privacy_findings,
            all_findings=findings,
            total_findings=len(findings),
            privacy_count=len(privacy_findings),
            generated_at=generated_at,
        )
        return self._render(ctx, "privacy.html", fmt, report_name)

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _render(self, ctx: dict, template_name: str, fmt: str, report_name: str) -> Path:
        output_dir = settings.reports_path
        output_dir.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            out = output_dir / f"{report_name}.json"
            out.write_text(self._to_json(ctx), encoding="utf-8")
            return out

        if fmt == "markdown":
            out = output_dir / f"{report_name}.md"
            out.write_text(self._to_markdown(ctx, template_name), encoding="utf-8")
            return out

        # HTML / PDF both need the Jinja template
        try:
            tmpl = self.env.get_template(template_name)
            html_content = tmpl.render(**ctx)
        except Exception:
            html_content = self._fallback_html(ctx, template_name)

        if fmt == "html":
            out = output_dir / f"{report_name}.html"
            out.write_text(html_content, encoding="utf-8")
            return out

        if fmt == "pdf":
            out = output_dir / f"{report_name}.pdf"
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(str(out))
            except ImportError:
                logger.warning("weasyprint not available, falling back to HTML")
                out = output_dir / f"{report_name}.html"
                out.write_text(html_content, encoding="utf-8")
            return out

        raise ValueError(f"Unknown format: {fmt}")

    # ── Serialisation helpers ─────────────────────────────────────────────────

    def _finding_to_dict(self, f) -> dict:
        return {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "tool": f.tool,
            "category": f.category,
            "location": f.location,
            "description": f.description,
            "owasp_mapping": f.owasp_mapping,
            "cwe_mapping": f.cwe_mapping,
        }

    def _to_json(self, ctx: dict) -> str:
        safe: dict = {}
        for k, v in ctx.items():
            if isinstance(v, list):
                safe[k] = [self._finding_to_dict(i) for i in v if hasattr(i, "title")]
            elif hasattr(v, "__table__"):
                safe[k] = {"id": str(getattr(v, "id", "")), "name": getattr(v, "name", "")}
            elif isinstance(v, datetime):
                safe[k] = v.isoformat()
            else:
                safe[k] = v
        return json.dumps(safe, indent=2, default=str)

    def _to_markdown(self, ctx: dict, template: str) -> str:
        project = ctx.get("project")
        findings = ctx.get("all_findings") or ctx.get("findings") or []
        generated_at = ctx.get("generated_at", datetime.utcnow())
        lines = [
            f"# IRVES {template.upper()} Report",
            f"**Project:** {getattr(project, 'name', 'Unknown')}",
            f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Findings",
            "",
        ]
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines += [
                f"### {f.title}",
                f"- **Severity:** `{sev.upper()}`",
                f"- **Tool:** {f.tool}",
                f"- **Location:** {f.location or 'N/A'}",
                f"- **Category:** {f.category or 'N/A'}",
                f"- **OWASP:** {f.owasp_mapping or 'N/A'}",
                "",
                f.description or "",
                "",
            ]
        return "\n".join(lines)

    def _fallback_html(self, ctx: dict, template_name: str) -> str:
        """Minimal HTML if Jinja template is missing."""
        project = ctx.get("project")
        findings = ctx.get("all_findings") or ctx.get("findings") or []
        rows = "".join(
            f"<tr><td>{f.title}</td><td>{f.severity.value if hasattr(f.severity,'value') else f.severity}</td><td>{f.tool}</td><td>{f.location or ''}</td></tr>"
            for f in findings
        )
        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>IRVES {template_name} Report</title>
<style>body{{font-family:sans-serif;padding:2rem;}}table{{border-collapse:collapse;width:100%;}}th,td{{border:1px solid #ccc;padding:.5rem;text-align:left;}}th{{background:#f0f0f0;}}</style>
</head><body>
<h1>IRVES Report — {getattr(project,'name','')}</h1>
<h2>Findings ({len(findings)} total)</h2>
<table><thead><tr><th>Title</th><th>Severity</th><th>Tool</th><th>Location</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""


# Global singleton
report_generator = ReportGenerator()
