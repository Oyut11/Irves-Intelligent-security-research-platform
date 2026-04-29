"""
IRVES — Architecture Analyzer
Analyzes architecture: tech stack, directory structure, arch style, patterns, coupling.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.tech_detection import (
    detect_tech_stack, analyze_directory_structure, detect_arch_style,
    detect_all_patterns, analyze_imports, generate_arch_observations,
)
from services.source_analysis.reports import build_architecture_report
from services.source_analysis.report_utils import resolve_project_name

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)



def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


async def analyze_architecture(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze architecture: produces a comprehensive architecture report as a single finding."""
    logger.info("[SourceAnalysis] Analyzing architecture — generating comprehensive report")

    try:
        # Resolve project name from DB
        project_name = None
        try:
            from database.crud import get_source_analysis_result, get_project
            ar = await get_source_analysis_result(get_db(), analysis_result_id)
            if ar and ar.project_id:
                proj = await get_project(get_db(), ar.project_id)
                if proj:
                    project_name = proj.name
        except Exception:
            pass

        files = await git_service.get_file_list(repo_path)

        # ── 1. Technology Stack ──
        tech_stack = detect_tech_stack(repo_path, files)

        # ── 2. Directory Structure ──
        dir_structure = analyze_directory_structure(repo_path, files)

        # ── 3. Architectural Style ──
        arch_style = detect_arch_style(repo_path, dir_structure, tech_stack)

        # ── 4. Design Patterns (aggregated) ──
        pattern_counts = detect_all_patterns(repo_path, files)

        # ── 5. Coupling & Cohesion (real import analysis) ──
        coupling, cohesion, import_stats = analyze_imports(repo_path, files)

        # ── 6. Key Observations ──
        observations = generate_arch_observations(tech_stack, arch_style, coupling, cohesion, import_stats, dir_structure)

        # ── 7. Build the markdown report ──
        report = build_architecture_report(
            repo_path, tech_stack, dir_structure, arch_style,
            pattern_counts, coupling, cohesion, import_stats, observations,
            project_name=project_name
        )

        findings = [{
            "type": "architecture_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "arch_analyzer",
            "extra_data": {
                "tech_stack": tech_stack,
                "arch_style": arch_style,
                "coupling": coupling,
                "cohesion": cohesion,
                "pattern_counts": pattern_counts,
            },
        }]

        summary = {
            "total_findings": 1,
            "tech_stack": tech_stack,
            "arch_style": arch_style,
            "coupling_score": coupling,
            "cohesion_score": cohesion,
            "module_count": len(files),
            "pattern_counts": pattern_counts,
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Architecture analysis failed: {e}")
        findings = [{
            "type": "architecture_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Architecture Report\n\nAnalysis failed: {e}",
            "tool": "arch_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


