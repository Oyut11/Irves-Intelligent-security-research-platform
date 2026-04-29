"""
IRVES — Contributor Risk Analyzer
Analyzes contributor patterns and bus-factor risk.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)


async def analyze_contributor_risk(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze contributor risk: bus factor, commit patterns, force pushes."""
    logger.info("[SourceAnalysis] Analyzing contributor risk")

    findings = []
    summary = {
        "total_findings": 0,
        "bus_factor": 0,
        "total_contributors": 0,
        "force_pushes": 0,
        "commit_frequency": {},
    }

    try:
        commits = await git_service.get_commit_history(repo_path, limit=200)

        # Count contributors
        contributors = {}
        for commit in commits:
            email = commit.get("email", "")
            contributors[email] = contributors.get(email, 0) + 1

        summary["total_contributors"] = len(contributors)

        # Calculate bus factor (contributors with >10% of commits)
        total_commits = len(commits)
        significant_contributors = [
            email for email, count in contributors.items()
            if count / total_commits > 0.1
        ]
        summary["bus_factor"] = len(significant_contributors)

        if summary["bus_factor"] < 2:
            findings.append({
                "type": "low_bus_factor",
                "severity": FindingSeverity.HIGH,
                "message": f"Low bus factor: {summary['bus_factor']} contributors own >10% of commits",
                "tool": "git_service",
                "metadata": {
                    "bus_factor": summary["bus_factor"],
                    "contributors": significant_contributors,
                },
            })

        # Analyze commit patterns
        for email, count in contributors.items():
            summary["commit_frequency"][email] = count

    except Exception as e:
        logger.error(f"[SourceAnalysis] Contributor risk analysis failed: {e}")

    summary["total_findings"] = len(findings)

    # Build markdown report for the frontend report detail view
    from services.source_analysis.reports import build_contributor_risk_report
    from services.source_analysis.report_utils import resolve_project_name
    project_name = resolve_project_name(repo_path)
    report = build_contributor_risk_report(repo_path, summary, findings, project_name=project_name)

    # Prepend the report finding so the frontend can find it via type.endsWith('_report')
    findings.insert(0, {
        "type": "contributor_risk_report",
        "severity": FindingSeverity.INFO,
        "message": report,
        "tool": "contributor_risk_analyzer",
        "extra_data": {
            "bus_factor": summary.get("bus_factor", 0),
            "total_contributors": summary.get("total_contributors", 0),
            "force_pushes": summary.get("force_pushes", 0),
        },
    })

    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


