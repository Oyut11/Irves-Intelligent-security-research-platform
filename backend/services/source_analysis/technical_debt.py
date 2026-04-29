"""
IRVES — Technical Debt Analyzer
Analyzes technical debt indicators and anti-patterns.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)


async def analyze_technical_debt(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze technical debt: TODO density, refactor candidates, legacy age."""
    logger.info("[SourceAnalysis] Analyzing technical debt")

    findings = []
    summary = {
        "total_findings": 0,
        "todo_count": 0,
        "fixme_count": 0,
        "hack_count": 0,
        "legacy_files": 0,
    }

    try:
        files = await git_service.get_file_list(repo_path)
        commits = await git_service.get_commit_history(repo_path, limit=100)

        # Analyze TODO/FIXME/HACK comments
        for file_path in files:
            file_full_path = repo_path / file_path
            if not file_full_path.exists():
                continue

            try:
                content = file_full_path.read_text(errors="ignore")
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    if "TODO" in line.upper():
                        summary["todo_count"] += 1
                        findings.append({
                            "type": "todo_comment",
                            "severity": FindingSeverity.LOW,
                            "file_path": file_path,
                            "line_number": i,
                            "message": line.strip(),
                            "tool": "custom",
                            "metadata": {"type": "TODO"},
                        })
                    elif "FIXME" in line.upper():
                        summary["fixme_count"] += 1
                        findings.append({
                            "type": "fixme_comment",
                            "severity": FindingSeverity.MEDIUM,
                            "file_path": file_path,
                            "line_number": i,
                            "message": line.strip(),
                            "tool": "custom",
                            "metadata": {"type": "FIXME"},
                        })
                    elif "HACK" in line.upper():
                        summary["hack_count"] += 1
                        findings.append({
                            "type": "hack_comment",
                            "severity": FindingSeverity.MEDIUM,
                            "file_path": file_path,
                            "line_number": i,
                            "message": line.strip(),
                            "tool": "custom",
                            "metadata": {"type": "HACK"},
                        })

            except Exception as e:
                logger.warning(f"[Technical Debt] Failed to analyze file {file_path}: {e}")

        # Analyze file age from git history
        file_ages = {}
        for commit in commits:
            # Track last commit date per file (simplified implementation)
            for changed_file in commit.get("files", []):
                if changed_file not in file_ages:
                    file_ages[changed_file] = commit.get("date", "")

        # Mark files older than 1 year as legacy
        from datetime import datetime, timedelta
        one_year_ago = datetime.now() - timedelta(days=365)
        legacy_count = 0
        for file_path, date_str in file_ages.items():
            try:
                file_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if file_date < one_year_ago:
                    legacy_count += 1
            except Exception:
                pass
        summary["legacy_files"] = legacy_count

    except Exception as e:
        logger.error(f"[SourceAnalysis] Technical debt analysis failed: {e}")
        return {
            "summary_metrics": summary,
            "detailed_findings": {},
            "findings": findings,
        }

    summary["total_findings"] = len(findings)

    # Build markdown report for the frontend report detail view
    from services.source_analysis.reports import build_technical_debt_report
    from services.source_analysis.report_utils import resolve_project_name
    project_name = resolve_project_name(repo_path)
    report = build_technical_debt_report(repo_path, summary, findings, project_name=project_name)

    # Prepend the report finding so the frontend can find it via type.endsWith('_report')
    findings.insert(0, {
        "type": "technical_debt_report",
        "severity": FindingSeverity.INFO,
        "message": report,
        "tool": "tech_debt_analyzer",
        "extra_data": {
            "td_score": max(0, 10 - summary.get("todo_count", 0) * 0.1 - summary.get("fixme_count", 0) * 0.2 - summary.get("hack_count", 0) * 0.3 - summary.get("legacy_files", 0) * 0.05),
            "todo_count": summary.get("todo_count", 0),
            "fixme_count": summary.get("fixme_count", 0),
            "hack_count": summary.get("hack_count", 0),
        },
    })

    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


