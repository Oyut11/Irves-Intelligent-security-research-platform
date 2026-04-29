"""
IRVES — Source Analysis Report Utilities
Shared helpers for report generation.
"""

from pathlib import Path
from typing import Optional


def resolve_project_name(repo_path: Path, project_name: Optional[str] = None) -> str:
    """Resolve project name from repo path or use provided name."""
    if project_name:
        return project_name
    dir_name = repo_path.name
    if dir_name.endswith("_src") and len(dir_name.split("_")[0]) == 8:
        return dir_name.replace("_src", "")
    return dir_name.replace("_src", "").replace("_", " ").title()
