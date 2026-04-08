"""
IRVES — Database Package
Async SQLite database layer with SQLAlchemy.
"""

from database.connection import get_db, get_db_session, init_db, close_db
from database.crud import (
    create_project,
    get_project,
    get_projects,
    update_project,
    delete_project,
    create_scan,
    get_scan,
    get_scans_by_project,
    update_scan_status,
    update_scan_progress,
    update_scan_progress_standalone,
    create_finding,
    get_finding,
    get_findings_by_scan,
    update_finding_status,
    create_tool_execution,
    update_tool_execution,
    get_tool_executions_by_scan,
    count_findings_by_severity,
    create_report,
    get_report,
    get_reports_by_project,
    update_report_file,
)
from database.models import (
    Project,
    Scan,
    Finding,
    ToolExecution,
    Report,
    ScanStatus,
    FindingSeverity,
    FindingStatus,
    ToolExecutionStatus,
)

__all__ = [
    # Connection
    "get_db",
    "get_db_session",
    "init_db",
    "close_db",
    # Models
    "Project",
    "Scan",
    "Finding",
    "ToolExecution",
    "Report",
    "ScanStatus",
    "FindingSeverity",
    "FindingStatus",
    "ToolExecutionStatus",
    # CRUD
    "create_project",
    "get_project",
    "get_projects",
    "update_project",
    "delete_project",
    "create_scan",
    "get_scan",
    "get_scans_by_project",
    "update_scan_status",
    "update_scan_progress",
    "create_finding",
    "get_finding",
    "get_findings_by_scan",
    "update_finding_status",
    "create_tool_execution",
    "update_tool_execution",
    "get_tool_executions_by_scan",
    "count_findings_by_severity",
    "create_report",
    "get_report",
    "get_reports_by_project",
    "update_report_file",
]