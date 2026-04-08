"""
IRVES — ID Utilities
Unique identifier generation.
"""

import uuid
import time
import secrets


def generate_short_id(length: int = 8) -> str:
    """
    Generate a short, URL-safe unique ID.

    Args:
        length: Length of the ID (default 8)

    Returns:
        Unique ID string
    """
    # Use UUID4 and take first N characters
    return uuid.uuid4().hex[:length]


def generate_scan_id() -> str:
    """Generate a scan ID with prefix."""
    return f"scan_{generate_short_id(8)}"


def generate_project_id() -> str:
    """Generate a project ID."""
    return generate_short_id(8)


def generate_finding_id() -> str:
    """Generate a finding ID with prefix."""
    return f"find_{generate_short_id(8)}"


def generate_report_id() -> str:
    """Generate a report ID with prefix."""
    return f"rpt_{generate_short_id(8)}"


def generate_timestamp_id() -> str:
    """
    Generate an ID based on timestamp for sortable IDs.

    Returns:
        Timestamp-based ID (e.g., "20240115_a1b2c3d4")
    """
    timestamp = time.strftime("%Y%m%d")
    random_part = secrets.token_hex(4)
    return f"{timestamp}_{random_part}"