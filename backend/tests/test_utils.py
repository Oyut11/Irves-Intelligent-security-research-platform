"""
IRVES — Unit Tests for Utility Modules
Tests for id_utils and file_utils (pure functions, no external dependencies).
"""

import os
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

import pytest

# ── id_utils ──────────────────────────────────────────────────────────────────

from utils.id_utils import (
    generate_short_id,
    generate_scan_id,
    generate_project_id,
    generate_finding_id,
    generate_report_id,
    generate_timestamp_id,
)


class TestGenerateShortId:
    def test_default_length(self):
        assert len(generate_short_id()) == 8

    def test_custom_length(self):
        assert len(generate_short_id(12)) == 12

    def test_hex_characters(self):
        sid = generate_short_id()
        assert sid.isalnum()

    def test_uniqueness(self):
        ids = {generate_short_id() for _ in range(100)}
        assert len(ids) == 100


class TestGenerateScanId:
    def test_prefix(self):
        sid = generate_scan_id()
        assert sid.startswith("scan_")

    def test_length(self):
        sid = generate_scan_id()
        assert len(sid) == 13  # "scan_" + 8 chars


class TestGenerateProjectId:
    def test_no_prefix(self):
        pid = generate_project_id()
        assert len(pid) == 8


class TestGenerateFindingId:
    def test_prefix(self):
        fid = generate_finding_id()
        assert fid.startswith("find_")

    def test_length(self):
        fid = generate_finding_id()
        assert len(fid) == 13  # "find_" + 8 chars


class TestGenerateReportId:
    def test_prefix(self):
        rid = generate_report_id()
        assert rid.startswith("rpt_")

    def test_length(self):
        rid = generate_report_id()
        assert len(rid) == 12  # "rpt_" + 8 chars


class TestGenerateTimestampId:
    def test_date_prefix(self):
        tid = generate_timestamp_id()
        today = datetime.now().strftime("%Y%m%d")
        assert tid.startswith(f"{today}_")

    def test_format(self):
        tid = generate_timestamp_id()
        parts = tid.split("_")
        assert len(parts) == 2
        assert len(parts[0]) == 8  # YYYYMMDD
        assert len(parts[1]) == 8  # 4 bytes hex


# ── file_utils ────────────────────────────────────────────────────────────────

from utils.file_utils import (
    ensure_directory,
    get_file_hash,
    get_file_size,
    safe_filename,
    format_file_size,
    detect_platform,
    cleanup_old_files,
)


class TestEnsureDirectory:
    def test_creates_directory(self, tmp_path):
        new_dir = tmp_path / "new" / "nested"
        result = ensure_directory(new_dir)
        assert result.exists()
        assert result.is_dir()

    def test_existing_directory(self, tmp_path):
        result = ensure_directory(tmp_path)
        assert result == tmp_path


class TestGetFileHash:
    def test_sha256(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        h = get_file_hash(f)
        assert len(h) == 64  # SHA-256 hex length

    def test_md5(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        h = get_file_hash(f, "md5")
        assert len(h) == 32  # MD5 hex length

    def test_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("same content")
        assert get_file_hash(f) == get_file_hash(f)


class TestGetFileSize:
    def test_size(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert get_file_size(f) == 5


class TestSafeFilename:
    def test_removes_unsafe_chars(self):
        assert safe_filename('file<>:"/\\|?*name') == "file________name"

    def test_strips_dots_spaces(self):
        assert safe_filename("  ..file..  ") == "file"

    def test_truncates_long_name(self):
        long_name = "a" * 300 + ".txt"
        assert len(safe_filename(long_name)) <= 255

    def test_fallback_empty(self):
        assert safe_filename("") == "unnamed"

    def test_preserves_extension(self):
        result = safe_filename("a" * 300 + ".txt")
        assert result.endswith(".txt")


class TestFormatFileSize:
    def test_bytes(self):
        assert format_file_size(500) == "500 B"

    def test_kilobytes(self):
        assert format_file_size(1024) == "1.0 KB"

    def test_megabytes(self):
        assert format_file_size(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        assert format_file_size(1024 ** 3) == "1.0 GB"


class TestDetectPlatform:
    def test_apk(self):
        assert detect_platform(Path("app.apk")) == "android"

    def test_aab(self):
        assert detect_platform(Path("app.aab")) == "android"

    def test_ipa(self):
        assert detect_platform(Path("app.ipa")) == "ios"

    def test_exe(self):
        assert detect_platform(Path("app.exe")) == "desktop"

    def test_dmg(self):
        assert detect_platform(Path("app.dmg")) == "desktop"

    def test_unknown(self):
        assert detect_platform(Path("app.zip")) == "unknown"


class TestCleanupOldFiles:
    def test_deletes_old_files(self, tmp_path):
        old_file = tmp_path / "old.txt"
        old_file.write_text("old")

        # Set mtime to 2 days ago
        old_mtime = (datetime.now() - timedelta(hours=48)).timestamp()
        os.utime(old_file, (old_mtime, old_mtime))

        deleted = cleanup_old_files(tmp_path, max_age_hours=24)
        assert deleted == 1
        assert not old_file.exists()

    def test_keeps_new_files(self, tmp_path):
        new_file = tmp_path / "new.txt"
        new_file.write_text("new")

        deleted = cleanup_old_files(tmp_path, max_age_hours=24)
        assert deleted == 0
        assert new_file.exists()

    def test_nonexistent_directory(self):
        assert cleanup_old_files(Path("/nonexistent"), max_age_hours=24) == 0
