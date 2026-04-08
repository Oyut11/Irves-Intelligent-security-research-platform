"""
IRVES — File Utilities
File handling helpers.
"""

import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import os
import logging

logger = logging.getLogger(__name__)


def ensure_directory(path: Path) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path

    Returns:
        The path object
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (sha256, md5, sha1)

    Returns:
        Hexadecimal hash string
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def get_file_size(file_path: Path) -> int:
    """
    Get file size in bytes.

    Args:
        file_path: Path to the file

    Returns:
        File size in bytes
    """
    return file_path.stat().st_size


def safe_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize a filename to be safe for filesystem.

    Args:
        filename: Original filename
        max_length: Maximum length

    Returns:
        Safe filename
    """
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    safe = "".join(c if c not in unsafe_chars else "_" for c in filename)

    # Remove leading/trailing dots and spaces
    safe = safe.strip(". ")

    # Truncate if too long
    if len(safe) > max_length:
        name, ext = os.path.splitext(safe)
        max_name = max_length - len(ext)
        safe = name[:max_name] + ext

    # Fallback if empty
    if not safe:
        safe = "unnamed"

    return safe


def cleanup_old_files(directory: Path, max_age_hours: int = 24, pattern: str = "*") -> int:
    """
    Clean up files older than a certain age.

    Args:
        directory: Directory to clean
        max_age_hours: Maximum age in hours
        pattern: File pattern to match

    Returns:
        Number of files deleted
    """
    if not directory.exists():
        return 0

    cutoff = datetime.now() - timedelta(hours=max_age_hours)
    deleted = 0

    for file_path in directory.glob(pattern):
        if file_path.is_file():
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            if mtime < cutoff:
                try:
                    file_path.unlink()
                    deleted += 1
                    logger.debug(f"Deleted old file: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete {file_path}: {e}")

    if deleted > 0:
        logger.info(f"Cleaned up {deleted} old files in {directory}")

    return deleted


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            if unit == "B":
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024

    return f"{size_bytes:.1f} PB"


def detect_platform(file_path: Path) -> str:
    """
    Detect platform from file extension.

    Args:
        file_path: Path to the file

    Returns:
        Platform string (android, ios, desktop, web)
    """
    ext = file_path.suffix.lower()

    platform_map = {
        ".apk": "android",
        ".aab": "android",
        ".ipa": "ios",
        ".app": "ios",
        ".exe": "desktop",
        ".msi": "desktop",
        ".dmg": "desktop",
        ".deb": "desktop",
        ".rpm": "desktop",
        ".appimage": "desktop",
    }

    return platform_map.get(ext, "unknown")


def extract_package_name(file_path: Path) -> str | None:
    """
    Extract package name from APK/IPA file using aapt or similar tools.

    Args:
        file_path: Path to the APK/IPA file

    Returns:
        Package name (e.g., com.example.app) or None if extraction fails
    """
    import subprocess

    ext = file_path.suffix.lower()

    if ext == ".apk":
        # Try aapt (Android Asset Packaging Tool)
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("package: name="):
                        # Format: package: name='com.example.app' versionCode='1' versionName='1.0'
                        for part in line.split():
                            if part.startswith("name="):
                                # Handle both name='value' and name=value formats
                                name = part.split("=", 1)[1]
                                name = name.strip("'\"")
                                return name
        except FileNotFoundError:
            logger.debug("aapt not found, trying aapt2")
        except subprocess.TimeoutExpired:
            logger.warning(f"aapt timeout extracting package name from {file_path}")
        except Exception as e:
            logger.debug(f"Failed to extract package name with aapt: {e}")

        # Try aapt2 as fallback
        try:
            result = subprocess.run(
                ["aapt2", "dump", "badging", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("package: name="):
                        for part in line.split():
                            if part.startswith("name="):
                                name = part.split("=", 1)[1]
                                name = name.strip("'\"")
                                return name
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Failed to extract package name with aapt2: {e}")

    elif ext == ".ipa":
        # For IPA files, the package name is the bundle identifier
        # This is typically in Info.plist within the Payload/*.app directory
        # For now, return None - this would require unzipping and parsing
        pass

    return None