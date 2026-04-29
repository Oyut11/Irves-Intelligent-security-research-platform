"""
IRVES — Settings Service
Handles persistence of user settings (API keys, tool paths, integrations).
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

from config import settings

logger = logging.getLogger(__name__)

_SETTINGS_FILE = Path.home() / ".irves" / "settings.json"
_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)

_DEFAULT_SETTINGS = {
    "ai": {
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "api_key": "",
        "api_base": "",
    },
    "device": {
        "adb_path": "adb",
        "frida_server_path": "/data/local/tmp/frida-server",
    },
    "scan": {
        "default_profile": "standard",
        "output_dir": str(settings.projects_path),
    },
    "integrations": {
        "github": {
            "connected": False,
            "access_token": "",
            "username": "",
        },
        "gitlab": {
            "connected": False,
            "access_token": "",
            "username": "",
        }
    }
}

class SettingsService:
    """Service for managing user settings persistence."""

    def load(self) -> Dict[str, Any]:
        """Load settings from disk, merging with defaults."""
        if _SETTINGS_FILE.exists():
            try:
                on_disk = json.loads(_SETTINGS_FILE.read_text())
                merged = self._deep_merge(dict(_DEFAULT_SETTINGS), on_disk)
                return merged
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load settings: {e}")
        return dict(_DEFAULT_SETTINGS)

    def save(self, data: Dict[str, Any]) -> None:
        """Persist settings to disk."""
        try:
            _SETTINGS_FILE.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.error(f"Failed to save settings: {e}")

    def update_section(self, section: str, values: Dict[str, Any]) -> Dict[str, Any]:
        """Update a specific section and return the full settings."""
        current = self.load()
        if section not in current:
            current[section] = {}
        
        # Deep merge for the section
        current[section] = self._deep_merge(current[section], values)
        self.save(current)
        return current

    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """Recursive merge of dictionaries."""
        for k, v in update.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                base[k] = self._deep_merge(base[k], v)
            else:
                base[k] = v
        return base

# Global singleton
settings_service = SettingsService()
