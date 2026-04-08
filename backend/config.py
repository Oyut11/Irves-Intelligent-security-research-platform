"""
IRVES — Configuration Module
Environment-based configuration with sensible defaults.
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from pathlib import Path
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──────────────────────────────────────────────────────
    APP_NAME: str = "IRVES"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # ── Database ─────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./irves.db"

    # ── Tool Paths ───────────────────────────────────────────────
    APKTOOL_PATH: str = "apktool"
    JADX_PATH: str = "jadx"
    FRIDA_PATH: str = "frida"
    MITMPROXY_PATH: str = "mitmproxy"

    # ── MobSF ────────────────────────────────────────────────────
    MOBSF_URL: str = "http://127.0.0.1:8000"
    MOBSF_API_KEY: str = ""

    # ── AI ───────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    AI_MODEL: str = "claude-sonnet-4-6"

    # ── Storage ──────────────────────────────────────────────────
    PROJECTS_DIR: str = "~/.irves/projects"
    REPORTS_DIR: str = "~/.irves/reports"

    # ── Server ───────────────────────────────────────────────────
    HOST: str = "127.0.0.1"
    PORT: int = 8765

    @field_validator("PROJECTS_DIR", "REPORTS_DIR", mode="before")
    @classmethod
    def expand_path(cls, v: str) -> str:
        """Expand ~ to user home directory."""
        return str(Path(v).expanduser())

    @property
    def projects_path(self) -> Path:
        """Get projects directory as Path object."""
        return Path(self.PROJECTS_DIR)

    @property
    def reports_path(self) -> Path:
        """Get reports directory as Path object."""
        return Path(self.REPORTS_DIR)

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.projects_path.mkdir(parents=True, exist_ok=True)
        self.reports_path.mkdir(parents=True, exist_ok=True)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Global settings instance
settings = Settings()