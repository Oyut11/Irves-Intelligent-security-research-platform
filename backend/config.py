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

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _parse_debug(cls, v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("1", "true", "yes", "on")
        return bool(v)
    ENVIRONMENT: str = "development"

    # ── Database ─────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./irves.db"

    # ── Tool Paths ───────────────────────────────────────────────
    APKTOOL_PATH: str = "apktool"
    JADX_PATH: str = "jadx"
    FRIDA_PATH: str = "frida"
    MITMPROXY_PATH: str = "mitmproxy"

    # ── AI ───────────────────────────────────────────────────────
    # We use LiteLLM for routing. Format for AI_MODEL:
    # "anthropic/claude-3-5-sonnet-20240620"
    # "openai/gpt-4o"
    # "ollama/llama3"
    AI_MODEL: str = "anthropic/claude-3-5-sonnet-20240620"
    
    # Generic keys for provider routing
    AI_API_KEY: str = ""
    AI_API_BASE: str = ""
    AI_PROVIDER: str = "anthropic"  # Active provider name (used in UI selection)
    
    
    # Fallbacks that LiteLLM looks for automatically
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    XAI_API_KEY: str = ""
    DEEPSEEK_API_KEY: str = ""
    TOGETHER_AI_API_KEY: str = ""
    HUGGINGFACE_API_KEY: str = ""

    # ── Storage ──────────────────────────────────────────────────
    PROJECTS_DIR: str = "~/.irves/projects"
    REPORTS_DIR: str = "~/.irves/reports"

    # ── Server ───────────────────────────────────────────────────
    HOST: str = "127.0.0.1"
    PORT: int = 8765
    SECRET_KEY: str = ""
    REDIRECT_URI: str = os.getenv("REDIRECT_URI", f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8765')}/api/auth/callback")

    # ── Git Integrations (Platform Level App Auth) ────────────────
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITLAB_CLIENT_ID: str = ""
    GITLAB_CLIENT_SECRET: str = ""

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