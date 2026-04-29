"""
IRVES — Database Connection
Async SQLite connection management with SQLAlchemy.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import event
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

from config import settings

logger = logging.getLogger(__name__)

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    # NullPool: every session checkout opens a fresh connection and returns
    # it on close.  This is essential for SQLite — a single long-lived
    # connection holds the write lock and blocks all other writers.
    poolclass=NullPool,  # No connection pooling — essential for SQLite concurrency
    # connect_args: SQLite WAL mode + 60s busy timeout (prevents write-contention lockups)
    connect_args={
        "timeout": 60,  # seconds to wait for lock acquisition
        "check_same_thread": False,
    },
)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()


def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Set PRAGMA settings for better concurrency on every new pooled connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=60000")  # 60 seconds retry timeout
    cursor.close()


# Register the listener on the synchronous engine underlying the async engine
# This is safe because the sync engine is used for pooled connections
from sqlalchemy import text  # noqa: E402,F811

# Note: for async engines we attach to the underlying sync engine pool events via event.listen
event.listen(engine.sync_engine, "connect", _set_sqlite_pragma)


async def init_db() -> None:
    """
    Initialize database - create all tables.
    Called on application startup.
    """
    async with engine.begin() as conn:
        # Import models to register them with Base
        from database import models  # noqa: F401

        # Phase 5: Enable WAL (Write-Ahead Logging) for SQLite concurrency
        from sqlalchemy import text
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA synchronous=NORMAL"))

        # Create all tables (idempotent — won't recreate existing ones)
        await conn.run_sync(Base.metadata.create_all)

        # Safe migrations: add columns introduced after initial schema creation.
        # SQLite doesn't support IF NOT EXISTS on ALTER TABLE,
        # so we check the column list first.
        
        # Migrate projects table
        result = await conn.execute(text("PRAGMA table_info(projects)"))
        existing_columns = {row[1] for row in result.fetchall()}

        git_columns = {
            "source_type": "VARCHAR(10) DEFAULT 'upload'",
            "repo_url":    "TEXT",
            "repo_branch": "VARCHAR(255) DEFAULT 'main'",
            "repo_token":  "TEXT",
        }
        for col_name, col_def in git_columns.items():
            if col_name not in existing_columns:
                await conn.execute(
                    text(f"ALTER TABLE projects ADD COLUMN {col_name} {col_def}")
                )
                logger.info(f"[DB Migration] Added column projects.{col_name}")
        
        # Migrate scans table
        result = await conn.execute(text("PRAGMA table_info(scans)"))
        existing_scan_columns = {row[1] for row in result.fetchall()}
        
        scan_columns = {
            "ast_data": "JSON",
        }
        for col_name, col_def in scan_columns.items():
            if col_name not in existing_scan_columns:
                await conn.execute(
                    text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_def}")
                )
                logger.info(f"[DB Migration] Added column scans.{col_name}")

    logger.info(f"[IRVES] Database initialized at {settings.DATABASE_URL}")


async def close_db() -> None:
    """
    Close database connections.
    Called on application shutdown.
    """
    await engine.dispose()
    logger.info("[IRVES] Database connections closed")


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session as async context manager.

    Usage:
        async with get_db() as db:
            result = await db.execute(query)
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db_session() -> AsyncSession:
    """
    Get database session for dependency injection.

    Usage in FastAPI:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db_session)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise