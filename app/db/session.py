"""Database engine and session factory utilities."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import _build_settings_source


def get_database_url() -> str:
    """Resolve the database URL from `.env` or process environment."""
    settings_source = _build_settings_source(env=None, dotenv_path=None)
    database_url = settings_source.get("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL must be configured before using the database layer.")
    return database_url


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Create and cache the primary SQLAlchemy engine."""
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    """Return the configured SQLAlchemy session factory."""
    return sessionmaker(
        bind=get_engine(),
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def get_db_session() -> Iterator[Session]:
    """Yield a database session for request or job-scoped work."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
