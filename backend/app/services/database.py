"""Shared SQLAlchemy database layer for SQLite and MySQL."""

import os
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from sqlalchemy import (
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.engine import Connection, Engine


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "incident_memory.db"

metadata = MetaData()

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(255), nullable=False),
    Column("logs", Text, nullable=False),
    Column("analysis_json", Text, nullable=False),
    Column("fix_description", Text, nullable=True),
    Column(
        "verification_status",
        String(32),
        nullable=False,
        server_default="not_run",
    ),
    Column(
        "verification_notes",
        Text,
        nullable=False,
    ),
    Column("created_at", String(64), nullable=False),
    Column("verified_at", String(64), nullable=True),
)

auth_users = Table(
    "auth_users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(64), nullable=False, unique=True),
    Column("password_hash", String(255), nullable=False),
    Column("created_at", String(64), nullable=False),
)

auth_sessions = Table(
    "auth_sessions",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column(
        "user_id",
        Integer,
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("created_at", String(64), nullable=False),
    Column("expires_at", String(64), nullable=False),
)

Index("idx_auth_sessions_expiry", auth_sessions.c.expires_at)


def get_database_url() -> str:
    configured_url = os.getenv("DATABASE_URL", "").strip()
    if configured_url:
        return configured_url

    db_path = Path(os.getenv("INCIDENT_DB_PATH", str(DEFAULT_DB_PATH)))
    return f"sqlite:///{db_path}"


@lru_cache(maxsize=8)
def _engine_for_url(database_url: str) -> Engine:
    if database_url.startswith("sqlite:"):
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


def get_engine() -> Engine:
    return _engine_for_url(get_database_url())


@contextmanager
def get_connection() -> Iterator[Connection]:
    with get_engine().begin() as connection:
        yield connection


def init_db() -> None:
    """Create missing tables without deleting existing data."""
    metadata.create_all(get_engine())
