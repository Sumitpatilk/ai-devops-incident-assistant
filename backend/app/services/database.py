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
    inspect,
    text,
)
from sqlalchemy.engine import Connection, Engine


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "incident_memory.db"

metadata = MetaData()

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "user_id",
        Integer,
        ForeignKey("auth_users.id"),
        nullable=True,
    ),
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
Index("idx_incidents_user_id", incidents.c.user_id)


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


def migrate_incident_ownership() -> None:
    """Safely add incident ownership after checking legacy ownership ambiguity.

    Run only after a verified backup and isolated-database testing.
    This function is intentionally not called by init_db.
    """
    engine = get_engine()

    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())

        if "incidents" not in tables:
            raise RuntimeError("The incidents table does not exist.")
        if "auth_users" not in tables:
            raise RuntimeError("The auth_users table does not exist.")

        columns = {
            column["name"]
            for column in inspector.get_columns("incidents")
        }

        # Preflight before making schema changes.
        if "user_id" not in columns:
            unowned_count = connection.execute(
                text("SELECT COUNT(*) FROM incidents")
            ).scalar_one()
        else:
            unowned_count = connection.execute(
                text("SELECT COUNT(*) FROM incidents WHERE user_id IS NULL")
            ).scalar_one()

        if unowned_count:
            user_count = connection.execute(
                text("SELECT COUNT(*) FROM auth_users")
            ).scalar_one()

            if user_count != 1:
                raise RuntimeError(
                    "Cannot safely assign legacy incidents: expected exactly "
                    "one user when unowned incidents exist. No owner was guessed."
                )

        if "user_id" not in columns:
            if connection.dialect.name == "sqlite":
                connection.execute(text(
                    "ALTER TABLE incidents "
                    "ADD COLUMN user_id INTEGER REFERENCES auth_users(id)"
                ))
            elif connection.dialect.name == "mysql":
                connection.execute(text(
                    "ALTER TABLE incidents ADD COLUMN user_id INTEGER NULL"
                ))
            else:
                raise RuntimeError(
                    "Incident ownership migration supports SQLite and MySQL only."
                )

        inspector = inspect(connection)
        columns = {
            column["name"]
            for column in inspector.get_columns("incidents")
        }
        foreign_keys = inspector.get_foreign_keys("incidents")
        has_owner_foreign_key = any(
            fk.get("constrained_columns") == ["user_id"]
            and fk.get("referred_table") == "auth_users"
            and fk.get("referred_columns") == ["id"]
            for fk in foreign_keys
        )

        if not has_owner_foreign_key:
            if connection.dialect.name == "mysql":
                connection.execute(text(
                    "ALTER TABLE incidents "
                    "ADD CONSTRAINT fk_incidents_user_id_auth_users "
                    "FOREIGN KEY (user_id) REFERENCES auth_users(id)"
                ))
            elif connection.dialect.name == "sqlite":
                raise RuntimeError(
                    "SQLite incidents.user_id exists without the required "
                    "foreign key. Use a separately tested table rebuild."
                )
            else:
                raise RuntimeError(
                    "Cannot create the incident owner foreign key on this database."
                )

        indexes = {
            index["name"]
            for index in inspect(connection).get_indexes("incidents")
        }
        if "idx_incidents_user_id" not in indexes:
            connection.execute(text(
                "CREATE INDEX idx_incidents_user_id ON incidents (user_id)"
            ))

        if unowned_count:
            connection.execute(text(
                "UPDATE incidents SET user_id = "
                "(SELECT id FROM auth_users LIMIT 1) WHERE user_id IS NULL"
            ))

        remaining = connection.execute(text(
            "SELECT COUNT(*) FROM incidents WHERE user_id IS NULL"
        )).scalar_one()

        if remaining:
            raise RuntimeError(
                "Incident ownership migration left unowned records."
            )
