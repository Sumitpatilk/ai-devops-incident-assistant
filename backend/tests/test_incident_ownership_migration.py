import sqlite3

import pytest
from sqlalchemy import create_engine, inspect, text

from app.services.database import (
    auth_users,
    migrate_incident_ownership,
)


def _create_legacy_database(db_path, monkeypatch):
    """Create an isolated database with the pre-ownership incidents schema."""
    database_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("INCIDENT_DB_PATH", str(db_path))

    engine = create_engine(database_url)

    # Create only the users table. Do not use metadata.create_all here:
    # the incidents table must retain its legacy schema without user_id.
    auth_users.create(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source VARCHAR(255) NOT NULL,
                    logs TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    fix_description TEXT,
                    verification_status VARCHAR(32) NOT NULL DEFAULT 'not_run',
                    verification_notes TEXT NOT NULL,
                    created_at VARCHAR(64) NOT NULL,
                    verified_at VARCHAR(64)
                )
                """
            )
        )

    engine.dispose()


def _insert_user_and_incidents(db_path, users, incident_count):
    """Insert test records directly into the temporary SQLite file."""
    connection = sqlite3.connect(db_path)
    try:
        user_ids = []

        for username in users:
            cursor = connection.execute(
                """
                INSERT INTO auth_users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (username, "test-hash", "2026-01-01T00:00:00Z"),
            )
            user_ids.append(cursor.lastrowid)

        for index in range(incident_count):
            connection.execute(
                """
                INSERT INTO incidents (
                    source, logs, analysis_json, fix_description,
                    verification_status, verification_notes,
                    created_at, verified_at
                )
                VALUES (?, ?, ?, NULL, 'not_run', '', ?, NULL)
                """,
                (
                    "migration-test",
                    f"test log {index}",
                    '{"severity":"low"}',
                    "2026-01-01T00:00:00Z",
                ),
            )

        connection.commit()
        return user_ids
    finally:
        connection.close()


def test_migration_assigns_legacy_incidents_to_the_only_user(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "legacy_success.db"
    _create_legacy_database(db_path, monkeypatch)
    user_ids = _insert_user_and_incidents(db_path, ["only-user"], 3)

    migrate_incident_ownership()

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text("SELECT id, user_id FROM incidents ORDER BY id")
            ).all()

        assert len(rows) == 3
        assert all(row.user_id == user_ids[0] for row in rows)

        inspector = inspect(engine)
        foreign_keys = inspector.get_foreign_keys("incidents")
        assert any(
            fk.get("constrained_columns") == ["user_id"]
            and fk.get("referred_table") == "auth_users"
            and fk.get("referred_columns") == ["id"]
            for fk in foreign_keys
        )

        indexes = {
            index["name"] for index in inspector.get_indexes("incidents")
        }
        assert "idx_incidents_user_id" in indexes
    finally:
        engine.dispose()


def test_migration_refuses_to_guess_between_multiple_users(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "legacy_ambiguous.db"
    _create_legacy_database(db_path, monkeypatch)
    _insert_user_and_incidents(
        db_path, ["user-one", "user-two"], 2
    )

    with pytest.raises(
        RuntimeError,
        match="Cannot safely assign legacy incidents",
    ):
        migrate_incident_ownership()

    # Verify ambiguity is rejected before changing the legacy schema.
    connection = sqlite3.connect(db_path)
    try:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(incidents)")
        }
        assert "user_id" not in columns

        rows = connection.execute(
            "SELECT id FROM incidents ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
    finally:
        connection.close()


def test_migration_is_idempotent_after_success(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy_idempotent.db"
    _create_legacy_database(db_path, monkeypatch)
    user_ids = _insert_user_and_incidents(db_path, ["stable-user"], 2)

    migrate_incident_ownership()
    migrate_incident_ownership()

    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT user_id FROM incidents ORDER BY id"
        ).fetchall()
        assert rows == [(user_ids[0],), (user_ids[0],)]
        assert connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0] == "ok"
    finally:
        connection.close()
