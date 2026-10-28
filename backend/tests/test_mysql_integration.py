import os

import pytest

from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url

from app.services.auth_store import (
    authenticate_user,
    create_session,
    create_user,
    delete_session,
    get_session_user,
)
from app.services.database import (
    get_connection,
    get_engine,
    init_db,
    migrate_incident_ownership,
)
from app.services.incident_store import (
    get_incident,
    list_incidents,
    save_incident,
    update_fix_description,
    update_verification,
)


@pytest.mark.skipif(
    not os.getenv("DATABASE_URL"),
    reason="MySQL integration test requires DATABASE_URL from the CI MySQL service.",
)
def test_mysql_incident_and_authentication_flow():
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required for MySQL integration tests.")

    parsed_url = make_url(database_url)
    allowed_database = os.getenv("MYSQL_INTEGRATION_TEST_DATABASE", "")
    destructive_opt_in = os.getenv(
        "MYSQL_INTEGRATION_TESTS_ALLOW_DESTRUCTIVE"
    )

    disposable_databases = {
        "incident_assistant_ci_test",
    }

    if (
        destructive_opt_in != "1"
        or parsed_url.get_backend_name() != "mysql"
        or parsed_url.database not in disposable_databases
        or parsed_url.database != allowed_database
    ):
        raise RuntimeError(
            "Safety check failed: explicitly enable destructive tests "
            "and select an approved disposable MySQL test database."
        )

    assert get_engine().dialect.name == "mysql"
    init_db()

    # This database must be disposable and dedicated to CI tests only.
    with get_connection() as connection:
        connection.execute(
            text("DELETE FROM auth_sessions")
        )
        connection.execute(
            text("DELETE FROM auth_users")
        )
        connection.execute(
            text("DELETE FROM incidents")
        )

    incident = save_incident(
        source="ci-mysql-test",
        logs="Example test log",
        analysis={"severity": "low", "summary": "MySQL integration test"},
    )
    incident_id = incident["id"]

    assert get_incident(incident_id)["analysis"]["severity"] == "low"
    assert any(
        item["id"] == incident_id for item in list_incidents(limit=100)
    )

    updated = update_fix_description(incident_id, "CI test fix")
    assert updated["fix_description"] == "CI test fix"

    verified = update_verification(
        incident_id, "passed", "MySQL integration test succeeded"
    )
    assert verified["verification_status"] == "passed"

    username = "mysql-ci-user"
    password = "mysql-ci-password-12345"
    create_user(username, password)

    user_id = authenticate_user(username, password)
    assert user_id is not None
    assert authenticate_user(username, "wrong-password") is None

    token, _ = create_session(user_id)
    assert get_session_user(token) == username

    delete_session(token)
    assert get_session_user(token) is None


@pytest.mark.skipif(
    not os.getenv("DATABASE_URL"),
    reason="MySQL migration test requires the CI MySQL service.",
)
def test_mysql_ownership_migration_from_legacy_schema():
    database_url = os.getenv("DATABASE_URL", "")
    parsed_url = make_url(database_url)
    allowed_database = os.getenv("MYSQL_INTEGRATION_TEST_DATABASE", "")
    destructive_opt_in = os.getenv("MYSQL_INTEGRATION_TESTS_ALLOW_DESTRUCTIVE")

    if (
        destructive_opt_in != "1"
        or parsed_url.get_backend_name() != "mysql"
        or parsed_url.database != "incident_assistant_ci_test"
        or parsed_url.database != allowed_database
    ):
        raise RuntimeError(
            "Safety check failed: migration test requires the approved "
            "disposable CI MySQL database."
        )

    init_db()

    # Destructive schema setup is allowed only in the disposable CI database.
    with get_connection() as connection:
        connection.execute(text("DELETE FROM auth_sessions"))
        connection.execute(text("DELETE FROM incidents"))
        connection.execute(text("DELETE FROM auth_users"))
        connection.execute(text("DROP TABLE incidents"))
        connection.execute(text("""
            CREATE TABLE incidents (
                id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
                source VARCHAR(255) NOT NULL,
                logs TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                fix_description TEXT NULL,
                verification_status VARCHAR(32) NOT NULL DEFAULT 'not_run',
                verification_notes TEXT NOT NULL,
                created_at VARCHAR(64) NOT NULL,
                verified_at VARCHAR(64) NULL
            )
        """))

    create_user("mysql-migration-user", "mysql-migration-password-12345")

    with get_connection() as connection:
        connection.execute(text("""
            INSERT INTO incidents
                (source, logs, analysis_json, verification_status,
                 verification_notes, created_at)
            VALUES
                ('legacy-ci-1', 'legacy log 1', '{}', 'not_run', '', '2026-01-01'),
                ('legacy-ci-2', 'legacy log 2', '{}', 'not_run', '', '2026-01-02')
        """))

    migrate_incident_ownership()

    with get_connection() as connection:
        owners = connection.execute(
            text("SELECT DISTINCT user_id FROM incidents")
        ).scalars().all()

        assert len(owners) == 1
        assert owners[0] is not None

        assert connection.execute(
            text("SELECT COUNT(*) FROM incidents")
        ).scalar_one() == 2

    inspector = inspect(get_engine())

    foreign_keys = inspector.get_foreign_keys("incidents")
    assert any(
        fk.get("constrained_columns") == ["user_id"]
        and fk.get("referred_table") == "auth_users"
        and fk.get("referred_columns") == ["id"]
        for fk in foreign_keys
    )

    indexes = inspector.get_indexes("incidents")
    assert any(index["name"] == "idx_incidents_user_id" for index in indexes)

    # Re-running must preserve the existing ownership assignments.
    migrate_incident_ownership()

    with get_connection() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM incidents WHERE user_id IS NULL")
        ).scalar_one() == 0
