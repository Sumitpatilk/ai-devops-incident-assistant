import os

import pytest

from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.services.auth_store import (
    authenticate_user,
    create_session,
    create_user,
    delete_session,
    get_session_user,
)
from app.services.database import get_connection, get_engine, init_db
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
    allowed_database = os.getenv(
        "MYSQL_INTEGRATION_TEST_DATABASE",
        "incident_assistant_test",
    )
    if (
        parsed_url.get_backend_name() != "mysql"
        or parsed_url.database != allowed_database
    ):
        raise RuntimeError(
            "Safety check failed: tests require the dedicated "
            "incident_assistant_test MySQL database."
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
