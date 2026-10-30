import pytest
from sqlalchemy import text

from app.services.auth_store import (
    authenticate_user,
    create_user,
    password_hasher,
)
from app.services.database import get_connection, init_db


TEST_PASSWORD = "secure-test-password-123"


@pytest.fixture(autouse=True)
def isolated_auth_database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "test_auth.db"),
    )


def insert_legacy_user(username):
    init_db()
    with get_connection() as connection:
        result = connection.execute(
            text("""
                INSERT INTO auth_users (username, password_hash, created_at)
                VALUES (:username, :password_hash, :created_at)
            """),
            {
                "username": username,
                "password_hash": password_hasher.hash(TEST_PASSWORD),
                "created_at": "2026-10-30T00:00:00+00:00",
            },
        )
        return int(result.lastrowid)


def test_create_user_trims_and_normalizes_username():
    create_user("  Test-User  ", TEST_PASSWORD)

    with get_connection() as connection:
        row = connection.execute(
            text("SELECT username FROM auth_users")
        ).first()

    assert row[0] == "test-user"
    assert authenticate_user("test-user", TEST_PASSWORD) is not None
    assert authenticate_user("  TEST-USER  ", TEST_PASSWORD) is not None


def test_authentication_supports_legacy_mixed_case_username():
    user_id = insert_legacy_user("Legacy-User")

    assert authenticate_user(" legacy-user ", TEST_PASSWORD) == user_id


def test_authentication_rejects_ambiguous_legacy_usernames():
    insert_legacy_user("Legacy-User")
    insert_legacy_user("LEGACY-USER")

    assert authenticate_user("legacy-user", TEST_PASSWORD) is None


def test_create_user_rejects_additional_account():
    create_user("test-user", TEST_PASSWORD)

    with pytest.raises(ValueError, match="already exists"):
        create_user("another-user", TEST_PASSWORD)


def test_authentication_rejects_wrong_password():
    create_user("test-user", TEST_PASSWORD)

    assert authenticate_user("test-user", "wrong-password") is None


def test_authentication_rejects_unknown_username():
    assert authenticate_user("unknown-user", TEST_PASSWORD) is None


@pytest.mark.parametrize(
    "username",
    [
        "ab",
        "invalid username",
        "invalid@username",
        "",
    ],
)
def test_create_user_rejects_invalid_username(username):
    with pytest.raises(ValueError):
        create_user(username, TEST_PASSWORD)
