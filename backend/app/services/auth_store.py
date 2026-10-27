import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import text

from app.services.database import get_connection, init_db

password_hasher = PasswordHasher()
SESSION_HOURS = 8


def init_auth_db():
    init_db()


def create_user(username: str, password: str) -> None:
    username = username.strip()

    if not 3 <= len(username) <= 64:
        raise ValueError("Username must be between 3 and 64 characters.")

    if not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError(
            "Username may contain letters, numbers, underscores, and hyphens."
        )

    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    init_auth_db()

    with get_connection() as connection:
        existing_user = connection.execute(
            text("SELECT 1 FROM auth_users LIMIT 1")
        ).first()

        if existing_user:
            raise ValueError(
                "An account already exists. Public registration is disabled."
            )

        connection.execute(
            text("""
                INSERT INTO auth_users (username, password_hash, created_at)
                VALUES (:username, :password_hash, :created_at)
            """),
            {
                "username": username,
                "password_hash": password_hasher.hash(password),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )


def authenticate_user(username: str, password: str) -> int | None:
    init_auth_db()

    with get_connection() as connection:
        row = connection.execute(
            text("""
                SELECT id, password_hash
                FROM auth_users
                WHERE username = :username
            """),
            {"username": username.strip()},
        ).mappings().first()

    if row is None:
        return None

    try:
        if not password_hasher.verify(row["password_hash"], password):
            return None
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return None

    if password_hasher.check_needs_rehash(row["password_hash"]):
        new_hash = password_hasher.hash(password)
        with get_connection() as connection:
            connection.execute(
                text("""
                    UPDATE auth_users
                    SET password_hash = :password_hash
                    WHERE id = :user_id
                """),
                {"password_hash": new_hash, "user_id": row["id"]},
            )

    return int(row["id"])


def create_session(user_id: int) -> tuple[str, str]:
    init_auth_db()

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=SESSION_HOURS)

    with get_connection() as connection:
        connection.execute(
            text("DELETE FROM auth_sessions WHERE expires_at <= :now"),
            {"now": now.isoformat()},
        )
        connection.execute(
            text("""
                INSERT INTO auth_sessions
                    (token_hash, user_id, created_at, expires_at)
                VALUES (:token_hash, :user_id, :created_at, :expires_at)
            """),
            {
                "token_hash": token_hash,
                "user_id": user_id,
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat(),
            },
        )

    return token, expires.isoformat()


def get_session_user(token: str) -> str | None:
    if not token:
        return None

    init_auth_db()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        row = connection.execute(
            text("""
                SELECT u.username
                FROM auth_sessions AS s
                JOIN auth_users AS u ON u.id = s.user_id
                WHERE s.token_hash = :token_hash
                  AND s.expires_at > :now
            """),
            {"token_hash": token_hash, "now": now},
        ).mappings().first()

    return str(row["username"]) if row else None


def delete_session(token: str) -> None:
    if not token:
        return

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    init_auth_db()

    with get_connection() as connection:
        connection.execute(
            text("DELETE FROM auth_sessions WHERE token_hash = :token_hash"),
            {"token_hash": token_hash},
        )
