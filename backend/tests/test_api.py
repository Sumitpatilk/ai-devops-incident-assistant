from app.services.auth_store import create_user

TEST_USERNAME = "test-user"
TEST_PASSWORD = "test-password-12345"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint(client):
    response = client.post(
        "/api/v1/analyze",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "findings"
    assert data["findings"][0]["rule_id"] == "K8S_OOM_KILLED"


def test_invalid_source(client):
    response = client.post(
        "/api/v1/analyze",
        json={
            "source": "unknown-tool",
            "logs": "Some error",
        },
    )
    assert response.status_code == 422


def test_empty_logs(client):
    response = client.post(
        "/api/v1/analyze",
        json={"source": "docker", "logs": ""},
    )
    assert response.status_code == 422


def test_protected_endpoint_rejects_unauthenticated_request(
    unauthenticated_client,
):
    response = unauthenticated_client.get("/api/v1/incidents")
    assert response.status_code == 401


def test_login_rejects_invalid_password(unauthenticated_client):
    create_user(TEST_USERNAME, TEST_PASSWORD)

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": "incorrect-password",
        },
    )

    assert response.status_code == 401
    assert "incident_session" not in response.cookies


def test_login_and_current_session(unauthenticated_client):
    create_user(TEST_USERNAME, TEST_PASSWORD)

    login_response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert login_response.status_code == 200
    assert login_response.json() == {
        "authenticated": True,
        "username": TEST_USERNAME,
    }
    assert "incident_session" in login_response.cookies

    session_response = unauthenticated_client.get("/api/v1/auth/me")
    assert session_response.status_code == 200
    assert session_response.json()["username"] == TEST_USERNAME


def test_logout_revokes_server_side_session(client):
    before = client.get("/api/v1/auth/me")
    assert before.status_code == 200

    logout_response = client.post("/api/v1/auth/logout")
    assert logout_response.status_code == 200
    assert logout_response.json()["authenticated"] is False

    after = client.get("/api/v1/auth/me")
    assert after.status_code == 401

def test_login_rejects_invalid_origin(unauthenticated_client):
    create_user(TEST_USERNAME, TEST_PASSWORD)

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://attacker.example"},
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 403
    assert "incident_session" not in response.cookies


def test_login_cookie_security_attributes(unauthenticated_client):
    create_user(TEST_USERNAME, TEST_PASSWORD)

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=28800" in cookie
    assert "path=/" in cookie


def test_login_cookie_secure_when_https_mode_enabled(
    unauthenticated_client, monkeypatch
):
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    create_user(TEST_USERNAME, TEST_PASSWORD)

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "secure" in [part.strip() for part in cookie.split(";")]


def test_expired_session_is_rejected(unauthenticated_client, monkeypatch):
    import hashlib
    from sqlalchemy import text
    from app.services.database import get_connection

    create_user(TEST_USERNAME, TEST_PASSWORD)

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )
    assert response.status_code == 200

    token = response.cookies.get("incident_session")
    assert token

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_connection() as connection:
        connection.execute(
            text("""
                UPDATE auth_sessions
                SET expires_at = :expires_at
                WHERE token_hash = :token_hash
            """),
            {
                "expires_at": "2000-01-01T00:00:00+00:00",
                "token_hash": token_hash,
            },
        )

    session_response = unauthenticated_client.get("/api/v1/auth/me")
    assert session_response.status_code == 401


def test_login_rate_limit_blocks_repeated_failures(unauthenticated_client):
    for _ in range(5):
        response = unauthenticated_client.post(
            "/api/v1/auth/login",
            json={
                "username": TEST_USERNAME,
                "password": "incorrect-password",
            },
        )
        assert response.status_code == 401

    blocked = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": "incorrect-password",
        },
    )
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "900"
