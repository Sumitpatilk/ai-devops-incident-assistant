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


def test_analyze_redacts_secrets_but_preserves_evidence(client):
    secret = "hunter2"
    response = client.post(
        "/api/v1/analyze",
        json={
            "source": "kubernetes",
            "logs": f"Container terminated: OOMKilled password={secret}",
        },
    )

    assert response.status_code == 200
    body = response.text
    assert secret not in body
    assert "[REDACTED]" in body
    assert "OOMKilled" in body


def test_complete_incident_lifecycle_api_workflow(unauthenticated_client):
    from app.services.auth_store import create_user

    secret = "e2e-synthetic-password-123"
    username = "e2e-workflow-user"
    password = "e2e-workflow-password-12345"

    create_user(username, password)

    login = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    assert login.json()["authenticated"] is True

    session = unauthenticated_client.get("/api/v1/auth/me")
    assert session.status_code == 200
    assert session.json()["username"] == username

    logs = f"Container terminated: OOMKilled password={secret}"

    analysis = unauthenticated_client.post(
        "/api/v1/analyze",
        json={"source": "kubernetes", "logs": logs},
    )
    assert analysis.status_code == 200
    assert secret not in analysis.text
    assert "[REDACTED]" in analysis.text

    created = unauthenticated_client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": logs,
            "fix_description": "Review container memory limits",
        },
    )
    assert created.status_code == 201

    incident = created.json()
    incident_id = incident["id"]

    assert incident["verification_status"] == "not_run"
    assert secret not in incident["logs"]
    assert "[REDACTED]" in incident["logs"]
    assert "OOMKilled" in incident["logs"]

    detail = unauthenticated_client.get(
        f"/api/v1/incidents/{incident_id}"
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == incident_id

    fix = unauthenticated_client.put(
        f"/api/v1/incidents/{incident_id}/fix",
        json={
            "fix_description": (
                "Adjusted memory limits and reviewed workload usage"
            )
        },
    )
    assert fix.status_code == 200
    assert fix.json()["fix_description"] == (
        "Adjusted memory limits and reviewed workload usage"
    )

    verification = unauthenticated_client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={
            "status": "passed",
            "notes": "Regression checks completed successfully",
        },
    )
    assert verification.status_code == 200
    assert verification.json()["verification_status"] == "passed"
    assert verification.json()["verified_at"] is not None

    history = unauthenticated_client.get(
        "/api/v1/incidents",
        params={"verification_status": "passed"},
    )
    assert history.status_code == 200

    matching = [
        item for item in history.json()["items"]
        if item["id"] == incident_id
    ]
    assert len(matching) == 1

    final_detail = unauthenticated_client.get(
        f"/api/v1/incidents/{incident_id}"
    )
    assert final_detail.status_code == 200
    assert final_detail.json()["verification_status"] == "passed"
    assert secret not in final_detail.text

    logout = unauthenticated_client.post("/api/v1/auth/logout")
    assert logout.status_code == 200

    after_logout = unauthenticated_client.get("/api/v1/incidents")
    assert after_logout.status_code == 401
