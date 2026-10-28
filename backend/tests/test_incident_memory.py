def test_create_and_retrieve_incident(client):
    response = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
            "fix_description": "Review container memory limits",
        },
    )

    assert response.status_code == 201
    incident = response.json()
    assert incident["source"] == "kubernetes"
    assert incident["analysis"]["status"] == "findings"
    assert incident["verification_status"] == "not_run"

    incident_id = incident["id"]

    detail = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == incident_id
    assert detail.json()["fix_description"] == (
        "Review container memory limits"
    )


def test_list_incidents(client):
    response = client.post(
        "/api/v1/incidents",
        json={
            "source": "docker",
            "logs": "failed to solve",
        },
    )
    assert response.status_code == 201

    history = client.get("/api/v1/incidents")
    assert history.status_code == 200
    assert len(history.json()["items"]) == 1


def test_update_verification(client):
    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    response = client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={
            "status": "passed",
            "notes": "Regression tests passed",
        },
    )

    assert response.status_code == 200
    assert response.json()["verification_status"] == "passed"
    assert response.json()["verification_notes"] == (
        "Regression tests passed"
    )
    assert response.json()["verified_at"] is not None


def test_missing_incident_returns_404(client):
    response = client.get("/api/v1/incidents/99999")
    assert response.status_code == 404


def test_update_fix_description(client):
    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
            "fix_description": "Initial remediation notes",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    response = client.put(
        f"/api/v1/incidents/{incident_id}/fix",
        json={
            "fix_description": (
                "Updated memory limits and tested the workload"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["fix_description"] == (
        "Updated memory limits and tested the workload"
    )

    detail = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["fix_description"] == (
        "Updated memory limits and tested the workload"
    )


def test_update_fix_description_missing_incident(client):
    response = client.put(
        "/api/v1/incidents/99999/fix",
        json={"fix_description": "Some remediation notes"},
    )
    assert response.status_code == 404

def test_users_cannot_access_each_others_incidents(
    client, monkeypatch
):
    from datetime import datetime, timezone

    from sqlalchemy import text

    from app.services.auth_store import create_session, password_hasher
    from app.services.database import get_connection

    # The existing client is authenticated as user A.
    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "User A private incident",
            "fix_description": "Original fix",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    # Create user B only in this isolated test database.
    with get_connection() as connection:
        result = connection.execute(
            text("""
                INSERT INTO auth_users (username, password_hash, created_at)
                VALUES (:username, :password_hash, :created_at)
            """),
            {
                "username": "test-user-b",
                "password_hash": password_hasher.hash(
                    "test-user-b-password-12345"
                ),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        user_b_id = result.lastrowid

    token_b, _ = create_session(user_b_id)

    # Use a separate HTTP client carrying user B's session.
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client_b:
        client_b.cookies.set("incident_session", token_b, path="/")

        history_b = client_b.get("/api/v1/incidents")
        assert history_b.status_code == 200
        assert all(
            item["id"] != incident_id
            for item in history_b.json()["items"]
        )

        detail_b = client_b.get(f"/api/v1/incidents/{incident_id}")
        assert detail_b.status_code == 404

        fix_b = client_b.put(
            f"/api/v1/incidents/{incident_id}/fix",
            json={"fix_description": "Unauthorized change"},
        )
        assert fix_b.status_code == 404

        verification_b = client_b.post(
            f"/api/v1/incidents/{incident_id}/verification",
            json={
                "status": "passed",
                "notes": "Unauthorized verification",
            },
        )
        assert verification_b.status_code == 404

    # User A's incident must remain unchanged.
    detail_a = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_a.status_code == 200
    assert detail_a.json()["fix_description"] == "Original fix"
    assert detail_a.json()["verification_status"] == "not_run"
