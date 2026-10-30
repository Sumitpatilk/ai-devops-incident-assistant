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

def test_reset_verification_clears_verified_at(client):
    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    passed = client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={
            "status": "passed",
            "notes": "Regression tests passed",
        },
    )
    assert passed.status_code == 200
    assert passed.json()["verified_at"] is not None

    reset = client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={
            "status": "not_run",
            "notes": "Verification needs to be rerun",
        },
    )

    assert reset.status_code == 200
    assert reset.json()["verification_status"] == "not_run"
    assert reset.json()["verification_notes"] == (
        "Verification needs to be rerun"
    )
    assert reset.json()["verified_at"] is None

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


def test_list_incidents_pagination_and_order(client):
    incident_ids = []

    for index in range(3):
        response = client.post(
            "/api/v1/incidents",
            json={
                "source": "docker",
                "logs": f"Pagination test incident {index + 1}",
            },
        )
        assert response.status_code == 201
        incident_ids.append(response.json()["id"])

    first_page = client.get("/api/v1/incidents?limit=2&offset=0")
    assert first_page.status_code == 200
    assert first_page.json()["limit"] == 2
    assert first_page.json()["offset"] == 0
    first_page_ids = [item["id"] for item in first_page.json()["items"]]
    assert len(first_page_ids) == 2
    assert first_page_ids == incident_ids[::-1][:2]

    second_page = client.get("/api/v1/incidents?limit=2&offset=2")
    assert second_page.status_code == 200
    second_page_ids = [item["id"] for item in second_page.json()["items"]]
    assert len(second_page_ids) == 1
    assert second_page_ids == incident_ids[::-1][2:]
    assert set(first_page_ids).isdisjoint(second_page_ids)


def test_list_incidents_rejects_invalid_pagination(client):
    for query in ("limit=0", "limit=101", "offset=-1"):
        response = client.get(f"/api/v1/incidents?{query}")
        assert response.status_code == 422, query


def test_list_incidents_uses_default_pagination(client):
    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "docker",
            "logs": "Default pagination test incident",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    assert response.json()["limit"] == 20
    assert response.json()["offset"] == 0
    assert incident_id in [item["id"] for item in response.json()["items"]]


def test_list_incidents_searches_logs_and_source(client):
    docker_incident = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "Unique container startup failure"},
    )
    github_incident = client.post(
        "/api/v1/incidents",
        json={"source": "github-actions", "logs": "Workflow dependency timeout"},
    )
    assert docker_incident.status_code == 201
    assert github_incident.status_code == 201

    by_logs = client.get("/api/v1/incidents?search=CONTAINER%20STARTUP")
    assert by_logs.status_code == 200
    assert [item["id"] for item in by_logs.json()["items"]] == [
        docker_incident.json()["id"]
    ]

    by_source = client.get("/api/v1/incidents?search=GITHUB-ACTIONS")
    assert by_source.status_code == 200
    assert [item["id"] for item in by_source.json()["items"]] == [
        github_incident.json()["id"]
    ]


def test_list_incidents_filters_by_verification_status(client):
    failed = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "Filter test failed incident"},
    )
    passed = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "Filter test passed incident"},
    )
    assert failed.status_code == 201
    assert passed.status_code == 201

    failed_id = failed.json()["id"]
    passed_id = passed.json()["id"]

    assert client.post(
        f"/api/v1/incidents/{failed_id}/verification",
        json={"status": "failed", "notes": "Test failure"},
    ).status_code == 200
    assert client.post(
        f"/api/v1/incidents/{passed_id}/verification",
        json={"status": "passed", "notes": "Test passed"},
    ).status_code == 200

    response = client.get("/api/v1/incidents?verification_status=failed")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == [failed_id]


def test_list_incidents_combines_search_status_and_pagination(client):
    matching_ids = []

    for index in range(3):
        created = client.post(
            "/api/v1/incidents",
            json={
                "source": "kubernetes",
                "logs": f"Combined filter marker {index}",
            },
        )
        assert created.status_code == 201
        incident_id = created.json()["id"]
        matching_ids.append(incident_id)
        assert client.post(
            f"/api/v1/incidents/{incident_id}/verification",
            json={"status": "passed", "notes": "Verified"},
        ).status_code == 200

    unrelated = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "Unrelated marker"},
    )
    assert unrelated.status_code == 201

    response = client.get(
        "/api/v1/incidents"
        "?search=combined%20filter%20marker"
        "&verification_status=passed&limit=2&offset=1"
    )
    assert response.status_code == 200
    assert response.json()["limit"] == 2
    assert response.json()["offset"] == 1
    assert [item["id"] for item in response.json()["items"]] == (
        matching_ids[::-1][1:]
    )


def test_list_incidents_rejects_invalid_search_filters(client):
    invalid_status = client.get(
        "/api/v1/incidents?verification_status=unknown"
    )
    assert invalid_status.status_code == 422

    oversized_search = client.get(
        "/api/v1/incidents",
        params={"search": "x" * 201},
    )
    assert oversized_search.status_code == 422



def test_list_incidents_search_treats_like_wildcards_literally(client):
    literal = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "literal 100%_ready! marker"},
    )
    unrelated = client.post(
        "/api/v1/incidents",
        json={"source": "docker", "logs": "literal 100XYZready marker"},
    )
    assert literal.status_code == 201
    assert unrelated.status_code == 201

    for term in ("100%", "_ready", "! marker"):
        response = client.get("/api/v1/incidents", params={"search": term})
        assert response.status_code == 200
        assert [item["id"] for item in response.json()["items"]] == [
            literal.json()["id"]
        ]

def test_search_and_status_filter_respect_user_ownership(client):
    from datetime import datetime, timezone

    from sqlalchemy import text

    from app.services.auth_store import create_session, password_hasher
    from app.services.database import get_connection
    from fastapi.testclient import TestClient
    from app.main import app

    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Private ownership search marker",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    assert client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={"status": "passed", "notes": "Verified"},
    ).status_code == 200

    with get_connection() as connection:
        result = connection.execute(
            text("""
                INSERT INTO auth_users (username, password_hash, created_at)
                VALUES (:username, :password_hash, :created_at)
            """),
            {
                "username": "search-filter-user-b",
                "password_hash": password_hasher.hash(
                    "search-filter-password-12345"
                ),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        user_b_id = result.lastrowid

    token_b, _ = create_session(user_b_id)

    with TestClient(app) as client_b:
        client_b.cookies.set("incident_session", token_b, path="/")

        for query in (
            "?search=Private%20ownership%20search%20marker",
            "?verification_status=passed",
            "?search=Private%20ownership%20search%20marker"
            "&verification_status=passed",
        ):
            response = client_b.get("/api/v1/incidents" + query)
            assert response.status_code == 200
            assert all(
                item["id"] != incident_id
                for item in response.json()["items"]
            )

    history_a = client.get(
        "/api/v1/incidents?search=Private%20ownership%20search%20marker"
        "&verification_status=passed"
    )
    assert history_a.status_code == 200
    assert [item["id"] for item in history_a.json()["items"]] == [incident_id]


def test_incident_storage_redacts_logs_and_evidence(client):
    secret = "incident-secret-987"
    response = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": (
                "Container terminated: OOMKilled "
                f"password={secret}"
            ),
        },
    )

    assert response.status_code == 201
    incident = response.json()

    assert secret not in incident["logs"]
    assert "[REDACTED]" in incident["logs"]

    evidence = incident["analysis"]["findings"][0]["evidence"]
    assert secret not in str(evidence)
    assert "[REDACTED]" in str(evidence)
    assert "OOMKilled" in str(evidence)


def test_incident_text_fields_redact_secrets(client):
    create_secret = "create-secret-123"
    update_secret = "update-secret-456"
    notes_secret = "notes-secret-789"

    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
            "fix_description": (
                f"Updated deployment password={create_secret}"
            ),
        },
    )

    assert created.status_code == 201
    incident = created.json()
    incident_id = incident["id"]

    assert create_secret not in incident["fix_description"]
    assert "[REDACTED]" in incident["fix_description"]

    updated = client.put(
        f"/api/v1/incidents/{incident_id}/fix",
        json={
            "fix_description": (
                f"Applied remediation token={update_secret}"
            ),
        },
    )

    assert updated.status_code == 200
    assert update_secret not in updated.json()["fix_description"]
    assert "[REDACTED]" in updated.json()["fix_description"]

    verification = client.post(
        f"/api/v1/incidents/{incident_id}/verification",
        json={
            "status": "passed",
            "notes": f"Tests completed api_key={notes_secret}",
        },
    )

    assert verification.status_code == 200
    assert notes_secret not in verification.json()["verification_notes"]
    assert "[REDACTED]" in verification.json()["verification_notes"]
