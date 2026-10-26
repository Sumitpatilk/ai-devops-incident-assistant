from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_create_and_retrieve_incident(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "test_incidents.db"),
    )

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


def test_list_incidents(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "list_test.db"),
    )

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


def test_update_verification(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "verification_test.db"),
    )

    created = client.post(
        "/api/v1/incidents",
        json={
            "source": "kubernetes",
            "logs": "Container terminated: OOMKilled",
        },
    )
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


def test_missing_incident_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "missing_test.db"),
    )

    response = client.get("/api/v1/incidents/99999")
    assert response.status_code == 404


def test_update_fix_description(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "fix_description_test.db"),
    )

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
            "fix_description": "Updated memory limits and tested the workload",
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


def test_update_fix_description_missing_incident(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_DB_PATH",
        str(tmp_path / "missing_fix_test.db"),
    )

    response = client.put(
        "/api/v1/incidents/99999/fix",
        json={"fix_description": "Some remediation notes"},
    )

    assert response.status_code == 404
