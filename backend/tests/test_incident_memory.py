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
