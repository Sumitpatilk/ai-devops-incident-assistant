from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint():
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


def test_invalid_source():
    response = client.post(
        "/api/v1/analyze",
        json={
            "source": "unknown-tool",
            "logs": "Some error",
        },
    )

    assert response.status_code == 422


def test_empty_logs():
    response = client.post(
        "/api/v1/analyze",
        json={
            "source": "docker",
            "logs": "",
        },
    )

    assert response.status_code == 422
