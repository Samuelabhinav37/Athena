from athena.main import app
from fastapi.testclient import TestClient


def test_health() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "athena-api"}


def test_metrics_are_bounded_and_prometheus_compatible() -> None:
    client = TestClient(app)
    client.get("/health")

    response = client.get("/metrics")

    assert response.status_code == 200
    assert "athena_http_requests_total" in response.text
    assert 'method="GET",status_class="2xx"' in response.text
    assert "request_id" not in response.text
