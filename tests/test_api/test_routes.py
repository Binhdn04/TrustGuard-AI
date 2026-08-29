import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v2/analyses", "/api/v3/analyses", "/api/v3/admin/actions"])
async def test_retired_v2_v3_routes_are_not_mounted(client, path: str) -> None:
    response = await client.get(path)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_ip_rate_limit_runs_before_authentication(client, monkeypatch) -> None:
    class DeniedLimiter:
        async def allow(self, key, limit, window_seconds=60):
            assert key.startswith("ip:")
            assert limit > 0
            return False

    monkeypatch.setattr("src.api.dependencies.get_rate_limiter", lambda: DeniedLimiter())

    response = await client.get("/api/v4/capabilities")

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert response.headers["x-request-id"]


@pytest.mark.asyncio
async def test_validation_error_does_not_echo_submitted_content(client) -> None:
    response = await client.post(
        "/api/v4/analyses",
        headers={"Authorization": "Bearer dev-user-token"},
        json={"message": "private-message-should-not-be-returned", "unexpected": "private-token"},
    )

    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert "private-message-should-not-be-returned" not in response.text
    assert "private-token" not in response.text
    assert body["details"]["errors"]
    assert set(body["details"]["errors"][0]) <= {"loc", "type"}


def test_openapi_contains_only_v4_product_routes() -> None:
    from src.main import app

    product_paths = [path for path in app.openapi()["paths"] if path.startswith("/api/")]
    assert product_paths
    assert all(path.startswith("/api/v4/") for path in product_paths)
