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


def test_openapi_contains_only_v4_product_routes() -> None:
    from src.main import app

    product_paths = [path for path in app.openapi()["paths"] if path.startswith("/api/")]
    assert product_paths
    assert all(path.startswith("/api/v4/") for path in product_paths)
