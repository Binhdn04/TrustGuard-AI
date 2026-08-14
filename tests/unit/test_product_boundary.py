import json
import logging

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.core.logging import RedactingJsonFormatter
from src.core.product_boundary import (
    LEGACY_API_PREFIXES,
    SECURITY_TRIAGE_API_PREFIX,
    SECURITY_TRIAGE_CONTRACT_VERSION,
    product_route_metadata,
)


def test_product_boundaries_are_versioned_and_disjoint() -> None:
    assert LEGACY_API_PREFIXES == ("/api/v2", "/api/v3")
    assert SECURITY_TRIAGE_API_PREFIX == "/api/v4"
    assert SECURITY_TRIAGE_CONTRACT_VERSION == "v4"
    assert SECURITY_TRIAGE_API_PREFIX not in LEGACY_API_PREFIXES


def test_legacy_api_usage_is_classified_by_contract_and_operation() -> None:
    read = product_route_metadata("/api/v2/analyses/id", "GET")
    write = product_route_metadata("/api/v3/analyses", "POST")

    assert read is not None
    assert read.api_contract == "v2"
    assert read.product_profile == "legacy_analysis"
    assert read.compatibility_usage == "legacy_read"
    assert write is not None
    assert write.api_contract == "v3"
    assert write.compatibility_usage == "legacy_write"


def test_security_vnext_and_unversioned_routes_are_not_counted_as_legacy() -> None:
    security = product_route_metadata("/api/v4/analyses", "POST")

    assert security is not None
    assert security.product_profile == "security_triage_vnext"
    assert security.compatibility_usage == "security_write"
    assert product_route_metadata("/health", "GET") is None
    assert product_route_metadata("/api/v30/analyses", "GET") is None


def test_reviewed_action_v3_contract_is_not_counted_as_legacy_analysis() -> None:
    read = product_route_metadata("/api/v3/admin/actions", "GET")
    write = product_route_metadata("/api/v3/admin/actions/action-1/decision", "POST")

    assert read is not None
    assert read.product_profile == "security_triage_vnext"
    assert read.compatibility_usage == "reviewed_action_read"
    assert write is not None
    assert write.compatibility_usage == "reviewed_action_write"


def test_structured_log_keeps_only_safe_product_usage_dimensions() -> None:
    record = logging.LogRecord("trustguard.http", logging.INFO, __file__, 1, "http_request_completed", (), None)
    record.api_contract = "v3"
    record.product_profile = "legacy_analysis"
    record.compatibility_usage = "legacy_write"

    payload = json.loads(RedactingJsonFormatter().format(record))

    assert payload["api_contract"] == "v3"
    assert payload["product_profile"] == "legacy_analysis"
    assert payload["compatibility_usage"] == "legacy_write"
    assert "body" not in payload


@pytest.mark.asyncio
async def test_cutover_middleware_freezes_legacy_writes_but_keeps_reviewed_actions() -> None:
    from src.api.middleware import StructuredRequestLogMiddleware

    test_app = FastAPI()
    test_app.add_middleware(StructuredRequestLogMiddleware, legacy_api_writes_enabled=False)

    @test_app.post("/api/v3/analyses")
    async def legacy_write():
        return {"written": True}

    @test_app.post("/api/v3/admin/actions/{action_id}/decision")
    async def reviewed_action(action_id: str):
        return {"action_id": action_id}

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        frozen = await client.post("/api/v3/analyses")
        allowed = await client.post("/api/v3/admin/actions/action-1/decision")

    assert frozen.status_code == 409
    assert frozen.json()["error"]["details"]["replacement_contract"] == "v4"
    assert allowed.status_code == 200
