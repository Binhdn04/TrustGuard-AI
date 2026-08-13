import json
import logging

import pytest

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
async def test_request_middleware_emits_legacy_usage_dimensions(client, caplog) -> None:
    with caplog.at_level(logging.INFO, logger="trustguard.http"):
        response = await client.get("/api/v2/status")

    assert response.status_code == 200
    record = next(item for item in caplog.records if item.getMessage() == "http_request_completed")
    assert record.api_contract == "v2"
    assert record.product_profile == "legacy_analysis"
    assert record.compatibility_usage == "legacy_read"
