import json
import logging

from src.core.logging import RedactingJsonFormatter
from src.core.product_boundary import (
    SECURITY_TRIAGE_API_PREFIX,
    SECURITY_TRIAGE_CONTRACT_VERSION,
    product_route_metadata,
)


def test_only_security_v4_is_a_product_boundary() -> None:
    assert SECURITY_TRIAGE_API_PREFIX == "/api/v4"
    assert SECURITY_TRIAGE_CONTRACT_VERSION == "v4"
    security = product_route_metadata("/api/v4/analyses", "POST")
    assert security is not None
    assert security.api_contract == "v4"
    assert security.product_profile == "security_triage_vnext"
    assert product_route_metadata("/api/v2/analyses/id", "GET") is None
    assert product_route_metadata("/api/v3/admin/actions", "GET") is None
    assert product_route_metadata("/health", "GET") is None


def test_structured_log_keeps_only_safe_v4_dimensions() -> None:
    record = logging.LogRecord("trustguard.http", logging.INFO, __file__, 1, "http_request_completed", (), None)
    record.api_contract = "v4"
    record.product_profile = "security_triage_vnext"
    payload = json.loads(RedactingJsonFormatter().format(record))
    assert payload["api_contract"] == "v4"
    assert payload["product_profile"] == "security_triage_vnext"
    assert "compatibility_usage" not in payload
    assert "body" not in payload
