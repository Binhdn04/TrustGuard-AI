import json
import logging

from starlette.requests import Request

from src.api.middleware import client_ip_for_request, ip_rate_limit_key
from src.config import Settings
from src.core.logging import RedactingJsonFormatter
from src.core.product_boundary import (
    SECURITY_TRIAGE_API_PREFIX,
    SECURITY_TRIAGE_CONTRACT_VERSION,
    product_route_metadata,
)
from src.main import documentation_urls


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


def test_structured_log_keeps_safe_ai_grounding_dimensions_without_raw_content() -> None:
    record = logging.LogRecord(
        "trustguard.security_ai",
        logging.WARNING,
        __file__,
        1,
        "security_ai_semantic_field_rejected",
        (),
        None,
    )
    record.operation = "understand"
    record.field_name = "scope_decision"
    record.failure_code = "missing_source_span"
    record.raw_response = "private model output"

    payload = json.loads(RedactingJsonFormatter().format(record))

    assert payload["operation"] == "understand"
    assert payload["field_name"] == "scope_decision"
    assert payload["failure_code"] == "missing_source_span"
    assert "raw_response" not in payload
    assert "private model output" not in json.dumps(payload)


def test_structured_log_redacts_secrets_embedded_in_strings() -> None:
    openai_key = "sk-proj-0123456789abcdef"
    bearer_token = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
    record = logging.LogRecord(
        "trustguard.http",
        logging.INFO,
        __file__,
        1,
        f"provider key={openai_key}; Authorization: Bearer {bearer_token}",
        (),
        None,
    )

    rendered = RedactingJsonFormatter().format(record)

    assert openai_key not in rendered
    assert bearer_token not in rendered
    assert "[REDACTED]" in rendered


def test_production_disables_interactive_api_documentation() -> None:
    assert documentation_urls("production") == {"docs_url": None, "redoc_url": None, "openapi_url": None}
    assert documentation_urls("test") == {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }


def test_ip_limiter_uses_peer_unless_the_proxy_is_explicitly_trusted() -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v4/capabilities",
            "headers": [(b"x-forwarded-for", b"198.51.100.10")],
            "client": ("10.0.0.8", 443),
        }
    )
    direct_settings = Settings(database_encryption_key="test-secret", _env_file=None)
    proxy_settings = Settings(
        database_encryption_key="test-secret",
        trusted_proxy_ips="10.0.0.0/8",
        _env_file=None,
    )

    assert client_ip_for_request(request, direct_settings) == "10.0.0.8"
    assert client_ip_for_request(request, proxy_settings) == "198.51.100.10"
    assert "198.51.100.10" not in ip_rate_limit_key("198.51.100.10", proxy_settings)
