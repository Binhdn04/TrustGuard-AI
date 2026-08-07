from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.agents.tools import (
    CacheMetadata,
    NormalizedToolResult,
    ToolName,
    ToolResultStatus,
    UrlReputationFinding,
    UsageMetadata,
)
from tests.fixture_loader import (
    load_rdap_v3_responses,
    load_redirect_resolver_responses,
    load_screenshot_responses,
    load_tool_policy_responses,
    load_url_reputation_v3_responses,
)

NOW = datetime(2026, 8, 7, 13, 0, tzinfo=UTC)


def test_tool_protocol_names_are_frozen() -> None:
    assert {item.value for item in ToolName} == {
        "url_reputation",
        "redirect_resolver",
        "rdap",
        "fact_check_corpus",
        "screenshot_renderer",
    }


def test_no_hit_cannot_be_normalized_as_safe() -> None:
    with pytest.raises(ValidationError, match="no-hit must be inconclusive"):
        UrlReputationFinding(
            provider="fixture-provider",
            provider_version="v1",
            normalized_url="https://unknown.example/",
            matched=False,
            verdict="safe",
            observed_at=NOW,
        )


def test_common_envelope_forbids_raw_provider_body() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedToolResult[str].model_validate(
            {
                "status": "success",
                "result": "normalized",
                "error": None,
                "cache": {"status": "miss"},
                "usage": {
                    "usage_ref": "usage:1",
                    "provider": "fixture",
                    "provider_version": "v1",
                    "operation": "lookup",
                    "attempts": 1,
                    "network_calls": 1,
                    "latency_ms": 1,
                    "observed_at": NOW,
                },
                "raw_provider_body": {"secret": "must-not-escape"},
            }
        )


def test_cache_hit_cannot_record_network_usage() -> None:
    with pytest.raises(ValidationError, match="cache hit cannot record a network call"):
        NormalizedToolResult[str](
            status=ToolResultStatus.SUCCESS,
            result="normalized",
            cache=CacheMetadata(
                status="hit",
                cache_key_hash="a" * 64,
                stored_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            ),
            usage=UsageMetadata(
                usage_ref="usage:cache:1",
                provider="fixture",
                provider_version="v1",
                operation="lookup",
                attempts=1,
                network_calls=1,
                latency_ms=1,
                observed_at=NOW,
            ),
        )


def test_offline_policy_fixtures_encode_consent_gate() -> None:
    fixtures = load_tool_policy_responses()
    assert fixtures["consent_allows_external_001"].allowed_tools
    assert fixtures["no_consent_blocks_external_001"].allowed_tools == []


def test_url_reputation_fixtures_cover_no_hit_conflict_and_429() -> None:
    fixtures = load_url_reputation_v3_responses()
    no_hit = fixtures["provider_no_hit_001"]
    conflict = fixtures["provider_conflict_001"]
    limited = fixtures["provider_429_001"]

    assert no_hit.status is ToolResultStatus.INCONCLUSIVE
    assert no_hit.result is not None and no_hit.result.verdict.value == "inconclusive"
    assert conflict.result is not None and conflict.result.provider_conflict is True
    assert limited.error is not None and limited.error.code.value == "RATE_LIMITED"
    assert limited.error.retry_after_ms == 30_000


def test_redirect_and_rdap_fixtures_cover_security_cache_and_429() -> None:
    redirects = load_redirect_resolver_responses()
    rdap = load_rdap_v3_responses()

    assert redirects["redirect_public_001"].result is not None
    assert redirects["redirect_private_hop_001"].status is ToolResultStatus.BLOCKED
    assert redirects["redirect_loop_001"].error is not None
    assert rdap["rdap_recent_domain_001"].cache.status.value == "hit"
    assert rdap["rdap_recent_domain_001"].usage.network_calls == 0
    assert rdap["rdap_429_001"].error is not None


def test_screenshot_security_fixture_matrix_is_complete() -> None:
    fixtures = load_screenshot_responses()
    assert set(fixtures) == {
        "screenshot_credential_url_001",
        "screenshot_private_ip_001",
        "screenshot_redirect_escape_001",
        "screenshot_download_001",
        "screenshot_timeout_001",
    }
    assert all(item.status in {ToolResultStatus.BLOCKED, ToolResultStatus.FAILED} for item in fixtures.values())
