from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.tools.bkns import BKNS_WHOIS_ENDPOINT, BknsWhoisProvider
from src.agents.tools.domain_registration import DomainRegistrationProvider
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from src.models import (
    DomainIntelligenceResult,
    InvestigationStepV4,
    SecurityEvidenceTypeV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
)

NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)


def _registered_payload(*, created: str = "2010-06-24T17:00:00.000Z") -> dict[str, object]:
    return {
        "domain": "example.vn",
        "tld": "vn",
        "status": "registered",
        "cached": False,
        "backendsTried": ["private-backend-name"],
        "data": {
            "registrant": {"name": "Must Never Escape"},
            "registrar": {"name": "Example Registrar"},
            "nameservers": ["ns1.private.example"],
            "dates": {
                "created": created,
                "updated": "2026-08-01T00:00:00Z",
                "expiry": "2030-06-24T17:00:00.000Z",
            },
            "domainStatus": ["clientTransferProhibited", "ok"],
            "dnssec": True,
        },
    }


@pytest.mark.asyncio
async def test_bkns_registered_normalization_is_minimized_cached_and_uses_fixed_endpoint() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert str(request.url.copy_with(query=None)) == BKNS_WHOIS_ENDPOINT
        assert dict(request.url.params) == {"domain": "example.vn"}
        assert request.headers["X-API-Key"] == "test-secret-key"
        return httpx.Response(200, json=_registered_payload())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = BknsWhoisProvider("test-secret-key", client=client, clock=lambda: NOW)
        first = await provider.lookup("login.example.vn")
        second = await provider.lookup("example.vn")

    assert first.status is ToolResultStatus.SUCCESS
    assert first.result is not None
    assert first.result.provider == "bkns-whois/v2"
    assert first.result.registrar == "Example Registrar"
    assert first.result.status == ["clientTransferProhibited", "ok"]
    assert first.result.privacy_redacted is True
    assert first.result.signals == []
    serialized = first.result.model_dump_json()
    assert "Must Never Escape" not in serialized
    assert "ns1.private.example" not in serialized
    assert "private-backend-name" not in serialized
    assert second.cache.status is CacheStatus.HIT
    assert second.usage.network_calls == 0
    assert calls == 1


@pytest.mark.asyncio
async def test_bkns_recent_registration_uses_existing_under_30_day_signal() -> None:
    payload = _registered_payload(created=(NOW - timedelta(days=29)).isoformat())
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await BknsWhoisProvider("key", client=client, clock=lambda: NOW).lookup("example.vn")
    assert result.result is not None
    assert result.result.signals == ["recent_registration"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected_signal", "expected_status"),
    [
        ("available", "not_found", ToolResultStatus.INCONCLUSIVE),
        ("pending", "pending", ToolResultStatus.SUCCESS),
        ("reserved", "reserved", ToolResultStatus.SUCCESS),
        ("auction", "auction", ToolResultStatus.SUCCESS),
    ],
)
async def test_bkns_non_registered_statuses_are_informational(
    status: str,
    expected_signal: str,
    expected_status: ToolResultStatus,
) -> None:
    payload: dict[str, object] = {"domain": "example.vn", "status": status}
    if status == "pending":
        payload["data"] = {"dates": {}, "domainStatus": []}
    if status == "reserved":
        payload["reservedBy"] = "Must Never Escape"
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await BknsWhoisProvider("key", client=client, clock=lambda: NOW).lookup("example.vn")
    assert result.status is expected_status
    assert result.result is not None and result.result.signals == [expected_signal]
    assert "Must Never Escape" not in result.result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (400, ToolErrorCode.INVALID_TARGET, False),
        (401, ToolErrorCode.PROVIDER_ERROR, False),
        (403, ToolErrorCode.PROVIDER_ERROR, False),
        (429, ToolErrorCode.RATE_LIMITED, True),
        (500, ToolErrorCode.PROVIDER_ERROR, True),
        (503, ToolErrorCode.PROVIDER_ERROR, True),
    ],
)
async def test_bkns_http_errors_are_normalized_without_provider_payload_or_key(
    status: int,
    code: ToolErrorCode,
    retryable: bool,
) -> None:
    secret = "never-log-this-key"
    provider_body = {"error": {"message": "private provider body"}}
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(status, headers={"Retry-After": "7"}, json=provider_body)
    )
    async with httpx.AsyncClient(transport=transport) as client:
        result = await BknsWhoisProvider(secret, client=client, clock=lambda: NOW).lookup("example.vn")
    assert result.error is not None
    assert result.error.code is code
    assert result.error.retryable is retryable
    assert result.error.http_status_code == status
    if status == 429:
        assert result.error.retry_after_ms == 7000
    serialized = result.model_dump_json()
    assert secret not in serialized
    assert "private provider body" not in serialized


@pytest.mark.asyncio
async def test_bkns_timeout_and_malformed_json_are_retryable_provider_failures() -> None:
    async def timeout_handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private timeout detail")

    timeout_client = httpx.AsyncClient(transport=httpx.MockTransport(timeout_handler))
    timeout = await BknsWhoisProvider("key", client=timeout_client, clock=lambda: NOW).lookup("example.vn")
    await timeout_client.aclose()
    malformed_transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"not-json"))
    async with httpx.AsyncClient(transport=malformed_transport) as client:
        malformed = await BknsWhoisProvider("key", client=client, clock=lambda: NOW).lookup("example.vn")
    assert timeout.error is not None and timeout.error.code is ToolErrorCode.PROVIDER_TIMEOUT
    assert malformed.error is not None and malformed.error.code is ToolErrorCode.PROVIDER_ERROR
    assert timeout.error.retryable is True and malformed.error.retryable is True


def _usage(provider: str, *, calls: int = 1) -> UsageMetadata:
    return UsageMetadata(
        usage_ref=f"usage:{provider}",
        provider=provider,
        provider_version="v1",
        operation="lookup",
        attempts=calls,
        network_calls=calls,
        latency_ms=1,
        request_units=calls,
        response_units=calls,
        observed_at=NOW,
    )


def _success(provider: str, signal: str = "") -> NormalizedToolResult[DomainIntelligenceResult]:
    signals = [signal] if signal else []
    return NormalizedToolResult(
        status=ToolResultStatus.INCONCLUSIVE
        if signal in {"not_found", "service_unavailable"}
        else ToolResultStatus.SUCCESS,
        result=DomainIntelligenceResult(provider=provider, domain="example.com", signals=signals, observed_at=NOW),
        cache=CacheMetadata(status=CacheStatus.MISS),
        usage=_usage(provider),
    )


def _failure(provider: str) -> NormalizedToolResult[DomainIntelligenceResult]:
    return NormalizedToolResult(
        status=ToolResultStatus.FAILED,
        error=NormalizedToolError(
            tool=ToolName.RDAP,
            code=ToolErrorCode.PROVIDER_TIMEOUT,
            message="provider timed out",
            retryable=True,
            provider=provider,
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="failure"),
        usage=_usage(provider),
    )


class _FakeProvider:
    def __init__(self, result: NormalizedToolResult[DomainIntelligenceResult]) -> None:
        self.result = result
        self.calls: list[str] = []
        self.close_calls = 0

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]:
        self.calls.append(domain)
        return self.result.model_copy(deep=True)

    async def aclose(self) -> None:
        self.close_calls += 1


@pytest.mark.asyncio
async def test_router_uses_bkns_directly_for_vn_and_subnamespace() -> None:
    rdap = _FakeProvider(_success("iana-rdap"))
    bkns = _FakeProvider(_success("bkns-whois/v2"))
    router = DomainRegistrationProvider("key", rdap=rdap, bkns=bkns)
    await router.lookup("login.example.com.vn")
    assert rdap.calls == []
    assert bkns.calls == ["example.com.vn"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rdap_result", [_success("iana-rdap"), _success("iana-rdap", "not_found"), _failure("iana-rdap")]
)
async def test_router_does_not_fallback_for_rdap_service_hit_no_hit_or_failure(
    rdap_result: NormalizedToolResult[DomainIntelligenceResult],
) -> None:
    rdap = _FakeProvider(rdap_result)
    bkns = _FakeProvider(_success("bkns-whois/v2"))
    result = await DomainRegistrationProvider("key", rdap=rdap, bkns=bkns).lookup("example.com")
    assert result.usage.provider == "iana-rdap"
    assert rdap.calls == ["example.com"]
    assert bkns.calls == []


@pytest.mark.asyncio
async def test_router_fallback_returns_only_bkns_result_and_combines_usage() -> None:
    rdap = _FakeProvider(_success("iana-rdap", "service_unavailable"))
    bkns = _FakeProvider(_success("bkns-whois/v2", "recent_registration"))
    result = await DomainRegistrationProvider("key", rdap=rdap, bkns=bkns).lookup("example.com")
    assert result.result is not None and result.result.signals == ["recent_registration"]
    assert result.usage.provider == "bkns-whois/v2"
    assert result.usage.attempts == 2
    assert result.usage.network_calls == 2
    assert rdap.calls == ["example.com"] and bkns.calls == ["example.com"]


@pytest.mark.asyncio
async def test_router_fallback_cache_hit_has_zero_end_to_end_network_calls() -> None:
    rdap_result = _success("iana-rdap", "service_unavailable").model_copy(
        update={
            "cache": CacheMetadata(
                status=CacheStatus.HIT,
                cache_key_hash="1" * 64,
                stored_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=1),
            ),
            "usage": _usage("iana-rdap", calls=0),
        }
    )
    bkns_result = _success("bkns-whois/v2").model_copy(
        update={
            "cache": CacheMetadata(
                status=CacheStatus.HIT,
                cache_key_hash="2" * 64,
                stored_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=1),
            ),
            "usage": _usage("bkns-whois/v2", calls=0),
        }
    )
    result = await DomainRegistrationProvider(
        "key",
        rdap=_FakeProvider(rdap_result),
        bkns=_FakeProvider(bkns_result),
    ).lookup("example.com")
    assert result.cache.status is CacheStatus.HIT
    assert result.usage.network_calls == 0


def test_bkns_result_keeps_public_rdap_evidence_type_and_actual_source() -> None:
    envelope = _success("bkns-whois/v2", "recent_registration")
    step = InvestigationStepV4(
        step_id="step-123456789abc",
        tool=SecurityInvestigationToolV4.RDAP,
        target="example.com",
        reason_code="registration_metadata",
        status=SecurityInvestigationStepStatusV4.PENDING,
    )
    evidence, limitations = SecurityInvestigationService()._provider_evidence(step, envelope)
    assert limitations == []
    assert len(evidence) == 1
    assert evidence[0].type is SecurityEvidenceTypeV4.RDAP
    assert evidence[0].source == "bkns-whois/v2"
    assert evidence[0].signal == "recent_registration"


@pytest.mark.asyncio
async def test_router_without_key_preserves_rdap_behavior_and_closes_each_provider_once() -> None:
    rdap = _FakeProvider(_success("iana-rdap", "service_unavailable"))
    unused_bkns = _FakeProvider(_success("bkns-whois/v2"))
    no_key = DomainRegistrationProvider("", rdap=rdap, bkns=unused_bkns)
    result = await no_key.lookup("example.vn")
    await no_key.aclose()
    assert result.result is not None and result.result.signals == ["service_unavailable"]
    assert rdap.calls == ["example.vn"] and unused_bkns.calls == []
    assert rdap.close_calls == 1 and unused_bkns.close_calls == 1


def test_bkns_configuration_is_not_present_in_normalized_contract() -> None:
    fields = set(DomainIntelligenceResult.model_fields)
    assert not fields & {"registrant", "nameservers", "raw", "reservedBy", "api_key"}
    assert "private provider body" not in json.dumps(sorted(fields))
