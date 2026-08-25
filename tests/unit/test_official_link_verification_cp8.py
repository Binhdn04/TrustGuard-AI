from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.agents.security_risk import assess_security_risk
from src.config import Settings
from src.core.logging import RedactingJsonFormatter
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    ClaimVerificationV4,
    ExposureStateV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    OfficialLinkReferenceV4,
    OfficialLinkVerificationReportV4,
    OfficialSourceReferenceV4,
    OfficialVerificationComponentV4,
    PublisherVerificationV4,
    RequestedActionV4,
    ResourceVerificationV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
)
from src.security_ai.runtime import TurnExecutionContext
from src.services.official_verification_coordinator import OfficialVerificationCoordinatorOutcome
from src.services.official_verification_rollout import (
    OfficialVerificationMode,
    OfficialVerificationRolloutStage,
    OfficialVerificationTelemetryEvent,
)
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 8, 20, tzinfo=UTC)
SOURCE_REF = f"source:{'1' * 16}"
LINK_REF = f"link:{'2' * 16}"


def _report(
    status: VerificationStatusV4,
    *,
    limitations: list[str] | None = None,
) -> OfficialLinkVerificationReportV4:
    identity = OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.PRIMARY_WEBSITE,
        canonical_value="vingroup.net",
        display_value="vingroup.net",
        entity_name="Vingroup",
        match_scope="host_and_subdomains",
        provenance="reviewed-brand-fixture",
        policy_version="brand-registry-v1",
        reviewed=True,
        source_ref=SOURCE_REF,
    )
    publisher = PublisherVerificationV4(
        applicable=True,
        status=status,
        reason_code="fixture_publisher",
        evidence_refs=[SOURCE_REF],
        identity=identity,
    )
    return OfficialLinkVerificationReportV4(
        intent={"organization_name": "Vingroup"},
        publisher_verification=publisher,
        claim_verification=ClaimVerificationV4(
            applicable=False,
            status=None,
            reason_code="not_applicable",
        ),
        resource_verification=ResourceVerificationV4(
            applicable=False,
            status=None,
            reason_code="not_applicable",
        ),
        overall_status=status,
        reason_code="fixture_status",
        source_refs=[
            OfficialSourceReferenceV4(
                source_ref=SOURCE_REF,
                identity=identity,
                display_url="https://vingroup.net/",
                canonical_url="https://vingroup.net/",
            )
        ],
        link_refs=[
            OfficialLinkReferenceV4(
                link_ref=LINK_REF,
                source_ref=SOURCE_REF,
                role="application",
                display_url="https://jobs.vingroup.net/",
                canonical_url="https://jobs.vingroup.net/",
            )
        ],
        limitations=limitations or [],
    )


def _scope(message: str = "Vingroup recruitment link https://jobs.vingroup.net"):
    request = SecurityTriageCreateRequestV4(message=message)
    return request, SecurityTriageScopeService().assess(request)


def _with_report(scope, report):
    return scope.model_copy(update={"official_verification": report})


def _brand_evidence(signal: str = "domain_mismatch") -> SecurityEvidenceV4:
    return SecurityEvidenceV4(
        evidence_ref=f"evidence:{'3' * 16}",
        type=SecurityEvidenceTypeV4.BRAND_MATCH,
        source="brand-registry",
        target="jobs.vingroup.net",
        signal=signal,
        description="Reviewed brand comparison fixture.",
        observed_at=NOW,
        provenance_ref="brand:fixture:brand-registry-v1",
    )


def _risk_fields(scope) -> tuple:
    return (
        scope.risk,
        scope.score,
        scope.confidence,
        scope.policy_version,
        scope.recommended_actions,
        scope.explanation_evidence_refs,
    )


class _Coordinator:
    def __init__(self, outcome: OfficialVerificationCoordinatorOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    async def coordinate(self, request, scope, *, execution_context):
        del request, scope, execution_context
        self.calls += 1
        return self.outcome


class _Telemetry:
    def __init__(self) -> None:
        self.events: list[OfficialVerificationTelemetryEvent] = []

    def record(self, event: OfficialVerificationTelemetryEvent) -> None:
        self.events.append(event)


def _verified_suppresses_only_same_target_reviewed_brand_mismatch() -> None:
    _, scoped = _scope()
    evidence = _brand_evidence()
    prepared = _with_report(scoped.model_copy(update={"evidence": [evidence]}), _report(VerificationStatusV4.VERIFIED))

    legacy = assess_security_risk(prepared)
    enforced = assess_security_risk(prepared, official_verification_enforced=True)
    wrong_provenance = assess_security_risk(
        prepared.model_copy(
            update={"evidence": [evidence.model_copy(update={"provenance_ref": "brand:fixture:brand-registry-v2"})]}
        ),
        official_verification_enforced=True,
    )

    assert legacy.policy_version == "security-risk-v6"
    assert legacy.risk is SecurityRiskV4.LOW_RISK
    assert enforced.policy_version == "security-risk-v6"
    assert enforced.risk is SecurityRiskV4.SAFE
    assert enforced.score < legacy.score
    assert wrong_provenance.score == legacy.score
    assert wrong_provenance.risk is not SecurityRiskV4.SAFE


@pytest.mark.parametrize(
    ("kind", "signal"),
    [
        (SecurityEvidenceTypeV4.URL_REPUTATION, "malicious"),
        (SecurityEvidenceTypeV4.BLACKLIST, "approved_blacklist_hit"),
    ],
)
def test_verified_never_hides_strong_reputation_or_blacklist(kind, signal) -> None:
    _, scoped = _scope()
    strong = _brand_evidence(signal).model_copy(
        update={
            "type": kind,
            "source": "approved-security-provider",
            "provenance_ref": "decision:fixture",
        }
    )
    result = assess_security_risk(
        _with_report(scoped.model_copy(update={"evidence": [strong]}), _report(VerificationStatusV4.VERIFIED)),
        official_verification_enforced=True,
    )

    assert result.risk is SecurityRiskV4.MALICIOUS
    assert result.score >= 95


def test_sensitive_action_is_safe_only_when_action_chain_is_verified() -> None:
    _, scoped = _scope("Vingroup asks me to login and share password at https://jobs.vingroup.net")
    base_report = _report(VerificationStatusV4.VERIFIED)
    report = base_report.model_copy(
        update={
            "intent": base_report.intent.model_copy(update={"requested_action": RequestedActionV4.LOGIN}),
            "action_endorsement_verification": OfficialVerificationComponentV4(
                applicable=True,
                status=VerificationStatusV4.VERIFIED,
                reason_code="official_action_and_resource_confirmed",
                evidence_refs=[SOURCE_REF],
            ),
        }
    )
    result = assess_security_risk(
        _with_report(scoped, report),
        official_verification_enforced=True,
    )

    assert result.risk is SecurityRiskV4.SAFE
    assert result.score == 0
    assert result.recommended_actions == [SecurityRecommendedActionV4.ALLOW_OPEN]


def test_sensitive_action_without_verified_endorsement_is_not_safe() -> None:
    _, scoped = _scope("Vingroup asks me to login at https://jobs.vingroup.net")
    base_report = _report(VerificationStatusV4.VERIFIED)
    report = base_report.model_copy(
        update={
            "intent": base_report.intent.model_copy(update={"requested_action": RequestedActionV4.LOGIN}),
            "action_endorsement_verification": OfficialVerificationComponentV4(
                applicable=True,
                status=VerificationStatusV4.UNVERIFIED,
                reason_code="official_action_not_confirmed",
            ),
            "overall_status": VerificationStatusV4.PARTIALLY_VERIFIED,
        }
    )

    result = assess_security_risk(
        _with_report(scoped, report),
        official_verification_enforced=True,
    )

    assert result.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE


def test_verified_never_hides_reviewed_malicious_memory() -> None:
    _, scoped = _scope()
    reviewed = _brand_evidence("reviewed_memory_malicious+domain").model_copy(
        update={
            "type": SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY,
            "source": "reviewed-security-memory",
            "provenance_ref": "security-memory:fixture",
        }
    )
    result = assess_security_risk(
        _with_report(scoped.model_copy(update={"evidence": [reviewed]}), _report(VerificationStatusV4.VERIFIED)),
        memory_enabled=True,
        official_verification_enforced=True,
    )

    assert result.risk is not SecurityRiskV4.SAFE
    assert result.score >= 50


def test_verified_never_suppresses_recovery_first_incident_signal() -> None:
    _, scoped = _scope()
    incident = scoped.model_copy(
        update={
            "assistant_context": AssistantContextV4(
                processing_mode=AssistantProcessingModeV4.RULES_ONLY,
                exposure_state=ExposureStateV4.LINK_OPENED,
                model_version="cp8-fixture",
            ),
            "evidence": [_brand_evidence()],
            "official_verification": _report(VerificationStatusV4.VERIFIED),
        }
    )

    result = assess_security_risk(incident, official_verification_enforced=True)

    assert result.risk is not SecurityRiskV4.SAFE
    assert result.score >= 15


@pytest.mark.parametrize(
    ("status", "expected_score"),
    [
        (VerificationStatusV4.CONFLICTING, 25),
        (VerificationStatusV4.UNVERIFIED, 0),
    ],
)
def test_conflicting_is_bounded_and_unverified_adds_zero(status, expected_score) -> None:
    _, scoped = _scope("Check security link https://example.test")
    result = assess_security_risk(
        _with_report(scoped, _report(status)),
        official_verification_enforced=True,
    )

    assert result.score == expected_score
    assert result.risk is not SecurityRiskV4.MALICIOUS


@pytest.mark.asyncio
async def test_shadow_does_not_attach_or_persist_report_data_and_emits_redacted_aggregate() -> None:
    request, scoped = _scope()
    coordinator = _Coordinator(OfficialVerificationCoordinatorOutcome(report=_report(VerificationStatusV4.VERIFIED)))
    telemetry = _Telemetry()
    stage = OfficialVerificationRolloutStage(
        coordinator,  # type: ignore[arg-type]
        mode=OfficialVerificationMode.SHADOW,
        telemetry=telemetry,
    )

    result = await stage.run(request, scoped, execution_context=TurnExecutionContext())

    assert result is scoped
    assert result.official_verification is None
    assert coordinator.calls == 1
    assert len(telemetry.events) == 1
    event = telemetry.events[0]
    assert set(event.__dataclass_fields__) == {
        "analysis_id",
        "stage",
        "provider",
        "operation",
        "counts",
        "latency_ms",
        "cost_usd",
        "status",
        "strength",
        "target_hash",
        "error_code",
    }
    assert "jobs.vingroup.net" not in repr(event)


@pytest.mark.asyncio
@pytest.mark.parametrize("memory_enabled", [False, True])
async def test_off_shadow_visible_keep_legacy_risk_fields_and_only_visible_exposes_report(
    memory_enabled: bool,
) -> None:
    request, scoped = _scope()
    outcome = OfficialVerificationCoordinatorOutcome(report=_report(VerificationStatusV4.VERIFIED))
    baseline = assess_security_risk(scoped, memory_enabled=memory_enabled)
    shadow_scope = await OfficialVerificationRolloutStage(
        _Coordinator(outcome),  # type: ignore[arg-type]
        mode="shadow",
    ).run(request, scoped, execution_context=TurnExecutionContext())
    visible_scope = await OfficialVerificationRolloutStage(
        _Coordinator(outcome),  # type: ignore[arg-type]
        mode="visible",
    ).run(request, scoped, execution_context=TurnExecutionContext())

    shadow = assess_security_risk(shadow_scope, memory_enabled=memory_enabled)
    visible = assess_security_risk(visible_scope, memory_enabled=memory_enabled)

    assert _risk_fields(shadow) == _risk_fields(baseline)
    assert _risk_fields(visible) == _risk_fields(baseline)
    assert shadow.official_verification is None
    assert visible.official_verification is not None


@pytest.mark.asyncio
async def _enforced_provider_unavailable_falls_back_without_safe_upgrade() -> None:
    request, scoped = _scope()
    scoped = scoped.model_copy(update={"evidence": [_brand_evidence("official_match")]})
    unavailable = _report(
        VerificationStatusV4.UNVERIFIED,
        limitations=["official_web_search_unavailable"],
    )
    stage = OfficialVerificationRolloutStage(
        _Coordinator(
            OfficialVerificationCoordinatorOutcome(
                report=unavailable,
                limitations=["official_web_search_unavailable"],
            )
        ),  # type: ignore[arg-type]
        mode="enforced",
    )
    staged = await stage.run(request, scoped, execution_context=TurnExecutionContext())
    result = assess_security_risk(staged, official_verification_enforced=stage.risk_v3_enforced)

    assert result.policy_version == "security-risk-v6"
    assert result.risk is not SecurityRiskV4.SAFE
    assert "official_web_search_unavailable" in result.limitations


def test_rollout_settings_capabilities_and_validation_do_not_require_search_or_openai() -> None:
    visible = Settings(
        security_official_verification_mode="visible",
        tavily_api_key="",
        openai_api_key="",
        _env_file=None,
    )
    capabilities = visible.enabled_security_capabilities()

    assert capabilities["official_link_verification"] is True
    assert capabilities["official_web_search_ready"] is False
    independent = Settings(
        security_official_verification_mode="off",
        tavily_api_key="configured",
        _env_file=None,
    ).enabled_security_capabilities()
    assert independent["official_link_verification"] is False
    assert independent["official_web_search_ready"] is False
    with pytest.raises(ValidationError):
        Settings(security_official_verification_mode="invalid", _env_file=None)


def test_production_enforced_startup_does_not_require_tavily_or_openai() -> None:
    settings = Settings(
        app_env="production",
        demo_auth_enabled=False,
        database_url="postgresql://app:password@db.example/trustguard",
        redis_url="rediss://redis.example/0",
        database_encryption_key="database-encryption-secret-000001",
        oidc_issuer="https://identity.example/",
        oidc_audience="https://api.example",
        cors_origins="https://app.example",
        security_official_verification_mode="enforced",
        tavily_api_key="",
        openai_api_key="",
        _env_file=None,
    )

    assert settings.security_official_verification_mode == "enforced"
    assert settings.enabled_security_capabilities()["official_link_verification"] is True
    assert settings.enabled_security_capabilities()["official_web_search_ready"] is False


def test_structured_telemetry_serializes_only_the_redacted_allowlist() -> None:
    event = OfficialVerificationTelemetryEvent(
        analysis_id="00000000-0000-0000-0000-000000000001",
        stage="official_link_verification",
        provider="local_registry",
        operation="coordinate",
        counts={"adapter_attempts": 0},
        latency_ms=1,
        cost_usd=0.0,
        status="completed",
        strength="VERIFIED",
        target_hash="a" * 16,
    )
    record = logging.LogRecord(
        "trustguard.official_verification",
        logging.INFO,
        __file__,
        1,
        "official_verification_stage",
        (),
        None,
    )
    record.official_verification = {field: getattr(event, field) for field in event.__dataclass_fields__}
    payload = json.loads(RedactingJsonFormatter().format(record))

    assert payload["official_verification"] == record.official_verification
    assert "message" not in payload["official_verification"]
    assert "url" not in payload["official_verification"]


def test_rollback_modes_are_stateless_and_require_no_database_downgrade() -> None:
    assert [
        Settings(security_official_verification_mode=mode, _env_file=None).security_official_verification_mode
        for mode in (
            "enforced",
            "visible",
            "off",
        )
    ] == ["enforced", "visible", "off"]
