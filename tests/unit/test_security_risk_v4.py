from datetime import UTC, datetime

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.tools import FakeBlacklistRepository
from src.models import (
    EntityUrlClaimV4,
    EntityUrlRelationshipV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationToolV4,
    SecurityRiskV4,
    SecurityToolErrorV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 1, 1, tzinfo=UTC)


async def _assess(message: str, *, blacklist: list[str] | None = None):
    request = SecurityTriageCreateRequestV4(message=message)
    scoped = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService(blacklist=FakeBlacklistRepository(blacklist or [])).investigate(
        request, scoped
    )
    return assess_security_risk(investigated)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Đăng nhập https://example.com/login và gửi mật khẩu ngay", SecurityRiskV4.HIGH_RISK),
        ("HR yêu cầu đóng 500k phí hồ sơ", SecurityRiskV4.HIGH_RISK),
        ("Ngân hàng giả mạo yêu cầu gửi OTP ngay", SecurityRiskV4.HIGH_RISK),
        ("Chuyển tiền ngay để mở khóa tài khoản", SecurityRiskV4.HIGH_RISK),
        ("Trúng voucher, đăng nhập https://example.com/login", SecurityRiskV4.HIGH_RISK),
    ],
)
async def test_high_risk_security_fixtures(message: str, expected: SecurityRiskV4) -> None:
    result = await _assess(message)
    assert result.risk is expected
    assert result.policy_version == (
        "security-risk-v6" if result.security_context and result.security_context.claimed_entity else "security-risk-v1"
    )
    assert result.explanation_evidence_refs


@pytest.mark.asyncio
async def test_approved_blacklist_is_strong_malicious_evidence() -> None:
    result = await _assess("Mở link https://bad.example/login", blacklist=["bad.example"])
    assert result.risk is SecurityRiskV4.MALICIOUS
    assert result.score >= 95


@pytest.mark.asyncio
async def test_no_hit_and_provider_failure_never_become_safe() -> None:
    result = await _assess("Kiểm tra link https://example.com")
    payload = result.model_dump()
    payload.update(
        limitations=["URL reputation provider no-hit; no-hit không chứng minh an toàn."],
        errors=[
            SecurityToolErrorV4(
                tool=SecurityInvestigationToolV4.URL_REPUTATION,
                target="https://example.com",
                code="PROVIDER_TIMEOUT",
                message="Provider timed out.",
                retryable=True,
                provider="fixture",
            )
        ],
        risk=None,
        score=None,
        confidence=None,
        threat_type=None,
        policy_version=None,
        recommended_actions=[],
        explanation=None,
        explanation_evidence_refs=[],
        terminal=False,
        next_step="RISK_ASSESSMENT",
        status="running",
        completed_at=None,
    )
    reassessed = assess_security_risk(type(result).model_validate(payload))
    assert reassessed.risk is not SecurityRiskV4.SAFE
    assert reassessed.confidence <= 0.65


@pytest.mark.asyncio
async def test_url_inspection_and_unverified_identity_are_not_action_or_risk_evidence() -> None:
    """Unknown verification states stay limitations for every submitted domain."""
    request = SecurityTriageCreateRequestV4(message="Check https://arbitrary.example")
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.security_context is not None
    assert scoped.security_context.requested_action is None

    context = scoped.security_context.model_copy(
        update={
            "claimed_entity": "Arbitrary Organization",
            "entity_url_claims": [
                EntityUrlClaimV4(
                    entity_name="Arbitrary Organization",
                    url_index=0,
                    relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
                    confidence=1.0,
                )
            ],
        }
    )
    investigated = await SecurityInvestigationService().investigate(
        request,
        scoped.model_copy(update={"security_context": context}),
    )
    unverified = SecurityEvidenceV4(
        evidence_ref=f"evidence:{'3' * 16}",
        type=SecurityEvidenceTypeV4.BRAND_MATCH,
        source="fixture",
        target="arbitrary.example",
        signal="claimed_identity_unverified",
        description="No reviewed association is available.",
        observed_at=NOW,
        confidence=0.5,
    )
    payload = investigated.model_dump()
    payload["evidence"] = [unverified]
    result = assess_security_risk(type(investigated).model_validate(payload))

    assert result.score == 0
    assert result.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert result.risk is not SecurityRiskV4.MALICIOUS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("evidence_type", "signal"),
    [
        (SecurityEvidenceTypeV4.URL_REPUTATION, "provider_no_hit"),
        (SecurityEvidenceTypeV4.URL_REPUTATION, "provider_conflict"),
        (SecurityEvidenceTypeV4.RDAP, "service_unavailable"),
        (SecurityEvidenceTypeV4.BRAND_MATCH, "claimed_identity_unverified"),
        (SecurityEvidenceTypeV4.BRAND_MATCH, "entity_url_relation_unresolved"),
    ],
)
async def test_non_positive_evidence_never_escalates_neutral_inspection(evidence_type, signal) -> None:
    request = SecurityTriageCreateRequestV4(message="Check https://arbitrary.example")
    investigated = await SecurityInvestigationService().investigate(
        request, SecurityTriageScopeService().assess(request)
    )
    evidence = SecurityEvidenceV4(
        evidence_ref=f"evidence:{'4' * 16}",
        type=evidence_type,
        source="fixture",
        target="arbitrary.example",
        signal=signal,
        description="Non-positive coverage or conflicting evidence.",
        observed_at=NOW,
    )
    payload = investigated.model_dump()
    payload["evidence"] = [evidence]

    result = assess_security_risk(type(investigated).model_validate(payload))

    assert result.score == 0
    assert result.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["domain_mismatch", "new_domain"])
async def test_isolated_domain_signal_is_never_malicious(signal: str) -> None:
    request = SecurityTriageCreateRequestV4(message="Kiểm tra link https://example.com")
    investigated = await SecurityInvestigationService().investigate(
        request, SecurityTriageScopeService().assess(request)
    )
    evidence = SecurityEvidenceV4(
        evidence_ref=f"evidence:{'1' * 16}",
        type=SecurityEvidenceTypeV4.RDAP,
        source="fixture",
        target="example.com",
        signal=signal,
        description="Một tín hiệu domain độc lập.",
        observed_at=NOW,
    )
    payload = investigated.model_dump()
    payload["evidence"] = [evidence]
    result = assess_security_risk(type(investigated).model_validate(payload))
    assert result.risk in {SecurityRiskV4.LOW_RISK, SecurityRiskV4.SUSPICIOUS}


@pytest.mark.asyncio
async def test_bkns_recent_registration_uses_the_existing_fifteen_point_rdap_rule() -> None:
    request = SecurityTriageCreateRequestV4(message="Kiểm tra link https://example.vn")
    investigated = await SecurityInvestigationService().investigate(
        request, SecurityTriageScopeService().assess(request)
    )
    evidence = SecurityEvidenceV4(
        evidence_ref=f"evidence:{'2' * 16}",
        type=SecurityEvidenceTypeV4.RDAP,
        source="bkns-whois/v2",
        target="example.vn",
        signal="recent_registration",
        description="Registration metadata marks the domain as recently created.",
        observed_at=NOW,
    )
    payload = investigated.model_dump()
    payload["evidence"] = [evidence]
    result = assess_security_risk(type(investigated).model_validate(payload))
    assert result.score == 15
    assert result.risk is SecurityRiskV4.LOW_RISK


@pytest.mark.asyncio
async def test_policy_is_deterministic_for_same_investigation() -> None:
    request = SecurityTriageCreateRequestV4(message="HR yêu cầu đóng 500k phí hồ sơ")
    investigated = await SecurityInvestigationService().investigate(
        request, SecurityTriageScopeService().assess(request)
    )
    first = assess_security_risk(investigated)
    second = assess_security_risk(investigated)
    assert (first.risk, first.score, first.confidence, first.policy_version, first.recommended_actions) == (
        second.risk,
        second.score,
        second.confidence,
        second.policy_version,
        second.recommended_actions,
    )
