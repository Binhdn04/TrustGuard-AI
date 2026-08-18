from datetime import UTC, datetime

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.tools import FakeBlacklistRepository
from src.models import (
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
    assert result.policy_version == "security-risk-v1"
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
