from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.agents.security_risk import assess_security_risk
from src.models import (
    AssistantGenerationModeV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import AssistantSynthesis, ModelResponse, SynthesisReason
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_response import (
    GroundedSecurityResponseService,
    SynthesisGroundingFailure,
    check_grounded_ai_response,
    grounded_ai_response,
)
from src.services.security_triage import SecurityTriageScopeService


def _risk_result():
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay")
    scoped = SecurityTriageScopeService().assess(request)
    evidence = SecurityEvidenceV4(
        evidence_ref="evidence:0123456789abcdef",
        type=SecurityEvidenceTypeV4.SECURITY_CONTEXT,
        source="security-context-v1",
        target="message",
        signal="account_verification+CREDENTIAL_THEFT+otp_request",
        description="Nội dung yêu cầu chia sẻ OTP với tính khẩn cấp.",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    return assess_security_risk(scoped.model_copy(update={"evidence": [evidence]}))


def test_grounding_verifier_rejects_hallucinated_refs_and_urls() -> None:
    scoped = _risk_result()
    invented = AssistantSynthesis(
        summary="Rủi ro cao.",
        top_reasons=[SynthesisReason(text="Threat hit", evidence_refs=["evidence:ffffffffffffffff"])],
    )
    linked = AssistantSynthesis(
        summary="Mở https://unsafe.example để kiểm tra.",
        top_reasons=[SynthesisReason(text="OTP request", evidence_refs=["evidence:0123456789abcdef"])],
    )
    statistical = AssistantSynthesis(
        summary="Rủi ro cao với điểm số 95/100 và độ tin cậy 90%.",
        top_reasons=[SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=["evidence:0123456789abcdef"])],
    )
    statistical_reason = AssistantSynthesis(
        summary="Nội dung này có nguy cơ cao.",
        top_reasons=[
            SynthesisReason(
                text="Tín hiệu OTP có độ tin cậy 90%.",
                evidence_refs=["evidence:0123456789abcdef"],
            )
        ],
    )
    natural_destination = AssistantSynthesis(
        summary="Liên kết này cần được xem xét thận trọng.",
        top_reasons=[
            SynthesisReason(
                text="Điểm đến cuối của liên kết cần được kiểm tra.",
                evidence_refs=["evidence:0123456789abcdef"],
            )
        ],
    )

    assert grounded_ai_response(scoped, invented) is None
    assert grounded_ai_response(scoped, linked) is None
    assert grounded_ai_response(scoped, statistical) is None
    assert grounded_ai_response(scoped, statistical_reason) is None
    assert grounded_ai_response(scoped, natural_destination) is not None

    assert check_grounded_ai_response(scoped, invented).failure is SynthesisGroundingFailure.UNKNOWN_EVIDENCE_REF
    assert check_grounded_ai_response(scoped, linked).failure is SynthesisGroundingFailure.UNSAFE_URL
    assert check_grounded_ai_response(scoped, statistical).failure is SynthesisGroundingFailure.TECHNICAL_METRIC


def test_grounding_verifier_allows_a_single_natural_reply_without_report_sections() -> None:
    scoped = _risk_result()
    synthesis = AssistantSynthesis(summary="Nội dung này cần được xem xét thận trọng.")

    checked = check_grounded_ai_response(scoped, synthesis)

    assert checked.response is not None
    assert checked.failure is None


class _ValidSynthesisModel:
    async def synthesize(self, result):
        ref = result["evidence"][0]["evidence_ref"]
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Yêu cầu OTP khẩn cấp có rủi ro cao.",
                top_reasons=[SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=[ref])],
                uncertainties=["Invented provider uncertainty must be ignored."],
                follow_up_offer="Invented procedural advice must be ignored.",
            ),
            provider="fake",
            model="synthesis-v1",
        )


class _MalformedSynthesisModel:
    async def synthesize(self, result):
        del result
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Unsupported claim.",
                top_reasons=[SynthesisReason(text="Invented signal.", evidence_refs=["evidence:ffffffffffffffff"])],
            ),
            provider="fake",
            model="synthesis-v1",
        )


@pytest.mark.asyncio
async def test_ai_response_keeps_actions_and_uncertainties_deterministic() -> None:
    scoped = _risk_result()
    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_ValidSynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(scoped)

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.AI
    assert [step.action for step in response.immediate_steps] == result.recommended_actions
    assert {step.policy_ref for step in response.immediate_steps} == {result.policy_version}
    assert response.uncertainties == scoped.limitations
    assert "Invented" not in response.follow_up_offer


@pytest.mark.asyncio
async def test_invalid_synthesis_uses_the_deterministic_fallback_only_when_composition_fails(caplog) -> None:
    with caplog.at_level("WARNING", logger="trustguard.security_ai"):
        result = await GroundedSecurityResponseService(
            ai_enabled=True,
            model=_MalformedSynthesisModel(),
            runtime=SecurityAssistantRuntime(max_retries=0),
        ).enrich(_risk_result())

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert "Unsupported claim" not in response.summary
    assert not any("grounding" in item.casefold() for item in response.uncertainties)
    assert any(item.getMessage() == "security_ai_composer_fallback" for item in caplog.records)


class _MetricSynthesisModel:
    async def synthesize(self, result):
        ref = result["evidence"][0]["evidence_ref"]
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Nội dung này đáng ngờ. Điểm số rủi ro là 95/100.",
                top_reasons=[
                    SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=[ref]),
                    SynthesisReason(text="Độ tin cậy 90%.", evidence_refs=[ref]),
                ],
            ),
            provider="fake",
            model="synthesis-v1",
        )


@pytest.mark.asyncio
async def test_metric_violation_falls_back_without_showing_internal_metrics() -> None:
    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_MetricSynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(_risk_result())

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert "95/100" not in response.summary
    assert "độ tin cậy" not in response.summary.casefold()


@pytest.mark.asyncio
async def test_disabled_ai_still_returns_a_policy_grounded_answer_without_failure_limitation() -> None:
    result = await GroundedSecurityResponseService(
        ai_enabled=False,
        model=None,
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(_risk_result())

    assert result.assistant_response is not None
    assert result.assistant_response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert "điểm số" not in result.assistant_response.summary.casefold()
    assert "độ tin cậy" not in result.assistant_response.summary.casefold()
    assert "Không chia sẻ mã OTP" in result.assistant_response.summary
    assert result.assistant_response.top_reasons[0].text == (
        "Người gửi yêu cầu mã OTP, là thông tin không nên chia sẻ."
    )
    assert not any("AI explanation" in item for item in result.limitations)


def test_composer_context_excludes_review_workflow_diagnostics() -> None:
    scoped = _risk_result().model_copy(
        update={
            "limitations": [
                "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức.",
                "Không thể xác nhận đầy đủ hành động được yêu cầu.",
            ]
        }
    )

    payload = GroundedSecurityResponseService._synthesis_payload(scoped)

    assert payload["important_uncertainties"] == ["Không thể xác nhận đầy đủ hành động được yêu cầu."]
    assert all("description" not in item for item in payload["evidence"])
    assert all("reviewed" not in str(value).casefold() for value in payload.values())
