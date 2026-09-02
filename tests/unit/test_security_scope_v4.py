import pytest
from pydantic import ValidationError

from src.agents.security_scope import classify_security_scope, extract_security_context
from src.models import (
    AnalysisStatus,
    AssistantImmediateStepV4,
    AssistantReasonV4,
    AssistantResponseV4,
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityInvestigationStatusV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_triage import SecurityTriageScopeService


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("Tây Ban Nha vô địch World Cup đúng không?", "general_fact_check_sports"),
        ("Tin tổng thống vừa từ chức có thật không?", "general_fact_check_politics"),
        ("Thuốc này chữa khỏi ung thư đúng không?", "general_fact_check_medical_science"),
        ("Bài báo này có phải fake news không?", "general_fact_check_news"),
    ],
)
def test_explicit_general_fact_check_categories_are_out_of_scope(message: str, reason: str) -> None:
    result = classify_security_scope(message)

    assert result.decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert result.reason_codes == (reason,)


def test_security_signal_takes_precedence_over_incidental_general_topic() -> None:
    result = classify_security_scope("Ngân hàng yêu cầu gửi OTP để xem kết quả World Cup")

    assert result.decision is ScopeDecisionV4.IN_SCOPE
    assert "otp_request" in result.reason_codes


def test_explicit_impersonation_is_in_scope() -> None:
    result = classify_security_scope("Có người giả mạo ngân hàng để liên hệ với tôi")

    assert result.decision is ScopeDecisionV4.IN_SCOPE
    assert "impersonation_signal" in result.reason_codes


@pytest.mark.parametrize("message", ["Xin chào", "Chào bạn!", "Hello", "Hi TrustGuard"])
def test_basic_greeting_is_a_terminal_local_boundary(message: str) -> None:
    response = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))

    assert response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert response.scope_reasons == ["assistant_greeting"]
    assert response.boundary_message is None
    assert response.risk is None
    assert response.tool_calls_used == 0


@pytest.mark.parametrize("message", ["Bạn là ai?", "TrustGuard là gì?", "Hướng dẫn sử dụng"])
def test_basic_capability_questions_are_a_terminal_local_boundary(message: str) -> None:
    response = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))

    assert response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert response.scope_reasons == ["assistant_capabilities"]
    assert response.boundary_message is None


def test_security_content_takes_precedence_over_a_greeting() -> None:
    result = classify_security_scope("Xin chào, ngân hàng yêu cầu tôi gửi OTP ngay")

    assert result.decision is ScopeDecisionV4.IN_SCOPE
    assert "otp_request" in result.reason_codes


def test_vague_phishing_question_needs_context() -> None:
    result = classify_security_scope("Đây có phải phishing không?")

    assert result.decision is ScopeDecisionV4.NEED_MORE_INFO


def test_vague_security_concern_defers_follow_up_prose_to_response_composer() -> None:
    response = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message="Tôi nhận được tin nhắn lạ"))

    assert response.scope_decision is ScopeDecisionV4.NEED_MORE_INFO
    assert response.terminal is True
    assert response.next_step == "END"
    assert response.follow_up_question is None
    assert response.security_context is None


def test_recruitment_fee_context_keeps_scenario_threat_payment_and_amount_separate() -> None:
    context = extract_security_context("HR yêu cầu tôi đóng 500k phí hồ sơ")

    assert context.claimed_entity == "HR"
    assert context.scenario is SecurityScenarioV4.RECRUITMENT
    assert context.potential_threat is PotentialThreatV4.RECRUITMENT_SCAM
    assert context.payment_request is True
    assert context.requested_action is RequestedActionV4.PAY_FEE
    assert context.amount == "500k"


def test_otp_account_verification_context() -> None:
    context = extract_security_context("Ngân hàng yêu cầu gửi OTP để xác minh tài khoản")

    assert context.claimed_entity == "ngân hàng"
    assert context.scenario is SecurityScenarioV4.ACCOUNT_VERIFICATION
    assert context.otp_request is True
    assert context.requested_action is RequestedActionV4.SHARE_OTP
    assert context.potential_threat is PotentialThreatV4.PHISHING
    assert context.impersonation_signals == []


def test_inline_markdown_url_does_not_include_the_closing_backtick() -> None:
    context = extract_security_context("Northstar Institute yêu cầu đăng nhập tại `https://northstar.example/contact`")

    assert context.urls == ["https://northstar.example/contact"]


@pytest.mark.parametrize(
    "message",
    [
        "Tôi đang tự xác minh tài khoản Google của mình.",
        "Kiểm tra cách xác minh tài khoản của tổ chức này.",
        "Google có yêu cầu xác minh tài khoản không?",
    ],
)
def test_neutral_account_verification_does_not_imply_brand_impersonation(message: str) -> None:
    context = extract_security_context(message)

    assert context.scenario is SecurityScenarioV4.ACCOUNT_VERIFICATION
    assert context.impersonation_signals == []
    assert context.credential_request is False
    assert context.otp_request is False
    assert context.payment_request is False
    assert context.potential_threat is PotentialThreatV4.UNDETERMINED_SECURITY_THREAT


def test_financial_transfer_context() -> None:
    context = extract_security_context("Chuyển tiền ngay vào tài khoản này để mở khóa tài khoản.")

    assert context.payment_request is True
    assert context.urgency is True
    assert context.scenario is SecurityScenarioV4.ACCOUNT_VERIFICATION
    assert context.requested_action is RequestedActionV4.TRANSFER_MONEY
    assert context.potential_threat is PotentialThreatV4.FINANCIAL_SCAM


def test_promotion_login_context_keeps_login_distinct_from_credential_disclosure() -> None:
    context = extract_security_context("Bạn trúng voucher 5 triệu, đăng nhập gift.example/login để nhận quà.")

    assert context.scenario is SecurityScenarioV4.PROMOTION_PRIZE
    assert context.potential_threat is PotentialThreatV4.PROMOTION_PRIZE_SCAM
    assert context.credential_request is False
    assert context.requested_action is RequestedActionV4.LOGIN
    assert context.amount == "5 triệu"
    assert context.urls == ["https://gift.example/login"]


def test_legitimate_login_and_passport_application_do_not_imply_credential_theft() -> None:
    context = extract_security_context(
        "Công an phường bảo tôi đăng nhập vào https://vpcp.dichvucong.gov.vn/p/home/dvc-trang-chu.html làm hộ chiếu"
    )

    assert context.requested_action is RequestedActionV4.APPLY_FOR_PASSPORT
    assert context.credential_request is False
    assert context.potential_threat is PotentialThreatV4.UNDETERMINED_SECURITY_THREAT


def test_url_only_is_in_scope_without_inventing_a_specific_threat() -> None:
    response = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message="https://example.com"))

    assert response.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert response.security_context is not None
    assert response.security_context.scenario is SecurityScenarioV4.UNKNOWN
    assert response.security_context.potential_threat is PotentialThreatV4.UNDETERMINED_SECURITY_THREAT
    assert response.security_context.urls == ["https://example.com/"]


def test_extraction_failure_returns_partial_context_instead_of_failing_analysis() -> None:
    def fail_extraction(_message: str):
        raise RuntimeError("synthetic extractor failure")

    service = SecurityTriageScopeService(context_extractor=fail_extraction)
    response = service.assess(SecurityTriageCreateRequestV4(message="Kiểm tra https://example.com/login"))

    assert response.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert response.security_context is not None
    assert response.security_context.urls == ["https://example.com/login"]
    assert response.limitations


def test_scope_response_rejects_non_terminal_out_of_scope_state() -> None:
    with pytest.raises(ValidationError, match="out-of-scope response requires"):
        SecurityScopeResponseV4(
            scope_decision=ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
            terminal=False,
            next_step="INVESTIGATION",
            scope_reasons=["general_fact_check_sports"],
            boundary_message="Out of scope.",
        )


def test_stored_response_drops_ungrounded_legacy_assistant_synthesis() -> None:
    response = SecurityTriageScopeService().assess(
        SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay")
    )
    payload = response.model_dump(mode="json")
    payload.update(
        {
            "status": AnalysisStatus.COMPLETED.value,
            "terminal": True,
            "next_step": "END",
            "investigation_status": SecurityInvestigationStatusV4.COMPLETED.value,
            "investigation_plan": [],
            "evidence": [],
            "risk": SecurityRiskV4.INSUFFICIENT_EVIDENCE.value,
            "score": 0,
            "confidence": 0.5,
            "threat_type": PotentialThreatV4.PHISHING.value,
            "policy_version": "security-risk-v7",
            "recommended_actions": [SecurityRecommendedActionV4.DO_NOT_SHARE_OTP.value],
            "explanation": "Không đủ bằng chứng để xác minh độc lập.",
            "assistant_response": AssistantResponseV4(
                summary="Không gửi OTP.",
                top_reasons=[
                    AssistantReasonV4(
                        text="Tin nhắn yêu cầu OTP.",
                        evidence_refs=["evidence:0000000000000000"],
                    )
                ],
                immediate_steps=[
                    AssistantImmediateStepV4(
                        action=SecurityRecommendedActionV4.DO_NOT_SHARE_OTP,
                        policy_ref="security-risk-v7",
                    )
                ],
                generation_mode="policy_grounded",
            ).model_dump(mode="json"),
        }
    )

    with pytest.raises(ValidationError, match="assistant response cites evidence"):
        SecurityScopeResponseV4.model_validate(payload)

    restored = SecurityScopeResponseV4.model_validate_stored(payload)

    assert restored.assistant_response is None
    assert restored.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE


def test_stored_scope_response_removes_retired_investigation_tool_only_in_storage_mode() -> None:
    response = SecurityTriageScopeService().assess(
        SecurityTriageCreateRequestV4(message="Kiểm tra https://example.com")
    )
    payload = response.model_dump(mode="json")
    retired_step_id = "step-111111111111"
    payload["investigation_plan"] = [
        {
            "step_id": retired_step_id,
            "tool": "official_claim_verifier",
            "target": "example.com",
            "reason_code": "legacy_official_claim",
            "depends_on": [],
            "status": "skipped",
            "status_reason": "retired_tool",
        },
        {
            "step_id": "step-222222222222",
            "tool": "security_context_analysis",
            "target": "message",
            "reason_code": "security_context_required",
            "depends_on": [retired_step_id],
            "status": "pending",
            "status_reason": None,
        },
    ]

    with pytest.raises(ValidationError, match="official_claim_verifier"):
        SecurityScopeResponseV4.model_validate(payload)

    restored = SecurityScopeResponseV4.model_validate_stored(payload)

    assert [step.tool.value for step in restored.investigation_plan] == ["security_context_analysis"]
    assert restored.investigation_plan[0].depends_on == []
