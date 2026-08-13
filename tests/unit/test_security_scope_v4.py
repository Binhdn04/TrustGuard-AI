import pytest
from pydantic import ValidationError

from src.agents.security_scope import classify_security_scope, extract_security_context
from src.models import (
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
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


def test_vague_phishing_question_needs_context() -> None:
    result = classify_security_scope("Đây có phải phishing không?")

    assert result.decision is ScopeDecisionV4.NEED_MORE_INFO


def test_vague_security_concern_needs_one_focused_follow_up() -> None:
    response = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message="Tôi nhận được tin nhắn lạ"))

    assert response.scope_decision is ScopeDecisionV4.NEED_MORE_INFO
    assert response.terminal is True
    assert response.next_step == "END"
    assert response.follow_up_question is not None
    assert response.follow_up_question.count("?") == 1
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
    assert "organization_requests_action" in context.impersonation_signals


def test_financial_transfer_context() -> None:
    context = extract_security_context("Chuyển tiền ngay vào tài khoản này để mở khóa tài khoản.")

    assert context.payment_request is True
    assert context.urgency is True
    assert context.scenario is SecurityScenarioV4.ACCOUNT_VERIFICATION
    assert context.requested_action is RequestedActionV4.TRANSFER_MONEY
    assert context.potential_threat is PotentialThreatV4.FINANCIAL_SCAM


def test_promotion_login_context_keeps_url_and_credential_signal() -> None:
    context = extract_security_context("Bạn trúng voucher 5 triệu, đăng nhập gift.example/login để nhận quà.")

    assert context.scenario is SecurityScenarioV4.PROMOTION_PRIZE
    assert context.potential_threat is PotentialThreatV4.PROMOTION_PRIZE_SCAM
    assert context.credential_request is True
    assert context.requested_action is RequestedActionV4.LOGIN
    assert context.amount == "5 triệu"
    assert context.urls == ["https://gift.example/login"]


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
