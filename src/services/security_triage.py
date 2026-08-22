from __future__ import annotations

from collections.abc import Callable

from src.agents.security_scope import (
    classify_security_scope,
    extract_security_context,
    partial_security_context,
)
from src.models import (
    MissingInformationSlotV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)

ContextExtractor = Callable[[str], SecurityContextV4]

_BOUNDARY_MESSAGE = (
    "Trợ lý này chỉ đánh giá rủi ro phishing, lừa đảo, giả mạo và các yêu cầu có thể gây mất tài khoản "
    "hoặc tiền; hệ thống không xác minh tin tức hay kiến thức phổ thông."
)
_FOLLOW_UP_QUESTION = (
    "Bạn có thể gửi nội dung đầy đủ của tin nhắn, tên người gửi và đường link hoặc hành động họ yêu cầu không?"
)
_EXTRACTION_LIMITATION = "Chỉ trích xuất được một phần security context; cần xác minh thêm ở bước điều tra."
_CAPABILITIES_MESSAGE = (
    "Tôi là TrustGuard, trợ lý hỗ trợ nhận diện phishing, lừa đảo, giả mạo thương hiệu, URL đáng ngờ "
    "và các yêu cầu chuyển tiền, đăng nhập hoặc cung cấp OTP. Hãy gửi nội dung tin nhắn hoặc đường link "
    "bạn muốn kiểm tra; nếu còn thiếu thông tin, tôi sẽ hỏi lại từng câu ngắn."
)
_GREETING_MESSAGE = (
    "Chào bạn! Tôi là TrustGuard. Tôi có thể giúp bạn kiểm tra tin nhắn, đường link hoặc yêu cầu đáng ngờ "
    "trước khi bạn đăng nhập, gửi OTP hay chuyển tiền. Bạn muốn kiểm tra tình huống nào?"
)
_GENERAL_FACT_BOUNDARY_MESSAGE = (
    "Tôi không hỗ trợ kiểm chứng tin tức chung. Nếu thông tin này đang được dùng để yêu cầu bạn chuyển tiền, "
    "đăng nhập, cung cấp OTP hoặc thực hiện hành động có rủi ro, hãy gửi thêm nội dung để tôi kiểm tra dấu hiệu lừa đảo."
)
_RECRUITMENT_FOLLOW_UP = (
    "Yêu cầu ứng viên đóng phí hồ sơ là dấu hiệu đáng ngờ. Bạn có thể gửi URL tuyển dụng, địa chỉ email, "
    "số điện thoại hoặc thông tin tài khoản nhận tiền của người liên hệ không?"
)


class SecurityTriageScopeService:
    """WP1 boundary: local scope/context only, with no investigation adapters."""

    def __init__(self, context_extractor: ContextExtractor = extract_security_context) -> None:
        self._context_extractor = context_extractor

    def assess(self, request: SecurityTriageCreateRequestV4) -> SecurityScopeResponseV4:
        assessment = classify_security_scope(request.message)
        reasons = list(assessment.reason_codes)
        if assessment.decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
            if "assistant_greeting" in reasons:
                boundary_message = _GREETING_MESSAGE
            elif "assistant_capabilities" in reasons:
                boundary_message = _CAPABILITIES_MESSAGE
            elif "no_security_signal" in reasons or any(reason.startswith("general_fact_check_") for reason in reasons):
                boundary_message = _GENERAL_FACT_BOUNDARY_MESSAGE
            else:
                boundary_message = _BOUNDARY_MESSAGE
            return SecurityScopeResponseV4(
                scope_decision=assessment.decision,
                terminal=True,
                next_step="END",
                scope_reasons=reasons,
                boundary_message=boundary_message,
            )
        if assessment.decision is ScopeDecisionV4.NEED_MORE_INFO:
            return SecurityScopeResponseV4(
                scope_decision=assessment.decision,
                terminal=True,
                next_step="END",
                scope_reasons=reasons,
                follow_up_question=_FOLLOW_UP_QUESTION,
            )

        limitations: list[str] = []
        try:
            context = self._context_extractor(request.message)
        except Exception:
            context = partial_security_context(request.message)
            limitations.append(_EXTRACTION_LIMITATION)
        if (
            context.claimed_entity == "Vingroup"
            and context.scenario.value == "recruitment"
            and context.payment_request
            and not context.urls
        ):
            return SecurityScopeResponseV4(
                scope_decision=ScopeDecisionV4.NEED_MORE_INFO,
                terminal=True,
                next_step="END",
                scope_reasons=[*reasons, "recruitment_contact_required"],
                security_context=context,
                follow_up_slot=MissingInformationSlotV4.URL_OR_CONTACT,
                follow_up_question=_RECRUITMENT_FOLLOW_UP,
                limitations=limitations,
            )
        return SecurityScopeResponseV4(
            scope_decision=ScopeDecisionV4.IN_SCOPE,
            terminal=False,
            next_step="INVESTIGATION",
            scope_reasons=reasons,
            security_context=context,
            limitations=limitations,
        )


__all__ = ["SecurityTriageScopeService"]
