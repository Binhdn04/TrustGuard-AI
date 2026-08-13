from __future__ import annotations

from collections.abc import Callable

from src.agents.security_scope import (
    classify_security_scope,
    extract_security_context,
    partial_security_context,
)
from src.models import (
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


class SecurityTriageScopeService:
    """WP1 boundary: local scope/context only, with no investigation adapters."""

    def __init__(self, context_extractor: ContextExtractor = extract_security_context) -> None:
        self._context_extractor = context_extractor

    def assess(self, request: SecurityTriageCreateRequestV4) -> SecurityScopeResponseV4:
        assessment = classify_security_scope(request.message)
        reasons = list(assessment.reason_codes)
        if assessment.decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
            return SecurityScopeResponseV4(
                scope_decision=assessment.decision,
                terminal=True,
                next_step="END",
                scope_reasons=reasons,
                boundary_message=_BOUNDARY_MESSAGE,
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
        return SecurityScopeResponseV4(
            scope_decision=ScopeDecisionV4.IN_SCOPE,
            terminal=False,
            next_step="INVESTIGATION",
            scope_reasons=reasons,
            security_context=context,
            limitations=limitations,
        )


__all__ = ["SecurityTriageScopeService"]
