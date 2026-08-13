from __future__ import annotations

import re
from dataclasses import dataclass

from src.agents.nodes.extraction import extract_urls
from src.agents.nodes.rules import normalize_url
from src.models import (
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityScenarioV4,
)

_SPACE_RE = re.compile(r"\s+")
_AMOUNT_RE = re.compile(
    r"(?<!\w)(?:\d{1,3}(?:[.,]\d{3})+|\d+(?:[.,]\d+)?)\s*(?:k|tr(?:iệu)?|triệu|đ|đồng|vnd|usd|\$)(?!\w)",
    re.IGNORECASE,
)

_CREDENTIAL_TERMS = (
    "đăng nhập",
    "dang nhap",
    "login",
    "sign in",
    "mật khẩu",
    "mat khau",
    "password",
    "thông tin đăng nhập",
    "credentials",
)
_OTP_TERMS = ("otp", "mã xác thực", "ma xac thuc", "mã xác minh", "verification code")
_PAYMENT_TERMS = (
    "chuyển tiền",
    "chuyen tien",
    "chuyển khoản",
    "chuyen khoan",
    "đóng phí",
    "dong phi",
    "nộp phí",
    "nop phi",
    "thanh toán",
    "payment",
    "pay fee",
    "bank account",
    "tài khoản nhận tiền",
    "qr thanh toán",
)
_RECRUITMENT_TERMS = (
    "tuyển dụng",
    "tuyen dung",
    "việc làm",
    "viec lam",
    "nhà tuyển dụng",
    "hr ",
    "hr yêu cầu",
    "phí hồ sơ",
    "phi ho so",
    "phỏng vấn",
    "recruitment",
    "job offer",
)
_PROMOTION_TERMS = (
    "trúng thưởng",
    "trung thuong",
    "trúng giải",
    "trung giai",
    "trúng voucher",
    "voucher",
    "khuyến mãi",
    "khuyen mai",
    "nhận quà",
    "nhan qua",
    "nhận thưởng",
    "prize",
    "giveaway",
)
_ACCOUNT_TERMS = (
    "xác minh tài khoản",
    "xac minh tai khoan",
    "mở khóa tài khoản",
    "mo khoa tai khoan",
    "khóa tài khoản",
    "khoa tai khoan",
    "account verification",
    "account locked",
)
_REFUND_TERMS = ("hoàn tiền", "hoan tien", "refund")
_PERSONAL_INFO_TERMS = (
    "cccd",
    "cmnd",
    "căn cước",
    "can cuoc",
    "thông tin cá nhân",
    "personal information",
    "số thẻ",
    "so the",
)
_IMPERSONATION_TERMS = ("giả mạo", "gia mao", "mạo danh", "mao danh", "impersonation", "impersonating")
_URGENCY_TERMS = (
    "ngay",
    "ngay lập tức",
    "ngay lap tuc",
    "chuyển ngay",
    "chuyen ngay",
    "làm ngay",
    "lam ngay",
    "khẩn cấp",
    "khan cap",
    "gấp",
    "trong hôm nay",
    "trong 24h",
    "immediately",
    "urgent",
)
_IMPERSONATION_ENTITIES = (
    ("ngân hàng", "ngân hàng"),
    ("ngan hang", "ngân hàng"),
    ("bank", "bank"),
    ("công an", "công an"),
    ("cong an", "công an"),
    ("police", "police"),
    ("cơ quan thuế", "cơ quan thuế"),
    ("co quan thue", "cơ quan thuế"),
    ("bảo hiểm", "bảo hiểm"),
    ("bao hiem", "bảo hiểm"),
    ("hr ", "HR"),
    ("hr yêu cầu", "HR"),
    ("nhà tuyển dụng", "nhà tuyển dụng"),
)
_IMPERSONATION_ACTION_TERMS = ("yêu cầu", "yeu cau", "thông báo", "thong bao", "gửi", "gui", "liên hệ")

_SPORTS_TERMS = (
    "world cup",
    "vô địch",
    "vo dich",
    "bóng đá",
    "bong da",
    "tỷ số",
    "ty so",
    "cầu thủ",
    "tran dau",
)
_POLITICS_TERMS = (
    "bầu cử",
    "bau cu",
    "tổng thống",
    "tong thong",
    "quốc hội",
    "quoc hoi",
    "chính trị",
    "chinh tri",
    "đảng phái",
)
_MEDICAL_SCIENCE_TERMS = (
    "chữa khỏi",
    "chua khoi",
    "ung thư",
    "ung thu",
    "vaccine",
    "vắc xin",
    "thuốc này",
    "nghiên cứu khoa học",
    "medical",
)
_GENERAL_NEWS_TERMS = (
    "tin tức",
    "tin tuc",
    "bài báo",
    "bai bao",
    "fake news",
    "sự kiện này có thật",
    "su kien nay co that",
)
_VAGUE_SECURITY_TERMS = (
    "tin nhắn lạ",
    "tin nhan la",
    "email lạ",
    "email la",
    "cuộc gọi lạ",
    "cuoc goi la",
    "có lừa đảo không",
    "co lua dao khong",
    "đáng ngờ",
    "dang ngo",
    "lừa đảo",
    "lua dao",
    "phishing",
    "scam",
    "suspicious message",
)


@dataclass(frozen=True, slots=True)
class ScopeAssessment:
    decision: ScopeDecisionV4
    reason_codes: tuple[str, ...]


def _fold(message: str) -> str:
    return _SPACE_RE.sub(" ", message.casefold()).strip()


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _is_payment_request(text: str, message: str) -> bool:
    if _contains_any(text, _PAYMENT_TERMS):
        return True
    has_fee_action = _contains_any(text, ("đóng", "dong", "nộp", "nop")) and _contains_any(
        text, ("phí", "phi")
    )
    return has_fee_action and _AMOUNT_RE.search(message) is not None


def classify_security_scope(message: str) -> ScopeAssessment:
    text = _fold(message)
    urls = extract_urls(message)
    reasons: list[str] = []

    security_groups = (
        ("credential_request", _CREDENTIAL_TERMS),
        ("otp_request", _OTP_TERMS),
        ("recruitment_context", _RECRUITMENT_TERMS),
        ("promotion_prize_context", _PROMOTION_TERMS),
        ("account_verification_context", _ACCOUNT_TERMS),
        ("refund_context", _REFUND_TERMS),
        ("personal_information_request", _PERSONAL_INFO_TERMS),
        ("impersonation_signal", _IMPERSONATION_TERMS),
    )
    for reason, terms in security_groups:
        if _contains_any(text, terms):
            reasons.append(reason)
    if _is_payment_request(text, message):
        reasons.append("payment_request")

    if reasons:
        if urls:
            reasons.append("url_present")
        return ScopeAssessment(ScopeDecisionV4.IN_SCOPE, tuple(dict.fromkeys(reasons)))

    out_of_scope_groups = (
        ("general_fact_check_sports", _SPORTS_TERMS),
        ("general_fact_check_politics", _POLITICS_TERMS),
        ("general_fact_check_medical_science", _MEDICAL_SCIENCE_TERMS),
        ("general_fact_check_news", _GENERAL_NEWS_TERMS),
    )
    for reason, terms in out_of_scope_groups:
        if _contains_any(text, terms):
            return ScopeAssessment(ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK, (reason,))

    if urls:
        return ScopeAssessment(ScopeDecisionV4.IN_SCOPE, ("url_present",))
    if _contains_any(text, _VAGUE_SECURITY_TERMS):
        return ScopeAssessment(ScopeDecisionV4.NEED_MORE_INFO, ("security_concern_missing_context",))
    return ScopeAssessment(ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK, ("no_security_signal",))


def _normalized_urls(message: str) -> list[str]:
    normalized: list[str] = []
    for value in extract_urls(message):
        candidate = normalize_url(value)
        if candidate is not None and candidate not in normalized:
            normalized.append(candidate)
    return normalized[:10]


def _claimed_entity(text: str) -> str | None:
    for term, entity in _IMPERSONATION_ENTITIES:
        if term in text:
            return entity
    return None


def _requested_action(
    text: str,
    *,
    otp_request: bool,
    credential_request: bool,
    payment_request: bool,
    recruitment: bool,
    personal_information_request: bool,
    urls: list[str],
) -> RequestedActionV4 | None:
    if otp_request:
        return RequestedActionV4.SHARE_OTP
    if credential_request:
        return RequestedActionV4.LOGIN if _contains_any(text, ("đăng nhập", "dang nhap", "login", "sign in")) else RequestedActionV4.SHARE_CREDENTIALS
    if payment_request:
        return RequestedActionV4.PAY_FEE if recruitment or _contains_any(text, ("đóng phí", "nộp phí", "pay fee")) else RequestedActionV4.TRANSFER_MONEY
    if personal_information_request:
        return RequestedActionV4.PROVIDE_PERSONAL_INFORMATION
    return RequestedActionV4.OPEN_LINK if urls else None


def extract_security_context(message: str) -> SecurityContextV4:
    text = _fold(message)
    urls = _normalized_urls(message)
    credential_request = _contains_any(text, _CREDENTIAL_TERMS)
    otp_request = _contains_any(text, _OTP_TERMS)
    payment_request = _is_payment_request(text, message)
    recruitment = _contains_any(text, _RECRUITMENT_TERMS)
    promotion = _contains_any(text, _PROMOTION_TERMS)
    account = _contains_any(text, _ACCOUNT_TERMS)
    refund = _contains_any(text, _REFUND_TERMS)
    personal_information_request = _contains_any(text, _PERSONAL_INFO_TERMS)
    entity = _claimed_entity(text)

    if recruitment:
        scenario = SecurityScenarioV4.RECRUITMENT
        threat = PotentialThreatV4.RECRUITMENT_SCAM
    elif promotion:
        scenario = SecurityScenarioV4.PROMOTION_PRIZE
        threat = PotentialThreatV4.PROMOTION_PRIZE_SCAM
    elif account:
        scenario = SecurityScenarioV4.ACCOUNT_VERIFICATION
        threat = (
            PotentialThreatV4.FINANCIAL_SCAM
            if payment_request
            else PotentialThreatV4.PHISHING
            if credential_request or otp_request
            else PotentialThreatV4.BRAND_IMPERSONATION
        )
    elif refund:
        scenario = SecurityScenarioV4.REFUND
        threat = PotentialThreatV4.FINANCIAL_SCAM
    elif payment_request:
        scenario = SecurityScenarioV4.PAYMENT
        threat = PotentialThreatV4.FINANCIAL_SCAM
    else:
        scenario = SecurityScenarioV4.UNKNOWN
        threat = (
            PotentialThreatV4.CREDENTIAL_THEFT
            if credential_request or otp_request
            else PotentialThreatV4.UNDETERMINED_SECURITY_THREAT
        )

    impersonation_signals: list[str] = []
    if entity is not None:
        impersonation_signals.append("claimed_organization")
        if _contains_any(text, _IMPERSONATION_ACTION_TERMS):
            impersonation_signals.append("organization_requests_action")

    amount_match = _AMOUNT_RE.search(message)
    return SecurityContextV4(
        claimed_entity=entity,
        scenario=scenario,
        requested_action=_requested_action(
            text,
            otp_request=otp_request,
            credential_request=credential_request,
            payment_request=payment_request,
            recruitment=recruitment,
            personal_information_request=personal_information_request,
            urls=urls,
        ),
        amount=amount_match.group(0) if amount_match else None,
        urgency=_contains_any(text, _URGENCY_TERMS),
        urls=urls,
        credential_request=credential_request,
        otp_request=otp_request,
        payment_request=payment_request,
        personal_information_request=personal_information_request,
        impersonation_signals=impersonation_signals,
        potential_threat=threat,
    )


def partial_security_context(message: str) -> SecurityContextV4:
    return SecurityContextV4(
        scenario=SecurityScenarioV4.UNKNOWN,
        urgency=False,
        urls=_normalized_urls(message),
        credential_request=False,
        otp_request=False,
        payment_request=False,
        personal_information_request=False,
        potential_threat=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
    )


__all__ = [
    "ScopeAssessment",
    "classify_security_scope",
    "extract_security_context",
    "partial_security_context",
]
