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
    VerificationTopicV4,
)
from src.services.security_entity_mentions import (
    deterministic_entity_url_claims,
    extract_entity_mentions,
)

_SPACE_RE = re.compile(r"\s+")
_AMOUNT_RE = re.compile(
    r"(?<!\w)(?:\d{1,3}(?:[.,]\d{3})+|\d+(?:[.,]\d+)?)\s*(?:k|củ|cu|tr(?:iệu)?|triệu|đ|đồng|vnd|usd|\$)(?!\w)",
    re.IGNORECASE,
)
_DEADLINE_RE = re.compile(r"\b(?:trước|truoc)\s+\d{1,2}\s*h\b", re.IGNORECASE)

_CREDENTIAL_TERMS = (
    "đăng nhập",
    "dang nhap",
    "login",
    "sign in",
    "mật khẩu",
    "mat khau",
    "password",
    "thông tin đăng nhập",
    "thong tin dang nhap",
    "credentials",
)
_OTP_TERMS = (
    "otp",
    "mã xác thực",
    "ma xac thuc",
    "ma xac thcc",
    "mã xác minh",
    "ma xac minh",
    "verification code",
)
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
    "chuyển toàn bộ tiền",
    "chuyen toan bo tien",
    "nạp tiền",
    "nap tien",
    "nạp ",
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
    "tuyendung",
    "tuyển cộng tác viên",
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
    "tài khoản sắp khóa",
    "tai khoan sap khoa",
    "tài khoản sắp bị khóa",
    "tai khoan sap bi khoa",
)
_REFUND_TERMS = ("hoàn tiền", "hoan tien", "refund")
_CHARITY_TERMS = ("quỹ cứu trợ", "quy cuu tro", "từ thiện", "tu thien", "quyên góp", "quyen gop")
_INVESTMENT_TERMS = ("đầu tư", "dau tu", "lợi nhuận", "loi nhuan", "cam kết lãi", "cam ket lai")
_ONLINE_TASK_TERMS = (
    "cộng tác viên",
    "cong tac vien",
    "đặt đơn online",
    "dat don online",
    "làm nhiệm vụ",
    "lam nhiem vu",
    "hoàn vốn",
    "hoan von",
)
_FEE_TERMS = ("phí xử lý", "phi xu ly", "phí hồ sơ", "phi ho so", "trả phí", "tra phi")
_PERSONAL_INFO_TERMS = (
    "cccd",
    "cmnd",
    "căn cước",
    "can cuoc",
    "thông tin cá nhân",
    "thong tin ca nhan",
    "personal information",
    "thông tin thẻ",
    "thong tin the",
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
    " lẹ",
    "le ",
)
_IMPERSONATION_ENTITIES = (
    ("tập đoàn vingroup", "Vingroup"),
    ("tap doan vingroup", "Vingroup"),
    ("vingroup", "Vingroup"),
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
    "có đúng không",
    "co dung khong",
    "có thật không",
    "co that khong",
)
_ASSISTANT_CAPABILITY_TERMS = (
    "bạn có thể làm gì",
    "ban co the lam gi",
    "bạn làm được gì",
    "ban lam duoc gi",
    "bạn là ai",
    "ban la ai",
    "trustguard là gì",
    "trustguard la gi",
    "cách sử dụng trustguard",
    "cach su dung trustguard",
    "hướng dẫn sử dụng",
    "huong dan su dung",
    "what can you do",
    "who are you",
    "how do i use trustguard",
)
_BASIC_GREETING_RE = re.compile(
    r"^(?:(?:xin\s+)?chào|hello|hi|hey|alo|good\s+(?:morning|afternoon|evening))"
    r"(?:\s+(?:bạn|trustguard))?[\s!,.?]*$",
    re.IGNORECASE,
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
_AMBIGUOUS_SENSITIVE_ACTION_TERMS = (
    "ck ",
    "chốt đơn",
    "chot don",
    "giữ suất",
    "giu suat",
    "nhập mã bí mật",
    "nhap ma bi mat",
)

_OPEN_LINK_TERMS = (
    "mở link",
    "mo link",
    "mở liên kết",
    "bấm link",
    "bam link",
    "nhấp link",
    "click link",
    "open link",
)
_INSTALL_APP_TERMS = (
    "cài ứng dụng",
    "cai ung dung",
    "cài app",
    "cai app",
    "cài anydesk",
    "cai anydesk",
    "cài teamviewer",
    "cai teamviewer",
    "install app",
)
_SHARE_SCREEN_TERMS = (
    "chia sẻ màn hình",
    "chia se man hinh",
    "bật chia sẻ màn hình",
    "bat chia se man hinh",
    "share screen",
)
_SCAN_QR_TERMS = ("quét mã qr", "quet ma qr", "quét qr", "quet qr", "scan qr")
_SUBMIT_FORM_TERMS = (
    "điền biểu mẫu",
    "dien bieu mau",
    "điền form",
    "dien form",
    "gửi form",
    "gui form",
    "nộp form",
    "nop form",
    "submit form",
)
_REGISTER_APPLY_TERMS = (
    "đăng ký",
    "dang ky",
    "ứng tuyển",
    "ung tuyen",
    "nộp hồ sơ",
    "nop ho so",
    "register",
    "apply",
)
_DOWNLOAD_FILE_TERMS = (
    "tải tệp",
    "tai tep",
    "tải file",
    "tai file",
    "tải xuống",
    "tai xuong",
    "download file",
    "download attachment",
)
_PASSPORT_APPLICATION_TERMS = (
    "làm hộ chiếu",
    "lam ho chieu",
    "xin hộ chiếu",
    "xin ho chieu",
    "cấp hộ chiếu",
    "cap ho chieu",
    "apply for a passport",
)

_FORM_CONTEXT_TERMS = (
    *_SUBMIT_FORM_TERMS,
    "biểu mẫu",
    "bieu mau",
    "google form",
    "microsoft form",
    "form đăng ký",
    "form dang ky",
    "form ứng tuyển",
    "form ung tuyen",
)
_EVENT_CONTEXT_TERMS = ("sự kiện", "su kien", "event", "hội thảo", "hoi thao", "workshop")
_COURSE_CONTEXT_TERMS = ("khóa học", "khoa hoc", "course", "lớp học", "lop hoc")
_SURVEY_CONTEXT_TERMS = ("khảo sát", "khao sat", "survey")

_NEUTRAL_CONTEXT_GROUPS = (
    ("neutral_recruitment_context", _RECRUITMENT_TERMS),
    ("neutral_promotion_context", _PROMOTION_TERMS),
    ("neutral_form_context", _FORM_CONTEXT_TERMS),
    ("neutral_event_context", _EVENT_CONTEXT_TERMS),
    ("neutral_course_context", _COURSE_CONTEXT_TERMS),
    ("neutral_survey_context", _SURVEY_CONTEXT_TERMS),
)

_ACTION_SOURCE_TERMS = {
    RequestedActionV4.LOGIN: ("đăng nhập", "dang nhap", "login", "sign in"),
    RequestedActionV4.SHARE_OTP: _OTP_TERMS,
    RequestedActionV4.SHARE_CREDENTIALS: _CREDENTIAL_TERMS,
    RequestedActionV4.TRANSFER_MONEY: _PAYMENT_TERMS,
    RequestedActionV4.PAY_FEE: (*_FEE_TERMS, "đóng phí", "dong phi", "nộp phí", "nop phi", "pay fee"),
    RequestedActionV4.PROVIDE_PERSONAL_INFORMATION: _PERSONAL_INFO_TERMS,
    RequestedActionV4.OPEN_LINK: _OPEN_LINK_TERMS,
    RequestedActionV4.INSTALL_APP: _INSTALL_APP_TERMS,
    RequestedActionV4.SHARE_SCREEN: _SHARE_SCREEN_TERMS,
    RequestedActionV4.SCAN_QR: _SCAN_QR_TERMS,
    RequestedActionV4.SUBMIT_FORM: _SUBMIT_FORM_TERMS,
    RequestedActionV4.REGISTER_OR_APPLY: _REGISTER_APPLY_TERMS,
    RequestedActionV4.DOWNLOAD_FILE: _DOWNLOAD_FILE_TERMS,
    RequestedActionV4.APPLY_FOR_PASSPORT: _PASSPORT_APPLICATION_TERMS,
}

_TOPIC_SOURCE_TERMS = (
    (VerificationTopicV4.RECRUITMENT, _RECRUITMENT_TERMS),
    (VerificationTopicV4.PROMOTION, _PROMOTION_TERMS),
    (VerificationTopicV4.EVENT, _EVENT_CONTEXT_TERMS),
    (VerificationTopicV4.COURSE, _COURSE_CONTEXT_TERMS),
    (VerificationTopicV4.SURVEY, _SURVEY_CONTEXT_TERMS),
    (VerificationTopicV4.ACCOUNT, _ACCOUNT_TERMS),
    (VerificationTopicV4.PAYMENT, _PAYMENT_TERMS),
    (VerificationTopicV4.CHARITY, _CHARITY_TERMS),
    (VerificationTopicV4.INVESTMENT, _INVESTMENT_TERMS),
)


@dataclass(frozen=True, slots=True)
class ScopeAssessment:
    decision: ScopeDecisionV4
    reason_codes: tuple[str, ...]


def _fold(message: str) -> str:
    return _SPACE_RE.sub(" ", message.casefold()).strip()


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _first_term_span(message: str, terms: tuple[str, ...]) -> tuple[int, int] | None:
    folded = message.casefold()
    matches: list[tuple[int, int]] = []
    for term in terms:
        candidate = term.strip().casefold()
        if not candidate:
            continue
        start = folded.find(candidate)
        if start >= 0:
            matches.append((start, start + len(candidate)))
    return min(matches, default=None)


def requested_action_source_span(message: str, action: RequestedActionV4) -> tuple[int, int] | None:
    """Return only a literal user-message span for a rule-supported action."""
    return _first_term_span(message, _ACTION_SOURCE_TERMS[action])


def verification_topic_source(
    message: str,
) -> tuple[VerificationTopicV4, str, tuple[int, int]] | None:
    """Return the first deterministic topic and its literal source text."""
    matches: list[tuple[int, VerificationTopicV4, tuple[int, int]]] = []
    for topic, terms in _TOPIC_SOURCE_TERMS:
        span = _first_term_span(message, terms)
        if span is not None:
            matches.append((span[0], topic, span))
    if not matches:
        return None
    _, topic, span = min(matches, key=lambda item: item[0])
    return topic, message[span[0] : span[1]], span


def _is_payment_request(text: str, message: str) -> bool:
    if _contains_any(text, _PAYMENT_TERMS):
        return True
    if _AMOUNT_RE.search(message) is not None and _contains_any(
        text,
        ("yêu cầu chuyển", "yeu cau chuyen", "chuyển trước", "chuyen truoc", "phải chuyển", "phai chuyen"),
    ):
        return True
    has_fee_action = _contains_any(text, ("đóng", "dong", "nộp", "nop")) and _contains_any(text, ("phí", "phi"))
    return has_fee_action and _AMOUNT_RE.search(message) is not None


def _is_refund_context(text: str, message: str) -> bool:
    return _contains_any(text, _REFUND_TERMS) or (
        _contains_any(text, ("hoàn ", "hoan ")) and _AMOUNT_RE.search(message) is not None
    )


def _neutral_context_reasons(text: str) -> list[str]:
    return [reason for reason, terms in _NEUTRAL_CONTEXT_GROUPS if _contains_any(text, terms)]


def _explicit_requested_action(text: str) -> RequestedActionV4 | None:
    if _contains_any(text, _PASSPORT_APPLICATION_TERMS):
        return RequestedActionV4.APPLY_FOR_PASSPORT
    if _contains_any(text, _INSTALL_APP_TERMS):
        return RequestedActionV4.INSTALL_APP
    if _contains_any(text, _SHARE_SCREEN_TERMS):
        return RequestedActionV4.SHARE_SCREEN
    if _contains_any(text, _SCAN_QR_TERMS):
        return RequestedActionV4.SCAN_QR
    if _contains_any(text, _DOWNLOAD_FILE_TERMS):
        return RequestedActionV4.DOWNLOAD_FILE
    if _contains_any(text, _SUBMIT_FORM_TERMS):
        return RequestedActionV4.SUBMIT_FORM
    if _contains_any(text, _REGISTER_APPLY_TERMS):
        return RequestedActionV4.REGISTER_OR_APPLY
    if _contains_any(text, _OPEN_LINK_TERMS):
        return RequestedActionV4.OPEN_LINK
    return None


def classify_security_scope(message: str) -> ScopeAssessment:
    text = _fold(message)
    urls = extract_urls(message)
    reasons: list[str] = []

    security_groups = (
        ("credential_request", _CREDENTIAL_TERMS),
        ("otp_request", _OTP_TERMS),
        ("account_verification_context", _ACCOUNT_TERMS),
        ("charity_context", _CHARITY_TERMS),
        ("investment_context", _INVESTMENT_TERMS),
        ("online_task_context", _ONLINE_TASK_TERMS),
        ("personal_information_request", _PERSONAL_INFO_TERMS),
        ("impersonation_signal", _IMPERSONATION_TERMS),
    )
    for reason, terms in security_groups:
        if _contains_any(text, terms):
            reasons.append(reason)
    if _is_refund_context(text, message):
        reasons.append("refund_context")
    if _is_payment_request(text, message):
        reasons.append("payment_request")

    neutral_reasons = _neutral_context_reasons(text)
    explicit_action = _explicit_requested_action(text)
    high_sensitivity_actions = {
        RequestedActionV4.OPEN_LINK,
        RequestedActionV4.INSTALL_APP,
        RequestedActionV4.SHARE_SCREEN,
        RequestedActionV4.SCAN_QR,
        RequestedActionV4.DOWNLOAD_FILE,
    }
    if explicit_action in high_sensitivity_actions:
        reasons.append(f"{explicit_action.value}_request")
    elif explicit_action in {RequestedActionV4.SUBMIT_FORM, RequestedActionV4.REGISTER_OR_APPLY} and (
        _contains_any(text, _VAGUE_SECURITY_TERMS)
        or _contains_any(text, _IMPERSONATION_TERMS)
        or _contains_any(text, _URGENCY_TERMS)
    ):
        reasons.append(f"{explicit_action.value}_security_context")

    if reasons:
        reasons.extend(neutral_reasons)
        if urls:
            reasons.append("url_present")
        return ScopeAssessment(ScopeDecisionV4.IN_SCOPE, tuple(dict.fromkeys(reasons)))

    if _contains_any(text, _ASSISTANT_CAPABILITY_TERMS):
        return ScopeAssessment(ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK, ("assistant_capabilities",))

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
    if neutral_reasons:
        if _contains_any(text, _VAGUE_SECURITY_TERMS):
            return ScopeAssessment(
                ScopeDecisionV4.IN_SCOPE,
                tuple(dict.fromkeys(["security_verification_request", *neutral_reasons])),
            )
        return ScopeAssessment(ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK, tuple(neutral_reasons))
    if _contains_any(text, _AMBIGUOUS_SENSITIVE_ACTION_TERMS):
        return ScopeAssessment(ScopeDecisionV4.NEED_MORE_INFO, ("ambiguous_sensitive_action",))
    if _contains_any(text, _VAGUE_SECURITY_TERMS):
        return ScopeAssessment(ScopeDecisionV4.NEED_MORE_INFO, ("security_concern_missing_context",))
    if _BASIC_GREETING_RE.fullmatch(text):
        return ScopeAssessment(ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK, ("assistant_greeting",))
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
        return (
            RequestedActionV4.LOGIN
            if _contains_any(text, ("đăng nhập", "dang nhap", "login", "sign in"))
            else RequestedActionV4.SHARE_CREDENTIALS
        )
    if payment_request:
        return (
            RequestedActionV4.PAY_FEE
            if recruitment or _contains_any(text, ("đóng phí", "nộp phí", "pay fee", *_FEE_TERMS))
            else RequestedActionV4.TRANSFER_MONEY
        )
    if personal_information_request:
        return RequestedActionV4.PROVIDE_PERSONAL_INFORMATION
    explicit_action = _explicit_requested_action(text)
    if explicit_action is not None:
        return explicit_action
    return RequestedActionV4.OPEN_LINK if urls else None


def derive_potential_threat(context: SecurityContextV4) -> PotentialThreatV4:
    """Derive threat type only from the validated, merged security context."""
    if context.scenario is SecurityScenarioV4.RECRUITMENT:
        return (
            PotentialThreatV4.RECRUITMENT_IMPERSONATION
            if context.impersonation_signals
            else PotentialThreatV4.RECRUITMENT_SCAM
        )
    if context.scenario is SecurityScenarioV4.PROMOTION_PRIZE:
        return (
            PotentialThreatV4.BRAND_IMPERSONATION
            if context.impersonation_signals
            else PotentialThreatV4.PROMOTION_PRIZE_SCAM
        )
    if context.scenario is SecurityScenarioV4.CHARITY:
        return PotentialThreatV4.CHARITY_IMPERSONATION_SCAM
    if context.scenario is SecurityScenarioV4.INVESTMENT:
        return PotentialThreatV4.INVESTMENT_IMPERSONATION_SCAM
    if context.scenario is SecurityScenarioV4.ONLINE_TASK:
        return PotentialThreatV4.ADVANCE_FEE_TASK_SCAM
    if context.scenario is SecurityScenarioV4.ACCOUNT_VERIFICATION:
        if context.payment_request:
            return PotentialThreatV4.FINANCIAL_SCAM
        if context.credential_request and context.otp_request:
            return PotentialThreatV4.CREDENTIAL_AND_OTP_PHISHING
        if context.credential_request or context.otp_request:
            return PotentialThreatV4.PHISHING
        return PotentialThreatV4.BRAND_IMPERSONATION
    if context.scenario is SecurityScenarioV4.REFUND and context.otp_request:
        return PotentialThreatV4.PAYMENT_AND_OTP_PHISHING
    if context.scenario is SecurityScenarioV4.REFUND and context.requested_action is RequestedActionV4.PAY_FEE:
        return PotentialThreatV4.ADVANCE_FEE_SCAM
    if context.scenario in {SecurityScenarioV4.PAYMENT, SecurityScenarioV4.REFUND}:
        if context.impersonation_signals:
            return PotentialThreatV4.IMPERSONATION_FINANCIAL_SCAM
        return PotentialThreatV4.FINANCIAL_SCAM
    if context.credential_request or context.otp_request:
        return PotentialThreatV4.CREDENTIAL_THEFT
    if context.impersonation_signals:
        return PotentialThreatV4.BRAND_IMPERSONATION
    return PotentialThreatV4.UNDETERMINED_SECURITY_THREAT


def extract_security_context(message: str) -> SecurityContextV4:
    text = _fold(message)
    urls = _normalized_urls(message)
    credential_request = _contains_any(text, _CREDENTIAL_TERMS)
    otp_request = _contains_any(text, _OTP_TERMS)
    payment_request = _is_payment_request(text, message)
    recruitment = _contains_any(text, _RECRUITMENT_TERMS)
    promotion = _contains_any(text, _PROMOTION_TERMS)
    account = _contains_any(text, _ACCOUNT_TERMS)
    account = account or (
        _contains_any(text, ("tài khoản", "tai khoan")) and _contains_any(text, ("bị khóa", "bi khoa", "sắp bị khóa"))
    )
    refund = _is_refund_context(text, message)
    charity = _contains_any(text, _CHARITY_TERMS)
    investment = _contains_any(text, _INVESTMENT_TERMS)
    online_task = _contains_any(text, _ONLINE_TASK_TERMS)
    personal_information_request = _contains_any(text, _PERSONAL_INFO_TERMS)
    entity = _claimed_entity(text)
    entity_mentions = extract_entity_mentions(message, (entity,) if entity else ())
    entity_url_claims = deterministic_entity_url_claims(message, entity_mentions, len(urls))
    if entity is None:
        if entity_url_claims:
            entity = entity_url_claims[0].entity_name
        elif len(entity_mentions) == 1 and urls:
            entity = entity_mentions[0].text

    if online_task:
        scenario = SecurityScenarioV4.ONLINE_TASK
    elif charity:
        scenario = SecurityScenarioV4.CHARITY
    elif investment:
        scenario = SecurityScenarioV4.INVESTMENT
    elif recruitment:
        scenario = SecurityScenarioV4.RECRUITMENT
    elif promotion:
        scenario = SecurityScenarioV4.PROMOTION_PRIZE
    elif account:
        scenario = SecurityScenarioV4.ACCOUNT_VERIFICATION
    elif refund:
        scenario = SecurityScenarioV4.REFUND
    elif payment_request:
        scenario = SecurityScenarioV4.PAYMENT
    else:
        scenario = SecurityScenarioV4.UNKNOWN

    # Entity attribution is a claim to verify, not evidence of impersonation.
    # Only explicit impersonation wording is a deterministic impersonation signal.
    impersonation_signals = ["explicit_impersonation"] if _contains_any(text, _IMPERSONATION_TERMS) else []

    amount_match = _AMOUNT_RE.search(message)
    context = SecurityContextV4(
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
        urgency=_contains_any(text, _URGENCY_TERMS) or _DEADLINE_RE.search(text) is not None,
        urls=urls,
        credential_request=credential_request,
        otp_request=otp_request,
        payment_request=payment_request,
        personal_information_request=personal_information_request,
        impersonation_signals=impersonation_signals,
        entity_url_claims=entity_url_claims,
        potential_threat=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
    )
    return context.model_copy(update={"potential_threat": derive_potential_threat(context)})


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
    "derive_potential_threat",
    "extract_security_context",
    "partial_security_context",
    "requested_action_source_span",
    "verification_topic_source",
]
