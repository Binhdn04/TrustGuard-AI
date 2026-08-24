from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Generic, Literal, TypeVar

from src.agents.security_scope import requested_action_source_span, verification_topic_source
from src.models import (
    AssistantContextV4,
    AssistantSourceSpanV4,
    RequestedActionV4,
    SecurityContextV4,
    VerificationIntentV4,
    VerificationTopicV4,
)

_MIN_GROUNDED_CONFIDENCE = 0.80
_MAX_QUERY_LENGTH = 300
_MAX_QUERY_VARIANTS = 6
_MAX_QUERY_ATTEMPTS = 4

_EMAIL_RE = re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+(?:com|vn|org|net|edu|gov|io|app)(?:/\S*)?")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:password|passcode|mật\s*khẩu|mat\s*khau|token|secret|api[_-]?key|credential)\s*[:=]\s*\S+"
)
_OTP_RE = re.compile(
    r"(?i)\b(?:otp|mã\s*xác\s*(?:thực|minh)|ma\s*xac\s*(?:thuc|minh)|verification\s*code)\s*[:=]?\s*\d{4,8}\b"
)
_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}(?:\.[a-zA-Z0-9_-]{10,})?\b")
_LONG_TOKEN_RE = re.compile(r"\b(?=[a-zA-Z0-9_-]{20,}\b)(?=[a-zA-Z0-9_-]*[a-zA-Z])(?=[a-zA-Z0-9_-]*\d)[a-zA-Z0-9_-]+\b")
_POSSIBLE_OTP_RE = re.compile(r"(?<!\d)\d{4,8}(?!\d)")
_SPACE_RE = re.compile(r"\s+")
_QUOTED_CLAIM_RE = re.compile(r'["“”]([^"“”]{4,200})["“”]')

_TOPIC_QUERY_TERMS = {
    VerificationTopicV4.RECRUITMENT: ("tuyển dụng", "recruitment"),
    VerificationTopicV4.PROMOTION: ("khuyến mãi", "promotion"),
    VerificationTopicV4.EVENT: ("sự kiện", "event"),
    VerificationTopicV4.COURSE: ("khóa học", "course"),
    VerificationTopicV4.SURVEY: ("khảo sát", "survey"),
    VerificationTopicV4.ACCOUNT: ("tài khoản", "account"),
    VerificationTopicV4.PAYMENT: ("thanh toán", "payment"),
    VerificationTopicV4.CHARITY: ("từ thiện", "charity"),
    VerificationTopicV4.INVESTMENT: ("đầu tư", "investment"),
    VerificationTopicV4.GENERAL_NOTICE: ("thông báo", "announcement"),
    VerificationTopicV4.UNKNOWN: ("thông báo", "announcement"),
}
_ACTION_QUERY_TERMS = {
    RequestedActionV4.LOGIN: "đăng nhập",
    RequestedActionV4.SHARE_OTP: "xác thực OTP",
    RequestedActionV4.SHARE_CREDENTIALS: "thông tin đăng nhập",
    RequestedActionV4.TRANSFER_MONEY: "chuyển tiền",
    RequestedActionV4.PAY_FEE: "đóng phí",
    RequestedActionV4.PROVIDE_PERSONAL_INFORMATION: "cung cấp thông tin cá nhân",
    RequestedActionV4.OPEN_LINK: "mở liên kết",
    RequestedActionV4.INSTALL_APP: "cài ứng dụng",
    RequestedActionV4.SHARE_SCREEN: "chia sẻ màn hình",
    RequestedActionV4.SCAN_QR: "quét mã QR",
    RequestedActionV4.SUBMIT_FORM: "gửi biểu mẫu",
    RequestedActionV4.REGISTER_OR_APPLY: "đăng ký ứng tuyển",
    RequestedActionV4.DOWNLOAD_FILE: "tải tệp",
    RequestedActionV4.APPLY_FOR_PASSPORT: "làm hộ chiếu",
}
_URL_RELEVANT_ACTIONS = {
    RequestedActionV4.LOGIN,
    RequestedActionV4.OPEN_LINK,
    RequestedActionV4.INSTALL_APP,
    RequestedActionV4.SUBMIT_FORM,
    RequestedActionV4.REGISTER_OR_APPLY,
    RequestedActionV4.DOWNLOAD_FILE,
    RequestedActionV4.APPLY_FOR_PASSPORT,
}


@dataclass(frozen=True, slots=True)
class GroundedTextValue:
    value: str
    confidence: float
    source_spans: tuple[AssistantSourceSpanV4, ...]

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("grounded value must not be blank")
        if not _MIN_GROUNDED_CONFIDENCE <= self.confidence <= 1:
            raise ValueError("grounded confidence is below the accepted threshold")
        if not self.source_spans:
            raise ValueError("grounded value requires at least one source span")


@dataclass(frozen=True, slots=True)
class GroundedActionValue:
    value: RequestedActionV4
    confidence: float
    source_spans: tuple[AssistantSourceSpanV4, ...]

    def __post_init__(self) -> None:
        if not _MIN_GROUNDED_CONFIDENCE <= self.confidence <= 1:
            raise ValueError("grounded confidence is below the accepted threshold")
        if not self.source_spans:
            raise ValueError("grounded action requires at least one source span")


@dataclass(frozen=True, slots=True)
class DerivedOrganizationName:
    value: str
    provenance: Literal["accent_fold", "configured_alias", "deterministic_translation", "semantic_normalization"]
    derived_from: Literal["organization_name"] = "organization_name"

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("derived organization name must not be blank")
        if len(self.value) > 200:
            raise ValueError("derived organization name is too long")


@dataclass(frozen=True, slots=True)
class GroundedVerificationIntent:
    contract: VerificationIntentV4
    organization: GroundedTextValue | None
    claim: GroundedTextValue | None
    action: GroundedActionValue | None
    derived_organizations: tuple[DerivedOrganizationName, ...] = ()

    def __post_init__(self) -> None:
        if (self.organization is None) != (self.contract.organization_name is None):
            raise ValueError("organization contract value must have grounding")
        if (self.claim is None) != (self.contract.claim_summary is None):
            raise ValueError("claim contract value must have grounding")
        if (self.action is None) != (self.contract.requested_action is None):
            raise ValueError("action contract value must have grounding")
        if self.contract.action_url_indices and self.action is None:
            raise ValueError("action URL indices require a grounded action")


@dataclass(frozen=True, slots=True)
class VerificationQuery:
    query_id: str
    text: str
    source_fields: tuple[str, ...]
    derivations: tuple[str, ...] = ()


QueryResultT = TypeVar("QueryResultT")


@dataclass(frozen=True, slots=True)
class VerificationQueryResult(Generic[QueryResultT]):
    query: VerificationQuery
    result: QueryResultT


def _valid_assistant_spans(
    message: str,
    assistant: AssistantContextV4 | None,
    field_name: str,
) -> tuple[AssistantSourceSpanV4, ...]:
    if assistant is None or assistant.field_confidences.get(field_name, 0) < _MIN_GROUNDED_CONFIDENCE:
        return ()
    return tuple(
        span
        for span in assistant.source_spans
        if span.field_name == field_name
        and span.end <= len(message)
        and span.start < span.end
        and message[span.start : span.end].strip()
    )


def _literal_span(message: str, value: str, field_name: str) -> AssistantSourceSpanV4 | None:
    start = message.casefold().find(value.casefold())
    if start < 0:
        return None
    return AssistantSourceSpanV4(field_name=field_name, start=start, end=start + len(value))


def _is_whole_message(value: str, message: str) -> bool:
    return _SPACE_RE.sub(" ", value).strip().casefold() == _SPACE_RE.sub(" ", message).strip().casefold()


def _bounded_semantic_source(
    message: str,
    spans: tuple[AssistantSourceSpanV4, ...],
) -> tuple[str, tuple[AssistantSourceSpanV4, ...]] | None:
    for span in spans:
        value = message[span.start : span.end].strip()
        if not value or len(value) > 200:
            continue
        if _is_whole_message(value, message):
            continue
        return value, (span,)
    return None


def _quoted_claim_source(message: str) -> tuple[str, int, int] | None:
    """Return a bounded literal title without letting arbitrary prose become a query."""
    for match in _QUOTED_CLAIM_RE.finditer(message):
        value = _SPACE_RE.sub(" ", match.group(1)).strip()
        if not value or any(
            pattern.search(value)
            for pattern in (
                _EMAIL_RE,
                _URL_RE,
                _SECRET_ASSIGNMENT_RE,
                _OTP_RE,
                _JWT_RE,
                _LONG_TOKEN_RE,
                _POSSIBLE_OTP_RE,
            )
        ):
            continue
        start, end = match.span(1)
        return value, start, end
    return None


def _accent_fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(char for char in normalized if not unicodedata.combining(char)).replace("đ", "d").replace("Đ", "D")


def _unique_derived(values: Iterable[DerivedOrganizationName]) -> tuple[DerivedOrganizationName, ...]:
    unique: list[DerivedOrganizationName] = []
    seen: set[str] = set()
    for item in values:
        key = item.value.casefold()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return tuple(unique[:10])


def build_grounded_verification_intent(
    message: str,
    context: SecurityContextV4,
    assistant: AssistantContextV4 | None = None,
    *,
    derived_organization_names: Sequence[DerivedOrganizationName] = (),
) -> GroundedVerificationIntent | None:
    """Build verification work only from literal rule or validated semantic spans."""
    organization: GroundedTextValue | None = None
    derived: list[DerivedOrganizationName] = [
        item for item in derived_organization_names if not _is_whole_message(item.value, message)
    ]
    if context.claimed_entity:
        literal = _literal_span(message, context.claimed_entity, "claimed_entity")
        semantic_spans = _valid_assistant_spans(message, assistant, "claimed_entity")
        if literal is not None and not _is_whole_message(context.claimed_entity, message):
            organization = GroundedTextValue(context.claimed_entity, 1.0, (literal,))
        elif semantic_spans:
            semantic_source = _bounded_semantic_source(message, semantic_spans)
            if semantic_source is not None:
                source_value, bounded_spans = semantic_source
                organization = GroundedTextValue(
                    source_value,
                    assistant.field_confidences["claimed_entity"],
                    bounded_spans,
                )
                if source_value.casefold() != context.claimed_entity.casefold() and not _is_whole_message(
                    context.claimed_entity, message
                ):
                    derived.append(DerivedOrganizationName(context.claimed_entity, "semantic_normalization"))

    claim: GroundedTextValue | None = None
    topic: VerificationTopicV4 | None = None
    topic_source = verification_topic_source(message)
    if topic_source is not None:
        topic, source_value, (start, end) = topic_source
    quoted_claim = _quoted_claim_source(message)
    if quoted_claim is not None:
        source_value, start, end = quoted_claim
        claim = GroundedTextValue(
            source_value,
            1.0,
            (AssistantSourceSpanV4(field_name="claim_summary", start=start, end=end),),
        )
    elif topic_source is not None:
        _, source_value, (start, end) = topic_source
        claim = GroundedTextValue(
            source_value,
            1.0,
            (AssistantSourceSpanV4(field_name="claim_summary", start=start, end=end),),
        )

    action: GroundedActionValue | None = None
    if context.requested_action is not None:
        rule_span = requested_action_source_span(message, context.requested_action)
        semantic_spans = _valid_assistant_spans(message, assistant, "requested_action")
        if rule_span is not None:
            action = GroundedActionValue(
                context.requested_action,
                1.0,
                (
                    AssistantSourceSpanV4(
                        field_name="requested_action",
                        start=rule_span[0],
                        end=rule_span[1],
                    ),
                ),
            )
        elif semantic_spans:
            action = GroundedActionValue(
                context.requested_action,
                assistant.field_confidences["requested_action"],
                semantic_spans,
            )

    if organization is None and claim is None and action is None:
        return None

    if organization is not None:
        folded = _accent_fold(organization.value)
        if folded.casefold() != organization.value.casefold():
            derived.append(DerivedOrganizationName(folded, "accent_fold"))
    derived_unique = _unique_derived(derived)
    action_url_indices = (
        list(range(len(context.urls))) if action is not None and action.value in _URL_RELEVANT_ACTIONS else []
    )
    contract = VerificationIntentV4(
        organization_name=organization.value if organization else None,
        derived_organization_names=[item.value for item in derived_unique],
        claim_summary=claim.value if claim else None,
        topic=topic,
        requested_action=action.value if action else None,
        action_url_indices=action_url_indices,
    )
    return GroundedVerificationIntent(
        contract=contract,
        organization=organization,
        claim=claim,
        action=action,
        derived_organizations=derived_unique,
    )


def _sanitize_query_segment(value: str) -> str:
    sanitized = value
    for pattern in (
        _EMAIL_RE,
        _URL_RE,
        _SECRET_ASSIGNMENT_RE,
        _OTP_RE,
        _JWT_RE,
        _LONG_TOKEN_RE,
        _POSSIBLE_OTP_RE,
    ):
        sanitized = pattern.sub(" ", sanitized)
    sanitized = _SPACE_RE.sub(" ", sanitized).strip(" \t\r\n,;:|-")
    return sanitized[:_MAX_QUERY_LENGTH].strip()


class OfficialVerificationQueryBuilder:
    max_variants = _MAX_QUERY_VARIANTS
    max_attempts = _MAX_QUERY_ATTEMPTS

    def build(self, intent: GroundedVerificationIntent) -> list[VerificationQuery]:
        contract = intent.contract
        organization = _sanitize_query_segment(contract.organization_name or "")
        claim = _sanitize_query_segment(contract.claim_summary or "")
        topic_local, topic_english = _TOPIC_QUERY_TERMS[contract.topic or VerificationTopicV4.UNKNOWN]
        action = _ACTION_QUERY_TERMS.get(contract.requested_action, "")

        candidates: list[tuple[list[str], tuple[str, ...], tuple[str, ...]]] = []
        if organization:
            candidates.extend(
                [
                    ([organization, claim, "chính thức"], ("organization_name", "claim_summary"), ()),
                    ([organization, topic_local, action], ("organization_name", "topic", "requested_action"), ()),
                    ([organization, action, "chính thức"], ("organization_name", "requested_action"), ()),
                ]
            )
        for item in intent.derived_organizations:
            candidates.append(
                (
                    [item.value, topic_english, "official"],
                    ("organization_name", "topic"),
                    (item.provenance,),
                )
            )
        if claim:
            candidates.append(([claim, action, "chính thức"], ("claim_summary", "requested_action"), ()))
        if action:
            candidates.append(([topic_local, action, "chính thức"], ("topic", "requested_action"), ()))

        queries: list[VerificationQuery] = []
        seen: set[str] = set()
        for segments, source_fields, derivations in candidates:
            text = _sanitize_query_segment(" ".join(filter(None, segments)))
            key = text.casefold()
            if not text or key in seen:
                continue
            seen.add(key)
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            queries.append(
                VerificationQuery(
                    query_id=f"query:{digest}",
                    text=text,
                    source_fields=tuple(field for field in source_fields if getattr(contract, field, None)),
                    derivations=derivations,
                )
            )
            if len(queries) == self.max_variants:
                break
        return queries

    async def execute_sequentially(
        self,
        queries: Sequence[VerificationQuery],
        search_one: Callable[[str], Awaitable[QueryResultT]],
    ) -> list[VerificationQueryResult[QueryResultT]]:
        results: list[VerificationQueryResult[QueryResultT]] = []
        for query in queries[: self.max_attempts]:
            results.append(VerificationQueryResult(query=query, result=await search_one(query.text)))
        return results


__all__ = [
    "DerivedOrganizationName",
    "GroundedActionValue",
    "GroundedTextValue",
    "GroundedVerificationIntent",
    "OfficialVerificationQueryBuilder",
    "VerificationQuery",
    "VerificationQueryResult",
    "build_grounded_verification_intent",
]
