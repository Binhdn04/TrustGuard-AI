from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.agents.state import AgentState
from src.models import InputType

_URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"']+|(?<![@\w])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/[^\s<>\"']*)?")
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_CLAIM_MARKERS = (
    "tặng",
    "quà",
    "khuyến mãi",
    "thông báo",
    "yêu cầu",
    "phải",
    "cảnh báo",
    "miễn phí",
    "trúng",
    "nộp phí",
    "mở khóa",
    "xác nhận",
    "đăng nhập",
    "chuyển khoản",
    "hôm nay",
)


def _extract_urls(message: str) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.finditer(message):
        candidate = match.group(0).rstrip(_TRAILING_PUNCTUATION)
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls


def classify_input(state: AgentState) -> dict:
    message = state.get("message", "").strip()
    urls = _extract_urls(message)
    only_url = False
    if len(urls) == 1:
        comparable = message.rstrip(_TRAILING_PUNCTUATION)
        only_url = comparable == urls[0]
    input_type = InputType.URL if only_url else InputType.TEXT_WITH_URL if urls else InputType.TEXT
    return {"input_type": input_type}


def extract_indicators(state: AgentState) -> dict:
    message = state.get("message", "").strip()
    urls = _extract_urls(message)
    # Remove every URL occurrence in one pass. Iterating over the de-duplicated
    # display list needlessly rescans the message and couples cleanup to the
    # exact candidate returned by ``_extract_urls``.
    text_without_urls = _URL_RE.sub(" ", message)
    text_without_urls = " ".join(text_without_urls.split()).strip(" -:;,.")

    lower = text_without_urls.casefold()
    claims: list[str] = []
    minimum_claim_length = 20 if urls else 12
    if len(text_without_urls) >= minimum_claim_length and any(marker in lower for marker in _CLAIM_MARKERS):
        claims.append(text_without_urls)

    # A URL's path is not a claim by itself.
    if state.get("input_type") is InputType.URL:
        claims = []
    return {"extracted_urls": urls, "claims": claims}


def host_for_url(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None
