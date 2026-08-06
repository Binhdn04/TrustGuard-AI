from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from src.agents.state import AgentState
from src.agents.tools.protocols import BlacklistRepository
from src.models import Evidence, EvidenceType

_CREDENTIAL_TOKENS = ("login", "signin", "verify", "account", "dang-nhap", "xac-minh")
_BRAND_LURE_TOKENS = ("-qua", "-gift", "khuyen-mai", "free-gift")


def normalize_url(raw_url: str) -> str | None:
    candidate = raw_url.strip()
    if candidate.startswith("www.") or "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
        port = parsed.port
        default_port = (parsed.scheme.casefold() == "http" and port == 80) or (
            parsed.scheme.casefold() == "https" and port == 443
        )
        netloc = host if port is None or default_port else f"{host}:{port}"
        path = quote(unquote(parsed.path or "/"), safe="/%:@-._~!$&'()*+,;=")
        return urlunsplit((parsed.scheme.casefold(), netloc, path, parsed.query, ""))
    except (UnicodeError, ValueError):
        return None


def _is_forbidden_host(host: str) -> bool:
    lowered = host.casefold().rstrip(".")
    if (
        lowered == "localhost"
        or lowered.endswith(".localhost")
        or lowered in {"metadata.google.internal", "metadata.azure.internal"}
    ):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return not address.is_global


def _evidence(title: str, finding: str, observed_at: datetime) -> Evidence:
    return Evidence(
        type=EvidenceType.URL_RULE,
        source="local-url-rules",
        title=title,
        finding=finding,
        observed_at=observed_at,
    )


def build_rule_check_node(blacklist: BlacklistRepository | None):
    async def normalize_and_check_rules(state: AgentState) -> dict:
        now = datetime.now(UTC)
        normalized: list[str] = []
        blocked: list[str] = []
        blacklisted: list[str] = []
        evidence = list(state.get("evidence", []))
        limitations = list(state.get("limitations", []))

        for raw_url in state.get("extracted_urls", []):
            url = normalize_url(raw_url)
            if url is None:
                limitations.append(f"Không thể chuẩn hóa URL: {raw_url}")
                continue
            if url not in normalized:
                normalized.append(url)
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            path = parsed.path.casefold()

            if _is_forbidden_host(host):
                blocked.append(url)
                evidence.append(
                    _evidence(
                        "URL đích bị chặn bởi SSRF guard",
                        f"Host {host} thuộc vùng mạng không được phép truy cập.",
                        now,
                    )
                )
                limitations.append("Không quét URL bên ngoài vì đích là địa chỉ private/local/metadata.")
            if host.startswith("xn--") or ".xn--" in host:
                evidence.append(
                    _evidence(
                        "Tên miền quốc tế hóa cần thận trọng",
                        f"Tên miền {host} dùng biểu diễn punycode và có thể gây nhầm lẫn.",
                        now,
                    )
                )
            if any(token in path for token in _CREDENTIAL_TOKENS):
                evidence.append(
                    _evidence(
                        "Đường dẫn yêu cầu thông tin tài khoản",
                        f"Đường dẫn của {host} có dấu hiệu trang đăng nhập hoặc xác minh.",
                        now,
                    )
                )
            if any(token in host for token in _BRAND_LURE_TOKENS):
                evidence.append(
                    _evidence(
                        "Tên miền có mẫu mạo danh khuyến mãi",
                        f"Tên miền {host} chứa mẫu thường dùng để dụ nhận quà/khuyến mãi.",
                        now,
                    )
                )
            if blacklist is not None and await blacklist.contains(host):
                blacklisted.append(host)
                evidence.append(
                    Evidence(
                        type=EvidenceType.BLACKLIST,
                        source="approved-blacklist",
                        title="Tên miền nằm trong blacklist đã duyệt",
                        finding=f"Tên miền {host} đã được Security Admin phê duyệt đưa vào blacklist.",
                        observed_at=now,
                    )
                )

        if normalized and not state.get("consent_to_scan_urls", False):
            limitations.append("Người dùng chưa đồng ý quét URL bằng provider bên ngoài.")
        if not normalized and not state.get("claims"):
            limitations.append("Không trích xuất được URL hoặc claim có thể kiểm chứng từ nội dung.")
        return {
            "normalized_urls": normalized,
            "blocked_urls": blocked,
            "blacklisted_domains": list(dict.fromkeys(blacklisted)),
            "evidence": evidence,
            "limitations": list(dict.fromkeys(limitations)),
        }

    return normalize_and_check_rules
