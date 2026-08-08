from __future__ import annotations

from urllib.parse import urlsplit

from src.agents.state import WorkflowState
from src.agents.tools.models import NormalizedToolResult, ToolResultStatus
from src.agents.tools.protocols import (
    BlacklistRepository,
    ClaimRetriever,
    DomainIntelligence,
    RedirectResolver,
    UrlReputationCascade,
    UrlScanner,
)
from src.models import Evidence, EvidenceType, ToolError


def _error_from_exception(tool: str, exc: Exception) -> ToolError:
    embedded = getattr(exc, "error", None)
    if isinstance(embedded, ToolError):
        return embedded
    return ToolError(tool=tool, code="TOOL_ERROR", message=str(exc) or type(exc).__name__, retryable=False)


def _advance(state: WorkflowState, tool: str, target: str) -> tuple[int, dict[str, int]]:
    attempts = dict(state.get("tool_attempts", {}))
    key = f"{tool}:{target}"
    attempts[key] = attempts.get(key, 0) + 1
    return state.get("tool_calls_used", 0) + 1, attempts


def _usage_update(state: WorkflowState, envelope: NormalizedToolResult) -> dict:
    return {
        "tool_usage_refs": list(state.get("tool_usage_refs", [])) + [envelope.usage.usage_ref],
        "tool_cost_used_usd": state.get("tool_cost_used_usd", 0.0) + envelope.usage.estimated_cost_usd,
        "tool_tokens_used": state.get("tool_tokens_used", 0) + envelope.usage.tokens,
    }


def build_scan_urls_node(
    scanner: UrlScanner | None,
    blacklist: BlacklistRepository | None = None,
    reputation: UrlReputationCascade | None = None,
):
    async def scan_urls(state: WorkflowState) -> dict:
        target = state["tool_target"]
        errors = list(state.get("errors", []))
        limitations = list(state.get("limitations", []))
        findings = list(state.get("url_findings", []))
        evidence = list(state.get("evidence", []))
        # This is deliberately before accounting, task creation, or adapter
        # access. Direct callers receive the same hard gate as the executor.
        if state.get("consent_to_scan_urls") is not True or target in state.get("blocked_urls", []):
            limitations.append("URL reputation lookup bị bỏ qua do consent hoặc URL policy.")
            return {
                "tool_calls_used": state.get("tool_calls_used", 0),
                "tool_attempts": dict(state.get("tool_attempts", {})),
                "errors": errors,
                "limitations": list(dict.fromkeys(limitations)),
                "url_findings": findings,
                "evidence": evidence,
            }
        used, attempts = _advance(state, "scan_url", target)
        usage_update: dict = {}
        if scanner is None and reputation is None:
            errors.append(
                ToolError(
                    tool="url_scanner", code="NOT_CONFIGURED", message="URL scanner is not configured", retryable=False
                )
            )
            limitations.append("Không có URL reputation provider được cấu hình.")
            attempts[f"scan_url:{target}"] = 2
        else:
            try:
                if reputation is not None:
                    envelope = await reputation.assess(target)
                    usage_update = _usage_update(state, envelope)
                    if envelope.result is None:
                        normalized_error = envelope.error
                        errors.append(
                            ToolError(
                                tool="url_scanner",
                                code=(normalized_error.code.value if normalized_error else "TOOL_ERROR"),
                                message=(normalized_error.message if normalized_error else "Reputation lookup failed"),
                                retryable=(normalized_error.retryable if normalized_error else False),
                            )
                        )
                        limitations.append(
                            f"URL scanner không trả được kết quả ({normalized_error.code.value if normalized_error else 'TOOL_ERROR'})."
                        )
                    else:
                        cascade = envelope.result
                        from src.models import UrlScanResult

                        result = UrlScanResult(
                            provider=envelope.usage.provider,
                            normalized_url=cascade.normalized_url,
                            verdict=cascade.verdict,
                            redirect_chain=[],
                            signals=[signal for finding in cascade.findings for signal in finding.signals]
                            + (["provider_conflict"] if cascade.provider_conflict else []),
                            observed_at=envelope.usage.observed_at,
                        )
                else:
                    result = await scanner.scan(target)  # type: ignore[union-attr]
                if reputation is not None and envelope.result is None:
                    result = None
                if result is None:
                    return {
                        "tool_calls_used": used,
                        "tool_attempts": attempts,
                        "errors": errors,
                        "limitations": list(dict.fromkeys(limitations)),
                        "url_findings": findings,
                        "evidence": evidence,
                        **usage_update,
                    }
                findings.append(result)
                evidence.append(
                    Evidence(
                        type=EvidenceType.DOMAIN_REPUTATION,
                        source=result.provider,
                        title="Kết quả URL reputation",
                        url=result.normalized_url,
                        finding=f"Provider đánh giá {result.verdict.value}; signals: {', '.join(result.signals) or 'none'}.",
                        observed_at=result.observed_at,
                    )
                )
                if result.redirect_chain:
                    evidence.append(
                        Evidence(
                            type=EvidenceType.REDIRECT,
                            source=result.provider,
                            title="Chuỗi chuyển hướng quan sát được",
                            url=result.normalized_url,
                            finding=" -> ".join(result.redirect_chain),
                            observed_at=result.observed_at,
                        )
                    )
                    if blacklist is not None:
                        for redirect_url in result.redirect_chain[1:]:
                            host = urlsplit(redirect_url).hostname
                            if host and await blacklist.contains(host):
                                evidence.append(
                                    Evidence(
                                        type=EvidenceType.BLACKLIST,
                                        source="approved-blacklist",
                                        title="Redirect tới tên miền trong blacklist đã duyệt",
                                        url=result.normalized_url,
                                        finding=f"Chuỗi redirect dẫn tới tên miền {host}.",
                                        observed_at=result.observed_at,
                                    )
                                )
                if "known_official_domain" in result.signals:
                    evidence.append(
                        Evidence(
                            type=EvidenceType.OFFICIAL_SOURCE,
                            source=result.provider,
                            title="Provider xác nhận tên miền chính thức",
                            url=result.normalized_url,
                            finding="Tên miền khớp nguồn chính thức trong dữ liệu provider.",
                            observed_at=result.observed_at,
                        )
                    )
            except Exception as exc:  # adapters expose heterogeneous exception types
                error = _error_from_exception("url_scanner", exc)
                errors.append(error)
                if not error.retryable:
                    attempts[f"scan_url:{target}"] = 2
                limitations.append(f"URL scanner không trả được kết quả ({error.code}).")
        return {
            "tool_calls_used": used,
            "tool_attempts": attempts,
            "errors": errors,
            "limitations": list(dict.fromkeys(limitations)),
            "url_findings": findings,
            "evidence": evidence,
            **usage_update,
        }

    return scan_urls


def build_resolve_redirects_node(resolver: RedirectResolver | None):
    async def resolve_redirects(state: WorkflowState) -> dict:
        target = state["tool_target"]
        used, attempts = _advance(state, "resolve_redirect", target)
        errors = list(state.get("errors", []))
        limitations = list(state.get("limitations", []))
        evidence = list(state.get("evidence", []))
        usage_update: dict = {}
        if state.get("consent_to_scan_urls") is not True or target in state.get("blocked_urls", []):
            limitations.append("Redirect lookup bị bỏ qua do consent hoặc URL policy.")
            return {
                "tool_calls_used": state.get("tool_calls_used", 0),
                "tool_attempts": dict(state.get("tool_attempts", {})),
                "errors": errors,
                "limitations": list(dict.fromkeys(limitations)),
                "evidence": evidence,
            }
        if resolver is None:
            errors.append(
                ToolError(
                    tool="redirect_resolver",
                    code="NOT_CONFIGURED",
                    message="Redirect resolver is not configured",
                    retryable=False,
                )
            )
            limitations.append("Không có redirect resolver được cấu hình.")
        else:
            try:
                envelope = await resolver.resolve(target)
                usage_update = _usage_update(state, envelope)
                if envelope.status in {ToolResultStatus.BLOCKED, ToolResultStatus.FAILED}:
                    error = envelope.error
                    errors.append(
                        ToolError(
                            tool="redirect_resolver",
                            code=error.code.value if error else "TOOL_ERROR",
                            message=error.message if error else "Redirect resolution failed",
                            retryable=error.retryable if error else False,
                        )
                    )
                    limitations.append("Không thể xác minh chuỗi redirect an toàn.")
                elif envelope.result is not None:
                    result = envelope.result
                    evidence.append(
                        Evidence(
                            type=EvidenceType.REDIRECT,
                            source=envelope.usage.provider,
                            title="Chuỗi chuyển hướng đã xác minh",
                            url=result.normalized_url,
                            finding=" -> ".join(result.redirect_chain),
                            observed_at=result.observed_at,
                        )
                    )
            except Exception as exc:
                error = _error_from_exception("redirect_resolver", exc)
                errors.append(error)
                limitations.append(f"Redirect resolver không trả được kết quả ({error.code}).")
        return {
            "tool_calls_used": used,
            "tool_attempts": attempts,
            "errors": errors,
            "limitations": list(dict.fromkeys(limitations)),
            "evidence": evidence,
            **usage_update,
        }

    return resolve_redirects


def _claim_type(finding: str) -> EvidenceType:
    folded = finding.casefold()
    if any(
        word in folded
        for word in (
            "bác bỏ",
            "sai sự thật",
            "giả mạo",
            "không đúng",
            "false",
            "incorrect",
            "misleading",
        )
    ):
        return EvidenceType.FACT_CHECK
    return EvidenceType.OFFICIAL_SOURCE


def build_verify_claims_node(retriever: ClaimRetriever | None):
    async def verify_claims(state: WorkflowState) -> dict:
        target = state["tool_target"]
        used, attempts = _advance(state, "verify_claim", target)
        errors = list(state.get("errors", []))
        limitations = list(state.get("limitations", []))
        findings = list(state.get("claim_findings", []))
        evidence = list(state.get("evidence", []))
        if retriever is None:
            errors.append(
                ToolError(
                    tool="claim_retriever",
                    code="NOT_CONFIGURED",
                    message="Claim retriever is not configured",
                    retryable=False,
                )
            )
            limitations.append("Không có nguồn fact-check được cấu hình để xác minh claim.")
        else:
            try:
                results = await retriever.search(target, limit=5)
                findings.extend(results)
                for item in results:
                    evidence.append(
                        Evidence(
                            type=EvidenceType.FACT_CHECK,
                            source=item.source,
                            title=item.title,
                            url=item.url,
                            finding=item.finding,
                            observed_at=item.observed_at,
                        )
                    )
                if not results:
                    limitations.append("Không tìm thấy nguồn đủ liên quan để xác minh claim.")
            except Exception as exc:
                error = _error_from_exception("claim_retriever", exc)
                errors.append(error)
                limitations.append(f"Nguồn fact-check không trả được kết quả ({error.code}).")
        return {
            "tool_calls_used": used,
            "tool_attempts": attempts,
            "errors": errors,
            "limitations": list(dict.fromkeys(limitations)),
            "claim_findings": findings,
            "evidence": evidence,
        }

    return verify_claims


def build_inspect_domains_node(domain_intelligence: DomainIntelligence | None):
    async def inspect_domains(state: WorkflowState) -> dict:
        target = state["tool_target"]
        errors = list(state.get("errors", []))
        limitations = list(state.get("limitations", []))
        findings = list(state.get("domain_findings", []))
        evidence = list(state.get("evidence", []))
        # Consent must be checked before touching the injected adapter. The
        # adapter performs registrable-domain and network policy validation.
        if state.get("consent_to_scan_urls") is not True:
            limitations.append("Domain intelligence lookup bị bỏ qua vì chưa có consent.")
            return {
                "tool_calls_used": state.get("tool_calls_used", 0),
                "tool_attempts": dict(state.get("tool_attempts", {})),
                "errors": errors,
                "limitations": list(dict.fromkeys(limitations)),
                "domain_findings": findings,
                "evidence": evidence,
            }
        used, attempts = _advance(state, "domain_intelligence", target)
        if domain_intelligence is None:
            errors.append(
                ToolError(
                    tool="domain_intelligence",
                    code="NOT_CONFIGURED",
                    message="Domain intelligence provider is not configured",
                    retryable=False,
                )
            )
            limitations.append("Không có RDAP domain intelligence provider được cấu hình.")
            attempts[f"domain_intelligence:{target}"] = 2
        else:
            try:
                result = await domain_intelligence.lookup(target)
                findings.append(result)
                details: list[str] = []
                if result.registered_at is not None:
                    details.append(f"registered_at={result.registered_at.isoformat()}")
                if result.expires_at is not None:
                    details.append(f"expires_at={result.expires_at.isoformat()}")
                if result.registrar is not None:
                    details.append(f"registrar={result.registrar}")
                if result.privacy_redacted:
                    details.append("privacy_redacted=true")
                evidence.append(
                    Evidence(
                        type=EvidenceType.DOMAIN_REGISTRATION,
                        source=result.provider,
                        title="Thông tin đăng ký domain",
                        finding="; ".join(details) or "RDAP không cung cấp trường đăng ký có thể sử dụng.",
                        observed_at=result.observed_at,
                    )
                )
                if result.privacy_redacted and result.registered_at is None:
                    limitations.append("RDAP đã ẩn hoặc không cung cấp ngày đăng ký domain.")
            except Exception as exc:
                error = _error_from_exception("domain_intelligence", exc)
                errors.append(error)
                if not error.retryable:
                    attempts[f"domain_intelligence:{target}"] = 2
                limitations.append(f"RDAP không trả được kết quả ({error.code}).")
        return {
            "tool_calls_used": used,
            "tool_attempts": attempts,
            "errors": errors,
            "limitations": list(dict.fromkeys(limitations)),
            "domain_findings": findings,
            "evidence": evidence,
        }

    return inspect_domains


__all__ = [
    "build_inspect_domains_node",
    "build_resolve_redirects_node",
    "build_scan_urls_node",
    "build_verify_claims_node",
]
