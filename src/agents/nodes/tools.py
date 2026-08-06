from __future__ import annotations

from urllib.parse import urlsplit

from src.agents.state import WorkflowState
from src.agents.tools.protocols import BlacklistRepository, ClaimRetriever, DomainIntelligence, UrlScanner
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


def build_scan_urls_node(scanner: UrlScanner | None, blacklist: BlacklistRepository | None = None):
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
        if scanner is None:
            errors.append(
                ToolError(
                    tool="url_scanner", code="NOT_CONFIGURED", message="URL scanner is not configured", retryable=False
                )
            )
            limitations.append("Không có URL reputation provider được cấu hình.")
            attempts[f"scan_url:{target}"] = 2
        else:
            try:
                result = await scanner.scan(target)
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
        }

    return scan_urls


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


__all__ = ["build_inspect_domains_node", "build_scan_urls_node", "build_verify_claims_node"]
