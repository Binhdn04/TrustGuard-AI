from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.tools import (
    CacheMetadata,
    CacheStatus,
    DnsResolutionEnvelope,
    DnsResolutionError,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from src.models import (
    AnalysisStatus,
    AssistantContextV4,
    AssistantProcessingModeV4,
    ExposureStateV4,
    ScopeDecisionV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_triage import SecurityTriageScopeService


def failed_provider_result(tool: ToolName) -> NormalizedToolResult[object]:
    return NormalizedToolResult(
        status=ToolResultStatus.FAILED,
        error=NormalizedToolError(
            tool=tool,
            code=ToolErrorCode.PROVIDER_ERROR,
            message="fixture failure",
            retryable=False,
            provider=f"phase0-{tool.value}",
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="phase0-fixture"),
        usage=UsageMetadata(
            usage_ref=f"usage:phase0:{tool.value}",
            provider=f"phase0-{tool.value}",
            provider_version="v1",
            operation=tool.value,
            attempts=1,
            network_calls=1,
            latency_ms=0,
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )


def phase0_usage(operation: str) -> UsageMetadata:
    return UsageMetadata(
        usage_ref=f"usage:phase0:{operation}",
        provider=f"phase0-{operation}",
        provider_version="v1",
        operation=operation,
        attempts=1,
        network_calls=1,
        latency_ms=0,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class RecordingBlacklist:
    def __init__(self, calls: list[tuple[str, str, bool | None]]) -> None:
        self._calls = calls

    async def get(self, target: str):
        self._calls.append(("blacklist", target, None))
        return None


class RecordingDns:
    provider = "phase0-dns"

    def __init__(self, calls: list[tuple[str, str, bool | None]]) -> None:
        self._calls = calls

    async def resolve(self, target: str) -> DnsResolutionEnvelope:
        self._calls.append(("dns", target, None))
        return DnsResolutionEnvelope(
            status=ToolResultStatus.FAILED,
            error=DnsResolutionError(
                code=ToolErrorCode.PROVIDER_ERROR,
                message="fixture failure",
                retryable=False,
                provider=self.provider,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="phase0-fixture"),
            usage=phase0_usage("dns"),
        )


class RecordingRedirect:
    provider = "phase0-redirect"

    def __init__(self, calls: list[tuple[str, str, bool | None]]) -> None:
        self._calls = calls

    async def resolve(self, target: str) -> NormalizedToolResult[object]:
        self._calls.append(("redirect", target, None))
        return failed_provider_result(ToolName.REDIRECT_RESOLVER)


class RecordingRdap:
    provider = "phase0-rdap"

    def __init__(self, calls: list[tuple[str, str, bool | None]]) -> None:
        self._calls = calls

    async def lookup(self, target: str) -> NormalizedToolResult[object]:
        self._calls.append(("rdap", target, None))
        return failed_provider_result(ToolName.RDAP)


class RecordingReputation:
    provider = "phase0-reputation"

    def __init__(self, calls: list[tuple[str, str, bool | None]]) -> None:
        self._calls = calls

    async def assess(self, target: str, *, high_risk: bool = False) -> NormalizedToolResult[object]:
        self._calls.append(("reputation", target, high_risk))
        return failed_provider_result(ToolName.URL_REPUTATION)


@dataclass
class PipelineTrace:
    """Characterization trace used to guard progress-observer parity."""

    calls: list[tuple[str, bool | None]] = field(default_factory=list)
    progress_steps: list[str] = field(default_factory=list)


class PassthroughUnderstanding:
    async def enrich(self, request, scoped):
        del request
        return scoped


class RecordingInvestigation:
    def __init__(self, trace: PipelineTrace) -> None:
        self._trace = trace

    async def investigate(self, request, scoped, *, runtime):
        del runtime
        self._trace.calls.append(("investigation", request.consent.external_url_lookup))
        return scoped


class RecordingTrust:
    def __init__(self, trace: PipelineTrace) -> None:
        self._trace = trace

    async def enrich(self, request, scoped):
        del request
        self._trace.calls.append(("trust", None))
        return scoped


class PassthroughResponse:
    async def enrich(self, scoped):
        return scoped


class MustNotRun:
    async def enrich(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("terminal or incident flow invoked investigation/trust")

    async def investigate(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("terminal or incident flow invoked investigation/trust")


async def record_progress(trace: PipelineTrace, step, message, evidence_refs, risk) -> None:
    del message, evidence_refs, risk
    trace.progress_steps.append(step)


def build_pipeline(trace: PipelineTrace, *, terminal_or_incident: bool = False) -> SecurityTriagePipeline:
    stage = MustNotRun() if terminal_or_incident else None
    return SecurityTriagePipeline(
        understanding=PassthroughUnderstanding(),
        investigation=stage or RecordingInvestigation(trace),
        trust=stage or RecordingTrust(trace),
        responses=PassthroughResponse(),
    )


@pytest.mark.asyncio
async def test_phase0_external_provider_trace_records_order_arguments_consent_and_call_counts() -> None:
    request = SecurityTriageCreateRequestV4(
        message="Check https://example.test/login",
        consent={"external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    calls: list[tuple[str, str, bool | None]] = []
    investigation = SecurityInvestigationService(
        blacklist=RecordingBlacklist(calls),
        dns=RecordingDns(calls),
        redirect=RecordingRedirect(calls),
        rdap=RecordingRdap(calls),
        reputation=RecordingReputation(calls),
        max_retries=0,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = await investigation.investigate(request, scoped)

    assert calls == [
        ("blacklist", "example.test", None),
        ("dns", "https://example.test/login", None),
        ("redirect", "https://example.test/login", None),
        ("reputation", "https://example.test/login", True),
        ("rdap", "example.test", None),
    ]
    assert result.tool_calls_used == 4


@pytest.mark.asyncio
async def test_phase0_in_scope_result_and_call_trace_are_unchanged_by_the_progress_observer() -> None:
    request = SecurityTriageCreateRequestV4(
        message="The bank asked me to share an OTP immediately.",
        consent={"external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.scope_decision is ScopeDecisionV4.IN_SCOPE

    inline_trace = PipelineTrace()
    inline_result = await build_pipeline(inline_trace).process(
        request,
        scoped,
        runtime=SecurityAssistantRuntime(),
    )

    observed_trace = PipelineTrace()
    observed_result = await build_pipeline(observed_trace).process(
        request,
        scoped.model_copy(update={"status": AnalysisStatus.RUNNING}),
        runtime=SecurityAssistantRuntime(),
        progress=lambda *args: record_progress(observed_trace, *args),
    )

    assert inline_result.model_dump(exclude={"completed_at"}) == observed_result.model_dump(exclude={"completed_at"})
    assert inline_trace.calls == observed_trace.calls == [("investigation", True), ("trust", None)]
    assert observed_trace.progress_steps == ["understanding", "investigation", "risk_assessment", "assistant_response"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        "World Cup result is true?",
        "Is this phishing?",
    ],
)
async def test_phase0_terminal_scope_has_no_investigation_calls_or_progress(message: str) -> None:
    request = SecurityTriageCreateRequestV4(message=message)
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.scope_decision in {
        ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
        ScopeDecisionV4.NEED_MORE_INFO,
    }
    trace = PipelineTrace()

    result = await build_pipeline(trace, terminal_or_incident=True).process(
        request,
        scoped,
        runtime=SecurityAssistantRuntime(),
        progress=lambda *args: record_progress(trace, *args),
    )

    assert result.status is AnalysisStatus.COMPLETED
    assert trace.calls == []
    assert trace.progress_steps == ["understanding"]


@pytest.mark.asyncio
async def test_phase0_incident_exposure_skips_investigation_and_keeps_progress_coarse() -> None:
    request = SecurityTriageCreateRequestV4(message="The bank asked me to share an OTP immediately.")
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.scope_decision is ScopeDecisionV4.IN_SCOPE
    scoped = scoped.model_copy(
        update={
            "assistant_context": AssistantContextV4(
                processing_mode=AssistantProcessingModeV4.RULES_ONLY,
                exposure_state=ExposureStateV4.OTP_SHARED,
                model_version="phase0-fixture",
            )
        }
    )
    trace = PipelineTrace()

    result = await build_pipeline(trace, terminal_or_incident=True).process(
        request,
        scoped,
        runtime=SecurityAssistantRuntime(),
        progress=lambda *args: record_progress(trace, *args),
    )

    assert result.status is AnalysisStatus.COMPLETED
    assert result.risk is not None
    assert trace.calls == []
    assert trace.progress_steps == ["understanding", "incident_response", "assistant_response"]
