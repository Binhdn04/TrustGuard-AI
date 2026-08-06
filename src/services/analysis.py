from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from src.agents.tools.protocols import BlacklistRepository
from src.core.auth import Principal, UserRole, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AdminDecisionRequest,
    AdminDecisionAudit,
    AdminDecisionResponse,
    AnalysisAcceptedResponse,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRequest,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    AnalysisStatus,
    BlacklistEntry,
    CaseStatus,
    ErrorCode,
    ReviewAction,
    ReviewDecision,
)


class AnalysisProcessor(Protocol):
    async def process(
        self,
        analysis_id: UUID,
        request: AnalysisCreateRequest,
        created_at: datetime,
    ) -> AnalysisResponse: ...


@dataclass(slots=True)
class _ReportRecord:
    reporter_id: str
    request: AnalysisReportRequest
    receipt: AnalysisReportResponse


@dataclass(slots=True)
class _DecisionRecord:
    reviewer_id: str
    request: AdminDecisionRequest
    receipt: AdminDecisionResponse


@dataclass(slots=True)
class _AnalysisRecord:
    owner_id: str
    request: AnalysisCreateRequest
    response: AnalysisResponse
    events: list[AnalysisEvent] = field(default_factory=list)
    reports: list[_ReportRecord] = field(default_factory=list)
    decisions: list[_DecisionRecord] = field(default_factory=list)


class AnalysisService:
    """Application service with a replaceable persistence/processor boundary.

    The in-memory state is intentional for the first vertical slice. Duc's
    repository implementation can replace it without changing the HTTP API.
    """

    def __init__(
        self,
        blacklist: BlacklistRepository | None = None,
        processor: AnalysisProcessor | None = None,
    ) -> None:
        self._records: dict[UUID, _AnalysisRecord] = {}
        self._lock = asyncio.Lock()
        self._decision_lock = asyncio.Lock()
        self._blacklist = blacklist
        self._processor = processor
        self._tasks: set[asyncio.Task[None]] = set()

    async def create(self, request: AnalysisCreateRequest, principal: Principal) -> AnalysisAcceptedResponse:
        now = datetime.now(UTC)
        analysis_id = uuid4()
        response = AnalysisResponse(
            analysis_id=analysis_id,
            status=AnalysisStatus.QUEUED,
            created_at=now,
        )
        event = AnalysisEvent(
            analysis_id=analysis_id,
            status=AnalysisStatus.QUEUED,
            step="queued",
            occurred_at=now,
        )
        async with self._lock:
            self._records[analysis_id] = _AnalysisRecord(
                owner_id=principal.user_id,
                request=request,
                response=response,
                events=[event],
            )
        create_analysis = getattr(self._blacklist, "create_analysis", None)
        if create_analysis is not None:
            try:
                await create_analysis(
                    owner_id=principal.user_id,
                    request=request,
                    response=response,
                    event=event,
                )
            except Exception:
                async with self._lock:
                    self._records.pop(analysis_id, None)
                raise
        if self._processor is not None:
            task = asyncio.create_task(
                self._run_processor(analysis_id, request.model_copy(deep=True), now),
                name=f"analysis-{analysis_id}",
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return AnalysisAcceptedResponse(analysis_id=analysis_id, created_at=now)

    async def _run_processor(
        self,
        analysis_id: UUID,
        request: AnalysisCreateRequest,
        created_at: datetime,
    ) -> None:
        running_at = datetime.now(UTC)
        running_event = AnalysisEvent(
            analysis_id=analysis_id,
            status=AnalysisStatus.RUNNING,
            step="running",
            occurred_at=running_at,
        )
        async with self._lock:
            record = self._records.get(analysis_id)
            if record is None:
                return
            record.response = record.response.model_copy(update={"status": AnalysisStatus.RUNNING})
            record.events.append(running_event)
            running_response = record.response.model_copy(deep=True)
        await self._persist_state(running_response, running_event)
        processor = self._processor
        if processor is None:
            return
        try:
            result = await processor.process(analysis_id, request, created_at)
        except Exception:
            failed_at = datetime.now(UTC)
            failed_event = AnalysisEvent(
                analysis_id=analysis_id,
                status=AnalysisStatus.FAILED,
                step="failed",
                occurred_at=failed_at,
            )
            async with self._lock:
                record = self._records.get(analysis_id)
                if record is None:
                    return
                record.response = AnalysisResponse(
                    analysis_id=analysis_id,
                    status=AnalysisStatus.FAILED,
                    created_at=created_at,
                )
                record.events.append(failed_event)
                failed_response = record.response.model_copy(deep=True)
            await self._persist_state(failed_response, failed_event)
            return
        await self.persist_result(analysis_id, result)

    async def list_for(self, principal: Principal) -> list[AnalysisResponse]:
        list_responses = getattr(self._blacklist, "list_analysis_responses", None)
        if list_responses is not None:
            return await list_responses(owner_id=principal.user_id)
        async with self._lock:
            records = [
                record.response.model_copy(deep=True)
                for record in self._records.values()
                if record.owner_id == principal.user_id
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    async def get_for(self, analysis_id: UUID, principal: Principal) -> AnalysisResponse:
        await self._ensure_record(analysis_id)
        async with self._lock:
            record = self._records.get(analysis_id)
            if record is None:
                raise self._not_found()
            if record.owner_id != principal.user_id:
                is_reviewable_admin = principal.role is UserRole.SECURITY_ADMIN and record.response.case_status in {
                    CaseStatus.PENDING_REVIEW,
                    CaseStatus.APPROVED,
                    CaseStatus.REJECTED,
                }
                if not is_reviewable_admin:
                    raise self._forbidden()
            return record.response.model_copy(deep=True)

    async def events_for(self, analysis_id: UUID, principal: Principal) -> list[AnalysisEvent]:
        await self.get_for(analysis_id, principal)
        async with self._lock:
            return [event.model_copy(deep=True) for event in self._records[analysis_id].events]

    async def report(
        self,
        analysis_id: UUID,
        request: AnalysisReportRequest,
        principal: Principal,
    ) -> AnalysisReportResponse:
        await self.get_for(analysis_id, principal)
        receipt = AnalysisReportResponse(
            report_id=uuid4(),
            analysis_id=analysis_id,
            created_at=datetime.now(UTC),
        )
        record_report = getattr(self._blacklist, "record_report", None)
        if record_report is not None:
            await record_report(
                report_id=str(receipt.report_id),
                analysis_id=str(analysis_id),
                reporter_id=principal.user_id,
                reason=request.reason,
                comment=request.comment,
                created_at=receipt.created_at,
            )
        async with self._lock:
            self._records[analysis_id].reports.append(
                _ReportRecord(
                    reporter_id=principal.user_id,
                    request=request.model_copy(deep=True),
                    receipt=receipt,
                )
            )
        return receipt.model_copy(deep=True)

    async def list_reports(self, *, limit: int, offset: int) -> list[AnalysisReportRecord]:
        list_reports = getattr(self._blacklist, "list_reports", None)
        if list_reports is None:
            async with self._lock:
                reports = [
                    AnalysisReportRecord(
                        **report.receipt.model_dump(),
                        reporter_id=report.reporter_id,
                        reason=report.request.reason,
                        comment=report.request.comment,
                    )
                    for record in self._records.values()
                    for report in record.reports
                ]
            return sorted(reports, key=lambda item: item.created_at, reverse=True)[offset : offset + limit]
        return await list_reports(limit=limit, offset=offset)

    async def list_decisions(self, *, limit: int, offset: int) -> list[AdminDecisionAudit]:
        list_decisions = getattr(self._blacklist, "list_decisions", None)
        if list_decisions is None:
            async with self._lock:
                decisions = [
                    AdminDecisionAudit(
                        decision_id=decision.receipt.decision_id,
                        analysis_id=analysis_id,
                        reviewer_id=decision.reviewer_id,
                        decision=decision.request.decision,
                        action=decision.request.action,
                        note=decision.request.note,
                        decided_at=decision.receipt.reviewed_at,
                    )
                    for analysis_id, record in self._records.items()
                    for decision in record.decisions
                ]
            return sorted(decisions, key=lambda item: item.decided_at, reverse=True)[offset : offset + limit]
        return await list_decisions(limit=limit, offset=offset)

    async def list_blacklist(
        self,
        *,
        query: str | None,
        limit: int,
        offset: int,
    ) -> list[BlacklistEntry]:
        list_blacklist = getattr(self._blacklist, "list_blacklist", None)
        if list_blacklist is None:
            return []
        return await list_blacklist(query=query, limit=limit, offset=offset)

    async def list_review_cases(self) -> list[AnalysisResponse]:
        list_responses = getattr(self._blacklist, "list_analysis_responses", None)
        if list_responses is not None:
            records = await list_responses(case_status=CaseStatus.PENDING_REVIEW.value)
            return sorted(records, key=lambda item: item.created_at)
        async with self._lock:
            records = [
                record.response.model_copy(deep=True)
                for record in self._records.values()
                if record.response.case_status is CaseStatus.PENDING_REVIEW
            ]
        return sorted(records, key=lambda item: item.created_at)

    async def decide(
        self,
        analysis_id: UUID,
        request: AdminDecisionRequest,
        principal: Principal,
    ) -> AdminDecisionResponse:
        require_security_admin(principal)
        async with self._decision_lock:
            await self._ensure_record(analysis_id)
            decision_id = uuid4()
            reviewed_at = datetime.now(UTC)
            async with self._lock:
                record = self._records.get(analysis_id)
                if record is None:
                    raise self._not_found()
                if record.response.case_status is not CaseStatus.PENDING_REVIEW:
                    raise PlatformError(
                        status_code=409,
                        code=ErrorCode.VALIDATION_ERROR,
                        message="Analysis is not pending review.",
                        retryable=False,
                    )
                normalized_urls = list(record.response.normalized_urls or [])

            blacklist = self._blacklist
            if request.action is ReviewAction.ADD_TO_BLACKLIST:
                if blacklist is None:
                    raise PlatformError(
                        status_code=503,
                        code=ErrorCode.INTERNAL_ERROR,
                        message="Blacklist repository is not configured.",
                        retryable=True,
                    )

            apply_decision = getattr(blacklist, "apply_decision", None)
            if apply_decision is not None:
                domains = tuple(
                    sorted(
                        domain
                        for domain in {urlsplit(url).hostname for url in normalized_urls}
                        if domain
                    )
                )
                await apply_decision(
                    decision_id=str(decision_id),
                    analysis_id=str(analysis_id),
                    reviewer_id=principal.user_id,
                    decision=request.decision.value,
                    action=request.action.value,
                    note=request.note,
                    domains=domains if request.action is ReviewAction.ADD_TO_BLACKLIST else (),
                )
            elif blacklist is not None:
                record_decision = getattr(blacklist, "record_decision", None)
                if record_decision is not None:
                    await record_decision(
                        decision_id=str(decision_id),
                        reviewer_id=principal.user_id,
                        decision=request.decision.value,
                        action=request.action.value,
                        note=request.note,
                    )

            if request.action is ReviewAction.ADD_TO_BLACKLIST and apply_decision is None:
                assert blacklist is not None
                domains = {urlsplit(url).hostname for url in normalized_urls}
                for domain in sorted(item for item in domains if item):
                    await blacklist.add_approved(domain, str(decision_id))

            case_status = CaseStatus.APPROVED if request.decision is ReviewDecision.APPROVED else CaseStatus.REJECTED
            response = AdminDecisionResponse(
                decision_id=decision_id,
                analysis_id=analysis_id,
                case_status=case_status,
                reviewed_at=reviewed_at,
            )
            async with self._lock:
                record = self._records[analysis_id]
                record.response = record.response.model_copy(update={"case_status": case_status})
                review_event = AnalysisEvent(
                    analysis_id=analysis_id,
                    status=record.response.status,
                    step=f"review_{case_status.value}",
                    occurred_at=reviewed_at,
                )
                record.events.append(review_event)
                reviewed_analysis = record.response.model_copy(deep=True)
                record.decisions.append(
                    _DecisionRecord(
                        reviewer_id=principal.user_id,
                        request=request.model_copy(deep=True),
                        receipt=response,
                    )
                )
            await self._persist_state(reviewed_analysis, review_event)
        return response.model_copy(deep=True)

    async def persist_result(self, analysis_id: UUID, result: AnalysisResponse) -> None:
        """Processor integration seam; validates ID and appends progress."""
        if result.analysis_id != analysis_id:
            raise ValueError("processor result analysis_id does not match")
        event = AnalysisEvent(
            analysis_id=analysis_id,
            status=result.status,
            step="completed" if result.status is AnalysisStatus.COMPLETED else result.status.value,
            occurred_at=result.completed_at or datetime.now(UTC),
        )
        async with self._lock:
            record = self._records.get(analysis_id)
            if record is None:
                raise self._not_found()
            record.response = result.model_copy(deep=True)
            record.events.append(event)
        await self._persist_state(result, event)

    async def _ensure_record(self, analysis_id: UUID) -> None:
        async with self._lock:
            if analysis_id in self._records:
                return
        load_analysis = getattr(self._blacklist, "load_analysis", None)
        if load_analysis is None:
            raise self._not_found()
        loaded = await load_analysis(str(analysis_id))
        if loaded is None:
            raise self._not_found()
        owner_id, request, response, events = loaded
        async with self._lock:
            self._records.setdefault(
                analysis_id,
                _AnalysisRecord(
                    owner_id=owner_id,
                    request=request,
                    response=response,
                    events=events,
                ),
            )

    async def _persist_state(self, response: AnalysisResponse, event: AnalysisEvent) -> None:
        update_analysis = getattr(self._blacklist, "update_analysis", None)
        if update_analysis is not None:
            await update_analysis(response, event)

    async def aclose(self) -> None:
        """Stop background work and close application-owned resources."""
        pending = list(self._tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        close_processor = getattr(self._processor, "aclose", None)
        if close_processor is not None:
            await close_processor()
        close_blacklist = getattr(self._blacklist, "close", None)
        if close_blacklist is not None:
            await close_blacklist()

    @staticmethod
    def _not_found() -> PlatformError:
        return PlatformError(
            status_code=404,
            code=ErrorCode.NOT_FOUND,
            message="Analysis was not found.",
            retryable=False,
        )

    @staticmethod
    def _forbidden() -> PlatformError:
        return PlatformError(
            status_code=403,
            code=ErrorCode.FORBIDDEN,
            message="You do not have access to this analysis.",
            retryable=False,
        )
