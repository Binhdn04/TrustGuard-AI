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
    AdminDecisionResponse,
    AnalysisAcceptedResponse,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRequest,
    AnalysisReportResponse,
    AnalysisResponse,
    AnalysisStatus,
    CaseStatus,
    ErrorCode,
    ReviewAction,
    ReviewDecision,
)


class AnalysisProcessor(Protocol):
    async def process(self, analysis_id: UUID, request: AnalysisCreateRequest) -> AnalysisResponse: ...


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

    def __init__(self, blacklist: BlacklistRepository | None = None) -> None:
        self._records: dict[UUID, _AnalysisRecord] = {}
        self._lock = asyncio.Lock()
        self._decision_lock = asyncio.Lock()
        self._blacklist = blacklist

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
        return AnalysisAcceptedResponse(analysis_id=analysis_id, created_at=now)

    async def list_for(self, principal: Principal) -> list[AnalysisResponse]:
        async with self._lock:
            records = [
                record.response.model_copy(deep=True)
                for record in self._records.values()
                if record.owner_id == principal.user_id
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    async def get_for(self, analysis_id: UUID, principal: Principal) -> AnalysisResponse:
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
        async with self._lock:
            self._records[analysis_id].reports.append(
                _ReportRecord(
                    reporter_id=principal.user_id,
                    request=request.model_copy(deep=True),
                    receipt=receipt,
                )
            )
        return receipt.model_copy(deep=True)

    async def list_review_cases(self) -> list[AnalysisResponse]:
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

            if request.action is ReviewAction.ADD_TO_BLACKLIST:
                if self._blacklist is None:
                    raise PlatformError(
                        status_code=503,
                        code=ErrorCode.INTERNAL_ERROR,
                        message="Blacklist repository is not configured.",
                        retryable=True,
                    )
                domains = {urlsplit(url).hostname for url in normalized_urls}
                for domain in sorted(item for item in domains if item):
                    await self._blacklist.add_approved(domain, str(decision_id))

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
                record.events.append(
                    AnalysisEvent(
                        analysis_id=analysis_id,
                        status=record.response.status,
                        step=f"review_{case_status.value}",
                        occurred_at=reviewed_at,
                    )
                )
                record.decisions.append(
                    _DecisionRecord(
                        reviewer_id=principal.user_id,
                        request=request.model_copy(deep=True),
                        receipt=response,
                    )
                )
        return response.model_copy(deep=True)

    async def persist_result(self, analysis_id: UUID, result: AnalysisResponse) -> None:
        """Processor integration seam; validates ID and appends progress."""
        if result.analysis_id != analysis_id:
            raise ValueError("processor result analysis_id does not match")
        async with self._lock:
            record = self._records.get(analysis_id)
            if record is None:
                raise self._not_found()
            record.response = result.model_copy(deep=True)
            record.events.append(
                AnalysisEvent(
                    analysis_id=analysis_id,
                    status=result.status,
                    step="completed" if result.status is AnalysisStatus.COMPLETED else result.status.value,
                    occurred_at=result.completed_at or datetime.now(UTC),
                )
            )

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
