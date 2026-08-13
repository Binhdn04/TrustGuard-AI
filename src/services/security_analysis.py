from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from src.core.auth import Principal
from src.core.errors import PlatformError
from src.models import (
    AnalysisStatus,
    ErrorCode,
    PotentialThreatV4,
    ScopeDecisionV4,
    SecurityAnalysisEventV4,
    SecurityAppealCreateRequestV4,
    SecurityAppealRecordV4,
    SecurityContextV4,
    SecurityConversationSummaryV4,
    SecurityConversationV4,
    SecurityReportCreateRequestV4,
    SecurityReportRecordV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)


def _redact_context(context: SecurityContextV4 | None) -> SecurityContextV4 | None:
    if context is None:
        return None
    urls: list[str] = []
    for value in context.urls:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        if parsed.port is not None:
            hostname = f"{hostname}:{parsed.port}"
        redacted = urlunsplit((parsed.scheme, hostname, parsed.path, "", ""))
        if redacted not in urls:
            urls.append(redacted)
    return context.model_copy(update={"urls": urls})


def _merge_context(previous: SecurityContextV4, current: SecurityContextV4) -> SecurityContextV4:
    entity_families = {
        "bank": "bank",
        "ngân hàng": "bank",
        "hr": "recruiter",
        "nhà tuyển dụng": "recruiter",
        "police": "police",
        "công an": "police",
    }
    previous_entity = (
        entity_families.get(previous.claimed_entity.casefold(), previous.claimed_entity.casefold())
        if previous.claimed_entity
        else None
    )
    current_entity = (
        entity_families.get(current.claimed_entity.casefold(), current.claimed_entity.casefold())
        if current.claimed_entity
        else None
    )
    if previous_entity is not None and current_entity is not None and previous_entity != current_entity:
        raise PlatformError(
            status_code=409,
            code=ErrorCode.CONFLICT,
            message="This message appears to describe a different case; start a new conversation.",
            retryable=False,
        )
    urls = list(dict.fromkeys([*previous.urls, *current.urls]))[:10]
    signals = list(dict.fromkeys([*previous.impersonation_signals, *current.impersonation_signals]))[:10]
    return current.model_copy(
        update={
            "claimed_entity": current.claimed_entity or previous.claimed_entity,
            "scenario": previous.scenario if current.scenario is SecurityScenarioV4.UNKNOWN else current.scenario,
            "requested_action": current.requested_action or previous.requested_action,
            "amount": current.amount or previous.amount,
            "urgency": current.urgency or previous.urgency,
            "urls": urls,
            "credential_request": current.credential_request or previous.credential_request,
            "otp_request": current.otp_request or previous.otp_request,
            "payment_request": current.payment_request or previous.payment_request,
            "personal_information_request": (
                current.personal_information_request or previous.personal_information_request
            ),
            "impersonation_signals": signals,
            "potential_threat": (
                previous.potential_threat
                if current.potential_threat is PotentialThreatV4.UNDETERMINED_SECURITY_THREAT
                else current.potential_threat
            ),
        }
    )


class SecurityAnalysisService:
    """Owner-scoped v4 result/event store, isolated from the frozen legacy contract."""

    def __init__(self, repository=None, *, conversation_retention_days: int = 30) -> None:
        self._repository = repository
        self._conversation_retention_days = conversation_retention_days
        self._records: dict[UUID, tuple[str, SecurityScopeResponseV4, list[SecurityAnalysisEventV4]]] = {}
        self._conversations: dict[UUID, tuple[str, SecurityConversationV4]] = {}
        self._reports: dict[UUID, tuple[str, SecurityReportRecordV4]] = {}
        self._appeals: dict[UUID, tuple[str, SecurityAppealRecordV4]] = {}
        self._lock = asyncio.Lock()

    async def begin_turn(
        self,
        request: SecurityTriageCreateRequestV4,
        response: SecurityScopeResponseV4,
        principal: Principal,
    ) -> SecurityScopeResponseV4:
        now = datetime.now(UTC)
        existing: SecurityConversationV4 | None = None
        if request.conversation_id is not None:
            existing = await self._load_conversation(request.conversation_id, principal)
            if existing.expires_at <= now:
                raise PlatformError(
                    status_code=404,
                    code=ErrorCode.NOT_FOUND,
                    message="Security conversation has expired.",
                    retryable=False,
                )
            if existing.context_version != request.conversation_version:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security conversation was updated by another turn.",
                    retryable=True,
                    details={"current_version": existing.context_version},
                )
            if response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="This message is outside the active security case; start a new conversation.",
                    retryable=False,
                )

        current = _redact_context(response.security_context)
        previous = existing.summary.security_context if existing else None
        merged = _merge_context(previous, current) if previous is not None and current is not None else current
        conversation_id = request.conversation_id or response.conversation_id
        version = (existing.context_version + 1) if existing else 1
        response = response.model_copy(
            update={
                "conversation_id": conversation_id,
                "conversation_version": version,
                "security_context": merged,
            }
        )
        record = SecurityConversationV4(
            conversation_id=conversation_id,
            active_analysis_id=response.analysis_id,
            summary=SecurityConversationSummaryV4(
                security_context=merged,
                evidence_refs=existing.summary.evidence_refs if existing else [],
            ),
            context_version=version,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            expires_at=now + timedelta(days=self._conversation_retention_days),
        )
        save = getattr(self._repository, "save_security_conversation", None)
        if save is not None:
            await save(
                principal.user_id,
                record,
                expected_version=request.conversation_version,
            )
        async with self._lock:
            self._conversations[conversation_id] = (principal.user_id, record)
        return response

    async def get_conversation_for(self, conversation_id: UUID, principal: Principal) -> SecurityConversationV4:
        return (await self._load_conversation(conversation_id, principal)).model_copy(deep=True)

    async def _load_conversation(self, conversation_id: UUID, principal: Principal) -> SecurityConversationV4:
        async with self._lock:
            cached = self._conversations.get(conversation_id)
        loaded = cached
        if loaded is None:
            load = getattr(self._repository, "load_security_conversation", None)
            loaded = await load(str(conversation_id)) if load is not None else None
        if loaded is None:
            raise PlatformError(
                status_code=404,
                code=ErrorCode.NOT_FOUND,
                message="Security conversation was not found.",
                retryable=False,
            )
        owner_id, record = loaded
        if owner_id != principal.user_id:
            raise PlatformError(
                status_code=403,
                code=ErrorCode.FORBIDDEN,
                message="Security conversation belongs to another user.",
                retryable=False,
            )
        if record.expires_at <= datetime.now(UTC):
            raise PlatformError(
                status_code=404,
                code=ErrorCode.NOT_FOUND,
                message="Security conversation has expired.",
                retryable=False,
            )
        return record

    async def persist_completed(self, response: SecurityScopeResponseV4, principal: Principal) -> None:
        await self._persist_terminal(response, principal, AnalysisStatus.COMPLETED)

    async def persist_failed(self, response: SecurityScopeResponseV4, principal: Principal) -> None:
        await self._persist_terminal(response, principal, AnalysisStatus.FAILED)

    async def _persist_terminal(
        self, response: SecurityScopeResponseV4, principal: Principal, terminal_status: AnalysisStatus
    ) -> None:
        completed_at = response.completed_at or datetime.now(UTC)
        response = response.model_copy(update={"status": terminal_status, "completed_at": completed_at})
        events = [
            SecurityAnalysisEventV4(
                analysis_id=response.analysis_id,
                sequence=1,
                status=AnalysisStatus.QUEUED,
                step="queued",
                occurred_at=response.created_at,
            ),
            SecurityAnalysisEventV4(
                analysis_id=response.analysis_id,
                sequence=2,
                status=AnalysisStatus.RUNNING,
                step="investigation" if response.security_context is not None else "scope_gate",
                occurred_at=response.created_at,
            ),
            SecurityAnalysisEventV4(
                analysis_id=response.analysis_id,
                sequence=3,
                status=terminal_status,
                step=terminal_status.value,
                occurred_at=completed_at,
            ),
        ]
        persist = getattr(self._repository, "save_security_analysis", None)
        if persist is not None:
            await persist(principal.user_id, response, events)
        async with self._lock:
            self._records[response.analysis_id] = (principal.user_id, response, events)
        await self._finalize_conversation(response, principal)

    async def _finalize_conversation(self, response: SecurityScopeResponseV4, principal: Principal) -> None:
        record = await self._load_conversation(response.conversation_id, principal)
        if record.context_version != response.conversation_version or record.active_analysis_id != response.analysis_id:
            return
        refs = list(dict.fromkeys([*record.summary.evidence_refs, *(item.evidence_ref for item in response.evidence)]))
        updated = record.model_copy(
            update={
                "summary": record.summary.model_copy(
                    update={"security_context": _redact_context(response.security_context), "evidence_refs": refs[:100]}
                ),
                "updated_at": response.completed_at or datetime.now(UTC),
            }
        )
        finalize = getattr(self._repository, "finalize_security_conversation", None)
        if finalize is not None:
            await finalize(principal.user_id, updated)
        async with self._lock:
            self._conversations[response.conversation_id] = (principal.user_id, updated)

    async def get_for(self, analysis_id: UUID, principal: Principal) -> SecurityScopeResponseV4:
        loaded = await self._load(analysis_id)
        if loaded is None:
            raise PlatformError(
                status_code=404, code=ErrorCode.NOT_FOUND, message="Security analysis was not found.", retryable=False
            )
        owner_id, response, _events = loaded
        if owner_id != principal.user_id:
            raise PlatformError(
                status_code=403,
                code=ErrorCode.FORBIDDEN,
                message="Security analysis belongs to another user.",
                retryable=False,
            )
        return response.model_copy(deep=True)

    async def events_for(self, analysis_id: UUID, principal: Principal) -> list[SecurityAnalysisEventV4]:
        await self.get_for(analysis_id, principal)
        loaded = await self._load(analysis_id)
        assert loaded is not None
        return [event.model_copy(deep=True) for event in loaded[2]]

    async def list_for(self, principal: Principal) -> list[SecurityScopeResponseV4]:
        load = getattr(self._repository, "list_security_analyses", None)
        if load is not None:
            persisted = await load(principal.user_id)
            return [item.model_copy(deep=True) for item in persisted]
        async with self._lock:
            records = [
                response.model_copy(deep=True)
                for owner_id, response, _events in self._records.values()
                if owner_id == principal.user_id
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    async def create_report(
        self, analysis_id: UUID, request: SecurityReportCreateRequestV4, principal: Principal
    ) -> SecurityReportRecordV4:
        await self.get_for(analysis_id, principal)
        record = SecurityReportRecordV4(analysis_id=analysis_id, **request.model_dump())
        save = getattr(self._repository, "save_security_report", None)
        if save is not None:
            await save(principal.user_id, record)
        async with self._lock:
            self._reports[record.report_id] = (principal.user_id, record)
        return record

    async def list_reports_for(
        self, analysis_id: UUID, principal: Principal
    ) -> list[SecurityReportRecordV4]:
        await self.get_for(analysis_id, principal)
        load = getattr(self._repository, "list_security_reports", None)
        if load is not None:
            return await load(str(analysis_id), principal.user_id)
        async with self._lock:
            return [
                item.model_copy(deep=True)
                for owner_id, item in self._reports.values()
                if owner_id == principal.user_id and item.analysis_id == analysis_id
            ]

    async def create_appeal(
        self, analysis_id: UUID, request: SecurityAppealCreateRequestV4, principal: Principal
    ) -> SecurityAppealRecordV4:
        await self.get_for(analysis_id, principal)
        if any(item.status.value != "resolved" for item in await self.list_appeals_for(analysis_id, principal)):
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="An active appeal already exists for this security analysis.",
                retryable=False,
            )
        record = SecurityAppealRecordV4(analysis_id=analysis_id, **request.model_dump())
        save = getattr(self._repository, "save_security_appeal", None)
        if save is not None:
            await save(principal.user_id, record)
        async with self._lock:
            self._appeals[record.appeal_id] = (principal.user_id, record)
        return record

    async def list_appeals_for(
        self, analysis_id: UUID, principal: Principal
    ) -> list[SecurityAppealRecordV4]:
        await self.get_for(analysis_id, principal)
        load = getattr(self._repository, "list_security_appeals", None)
        if load is not None:
            return await load(str(analysis_id), principal.user_id)
        async with self._lock:
            return [
                item.model_copy(deep=True)
                for owner_id, item in self._appeals.values()
                if owner_id == principal.user_id and item.analysis_id == analysis_id
            ]

    async def _load(
        self, analysis_id: UUID
    ) -> tuple[str, SecurityScopeResponseV4, list[SecurityAnalysisEventV4]] | None:
        async with self._lock:
            record = self._records.get(analysis_id)
        if record is not None:
            return record
        load = getattr(self._repository, "load_security_analysis", None)
        if load is None:
            return None
        loaded = await load(str(analysis_id))
        if loaded is not None:
            async with self._lock:
                self._records[analysis_id] = loaded
        return loaded

    async def aclose(self) -> None:
        close = getattr(self._repository, "aclose", None) or getattr(self._repository, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result


__all__ = ["SecurityAnalysisService"]
