from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from src.core.auth import Principal, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AnalysisStatus,
    AppealOutcome,
    AppealStatus,
    AssistantContextV4,
    ErrorCode,
    MissingInformationSlotV4,
    PotentialThreatV4,
    ReportReviewDecision,
    ReportStatus,
    ScopeDecisionV4,
    SecurityAdminAuditEventV4,
    SecurityAnalysisAcceptedResponseV4,
    SecurityAnalysisEventKindV4,
    SecurityAnalysisEventV4,
    SecurityAppealAdminRecordV4,
    SecurityAppealCreateRequestV4,
    SecurityAppealRecordV4,
    SecurityAuditResourceV4,
    SecurityContextV4,
    SecurityConversationSummaryV4,
    SecurityConversationV4,
    SecurityReportAdminRecordV4,
    SecurityReportCreateRequestV4,
    SecurityReportRecordV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_conversation_policy import deterministic_question, highest_exposure

_EXPLICIT_GENERAL_FACT_REASONS = {
    "general_fact_check_sports",
    "general_fact_check_politics",
    "general_fact_check_medical_science",
    "general_fact_check_news",
}
_LOCAL_CONVERSATION_REASONS = {"assistant_capabilities", "assistant_greeting"}
_SENSITIVE_SUMMARY_VALUE = re.compile(
    r"(?:otp|one[- ]time|pass(?:word|code)?|mật khẩu|mat khau|pin|secret|token|credential)"
    r"|\b\d{4,8}\b|[\w.+-]+@[\w.-]+",
    re.IGNORECASE,
)
_SENSITIVE_PATH_SEGMENT = re.compile(
    r"^(?:\d{4,8}|.{24,})$|(?:otp|pass(?:word|code)?|secret|token|credential)",
    re.IGNORECASE,
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
        safe_path = "/".join(
            "redacted" if _SENSITIVE_PATH_SEGMENT.search(segment) else segment for segment in parsed.path.split("/")
        )
        redacted = urlunsplit((parsed.scheme, hostname, safe_path, "", ""))
        if redacted not in urls:
            urls.append(redacted)
    return context.model_copy(
        update={
            "urls": urls,
            "claimed_entity": (
                None
                if context.claimed_entity and _SENSITIVE_SUMMARY_VALUE.search(context.claimed_entity)
                else context.claimed_entity
            ),
        }
    )


def _redact_assistant_context(context: AssistantContextV4 | None) -> AssistantContextV4 | None:
    if context is None:
        return None
    allowed_slots = {slot.value for slot in MissingInformationSlotV4}
    return context.model_copy(
        update={
            "sender_intent": (
                None
                if context.sender_intent and _SENSITIVE_SUMMARY_VALUE.search(context.sender_intent)
                else context.sender_intent
            ),
            "social_engineering_techniques": [
                value for value in context.social_engineering_techniques if not _SENSITIVE_SUMMARY_VALUE.search(value)
            ],
            "missing_information": [value for value in context.missing_information if value in allowed_slots],
        }
    )


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
        self._admin_audit: list[SecurityAdminAuditEventV4] = []
        self._lock = asyncio.Lock()

    @property
    def repository(self):
        return self._repository

    async def begin_turn(
        self,
        request: SecurityTriageCreateRequestV4,
        response: SecurityScopeResponseV4,
        principal: Principal,
        *,
        persist: bool = True,
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
            if (
                response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
                and set(response.scope_reasons) & _EXPLICIT_GENERAL_FACT_REASONS
            ):
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="This message is outside the active security case; start a new conversation.",
                    retryable=False,
                )

        previous_assistant = existing.summary.assistant_context if existing else None
        local_conversation = bool(set(response.scope_reasons) & _LOCAL_CONVERSATION_REASONS)
        if (
            existing is not None
            and response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
            and not local_conversation
        ):
            response = response.model_copy(
                update={
                    "scope_decision": ScopeDecisionV4.NEED_MORE_INFO,
                    "terminal": True,
                    "next_step": "END",
                    "scope_reasons": [*response.scope_reasons, "active_security_conversation"],
                    "security_context": existing.summary.security_context,
                    "assistant_context": previous_assistant,
                    "follow_up_question": deterministic_question(MissingInformationSlotV4.ACTION_TAKEN),
                    "follow_up_slot": MissingInformationSlotV4.ACTION_TAKEN,
                    "boundary_message": None,
                }
            )

        current = _redact_context(response.security_context)
        previous = existing.summary.security_context if existing else None
        if previous is not None and current is not None:
            merged = _merge_context(previous, current)
        else:
            merged = current or previous
        assistant_context = response.assistant_context or previous_assistant
        if assistant_context is not None and previous_assistant is not None:
            assistant_context = assistant_context.model_copy(
                update={
                    "exposure_state": highest_exposure(
                        previous_assistant.exposure_state,
                        assistant_context.exposure_state,
                    )
                }
            )
        conversation_id = request.conversation_id or response.conversation_id
        version = (existing.context_version + 1) if existing else 1
        response = response.model_copy(
            update={
                "conversation_id": conversation_id,
                "conversation_version": version,
                # Greeting/help responses may occur inside an active case. They
                # must not expose the retained case context on an out-of-scope
                # response, while the conversation summary below keeps it for
                # the next genuine security turn.
                "security_context": (
                    None
                    if response.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
                    else merged
                ),
                "assistant_context": assistant_context,
            }
        )
        record = SecurityConversationV4(
            conversation_id=conversation_id,
            active_analysis_id=response.analysis_id,
            summary=SecurityConversationSummaryV4(
                security_context=merged,
                assistant_context=_redact_assistant_context(assistant_context),
                unresolved_slots=existing.summary.unresolved_slots if existing else [],
                evidence_refs=existing.summary.evidence_refs if existing else [],
            ),
            context_version=version,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            expires_at=now + timedelta(days=self._conversation_retention_days),
        )
        save = getattr(self._repository, "save_security_conversation", None)
        if persist and save is not None:
            await save(
                principal.user_id,
                record,
                expected_version=request.conversation_version,
            )
        async with self._lock:
            self._conversations[conversation_id] = (principal.user_id, record)
        return response

    async def pending_conversation_for(
        self,
        response: SecurityScopeResponseV4,
        principal: Principal,
    ) -> SecurityConversationV4:
        """Return the prepared immutable turn snapshot before durable enqueue."""
        async with self._lock:
            stored = self._conversations.get(response.conversation_id)
        if stored is None or stored[0] != principal.user_id:
            raise RuntimeError("prepared security conversation is unavailable")
        record = stored[1]
        if record.active_analysis_id != response.analysis_id or record.context_version != response.conversation_version:
            raise RuntimeError("prepared security conversation does not match analysis turn")
        return record.model_copy(deep=True)

    async def enqueue_turn(
        self,
        request: SecurityTriageCreateRequestV4,
        response: SecurityScopeResponseV4,
        principal: Principal,
        idempotency_key: str,
    ) -> SecurityAnalysisAcceptedResponseV4:
        enqueue = getattr(self._repository, "enqueue_security_analysis", None)
        if enqueue is None:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Async Security v4 execution requires PostgreSQL.",
                retryable=False,
            )
        request_json = request.model_dump_json()
        payload_hash = hashlib.sha256(request_json.encode()).hexdigest()
        idempotent = getattr(self._repository, "load_security_idempotent", None)
        if idempotent is not None:
            existing = await idempotent(principal.user_id, idempotency_key, payload_hash)
            if existing is not None:
                return SecurityAnalysisAcceptedResponseV4(
                    analysis_id=existing.analysis_id,
                    conversation_id=existing.conversation_id,
                    conversation_version=existing.conversation_version,
                    status=AnalysisStatus.QUEUED
                    if existing.status in {AnalysisStatus.QUEUED, AnalysisStatus.RUNNING}
                    else AnalysisStatus.QUEUED,
                    created_at=existing.created_at,
                )

        prepared = await self.begin_turn(request, response, principal, persist=False)
        queued = prepared.model_copy(update={"status": AnalysisStatus.QUEUED})
        conversation = await self.pending_conversation_for(queued, principal)
        hint = self._provisional_risk_hint(queued)
        events = [
            SecurityAnalysisEventV4(
                analysis_id=queued.analysis_id,
                sequence=1,
                status=AnalysisStatus.QUEUED,
                step="queued",
                kind=SecurityAnalysisEventKindV4.STATUS,
                message="Security v4 analysis was queued.",
                occurred_at=queued.created_at,
            )
        ]
        if queued.scope_decision is ScopeDecisionV4.IN_SCOPE:
            events.append(
                SecurityAnalysisEventV4(
                    analysis_id=queued.analysis_id,
                    sequence=2,
                    status=AnalysisStatus.QUEUED,
                    step="provisional_warning",
                    kind=SecurityAnalysisEventKindV4.PROVISIONAL,
                    message="Đã phát hiện tín hiệu bảo mật cục bộ; không thực hiện hành động rủi ro trong khi chờ kết quả.",
                    risk_hint=hint,
                    occurred_at=queued.created_at,
                )
            )
        try:
            stored = await enqueue(
                owner_id=principal.user_id,
                request=request,
                response=queued,
                conversation=conversation,
                expected_version=request.conversation_version,
                idempotency_key=idempotency_key,
                payload_hash=payload_hash,
                events=events,
            )
        except Exception:
            await self._refresh_conversation_cache(queued.conversation_id, principal.user_id)
            raise
        if stored.analysis_id == queued.analysis_id:
            await self.cache_enqueued(principal.user_id, queued, events)
        else:
            await self._refresh_conversation_cache(stored.conversation_id, principal.user_id)
        return SecurityAnalysisAcceptedResponseV4(
            analysis_id=stored.analysis_id,
            conversation_id=stored.conversation_id,
            conversation_version=stored.conversation_version,
            created_at=stored.created_at,
        )

    async def _refresh_conversation_cache(self, conversation_id: UUID, owner_id: str) -> None:
        load = getattr(self._repository, "load_security_conversation", None)
        loaded = await load(str(conversation_id)) if load is not None else None
        async with self._lock:
            if loaded is None:
                self._conversations.pop(conversation_id, None)
            elif loaded[0] == owner_id:
                self._conversations[conversation_id] = loaded

    @staticmethod
    def _provisional_risk_hint(response: SecurityScopeResponseV4) -> SecurityRiskV4:
        context = response.security_context
        if context is not None and (
            context.credential_request or context.otp_request or context.payment_request
        ):
            return SecurityRiskV4.HIGH_RISK
        return SecurityRiskV4.SUSPICIOUS

    async def cache_enqueued(
        self,
        owner_id: str,
        response: SecurityScopeResponseV4,
        events: list[SecurityAnalysisEventV4],
    ) -> None:
        async with self._lock:
            self._records[response.analysis_id] = (owner_id, response, events)

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

    async def finalize_durable(self, response: SecurityScopeResponseV4, principal: Principal) -> None:
        """Refresh process-local state after PostgreSQL committed a durable result."""
        loaded = await self._repository.load_security_analysis(str(response.analysis_id))
        if loaded is not None:
            async with self._lock:
                self._records[response.analysis_id] = loaded
        await self._finalize_conversation(response, principal)

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
                kind=SecurityAnalysisEventKindV4.STATUS,
                message="Security v4 analysis was queued.",
                occurred_at=response.created_at,
            ),
            SecurityAnalysisEventV4(
                analysis_id=response.analysis_id,
                sequence=2,
                status=AnalysisStatus.RUNNING,
                step="investigation" if response.security_context is not None else "scope_gate",
                kind=SecurityAnalysisEventKindV4.PROGRESS,
                message="Security v4 analysis was processed inline.",
                occurred_at=response.created_at,
            ),
            SecurityAnalysisEventV4(
                analysis_id=response.analysis_id,
                sequence=3,
                status=terminal_status,
                step=terminal_status.value,
                kind=SecurityAnalysisEventKindV4.FINAL,
                message=f"Security v4 analysis {terminal_status.value}.",
                evidence_refs=list(response.explanation_evidence_refs),
                risk_hint=response.risk,
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
        local_conversation = bool(set(response.scope_reasons) & _LOCAL_CONVERSATION_REASONS)
        summary_context = (
            record.summary.security_context if local_conversation else _redact_context(response.security_context)
        )
        summary_assistant = (
            record.summary.assistant_context
            if local_conversation
            else _redact_assistant_context(response.assistant_context)
        )
        unresolved = (
            record.summary.unresolved_slots
            if local_conversation
            else [
                MissingInformationSlotV4(value)
                for value in (response.assistant_context.missing_information if response.assistant_context else [])
                if value in {slot.value for slot in MissingInformationSlotV4}
            ]
        )
        refs = list(dict.fromkeys([*record.summary.evidence_refs, *(item.evidence_ref for item in response.evidence)]))
        updated = record.model_copy(
            update={
                "summary": record.summary.model_copy(
                    update={
                        "security_context": summary_context,
                        "assistant_context": summary_assistant,
                        "unresolved_slots": unresolved,
                        "evidence_refs": refs[:100],
                    }
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

    async def get_for_admin(self, analysis_id: UUID, principal: Principal) -> SecurityScopeResponseV4:
        """Return the stored, structured case without exposing owner or conversation text."""
        require_security_admin(principal)
        loaded = await self._load(analysis_id)
        if loaded is None:
            raise PlatformError(
                status_code=404,
                code=ErrorCode.NOT_FOUND,
                message="Security analysis was not found.",
                retryable=False,
            )
        _owner_id, response, _events = loaded
        return response.model_copy(
            deep=True,
            update={"security_context": _redact_context(response.security_context)},
        )

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

    async def list_conversations_for(self, principal: Principal) -> list[SecurityConversationV4]:
        load = getattr(self._repository, "list_security_conversations", None)
        if load is not None:
            return [item.model_copy(deep=True) for item in await load(principal.user_id)]
        async with self._lock:
            records = [
                item.model_copy(deep=True)
                for owner_id, item in self._conversations.values()
                if owner_id == principal.user_id
            ]
        return sorted(records, key=lambda item: item.updated_at, reverse=True)

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

    async def list_reports_for(self, analysis_id: UUID, principal: Principal) -> list[SecurityReportRecordV4]:
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

    async def list_appeals_for(self, analysis_id: UUID, principal: Principal) -> list[SecurityAppealRecordV4]:
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

    async def list_reports_admin(
        self, principal: Principal, *, status: ReportStatus | None = None
    ) -> list[SecurityReportAdminRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_reports_admin", None)
        if load is not None:
            return await load(status.value if status is not None else None)
        async with self._lock:
            records = [
                SecurityReportAdminRecordV4(**item.model_dump(), owner_id=owner_id)
                for owner_id, item in self._reports.values()
                if status is None or item.status is status
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    async def decide_report(
        self,
        report_id: UUID,
        decision: ReportReviewDecision,
        note: str,
        principal: Principal,
    ) -> SecurityReportAdminRecordV4:
        require_security_admin(principal)
        now = datetime.now(UTC)
        decide = getattr(self._repository, "decide_security_report", None)
        if decide is not None:
            record = await decide(report_id, decision, note, principal.user_id, now)
            if record is None:
                raise PlatformError(
                    status_code=404,
                    code=ErrorCode.NOT_FOUND,
                    message="Security report was not found.",
                    retryable=False,
                )
            return record
        async with self._lock:
            stored = self._reports.get(report_id)
            if stored is None:
                raise PlatformError(
                    status_code=404,
                    code=ErrorCode.NOT_FOUND,
                    message="Security report was not found.",
                    retryable=False,
                )
            owner_id, current = stored
            if current.status is ReportStatus.PROCESSED:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security report was already processed.",
                    retryable=False,
                )
            updated = current.model_copy(
                update={
                    "status": ReportStatus.PROCESSED,
                    "decision": decision,
                    "reviewer_id": principal.user_id,
                    "review_note": note,
                    "reviewed_at": now,
                }
            )
            self._reports[report_id] = (owner_id, updated)
            self._admin_audit.append(
                SecurityAdminAuditEventV4(
                    resource_type=SecurityAuditResourceV4.REPORT,
                    resource_id=report_id,
                    action=f"report_{decision.value}",
                    actor_id=principal.user_id,
                    note=note,
                    occurred_at=now,
                )
            )
        return SecurityReportAdminRecordV4(**updated.model_dump(), owner_id=owner_id)

    async def list_appeals_admin(
        self, principal: Principal, *, status: AppealStatus | None = None
    ) -> list[SecurityAppealAdminRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_appeals_admin", None)
        if load is not None:
            return await load(status.value if status is not None else None)
        async with self._lock:
            records = [
                SecurityAppealAdminRecordV4(**item.model_dump(), owner_id=owner_id)
                for owner_id, item in self._appeals.values()
                if status is None or item.status is status
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    async def decide_appeal(
        self,
        appeal_id: UUID,
        outcome: AppealOutcome,
        note: str,
        principal: Principal,
    ) -> SecurityAppealAdminRecordV4:
        require_security_admin(principal)
        now = datetime.now(UTC)
        decide = getattr(self._repository, "decide_security_appeal", None)
        if decide is not None:
            record = await decide(appeal_id, outcome, note, principal.user_id, now)
            if record is None:
                raise PlatformError(
                    status_code=404,
                    code=ErrorCode.NOT_FOUND,
                    message="Security appeal was not found.",
                    retryable=False,
                )
            return record
        async with self._lock:
            stored = self._appeals.get(appeal_id)
            if stored is None:
                raise PlatformError(
                    status_code=404,
                    code=ErrorCode.NOT_FOUND,
                    message="Security appeal was not found.",
                    retryable=False,
                )
            owner_id, current = stored
            if current.status is AppealStatus.RESOLVED:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security appeal was already resolved.",
                    retryable=False,
                )
            updated = current.model_copy(
                update={
                    "status": AppealStatus.RESOLVED,
                    "outcome": outcome,
                    "resolution_note": note,
                    "reviewer_id": principal.user_id,
                    "resolved_at": now,
                }
            )
            self._appeals[appeal_id] = (owner_id, updated)
            self._admin_audit.append(
                SecurityAdminAuditEventV4(
                    resource_type=SecurityAuditResourceV4.APPEAL,
                    resource_id=appeal_id,
                    action=f"appeal_{outcome.value}",
                    actor_id=principal.user_id,
                    note=note,
                    occurred_at=now,
                )
            )
        return SecurityAppealAdminRecordV4(**updated.model_dump(), owner_id=owner_id)

    async def list_admin_audit(self, principal: Principal) -> list[SecurityAdminAuditEventV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_admin_audit", None)
        if load is None:
            async with self._lock:
                return sorted(
                    (item.model_copy(deep=True) for item in self._admin_audit),
                    key=lambda item: item.occurred_at,
                    reverse=True,
                )
        return await load()

    async def _load(
        self, analysis_id: UUID
    ) -> tuple[str, SecurityScopeResponseV4, list[SecurityAnalysisEventV4]] | None:
        async with self._lock:
            record = self._records.get(analysis_id)
        if record is not None and record[1].status in {AnalysisStatus.COMPLETED, AnalysisStatus.FAILED}:
            return record
        load = getattr(self._repository, "load_security_analysis", None)
        if load is None:
            return record
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
