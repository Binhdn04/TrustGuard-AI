from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from src.core.auth import Principal, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AssistantGenerationModeV4,
    ErrorCode,
    SecurityAdminCopilotActionV4,
    SecurityAdminCopilotCampaignV4,
    SecurityAdminCopilotDispositionV4,
    SecurityAdminCopilotRationaleV4,
    SecurityAdminCopilotResponseV4,
    SecurityAdminCopilotUsageV4,
    SecurityCampaignReviewerStatusV4,
    SecurityRiskV4,
)
from src.security_ai import SecurityAssistantRuntime
from src.security_ai.contracts import AdminReviewDraft, AssistantOperation


class SecurityAdminCopilotService:
    """Grounded, suggestion-only assistant for the existing human review flow."""

    def __init__(self, analyses, memory, repository, model, runtime: SecurityAssistantRuntime, *, enabled: bool) -> None:
        self._analyses = analyses
        self._memory = memory
        self._repository = repository
        self._model = model
        self._runtime = runtime
        self._enabled = enabled
        self._cache: dict[UUID, tuple[str, SecurityAdminCopilotResponseV4]] = {}
        self._lock = asyncio.Lock()

    async def suggest(
        self,
        analysis_id: UUID,
        principal: Principal,
        *,
        refresh: bool = False,
    ) -> SecurityAdminCopilotResponseV4:
        require_security_admin(principal)
        if not self._enabled or self._model is None:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Security Admin Copilot is not enabled.",
                retryable=False,
            )

        case = await self._analyses.get_for_admin(analysis_id, principal)
        campaigns = [
            SecurityAdminCopilotCampaignV4(
                campaign_id=item.campaign_id,
                hypothesis=item.hypothesis,
                reviewed_at=item.reviewed_at,
                evidence_refs=item.evidence_refs,
            )
            for item in await self._memory.list_campaigns(principal)
            if item.reviewer_status is SecurityCampaignReviewerStatusV4.CONFIRMED
            and item.reviewed_at is not None
            and analysis_id in item.analysis_ids
        ][:20]
        snapshot = self._snapshot(case, campaigns)
        snapshot_hash = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()

        if not refresh:
            load = getattr(self._repository, "latest_security_admin_copilot", None)
            cached = await load(analysis_id, snapshot_hash) if load is not None else None
            if cached is None:
                async with self._lock:
                    item = self._cache.get(analysis_id)
                    cached = item[1].model_copy(deep=True) if item and item[0] == snapshot_hash else None
            if cached is not None:
                return cached

        requested_at = datetime.now(UTC)
        result = await self._runtime.invoke(
            AssistantOperation.DRAFT_ADMIN_REVIEW,
            lambda: self._model.draft_admin_review(snapshot),
            AdminReviewDraft,
        )
        allowed_refs = {item.evidence_ref for item in case.evidence}
        draft = result.output
        grounded = (
            draft is not None
            and self._is_grounded(draft, allowed_refs)
            and self._disposition_allowed(draft.proposed_disposition, case.risk)
        )
        if grounded:
            disposition = SecurityAdminCopilotDispositionV4(draft.proposed_disposition)
            action = SecurityAdminCopilotActionV4(draft.proposed_admin_action)
            # High-impact suggestions are allowed only for deterministically high-risk cases.
            if action is not SecurityAdminCopilotActionV4.NONE and case.risk not in {
                SecurityRiskV4.HIGH_RISK,
                SecurityRiskV4.MALICIOUS,
            }:
                action = SecurityAdminCopilotActionV4.NONE
            evidence_summary = draft.evidence_summary
            conflicts = draft.conflicts
            missing = draft.missing_information
            rationale = [
                SecurityAdminCopilotRationaleV4.model_validate(item.model_dump())
                for item in draft.grounded_rationale
            ]
            refs = list(dict.fromkeys(draft.evidence_refs))
            mode = AssistantGenerationModeV4.AI
        else:
            disposition, action, evidence_summary, conflicts, missing, rationale, refs = self._fallback(case)
            mode = AssistantGenerationModeV4.TEMPLATE_FALLBACK

        completed_at = datetime.now(UTC)
        suggestion = SecurityAdminCopilotResponseV4(
            analysis_id=analysis_id,
            evidence_summary=evidence_summary,
            conflicts=conflicts,
            missing_information=missing,
            related_reviewed_campaigns=campaigns,
            proposed_disposition=disposition,
            proposed_admin_action=action,
            action_executable=action is SecurityAdminCopilotActionV4.ADD_TO_BLACKLIST,
            grounded_rationale=rationale,
            evidence_refs=refs,
            provider=result.provider,
            model=result.model,
            generation_mode=mode,
            usage=SecurityAdminCopilotUsageV4(
                input_tokens=self._runtime.budget.input_tokens,
                output_tokens=self._runtime.budget.output_tokens,
                cost_usd=self._runtime.budget.cost_usd,
                status="ok" if grounded else "fallback",
            ),
            generated_at=completed_at,
        )
        save = getattr(self._repository, "save_security_admin_copilot", None)
        if save is not None:
            await save(suggestion, snapshot_hash, principal.user_id, requested_at, completed_at)
        else:
            async with self._lock:
                self._cache[analysis_id] = (snapshot_hash, suggestion.model_copy(deep=True))
        return suggestion

    @staticmethod
    def _snapshot(case, campaigns: list[SecurityAdminCopilotCampaignV4]) -> dict:
        context = case.security_context
        return {
            "analysis_id": str(case.analysis_id),
            "scope_decision": case.scope_decision.value,
            "risk": case.risk.value if case.risk else None,
            "score": case.score,
            "confidence": case.confidence,
            "threat_type": case.threat_type.value if case.threat_type else None,
            "context": {
                "scenario": context.scenario.value,
                "requested_action": context.requested_action.value if context.requested_action else None,
                "potential_threat": context.potential_threat.value,
                "signals": {
                    "urgency": context.urgency,
                    "credential_request": context.credential_request,
                    "otp_request": context.otp_request,
                    "payment_request": context.payment_request,
                    "personal_information_request": context.personal_information_request,
                },
            } if context else None,
            "evidence": [
                {
                    "evidence_ref": item.evidence_ref,
                    "type": item.type.value,
                    "signal": item.signal,
                    "description": item.description,
                    "confidence": item.confidence,
                    "provenance_ref": item.provenance_ref,
                }
                for item in case.evidence
            ],
            "limitations": case.limitations,
            "related_reviewed_campaigns": [item.model_dump(mode="json") for item in campaigns],
            "allowed_dispositions": [item.value for item in SecurityAdminCopilotDispositionV4],
            "allowed_admin_actions": [item.value for item in SecurityAdminCopilotActionV4],
        }

    @staticmethod
    def _is_grounded(draft: AdminReviewDraft, allowed_refs: set[str]) -> bool:
        cited = [*draft.evidence_refs, *(ref for reason in draft.grounded_rationale for ref in reason.evidence_refs)]
        return (
            bool(draft.evidence_refs)
            and bool(draft.grounded_rationale)
            and set(cited).issubset(allowed_refs)
        )

    @staticmethod
    def _disposition_allowed(disposition: str, risk: SecurityRiskV4 | None) -> bool:
        allowed = {
            SecurityRiskV4.HIGH_RISK: {"confirm_malicious", "needs_more_information", "no_change"},
            SecurityRiskV4.MALICIOUS: {"confirm_malicious", "needs_more_information", "no_change"},
            SecurityRiskV4.SAFE: {"confirm_safe", "mark_false_positive", "no_change"},
            SecurityRiskV4.INSUFFICIENT_EVIDENCE: {"needs_more_information", "no_change"},
            SecurityRiskV4.LOW_RISK: {"needs_more_information", "no_change"},
            SecurityRiskV4.SUSPICIOUS: {"needs_more_information", "no_change"},
        }
        return disposition in allowed.get(risk, {"needs_more_information", "no_change"})

    @staticmethod
    def _fallback(case):
        refs = [item.evidence_ref for item in case.evidence[:5]]
        if case.risk in {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}:
            disposition = SecurityAdminCopilotDispositionV4.CONFIRM_MALICIOUS
        elif case.risk is SecurityRiskV4.SAFE:
            disposition = SecurityAdminCopilotDispositionV4.CONFIRM_SAFE
        elif case.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE:
            disposition = SecurityAdminCopilotDispositionV4.NEEDS_MORE_INFORMATION
        else:
            disposition = SecurityAdminCopilotDispositionV4.NO_CHANGE
        rationale = (
            [SecurityAdminCopilotRationaleV4(text="Review the deterministic case evidence before deciding.", evidence_refs=[refs[0]])]
            if refs else []
        )
        return (
            disposition,
            SecurityAdminCopilotActionV4.NONE,
            f"Deterministic case result: {case.risk.value if case.risk else 'not assessed'}.",
            [],
            list(case.limitations[:20]),
            rationale,
            refs,
        )


__all__ = ["SecurityAdminCopilotService"]
