from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.tools import FakeBlacklistRepository
from src.core.errors import PlatformError
from src.models import (
    AdminActionStatus,
    Evidence,
    EvidenceType,
    ReviewDecision,
    ReviewedAction,
    SecurityTriageCreateRequestV4,
)
from src.services.platform_wave2 import ArtifactSigner, MemoryWave2Repository, Wave2PlatformService
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 1, 1, tzinfo=UTC)


async def _high_risk_response():
    request = SecurityTriageCreateRequestV4(
        message="Đăng nhập https://login.bad.example/verify?token=private và gửi mật khẩu ngay"
    )
    scoped = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService(blacklist=FakeBlacklistRepository()).investigate(request, scoped)
    return assess_security_risk(investigated)


def _evidence() -> list[Evidence]:
    return [
        Evidence(
            type=EvidenceType.DOMAIN_REPUTATION,
            source="fixture",
            title="reviewed_threat",
            url="https://bad.example/",
            finding="Reviewed security evidence.",
            observed_at=NOW,
        )
    ]


@pytest.mark.asyncio
async def test_v4_high_risk_producer_is_idempotent_and_privacy_minimized() -> None:
    repository = MemoryWave2Repository()
    service = Wave2PlatformService(repository, ArtifactSigner("hitl-test-signing-key"))
    response = await _high_risk_response()

    first = await service.propose_security_admin_actions(response)
    second = await service.propose_security_admin_actions(response)

    assert len(first) == 1
    assert second[0].action_id == first[0].action_id
    assert len(repository.actions) == 1
    action = first[0]
    assert action.security_analysis_id == response.analysis_id
    assert action.analysis_id is None
    assert action.target == "login.bad.example"
    assert all(item.url == "https://login.bad.example/" for item in action.evidence_snapshot)
    assert "token=private" not in action.model_dump_json()


@pytest.mark.asyncio
async def test_approved_blacklist_action_executes_and_changes_follow_up_lookup() -> None:
    sink = FakeBlacklistRepository()
    repository = MemoryWave2Repository(action_sink=sink)
    action = await repository.propose_admin_action(
        analysis_id=None,
        security_analysis_id=uuid4(),
        campaign_id=None,
        action=ReviewedAction.ADD_TO_BLACKLIST,
        target="https://Bad.Example/login?secret=removed",
        evidence=_evidence(),
    )

    receipt = await repository.decide_admin_action(
        action.action_id,
        ReviewDecision.APPROVED,
        "Reviewed evidence supports execution.",
        "security-admin",
    )

    assert receipt is not None and receipt.status is AdminActionStatus.EXECUTED
    assert await sink.contains("bad.example")
    stored = await repository.get_admin_action(action.action_id)
    assert stored is not None and stored.executed_at is not None
    audit = await repository.list_admin_action_audit(action.action_id)
    assert audit[0].execution_status is AdminActionStatus.EXECUTED
    assert audit[0].evidence_snapshot == _evidence()

    with pytest.raises(PlatformError):
        await repository.decide_admin_action(
            action.action_id,
            ReviewDecision.APPROVED,
            "Duplicate decision must not execute.",
            "security-admin",
        )
    assert len(sink.decisions) == 1


@pytest.mark.asyncio
async def test_reject_never_executes_and_unsupported_approved_action_fails_explicitly() -> None:
    sink = FakeBlacklistRepository()
    repository = MemoryWave2Repository(action_sink=sink)
    rejected = await repository.propose_admin_action(
        analysis_id=None,
        campaign_id=None,
        action=ReviewedAction.ADD_TO_BLACKLIST,
        target="reject.example",
        evidence=_evidence(),
    )
    rejected_receipt = await repository.decide_admin_action(
        rejected.action_id, ReviewDecision.REJECTED, "Evidence is insufficient.", "security-admin"
    )
    assert rejected_receipt is not None and rejected_receipt.status is AdminActionStatus.REJECTED
    assert not await sink.contains("reject.example")

    unsupported = await repository.propose_admin_action(
        analysis_id=None,
        campaign_id=None,
        action=ReviewedAction.PUBLISH_BROAD_WARNING,
        target="warning.example",
        evidence=_evidence(),
    )
    failed = await repository.decide_admin_action(
        unsupported.action_id, ReviewDecision.APPROVED, "Try publish.", "security-admin"
    )
    assert failed is not None and failed.status is AdminActionStatus.FAILED
    assert failed.execution_error == "ACTION_SINK_NOT_CONFIGURED"


@pytest.mark.asyncio
async def test_execution_failure_has_no_blacklist_side_effect_and_is_audited() -> None:
    class FailingSink:
        async def apply_decision(self, **kwargs):
            del kwargs
            raise RuntimeError("synthetic transaction rollback")

    repository = MemoryWave2Repository(action_sink=FailingSink())
    action = await repository.propose_admin_action(
        analysis_id=None,
        campaign_id=None,
        action=ReviewedAction.ADD_TO_BLACKLIST,
        target="rollback.example",
        evidence=_evidence(),
    )
    receipt = await repository.decide_admin_action(
        action.action_id, ReviewDecision.APPROVED, "Execute atomically.", "security-admin"
    )

    assert receipt is not None and receipt.status is AdminActionStatus.FAILED
    assert receipt.execution_error == "ACTION_EXECUTION_FAILED"
    assert repository.executed_blacklist == set()
    assert (await repository.list_admin_action_audit(action.action_id))[0].execution_error == (
        "ACTION_EXECUTION_FAILED"
    )


@pytest.mark.asyncio
async def test_action_proposal_rejects_non_canonical_or_non_registrable_target() -> None:
    repository = MemoryWave2Repository()
    with pytest.raises(ValueError, match="registrable domain"):
        await repository.propose_admin_action(
            analysis_id=None,
            campaign_id=None,
            action=ReviewedAction.ADD_TO_BLACKLIST,
            target="localhost",
            evidence=_evidence(),
        )
