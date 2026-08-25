from uuid import uuid4

import pytest

from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    SecurityBlacklistDisableRequestV4,
    SecurityBlacklistLifecycleV4,
    SecurityBlacklistProposalRequestV4,
    SecurityBlacklistReviewDecisionV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService
from src.services.security_blacklist import SecurityBlacklistAdminService

ADMIN = Principal("m3-admin", UserRole.SECURITY_ADMIN)
USER = Principal("m3-user", UserRole.USER)


def _proposal(domain: str = "xn--bd-via.example") -> SecurityBlacklistProposalRequestV4:
    return SecurityBlacklistProposalRequestV4(
        canonical_domain=domain,
        reason="Reviewer confirmed credential theft evidence.",
        evidence_refs=["evidence:reviewed-domain"],
        provenance="security-report:reviewed",
        source_analysis_id=uuid4(),
        source_report_id=uuid4(),
    )


@pytest.mark.asyncio
async def test_blacklist_lifecycle_is_reviewed_idempotent_and_restart_safe(tmp_path) -> None:
    database = tmp_path / "m3-blacklist.db"
    sink = SQLiteBlacklistRepository(database)
    wave_repository = MemoryWave2Repository(action_sink=sink)
    service = SecurityBlacklistAdminService(Wave2PlatformService(wave_repository))

    request = _proposal()
    proposed = await service.propose_add(request, ADMIN)
    duplicate = await service.propose_add(request, ADMIN)
    assert duplicate.action_id == proposed.action_id
    assert await sink.get("xn--bd-via.example") is None

    approved = await service.decide(
        proposed.action_id,
        SecurityBlacklistReviewDecisionV4.APPROVED,
        "Approve after human review.",
        ADMIN,
    )
    assert approved.status.value == "executed"
    assert approved.record is not None
    assert approved.record.lifecycle is SecurityBlacklistLifecycleV4.ACTIVE
    assert await sink.get("xn--bd-via.example") is not None

    with pytest.raises(PlatformError) as active_error:
        await service.propose_add(_proposal(), ADMIN)
    assert active_error.value.status_code == 409

    disable = await service.propose_disable(
        approved.record.blacklist_id,
        SecurityBlacklistDisableRequestV4(
            reason="Domain ownership has been remediated.",
            evidence_refs=["evidence:remediation"],
            provenance="admin-review:m3",
        ),
        ADMIN,
    )
    disabled = await service.decide(
        disable.action_id,
        SecurityBlacklistReviewDecisionV4.APPROVED,
        "Disable after human review.",
        ADMIN,
    )
    assert disabled.record is not None
    assert disabled.record.lifecycle is SecurityBlacklistLifecycleV4.DISABLED
    assert await sink.get("xn--bd-via.example") is None

    restarted_repository = SQLiteBlacklistRepository(database)
    restarted = SecurityBlacklistAdminService(
        Wave2PlatformService(MemoryWave2Repository(action_sink=restarted_repository))
    )
    page = await restarted.list_records(ADMIN)
    assert page.total == 1
    assert page.items[0].lifecycle is SecurityBlacklistLifecycleV4.DISABLED
    assert len(await restarted.list_audit(page.items[0].blacklist_id, ADMIN)) == 2
    unified = await restarted_repository.list_security_admin_audit()
    assert [item.resource_type.value for item in unified].count("blacklist") == 2

    reproposed = await restarted.propose_add(_proposal(), ADMIN)
    assert reproposed.action_id not in {proposed.action_id, disable.action_id}


@pytest.mark.asyncio
async def test_blacklist_admin_surface_rejects_regular_user() -> None:
    service = SecurityBlacklistAdminService(Wave2PlatformService(MemoryWave2Repository()))
    with pytest.raises(PlatformError) as error:
        await service.list_records(USER)
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_blacklist_rejected_review_never_creates_an_active_record() -> None:
    wave = Wave2PlatformService(MemoryWave2Repository())
    service = SecurityBlacklistAdminService(wave)
    proposal = await service.propose_add(_proposal("rejected.example"), ADMIN)

    result = await service.decide(
        proposal.action_id,
        SecurityBlacklistReviewDecisionV4.REJECTED,
        "Evidence is insufficient to block this domain.",
        ADMIN,
    )

    assert result.status.value == "rejected"
    assert result.record is None
    assert (await service.list_records(ADMIN)).total == 0
    audit = await wave.list_admin_action_audit(proposal.action_id)
    assert len(audit) == 1
    assert audit[0].decision.value == "rejected"
    assert audit[0].execution_status.value == "rejected"


@pytest.mark.asyncio
async def test_blacklist_execution_failure_is_terminal_audited_and_has_no_record() -> None:
    class FailingSink:
        async def apply_decision(self, **kwargs) -> None:
            del kwargs
            raise RuntimeError("synthetic blacklist transaction rollback")

    wave = Wave2PlatformService(MemoryWave2Repository(action_sink=FailingSink()))
    service = SecurityBlacklistAdminService(wave)
    proposal = await service.propose_add(_proposal("failed.example"), ADMIN)

    result = await service.decide(
        proposal.action_id,
        SecurityBlacklistReviewDecisionV4.APPROVED,
        "Execute only if the transaction commits.",
        ADMIN,
    )

    assert result.status.value == "failed"
    assert result.execution_error == "ACTION_EXECUTION_FAILED"
    assert result.record is None
    assert (await service.list_records(ADMIN)).total == 0
    audit = await wave.list_admin_action_audit(proposal.action_id)
    assert audit[0].execution_status.value == "failed"
    assert audit[0].execution_error == "ACTION_EXECUTION_FAILED"
