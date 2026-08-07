from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest

from src.agents.nodes.risk import assess_risk
from src.agents.nodes.tools import build_verify_claims_node
from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.fact_check import normalize_claim_rating
from src.agents.tools.fakes import FakeClaimRetriever
from src.agents.tools.network import GuardedHttpClient, SsrfGuard
from src.agents.tools.providers import (
    GoogleFactCheckRetriever,
    GoogleSafeBrowsingScanner,
    map_google_fact_check_rating,
)
from src.agents.tools.rdap import RdapDomainIntelligence
from src.models import (
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisResponse,
    AnalysisStatus,
    CaseStatus,
    ClaimEvidence,
    ClaimStance,
    Evidence,
    InvestigationStep,
    ToolError,
    Verdict,
)
from src.repositories import JsonFactCheckRepository, SQLiteBlacklistRepository


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
async def test_ssrf_guard_blocks_every_non_global_dns_answer(address):
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8", address]

    with pytest.raises(UnsafeUrlError):
        await SsrfGuard(resolver=resolver).validate("https://example.com/path")


@pytest.mark.asyncio
async def test_guarded_client_revalidates_redirect_target():
    async def resolver(host: str, _port: int) -> list[str]:
        return ["8.8.8.8"] if host == "public.example" else ["127.0.0.1"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.example/admin"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        guarded = GuardedHttpClient(client, SsrfGuard(resolver=resolver))
        with pytest.raises(UnsafeUrlError):
            await guarded.get("https://public.example/")


@pytest.mark.asyncio
async def test_guarded_client_connects_to_the_validated_ip_and_preserves_host():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "93.184.216.34"
        assert request.headers["host"] == "public.example"
        assert request.extensions["sni_hostname"] == b"public.example"
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        guarded = GuardedHttpClient(client, SsrfGuard(resolver=resolver))
        response, _ = await guarded.get("https://public.example/path")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_safe_browsing_no_hit_is_inconclusive():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "secret"
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scanner = GoogleSafeBrowsingScanner("secret", client=client, guard=SsrfGuard(resolver=resolver))
        result = await scanner.scan("https://example.com/")

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.signals == ["no_known_threat_match"]


@pytest.mark.asyncio
async def test_safe_browsing_timeout_is_normalized():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scanner = GoogleSafeBrowsingScanner("secret", client=client, guard=SsrfGuard(resolver=resolver))
        with pytest.raises(ToolCallError) as caught:
            await scanner.scan("https://example.com/")

    assert caught.value.error.code == "PROVIDER_TIMEOUT"
    assert caught.value.error.retryable is True


@pytest.mark.asyncio
async def test_fact_check_provider_normalizes_reviews():
    payload = {
        "claims": [
            {
                "text": "claim",
                "claimReview": [
                    {
                        "publisher": {"name": "Verified Source"},
                        "url": "https://fact.example/review",
                        "title": "Review title",
                        "textualRating": "False",
                        "reviewDate": "2026-08-03T13:00:00Z",
                    }
                ],
            }
        ]
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        retriever = GoogleFactCheckRetriever("secret", client=client)
        results = await retriever.search("claim", limit=1)

    assert results[0].source == "Verified Source"
    assert results[0].finding == "False"
    assert results[0].stance is ClaimStance.REFUTES
    assert results[0].observed_at.tzinfo is UTC
    assert results[0].stance is ClaimStance.REFUTES


def test_unknown_fact_check_rating_is_not_inferred_from_prose():
    assert map_google_fact_check_rating("Definitely bogus according to this article") is ClaimStance.UNRATED


@pytest.mark.asyncio
async def test_rdap_normalizes_registrable_domain_redaction_and_caches():
    observed_at = datetime(2026, 8, 6, 13, tzinfo=UTC)
    requests: list[str] = []

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        requests.append(host)
        if host == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]})
        assert host == "rdap.example"
        assert request.url.path == "/domain/example.com"
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": "2026-07-26T13:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-07-26T13:00:00Z"},
                ],
                "status": ["active"],
                "remarks": [{"description": ["Registrant data redacted for privacy"]}],
                "entities": [{"vcardArray": ["vcard", [["email", {}, "text", "secret@example.com"]]]}],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RdapDomainIntelligence(
            client=client,
            guard=SsrfGuard(resolver=resolver),
            clock=lambda: observed_at,
        )
        first = await adapter.lookup("login.shop.example.com")
        second = await adapter.lookup("example.com")

    assert first == second
    assert first.domain == "example.com"
    assert first.registrar is None
    assert first.privacy_redacted is True
    assert first.signals == ["recent_registration"]
    assert requests == ["data.iana.org", "rdap.example"]


@pytest.mark.asyncio
async def test_rdap_not_found_uses_separate_ttl():
    current = datetime(2026, 8, 6, 13, tzinfo=UTC)
    rdap_calls = 0

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal rdap_calls
        if request.headers["host"] == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]})
        rdap_calls += 1
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RdapDomainIntelligence(
            client=client,
            guard=SsrfGuard(resolver=resolver),
            not_found_ttl=timedelta(minutes=5),
            clock=lambda: current,
        )
        assert (await adapter.lookup("missing.com")).signals == ["not_found"]
        assert (await adapter.lookup("missing.com")).signals == ["not_found"]

    assert rdap_calls == 1


def test_rdap_skips_ip_and_public_suffix():
    adapter = RdapDomainIntelligence()
    assert adapter.registrable_domain("127.0.0.1") is None
    assert adapter.registrable_domain("com") is None
    assert adapter.registrable_domain("a.b.example.co.uk") == "example.co.uk"


def test_fact_check_rating_mapping_does_not_infer_from_prose():
    assert normalize_claim_rating("False") is ClaimStance.REFUTES
    assert normalize_claim_rating("The review says this is false") is ClaimStance.UNRATED


@pytest.mark.asyncio
async def test_english_false_rating_affects_deterministic_score():
    evidence = ClaimEvidence(
        source="Verified Source",
        title="Review title",
        url="https://fact.example/review",
        finding="False",
        relevance=1.0,
        observed_at=datetime.now(UTC),
    )
    verify = build_verify_claims_node(FakeClaimRetriever({"false": [evidence]}, "false"))
    update = await verify(
        {
            "tool_target": "claim",
            "claims": ["claim"],
            "tool_calls_used": 0,
        }
    )

    assessment = assess_risk(update)

    assert update["evidence"][0].type.value == "fact_check"
    assert assessment["risk_score"] == 70


@pytest.mark.asyncio
async def test_blacklist_requires_audited_approval(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    with pytest.raises(PermissionError):
        await repository.add_approved("bad.example", "missing")

    await repository.record_decision(
        decision_id="decision-1",
        reviewer_id="admin-1",
        decision="approved",
        action="add_to_blacklist",
        note="Evidence reviewed",
    )
    await repository.add_approved("BÄD.example.", "decision-1")

    assert await repository.contains("xn--bd-via.example")
    entry = await repository.get("xn--bd-via.example")
    assert entry is not None
    assert entry.decision_id == "decision-1"
    assert entry.source == "approved-blacklist"
    assert entry.active is True
    await repository.close()


@pytest.mark.asyncio
async def test_blacklist_preserves_subdomain_scope(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    await repository.record_decision(
        decision_id="decision-1",
        reviewer_id="admin-1",
        decision="approved",
        action="add_to_blacklist",
        note="Evidence reviewed",
    )

    await repository.add_approved("Login.Sub.Example.COM.", "decision-1")

    assert await repository.contains("login.sub.example.com") is True
    assert await repository.contains("sub.example.com") is False
    assert await repository.contains("example.com") is False
    await repository.close()


@pytest.mark.asyncio
async def test_security_repository_persists_admin_views_atomically(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    analysis_id = uuid4()
    report_id = uuid4()
    decision_id = uuid4()
    created_at = datetime.now(UTC)
    request = AnalysisCreateRequest(message="Check https://bad.example", consent_to_scan_urls=True)
    response = AnalysisResponse(
        analysis_id=analysis_id,
        status=AnalysisStatus.QUEUED,
        created_at=created_at,
    )
    event = AnalysisEvent(
        analysis_id=analysis_id,
        status=AnalysisStatus.QUEUED,
        step="queued",
        occurred_at=created_at,
    )

    await repository.create_analysis(
        owner_id="user-1",
        request=request,
        response=response,
        event=event,
    )

    await repository.record_report(
        report_id=str(report_id),
        analysis_id=str(analysis_id),
        reporter_id="user-1",
        reason="Evidence needs another review",
        comment="Please verify the provider result.",
        created_at=created_at,
    )
    reviewed_response = response.model_copy(update={"case_status": CaseStatus.APPROVED})
    review_event = AnalysisEvent(
        analysis_id=analysis_id,
        status=AnalysisStatus.QUEUED,
        step="review_approved",
        occurred_at=created_at,
    )
    await repository.apply_review_decision(
        decision_id=str(decision_id),
        analysis_id=str(analysis_id),
        reviewer_id="admin-1",
        decision="approved",
        action="add_to_blacklist",
        note="Evidence reviewed",
        domains=["Bad.Example", "second.example"],
        response=reviewed_response,
        event=review_event,
    )

    reports = await repository.list_reports(limit=50, offset=0)
    decisions = await repository.list_decisions(limit=50, offset=0)
    blacklist = await repository.list_blacklist(query=None, limit=50, offset=0)

    assert reports[0].report_id == report_id
    assert decisions[0].analysis_id == analysis_id
    assert {entry.domain for entry in blacklist} == {"bad.example", "second.example"}
    persisted = await repository.load_analysis(str(analysis_id))
    assert persisted is not None
    assert persisted[0] == "user-1"
    assert persisted[2].status is AnalysisStatus.QUEUED
    assert persisted[2].case_status.value == "approved"

    with pytest.raises(sqlite3.IntegrityError):
        await repository.apply_decision(
            decision_id=str(decision_id),
            analysis_id=str(analysis_id),
            reviewer_id="admin-2",
            decision="approved",
            action="add_to_blacklist",
            note="Duplicate decision ID",
            domains=["must-not-be-written.example"],
        )

    blacklist_after_failure = await repository.list_blacklist(query=None, limit=50, offset=0)
    assert "must-not-be-written.example" not in {entry.domain for entry in blacklist_after_failure}
    await repository.close()


@pytest.mark.asyncio
async def test_v2_migration_persists_artifacts_dedupes_tools_and_writes_outbox(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    analysis_id = uuid4()
    created_at = datetime.now(UTC)
    request = AnalysisCreateRequest(message="Check https://bad.example", consent_to_scan_urls=True)
    queued = AnalysisResponse(analysis_id=analysis_id, status="queued", created_at=created_at)
    queued_event = AnalysisEvent(
        analysis_id=analysis_id,
        status="queued",
        step="queued",
        occurred_at=created_at,
    )
    await repository.create_analysis(owner_id="user-1", request=request, response=queued, event=queued_event)

    step = InvestigationStep(
        step_id="step-url",
        tool="url_scanner",
        target="https://bad.example",
        reason_code="url_reputation_needed",
        status="completed",
    )
    evidence = Evidence(
        type="domain_reputation",
        source="fixture-provider",
        title="Reputation",
        finding="Provider marked the URL as malicious.",
        observed_at=created_at,
    )
    error = ToolError(
        tool="domain_intelligence",
        code="PROVIDER_TIMEOUT",
        message="RDAP timed out",
        retryable=True,
    )
    completed = AnalysisResponse(
        analysis_id=analysis_id,
        status="completed",
        input_type="url",
        normalized_urls=["https://bad.example"],
        claims=[],
        investigation_plan=[step],
        risk_score=90,
        risk_level="critical",
        verdict="malicious",
        recommended_action="escalate_for_review",
        confidence=0.9,
        summary="Malicious URL.",
        reasons=["Provider evidence."],
        evidence=[evidence],
        limitations=["RDAP unavailable."],
        case_status="pending_review",
        scoring_version="risk-v2",
        created_at=created_at,
        completed_at=created_at,
    )
    completed_event = AnalysisEvent(
        analysis_id=analysis_id,
        status="completed",
        step="completed",
        occurred_at=created_at,
    )
    await repository.complete_analysis(completed, completed_event, [error])

    assert await repository.claim_tool_execution(str(analysis_id), step.step_id, step.target, "fixture-provider")
    assert not await repository.claim_tool_execution(str(analysis_id), step.step_id, step.target, "fixture-provider")
    await repository.finish_tool_execution(str(analysis_id), step.step_id, step.target, "fixture-provider", "completed")
    assert not await repository.claim_tool_execution(str(analysis_id), step.step_id, step.target, "fixture-provider")

    artifacts = await repository.load_analysis_artifacts(str(analysis_id))
    assert artifacts == {
        "investigation_plan": [step],
        "evidence": [evidence],
        "errors": [error],
    }
    executions = await repository.list_tool_executions(str(analysis_id))
    assert executions == [(step.step_id, step.target, "fixture-provider", "completed", 1)]
    outbox = await repository.list_outbox_events()
    assert {event_type for _, event_type, _ in outbox} >= {
        "analysis.queued",
        "analysis.progressed",
        "tool.execution.claimed",
        "tool.execution.finished",
    }
    await repository.close()


@pytest.mark.asyncio
async def test_v2_migration_upgrades_existing_v1_analysis_json(tmp_path):
    database = tmp_path / "legacy.db"
    analysis_id = uuid4()
    created_at = datetime.now(UTC)
    connection = sqlite3.connect(database)
    connection.execute(
        """CREATE TABLE analyses (
               analysis_id TEXT PRIMARY KEY,
               owner_id TEXT NOT NULL,
               request_json TEXT NOT NULL,
               response_json TEXT NOT NULL,
               case_status TEXT,
               created_at TEXT NOT NULL
           )"""
    )
    connection.execute(
        """INSERT INTO analyses(
               analysis_id, owner_id, request_json, response_json, case_status, created_at
           ) VALUES (?, ?, ?, ?, NULL, ?)""",
        (
            str(analysis_id),
            "user-1",
            '{"message":"legacy","consent_to_scan_urls":false}',
            (
                '{"contract_version":"v1","analysis_id":"'
                + str(analysis_id)
                + '","status":"queued","investigation_plan":[],"created_at":"'
                + created_at.isoformat()
                + '"}'
            ),
            created_at.isoformat(),
        ),
    )
    connection.commit()
    connection.close()

    repository = SQLiteBlacklistRepository(database)
    loaded = await repository.load_analysis(str(analysis_id))
    assert loaded is not None
    assert loaded[2].contract_version == "v2"
    await repository.close()


@pytest.mark.asyncio
async def test_v2_migration_quarantines_malformed_json_without_blocking_startup(tmp_path):
    database = tmp_path / "malformed.db"
    analysis_id = uuid4()
    created_at = datetime.now(UTC)
    connection = sqlite3.connect(database)
    connection.execute(
        """CREATE TABLE analyses (
               analysis_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
               request_json TEXT NOT NULL, response_json TEXT NOT NULL,
               case_status TEXT, created_at TEXT NOT NULL)"""
    )
    connection.execute(
        """INSERT INTO analyses(
               analysis_id, owner_id, request_json, response_json, case_status, created_at
           ) VALUES (?, 'user-1', ?, ?, NULL, ?)""",
        (
            str(analysis_id),
            '{"message":"legacy","consent_to_scan_urls":false}',
            "{malformed-json",
            created_at.isoformat(),
        ),
    )
    connection.commit()
    connection.close()

    repository = SQLiteBlacklistRepository(database)
    loaded = await repository.load_analysis(str(analysis_id))
    assert loaded is not None
    assert loaded[2].status is AnalysisStatus.FAILED
    assert loaded[2].contract_version == "v2"
    assert await repository.list_migration_errors() == [(str(analysis_id), "JSONDecodeError", False)]
    await repository.close()


@pytest.mark.asyncio
async def test_analysis_filters_bind_injection_shaped_values(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    analysis_id = uuid4()
    created_at = datetime.now(UTC)
    request = AnalysisCreateRequest(message="safe", consent_to_scan_urls=False)
    response = AnalysisResponse(analysis_id=analysis_id, status="queued", created_at=created_at)
    event = AnalysisEvent(
        analysis_id=analysis_id,
        status="queued",
        step="queued",
        occurred_at=created_at,
    )
    await repository.create_analysis(owner_id="user-1", request=request, response=response, event=event)

    assert len(await repository.list_analysis_responses(owner_id="user-1")) == 1
    assert await repository.list_analysis_responses(owner_id="user-1' OR 1=1 --") == []
    assert await repository.list_analysis_responses(case_status="pending_review' OR 1=1 --") == []
    assert len(await repository.list_analysis_responses()) == 1
    await repository.close()


@pytest.mark.asyncio
async def test_offline_fact_check_repository_is_ranked_and_copied():
    corpus = JsonFactCheckRepository(
        [
            ClaimEvidence(
                source="source",
                title="Cảnh báo phí mở khóa tài khoản",
                url="https://example.com/review",
                finding="Yêu cầu phí mở khóa là giả mạo",
                stance=ClaimStance.REFUTES,
                relevance=1,
                observed_at=datetime(2026, 8, 3, tzinfo=UTC),
            )
        ]
    )
    results = await corpus.search("nộp phí mở khóa tài khoản")

    assert len(results) == 1
    assert 0 < results[0].relevance <= 1
