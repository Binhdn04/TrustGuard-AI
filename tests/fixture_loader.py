from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.models import (
    CaseStatus,
    ClaimEvidence,
    DomainIntelligenceResult,
    EvidenceType,
    InputType,
    RecommendedAction,
    RiskLevel,
    ToolError,
    UrlScanResult,
    Verdict,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


class FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FixtureRequest(FixtureModel):
    # Empty is allowed here because empty_message_001 is a negative API fixture.
    message: str = Field(max_length=5000)
    consent_to_scan_urls: bool


class FixtureMocks(FixtureModel):
    url_scanner: str | None = None
    claim_retriever: str | None = None
    blacklist: str | None = None
    domain_intelligence: str | None = None


class FixtureExpected(FixtureModel):
    input_type: InputType | None = None
    verdict: Verdict | None = None
    risk_level: RiskLevel | None = None
    risk_score_min: int | None = Field(default=None, ge=0, le=100)
    risk_score_max: int | None = Field(default=None, ge=0, le=100)
    recommended_action: RecommendedAction | None = None
    case_status: CaseStatus | None = None
    required_evidence_types: list[EvidenceType] = Field(default_factory=list)
    required_limitation: bool = False
    external_url_scan_allowed: bool | None = None
    ssrf_blocked: bool | None = None
    http_status: int | None = None
    blacklist_write: bool | None = None

    @model_validator(mode="after")
    def valid_score_range(self) -> FixtureExpected:
        if (
            self.risk_score_min is not None
            and self.risk_score_max is not None
            and self.risk_score_min > self.risk_score_max
        ):
            raise ValueError("risk_score_min must not exceed risk_score_max")
        return self


class AnalysisFixture(FixtureModel):
    id: str
    request: FixtureRequest
    mocks: FixtureMocks
    expected: FixtureExpected


class UrlScannerFixtureResponse(FixtureModel):
    result: UrlScanResult | None = None
    error: ToolError | None = None

    @model_validator(mode="after")
    def exactly_one_outcome(self) -> UrlScannerFixtureResponse:
        if (self.result is None) == (self.error is None):
            raise ValueError("fixture response requires exactly one of result or error")
        return self


class ClaimRetrieverFixtureResponse(FixtureModel):
    results: list[ClaimEvidence] | None = None
    error: ToolError | None = None

    @model_validator(mode="after")
    def exactly_one_outcome(self) -> ClaimRetrieverFixtureResponse:
        if (self.results is None) == (self.error is None):
            raise ValueError("fixture response requires exactly one of results or error")
        return self


class BlacklistFixtureResponse(FixtureModel):
    domains: list[str]


class DomainIntelligenceFixtureResponse(FixtureModel):
    result: DomainIntelligenceResult | None = None
    error: ToolError | None = None

    @model_validator(mode="after")
    def exactly_one_outcome(self) -> DomainIntelligenceFixtureResponse:
        if (self.result is None) == (self.error is None):
            raise ValueError("fixture response requires exactly one of result or error")
        return self


def load_analyses(path: Path = FIXTURE_ROOT / "analyses.jsonl") -> list[AnalysisFixture]:
    fixtures: list[AnalysisFixture] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                fixtures.append(AnalysisFixture.model_validate_json(line))
            except ValueError as exc:
                raise ValueError(f"invalid fixture at {path}:{line_number}") from exc
    return fixtures


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"fixture file must contain an object: {path}")
    return payload


def load_url_scanner_responses() -> dict[str, UrlScannerFixtureResponse]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "url_scanner.json")
    return {key: UrlScannerFixtureResponse.model_validate(value) for key, value in payload.items()}


def load_claim_retriever_responses() -> dict[str, ClaimRetrieverFixtureResponse]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "claim_retriever.json")
    return {key: ClaimRetrieverFixtureResponse.model_validate(value) for key, value in payload.items()}


def load_blacklist_responses() -> dict[str, BlacklistFixtureResponse]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "blacklist.json")
    return {key: BlacklistFixtureResponse.model_validate(value) for key, value in payload.items()}


def load_domain_intelligence_responses() -> dict[str, DomainIntelligenceFixtureResponse]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "domain_intelligence.json")
    return {key: DomainIntelligenceFixtureResponse.model_validate(value) for key, value in payload.items()}
