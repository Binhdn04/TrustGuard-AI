from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.tools.models import (
    NormalizedToolResult,
    RedirectResolutionResult,
    ToolName,
    UrlReputationCascadeResult,
)
from src.models import (
    DomainIntelligenceResult,
    PotentialThreatV4,
    ScopeDecisionV4,
    SecurityConsentV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityRiskV4,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


class FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolPolicyFixture(FixtureModel):
    consent_to_scan_urls: bool
    requested_tools: list[ToolName]
    allowed_tools: list[ToolName]

    @model_validator(mode="after")
    def enforce_consent(self) -> ToolPolicyFixture:
        if not set(self.allowed_tools) <= set(self.requested_tools):
            raise ValueError("allowed tools must be requested")
        if not self.consent_to_scan_urls and self.allowed_tools:
            raise ValueError("external tools require consent")
        return self


class ChromeExtensionCaptureFixture(FixtureModel):
    kind: Literal["selection", "link"]
    value: str = Field(min_length=1, max_length=5000)

    @model_validator(mode="after")
    def validate_link_capture(self) -> ChromeExtensionCaptureFixture:
        if self.kind == "link":
            parsed = urlsplit(self.value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("link capture must be an absolute HTTP(S) URL")
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("link capture cannot contain credentials or a fragment")
        return self


class ChromeExtensionPlanStepFixture(FixtureModel):
    tool: SecurityInvestigationToolV4
    status: SecurityInvestigationStepStatusV4
    target: str = Field(min_length=1)


class ChromeExtensionProviderCallFixture(FixtureModel):
    tool: Literal["blacklist_lookup", "dns", "redirect_resolver", "url_reputation", "rdap"]
    target: str = Field(min_length=1)
    high_risk: bool | None = None


class ChromeExtensionBaselineFixture(FixtureModel):
    scope_decision: ScopeDecisionV4
    threat_type: PotentialThreatV4 | None = None
    risk: SecurityRiskV4 | None = None
    planned_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    planned_provider_calls: int = Field(default=0, ge=0)
    plan: list[ChromeExtensionPlanStepFixture] = Field(default_factory=list)
    provider_trace: list[ChromeExtensionProviderCallFixture] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_final_projection(self) -> ChromeExtensionBaselineFixture:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.threat_type is None or self.risk is None:
                raise ValueError("in-scope extension baseline requires threat_type and risk")
        elif (
            self.threat_type is not None
            or self.risk is not None
            or self.planned_tools
            or self.planned_provider_calls
            or self.plan
            or self.provider_trace
        ):
            raise ValueError("terminal extension baseline cannot contain investigation output")
        return self


class ChromeExtensionPhase0Case(FixtureModel):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: Literal[
        "in_scope",
        "out_of_scope",
        "need_more_info",
        "no_consent",
        "provider_error",
        "provider_no_hit",
    ]
    capture: ChromeExtensionCaptureFixture
    consent: SecurityConsentV4
    fixture_evidence: list[dict[str, Any]] = Field(default_factory=list)
    fixture_error: str | None = None
    expected: ChromeExtensionBaselineFixture


class ChromeExtensionPhase0FixtureSet(FixtureModel):
    schema_version: Literal["chrome-extension-phase0-v1"]
    cases: list[ChromeExtensionPhase0Case] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_coverage(self) -> ChromeExtensionPhase0FixtureSet:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("chrome extension phase 0 case IDs must be unique")
        required = {
            "in_scope",
            "out_of_scope",
            "need_more_info",
            "no_consent",
            "provider_error",
            "provider_no_hit",
        }
        categories = {case.category for case in self.cases}
        if missing := required - categories:
            raise ValueError("chrome extension phase 0 fixtures are missing: " + ", ".join(sorted(missing)))
        if {case.capture.kind for case in self.cases} != {"selection", "link"}:
            raise ValueError("chrome extension phase 0 fixtures must cover selection and link capture")
        return self


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"fixture file must contain an object: {path}")
    return payload


def load_tool_policy_responses() -> dict[str, ToolPolicyFixture]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "tool_policy.json")
    return {key: ToolPolicyFixture.model_validate(value) for key, value in payload.items()}


def load_url_reputation_v3_responses() -> dict[str, NormalizedToolResult[UrlReputationCascadeResult]]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "url_reputation_v3.json")
    model = NormalizedToolResult[UrlReputationCascadeResult]
    return {key: model.model_validate(value) for key, value in payload.items()}


def load_redirect_resolver_responses() -> dict[str, NormalizedToolResult[RedirectResolutionResult]]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "redirect_resolver.json")
    model = NormalizedToolResult[RedirectResolutionResult]
    return {key: model.model_validate(value) for key, value in payload.items()}


def load_rdap_v3_responses() -> dict[str, NormalizedToolResult[DomainIntelligenceResult]]:
    payload = _load_json(FIXTURE_ROOT / "tool_responses" / "rdap_v3.json")
    model = NormalizedToolResult[DomainIntelligenceResult]
    return {key: model.model_validate(value) for key, value in payload.items()}


def load_chrome_extension_phase0_fixtures() -> ChromeExtensionPhase0FixtureSet:
    payload = _load_json(FIXTURE_ROOT / "chrome_extension" / "phase0_cases.json")
    return ChromeExtensionPhase0FixtureSet.model_validate(payload)
