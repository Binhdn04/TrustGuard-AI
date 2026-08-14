from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from src.agents.tools.models import (
    NormalizedToolResult,
    RedirectResolutionResult,
    ToolName,
    UrlReputationCascadeResult,
)
from src.models import DomainIntelligenceResult

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
