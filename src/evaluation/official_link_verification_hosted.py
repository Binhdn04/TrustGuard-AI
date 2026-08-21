from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

REQUIRED_HOSTED_CHECKS = frozenset(
    {
        "hosted_smoke",
        "postgres_persistence",
        "redis_worker",
        "oidc_user",
        "oidc_admin_rbac",
        "backup_restore",
        "ssrf",
        "prompt_injection",
        "provider_failure",
        "load",
        "rollback",
    }
)
REQUIRED_STAGE_SEQUENCE = ("shadow", "visible", "enforced", "visible", "off")


class HostedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostedCheck(HostedModel):
    name: str = Field(pattern=r"^[a-z0-9_]+$")
    status: Literal["passed"]
    evidence_ref: str = Field(min_length=1, max_length=500)
    reviewed_by: str = Field(min_length=1, max_length=200)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_observation_time(self) -> HostedCheck:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("hosted check observed_at must include a UTC offset")
        return self


class HostedStageObservation(HostedModel):
    stage: Literal["shadow", "visible", "enforced", "off"]
    started_at: datetime
    ended_at: datetime
    sample_count: int = Field(ge=1)
    p95_latency_ms: float = Field(ge=0, le=30_000)
    max_estimated_cost_usd: float = Field(ge=0, le=0.05)
    error_rate: float = Field(ge=0, le=1)
    evidence_ref: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_window(self) -> HostedStageObservation:
        if any(value.tzinfo is None or value.utcoffset() is None for value in (self.started_at, self.ended_at)):
            raise ValueError("hosted observation timestamps must include a UTC offset")
        if self.ended_at <= self.started_at:
            raise ValueError("hosted observation window must have positive duration")
        return self


class HostedHardCase(HostedModel):
    input_language: Literal["vi"]
    derived_query_language: Literal["en"]
    official_source_kind: Literal["social_announcement"]
    short_url_observed: Literal[True]
    third_party_form_observed: Literal[True]
    overall_status: Literal["VERIFIED"]
    resource_match_status: Literal["EXACT_RESOURCE", "EXACT_CANONICAL_URL"]
    evidence_reference_closure: Literal[True]
    fabricated_ref_count: Literal[0]
    fabricated_url_count: Literal[0]
    latency_ms: float = Field(ge=0, le=30_000)
    estimated_cost_usd: float = Field(ge=0, le=0.05)
    evidence_ref: str = Field(min_length=1, max_length=500)


class OfficialVerificationHostedEvidence(HostedModel):
    schema_version: Literal["official-link-verification-hosted-evidence-v1"]
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    environment: str = Field(min_length=1, max_length=100)
    deployment_ref: str = Field(min_length=1, max_length=500)
    collected_at: datetime
    checks: list[HostedCheck]
    stages: list[HostedStageObservation]
    hard_case: HostedHardCase

    @model_validator(mode="after")
    def validate_release_evidence(self) -> OfficialVerificationHostedEvidence:
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("hosted evidence collected_at must include a UTC offset")
        check_names = [item.name for item in self.checks]
        if len(check_names) != len(set(check_names)):
            raise ValueError("hosted checks must be unique")
        missing = REQUIRED_HOSTED_CHECKS - set(check_names)
        if missing:
            raise ValueError("hosted evidence is missing checks: " + ", ".join(sorted(missing)))
        stages = tuple(item.stage for item in self.stages)
        if stages != REQUIRED_STAGE_SEQUENCE:
            raise ValueError(f"hosted rollout sequence must be {REQUIRED_STAGE_SEQUENCE}")
        for previous, current in zip(self.stages, self.stages[1:], strict=False):
            if current.started_at < previous.ended_at:
                raise ValueError("hosted rollout observation windows must be chronological and non-overlapping")
        latest_observation = max(
            *(item.observed_at for item in self.checks),
            *(item.ended_at for item in self.stages),
        )
        if self.collected_at < latest_observation:
            raise ValueError("hosted evidence cannot be collected before its observations complete")
        return self


def load_hosted_evidence(path: str | Path) -> tuple[OfficialVerificationHostedEvidence, str]:
    source = Path(path)
    payload = source.read_bytes()
    return OfficialVerificationHostedEvidence.model_validate_json(payload), hashlib.sha256(payload).hexdigest()


def evaluate_hosted_evidence(
    evidence: OfficialVerificationHostedEvidence,
    evidence_sha256: str,
    *,
    expected_commit_sha: str,
) -> dict[str, object]:
    if re.fullmatch(r"[a-f0-9]{40}", expected_commit_sha) is None:
        raise ValueError("expected_commit_sha must be a 40-character lowercase Git SHA")
    metrics = {
        "check_count": len(evidence.checks),
        "stage_count": len(evidence.stages),
        "total_stage_samples": sum(item.sample_count for item in evidence.stages),
        "max_stage_p95_latency_ms": max(item.p95_latency_ms for item in evidence.stages),
        "max_stage_estimated_cost_usd": max(item.max_estimated_cost_usd for item in evidence.stages),
        "max_stage_error_rate": max(item.error_rate for item in evidence.stages),
        "hard_case_latency_ms": evidence.hard_case.latency_ms,
        "hard_case_estimated_cost_usd": evidence.hard_case.estimated_cost_usd,
    }
    gates = {
        "candidate_commit": evidence.commit_sha == expected_commit_sha,
        "all_required_checks_reviewed": {item.name for item in evidence.checks} >= REQUIRED_HOSTED_CHECKS,
        "rollout_and_rollback_sequence": tuple(item.stage for item in evidence.stages) == REQUIRED_STAGE_SEQUENCE,
        "stage_latency": metrics["max_stage_p95_latency_ms"] <= 30_000,
        "stage_cost": metrics["max_stage_estimated_cost_usd"] <= 0.05,
        "hard_case_grounded": evidence.hard_case.evidence_reference_closure,
        "hard_case_no_fabrication": evidence.hard_case.fabricated_ref_count
        == evidence.hard_case.fabricated_url_count
        == 0,
        "hard_case_resource_match": evidence.hard_case.resource_match_status
        in {"EXACT_RESOURCE", "EXACT_CANONICAL_URL"},
    }
    return {
        "schema_version": "official-link-verification-hosted-report-v1",
        "commit_sha": evidence.commit_sha,
        "expected_commit_sha": expected_commit_sha,
        "environment": evidence.environment,
        "deployment_ref": evidence.deployment_ref,
        "evidence_sha256": evidence_sha256,
        "collected_at": evidence.collected_at.isoformat(),
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
    }


def write_hosted_report(report: dict[str, object], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "REQUIRED_HOSTED_CHECKS",
    "REQUIRED_STAGE_SEQUENCE",
    "OfficialVerificationHostedEvidence",
    "evaluate_hosted_evidence",
    "load_hosted_evidence",
    "write_hosted_report",
]
