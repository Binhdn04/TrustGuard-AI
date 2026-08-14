from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from src.agents.security_risk import assess_security_risk
from src.models import (
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_triage import SecurityTriageScopeService

SECURITY_MEMORY_V2_EVALUATION_VERSION = "security-memory-v2-eval-v1"
REQUIRED_MEMORY_CATEGORIES = frozenset(
    {"malicious_match", "false_positive", "strong_override", "target_isolation", "v1_fallback"}
)
OBSERVED_AT = datetime(2026, 8, 15, tzinfo=UTC)


class MemoryEvaluationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: SecurityEvidenceTypeV4
    signal: str = Field(min_length=1)
    target: str | None = None


class MemoryEvaluationExpected(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk: SecurityRiskV4
    score: int = Field(ge=0, le=100)
    policy_version: str


class SecurityMemoryEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_version: str
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: str
    memory_enabled: bool
    evidence: list[MemoryEvaluationEvidence]
    expected: MemoryEvaluationExpected


def load_memory_evaluation_set(path: str | Path) -> list[SecurityMemoryEvaluationCase]:
    source = Path(path)
    cases = [
        SecurityMemoryEvaluationCase.model_validate_json(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("memory evaluation requires unique non-empty cases")
    if {case.dataset_version for case in cases} != {SECURITY_MEMORY_V2_EVALUATION_VERSION}:
        raise ValueError("unexpected Security Memory evaluation version")
    missing = REQUIRED_MEMORY_CATEGORIES - {case.category for case in cases}
    if missing:
        raise ValueError("Security Memory evaluation is missing categories: " + ", ".join(sorted(missing)))
    return cases


def _evidence_ref(case_id: str, index: int) -> str:
    return "evidence:" + hashlib.sha256(f"{case_id}\0{index}".encode()).hexdigest()[:16]


def evaluate_memory_case(case: SecurityMemoryEvaluationCase) -> dict[str, object]:
    request = SecurityTriageCreateRequestV4(message="Website này có đáng tin không https://reviewed.example/")
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.security_context is not None
    evidence = [
        SecurityEvidenceV4(
            evidence_ref=_evidence_ref(case.id, index),
            type=item.type,
            source="security-memory-v2-evaluation",
            target=item.target,
            signal=item.signal,
            description=f"Versioned WP6 evaluation fixture: {item.signal}.",
            observed_at=OBSERVED_AT,
            provenance_ref=f"dataset:{case.dataset_version}:{case.id}",
        )
        for index, item in enumerate(case.evidence)
    ]
    staged = scoped.model_copy(
        update={
            "next_step": "RISK_ASSESSMENT",
            "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
            "evidence": evidence,
        }
    )
    result = assess_security_risk(staged, memory_enabled=case.memory_enabled)
    passed = (
        result.risk is case.expected.risk
        and result.score == case.expected.score
        and result.policy_version == case.expected.policy_version
    )
    return {
        "id": case.id,
        "category": case.category,
        "risk": result.risk.value if result.risk else None,
        "score": result.score,
        "policy_version": result.policy_version,
        "passed": passed,
    }


def evaluate_memory_set(cases: list[SecurityMemoryEvaluationCase], *, dataset_path: str | Path) -> dict[str, object]:
    results = [evaluate_memory_case(case) for case in cases]
    content = Path(dataset_path).read_bytes()
    return {
        "evaluation_version": SECURITY_MEMORY_V2_EVALUATION_VERSION,
        "dataset_sha256": hashlib.sha256(content).hexdigest(),
        "passed": all(bool(item["passed"]) for item in results),
        "cases": results,
    }


def write_memory_report(report: dict[str, object], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "REQUIRED_MEMORY_CATEGORIES",
    "SECURITY_MEMORY_V2_EVALUATION_VERSION",
    "evaluate_memory_case",
    "evaluate_memory_set",
    "load_memory_evaluation_set",
    "write_memory_report",
]
