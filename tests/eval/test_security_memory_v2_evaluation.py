from src.evaluation.security_memory_v2 import (
    REQUIRED_MEMORY_CATEGORIES,
    SECURITY_MEMORY_V2_EVALUATION_VERSION,
    evaluate_memory_set,
    load_memory_evaluation_set,
)

DATASET = "tests/eval/security_memory_v2_v1.jsonl"


def test_versioned_security_memory_v2_evaluation_passes() -> None:
    cases = load_memory_evaluation_set(DATASET)
    report = evaluate_memory_set(cases, dataset_path=DATASET)

    assert {case.dataset_version for case in cases} == {SECURITY_MEMORY_V2_EVALUATION_VERSION}
    assert REQUIRED_MEMORY_CATEGORIES <= {case.category for case in cases}
    assert report["dataset_sha256"]
    assert report["passed"] is True
    assert all(item["passed"] for item in report["cases"])
