"""Run the versioned deterministic reviewed Security Memory evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.security_memory_v2 import (  # noqa: E402
    evaluate_memory_set,
    load_memory_evaluation_set,
    write_memory_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="tests/eval/security_memory_v2_v1.jsonl")
    parser.add_argument("--output", default="docs/evidence/security-memory-v2-v1-report.json")
    args = parser.parse_args()
    cases = load_memory_evaluation_set(args.dataset)
    report = evaluate_memory_set(cases, dataset_path=args.dataset)
    write_memory_report(report, args.output)
    print(json.dumps({"passed": report["passed"], "dataset_sha256": report["dataset_sha256"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
