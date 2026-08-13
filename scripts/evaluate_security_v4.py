"""Run the versioned deterministic Security v4 release evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.security_v4 import evaluate_set, load_evaluation_set, write_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="tests/eval/security_v4_v1.jsonl",
        help="Versioned Security v4 JSONL dataset",
    )
    parser.add_argument(
        "--output",
        default="docs/evidence/security-v4-v1-report.json",
        help="JSON report destination",
    )
    args = parser.parse_args()
    report = evaluate_set(load_evaluation_set(Path(args.dataset)))
    write_report(report, Path(args.output))
    print(json.dumps({"passed": report["passed"], "metrics": report["metrics"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
