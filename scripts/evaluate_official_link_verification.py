"""Run the immutable security-v4-v2 official-link release evaluation."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation.official_link_verification import (  # noqa: E402
    evaluate_set,
    load_evaluation_set,
    write_report,
)


async def _run(dataset: str, output: str) -> int:
    cases = load_evaluation_set(dataset)
    report = await evaluate_set(cases, dataset_path=dataset)
    write_report(report, output)
    print(json.dumps({"passed": report["passed"], "metrics": report["metrics"]}, indent=2))
    return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="tests/eval/security_v4_v2.jsonl")
    parser.add_argument("--output", default="eval/results/security-v4-v2-report.json")
    args = parser.parse_args()
    return asyncio.run(_run(args.dataset, args.output))


if __name__ == "__main__":
    raise SystemExit(main())
