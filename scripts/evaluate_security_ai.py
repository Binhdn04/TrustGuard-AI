"""Run the versioned WP8 AI understanding/conversation/grounding evaluation."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation.security_ai_v1 import (  # noqa: E402
    evaluate_ai_set,
    load_ai_evaluation_set,
    write_ai_report,
)


async def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="tests/eval/security_ai_v1.jsonl")
    parser.add_argument("--output", default="docs/evidence/security-ai-v1-report.json")
    args = parser.parse_args()
    report = await evaluate_ai_set(load_ai_evaluation_set(args.dataset))
    write_ai_report(report, args.output)
    print(json.dumps({"passed": report["passed"], "dataset_sha256": report["dataset_sha256"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
