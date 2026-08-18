"""Fail closed unless WP8 evaluation and sequential feature-flag gates are satisfied."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import Settings  # noqa: E402
from src.evaluation.security_ai_rollout import (  # noqa: E402
    SecurityAIRolloutStage,
    evaluate_rollout_readiness,
    load_evaluation_report,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-stage", choices=[item.value for item in SecurityAIRolloutStage], required=True)
    parser.add_argument("--deterministic-report", default="docs/evidence/security-v4-v1-report.json")
    parser.add_argument("--ai-report", default="docs/evidence/security-ai-v1-report.json")
    parser.add_argument("--memory-report", default="docs/evidence/security-memory-v2-v1-report.json")
    parser.add_argument("--hosted-report")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = evaluate_rollout_readiness(
        Settings(),
        SecurityAIRolloutStage(args.target_stage),
        deterministic_report=load_evaluation_report(args.deterministic_report),
        ai_report=load_evaluation_report(args.ai_report),
        memory_report=load_evaluation_report(args.memory_report),
        hosted_report=load_evaluation_report(args.hosted_report),
    )
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
