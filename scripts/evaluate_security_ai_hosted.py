"""Validate collected hosted WP8 observations; this script does not fabricate hosted evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation.security_ai_hosted import (  # noqa: E402
    evaluate_hosted_ai_evidence,
    load_hosted_ai_evidence,
    write_hosted_ai_report,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, help="Collected hosted observation JSON")
    parser.add_argument("--output", required=True, help="Validated hosted evaluation report JSON")
    args = parser.parse_args()
    report = evaluate_hosted_ai_evidence(load_hosted_ai_evidence(args.evidence))
    write_hosted_ai_report(report, args.output)
    print(json.dumps({"passed": report["passed"], "evidence_sha256": report["evidence_sha256"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
