"""Validate reviewed hosted CP10 evidence without fabricating observations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation.official_link_verification_hosted import (  # noqa: E402
    evaluate_hosted_evidence,
    load_hosted_evidence,
    write_hosted_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="Reviewed hosted observation JSON")
    parser.add_argument("--output", required=True, help="Validated hosted report JSON")
    parser.add_argument("--expected-commit", required=True, help="40-character candidate commit deployed for CP10")
    args = parser.parse_args()
    evidence, digest = load_hosted_evidence(args.evidence)
    report = evaluate_hosted_evidence(evidence, digest, expected_commit_sha=args.expected_commit)
    write_hosted_report(report, args.output)
    print(json.dumps({"passed": report["passed"], "evidence_sha256": digest}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
