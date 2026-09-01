"""Sync, run, and diagnose the Security Triage Langfuse evaluation dataset."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Make the evaluation CLI convenient for local use without changing the
# environment supplied by CI or a deployment platform.
load_dotenv(ROOT / ".env", override=False)

from src.evaluation.security_langfuse import (  # noqa: E402
    DEFAULT_LANGFUSE_DATASET,
    MetricResult,
    MetricStatus,
    SecurityAction,
    TraceOutput,
    build_report,
    dataset_sha256,
    evaluate_case,
    is_permissive_action,
    load_security_evaluation_set,
    to_langfuse_item,
    write_report,
)

DEFAULT_DATASET_PATH = "eval/test_cases.jsonl"
DEFAULT_REPORT_PATH = "eval/results/security-langfuse-report.json"


class JudgeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_completion: float = Field(ge=0, le=1)
    contextual_precision: float = Field(ge=0, le=1)
    faithfulness: float = Field(ge=0, le=1)
    failure_code: str = Field(pattern=r"^[a-z0-9_]+$")
    rationale: str = Field(min_length=1, max_length=1000)


class HumanJudgeScores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_completion: float = Field(ge=0, le=1)
    contextual_precision: float = Field(ge=0, le=1)
    faithfulness: float = Field(ge=0, le=1)


class JudgeCalibrationAnnotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    output: dict[str, Any]
    human_scores: HumanJudgeScores


def _client():
    from langfuse import Langfuse

    public_key = os.getenv("LANGFUSE_PUBLIC_KEY", "").strip()
    secret_key = os.getenv("LANGFUSE_SECRET_KEY", "").strip()
    base_url = os.getenv("LANGFUSE_BASE_URL", os.getenv("LANGFUSE_HOST", "")).strip()
    if not public_key or not secret_key or not base_url:
        raise RuntimeError("set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, and LANGFUSE_BASE_URL")
    return Langfuse(public_key=public_key, secret_key=secret_key, base_url=base_url)


def _git_sha() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or "unknown"


def sync_dataset(args: argparse.Namespace) -> int:
    cases = load_security_evaluation_set(args.dataset)
    client = _client()
    digest = dataset_sha256(cases)
    page_number = 1
    exists = False
    while True:
        page = client.api.datasets.list(page=page_number, limit=100)
        exists = any(item.name == args.langfuse_dataset for item in page.data)
        if exists or len(page.data) < 100:
            break
        page_number += 1
    if not exists:
        client.create_dataset(
            name=args.langfuse_dataset,
            description="TrustGuard Security v4 triage evaluation; synthetic Vietnamese cases.",
            metadata={"dataset_version": cases[0].dataset_version, "sha256": digest, "case_count": len(cases)},
            input_schema=type(cases[0].input).model_json_schema(),
            expected_output_schema=type(cases[0].expected_output).model_json_schema(),
        )
    for case in cases:
        item = to_langfuse_item(case)
        client.create_dataset_item(
            dataset_name=args.langfuse_dataset,
            id=str(uuid5(NAMESPACE_URL, f"{args.langfuse_dataset}:{case.id}")),
            **item,
        )
    client.flush()
    print(json.dumps({"dataset": args.langfuse_dataset, "cases": len(cases), "sha256": digest}))
    return 0


def _output_from_api(payload: dict[str, Any], *, latency_ms: float) -> dict[str, Any]:
    response = payload.get("assistant_response")
    plan = payload.get("investigation_plan") or []
    tools = [
        step.get("tool")
        for step in plan
        if isinstance(step, dict) and step.get("tool") and str(step.get("status", "")).casefold() in {"completed", "failed"}
    ]
    return {
        "status": payload.get("status"),
        "scope": payload.get("scope_decision"),
        "risk": payload.get("risk"),
        "threat_type": payload.get("threat_type"),
        "recommended_actions": payload.get("recommended_actions", []),
        "tools_called": tools,
        "tool_calls_used": payload.get("tool_calls_used", 0),
        "evidence_refs": [item.get("evidence_ref") for item in payload.get("evidence", []) if item.get("evidence_ref")],
        "explanation_evidence_refs": payload.get("explanation_evidence_refs", []),
        "errors": payload.get("errors", []),
        "assistant_response": response,
        "boundary_message": payload.get("boundary_message"),
        "follow_up_question": payload.get("follow_up_question"),
        "latency_ms": round(latency_ms, 3),
    }


def _deterministic_evaluator(*, output, expected_output, metadata, **_kwargs):
    from langfuse import Evaluation

    case_id = str((metadata or {}).get("case_id", "unknown"))
    case_payload = {
        "dataset_version": (metadata or {}).get("dataset_version"),
        "id": case_id,
        "input": _kwargs.get("input"),
        "expected_output": expected_output,
        "metadata": {key: value for key, value in (metadata or {}).items() if key not in {"case_id", "dataset_version"}},
    }
    from src.evaluation.security_langfuse import SecurityEvaluationCase

    case = SecurityEvaluationCase.model_validate(case_payload)
    evaluated = evaluate_case(case, TraceOutput.model_validate(output))
    scores = []
    for metric in evaluated.metrics:
        if metric.status is MetricStatus.SCORED and metric.value is not None:
            scores.append(
                Evaluation(
                    name=metric.name.replace("_", "-"),
                    value=metric.value,
                    comment=metric.reason,
                    metadata={"failure_codes": metric.failure_codes, **metric.details},
                )
            )
    expected_positive = case.expected_output.security_action is SecurityAction.DO_NOT_PROCEED
    # For context-and-URL triage, a false negative is an unsafe authorization to
    # proceed, not a cautious response that withholds authorization while the
    # sender/action remains unverified.
    actual_permissive = is_permissive_action(evaluated.actual_action)
    if case.expected_output.security_action is not SecurityAction.NEEDS_MORE_INFO:
        scores.extend(
            [
                Evaluation(name="security-is-fp", value=int(not expected_positive and not actual_permissive)),
                Evaluation(name="security-is-fn", value=int(expected_positive and actual_permissive)),
                Evaluation(name="security-is-tp", value=int(expected_positive and not actual_permissive)),
                Evaluation(name="security-is-tn", value=int(not expected_positive and actual_permissive)),
            ]
        )
    return scores


def _judge_evaluator(model_name: str):
    from langchain_openai import ChatOpenAI
    from langfuse import Evaluation

    model = ChatOpenAI(model=model_name, temperature=0).with_structured_output(JudgeResult)

    async def evaluate(*, input, output, expected_output, metadata, **_kwargs):
        judged = await _invoke_judge(
            model,
            input=input,
            output=output,
            expected_output=expected_output,
            metadata=metadata,
        )
        common = {"judge_model": model_name, "rubric_version": "security-judge-v1", "failure_code": judged.failure_code}
        return [
            Evaluation(name="judge-task-completion", value=judged.task_completion, comment=judged.rationale, metadata=common),
            Evaluation(name="judge-contextual-precision", value=judged.contextual_precision, comment=judged.rationale, metadata=common),
            Evaluation(name="judge-faithfulness", value=judged.faithfulness, comment=judged.rationale, metadata=common),
        ]

    return evaluate


async def _invoke_judge(model, *, input, output, expected_output, metadata) -> JudgeResult:
    prompt = {
        "role": "security evaluation judge",
        "rubric_version": "security-judge-v1",
        "instructions": [
            "Score only the user-visible answer against the supplied expected policy and evidence inventory.",
            "Task completion: required security guidance and next steps are present.",
            "Contextual precision: cited reasons are relevant to this message and avoid irrelevant generic warnings.",
            "Faithfulness: claims and actions are supported by recorded evidence/policy; no invented facts.",
            "Return conservative 0..1 scores and one observable failure code; do not infer hidden reasoning.",
        ],
        "input": input,
        "expected_policy": expected_output,
        "actual": output,
        "case_metadata": metadata,
    }
    judged = await model.ainvoke(json.dumps(prompt, ensure_ascii=False))
    return judged if isinstance(judged, JudgeResult) else JudgeResult.model_validate(judged)


def calibrate_judge(args: argparse.Namespace) -> int:
    from langchain_openai import ChatOpenAI

    if not 0 <= args.tolerance <= 1:
        raise ValueError("--tolerance must be between 0 and 1")
    cases = {case.id: case for case in load_security_evaluation_set(args.dataset)}
    annotations = [
        JudgeCalibrationAnnotation.model_validate_json(line)
        for line in Path(args.annotations).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not annotations or len({item.case_id for item in annotations}) != len(annotations):
        raise ValueError("judge calibration annotations must be non-empty with unique case IDs")
    if unknown := sorted({item.case_id for item in annotations} - cases.keys()):
        raise ValueError(f"unknown calibration case IDs: {unknown}")
    if non_dev := sorted(item.case_id for item in annotations if cases[item.case_id].metadata.split.value != "dev"):
        raise ValueError(f"judge calibration accepts dev cases only: {non_dev}")
    model = ChatOpenAI(model=args.judge_model, temperature=0).with_structured_output(JudgeResult)

    async def run_all():
        rows = []
        for annotation in annotations:
            case = cases[annotation.case_id]
            item = to_langfuse_item(case)
            judged = await _invoke_judge(
                model,
                input=item["input"],
                output=annotation.output,
                expected_output=item["expected_output"],
                metadata=item["metadata"],
            )
            rows.append((annotation, judged))
        return rows

    rows = asyncio.run(run_all())
    metric_names = ("task_completion", "contextual_precision", "faithfulness")
    metrics = {}
    disagreements = []
    for name in metric_names:
        deltas = [abs(getattr(annotation.human_scores, name) - getattr(judged, name)) for annotation, judged in rows]
        metrics[name] = {
            "mean_absolute_error": round(sum(deltas) / len(deltas), 4),
            "agreement_within_tolerance": round(sum(delta <= args.tolerance for delta in deltas) / len(deltas), 4),
        }
        disagreements.extend(
            {
                "case_id": annotation.case_id,
                "metric": name,
                "human": getattr(annotation.human_scores, name),
                "judge": getattr(judged, name),
                "delta": round(delta, 4),
                "failure_code": judged.failure_code,
                "rationale": judged.rationale,
            }
            for (annotation, judged), delta in zip(rows, deltas, strict=True)
            if delta > args.tolerance
        )
    report = {
        "calibration_version": "security-judge-calibration-v1",
        "dataset_version": "security-triage-langfuse-v1",
        "dataset_sha256": dataset_sha256(list(cases.values())),
        "judge_model": args.judge_model,
        "rubric_version": "security-judge-v1",
        "sample_count": len(rows),
        "tolerance": args.tolerance,
        "metrics": metrics,
        "disagreements": disagreements,
        "generated_at": datetime.now(UTC).isoformat(),
    }
    write_report(report, args.output)
    print(json.dumps({"samples": len(rows), "disagreements": len(disagreements), "output": args.output}))
    return 0


def _run_aggregate_evaluator(*, item_results, **_kwargs):
    from langfuse import Evaluation

    names = [
        "security-decision-accuracy",
        "task-completion",
        "tool-correctness",
        "tool-efficiency",
        "faithfulness",
        "judge-task-completion",
        "judge-contextual-precision",
        "judge-faithfulness",
    ]
    evaluations = []
    for name in names:
        values = [float(score.value) for item in item_results for score in item.evaluations if score.name == name]
        if values:
            evaluations.append(Evaluation(name=f"mean-{name}", value=sum(values) / len(values)))
    cells = {
        name: sum(int(score.value) for item in item_results for score in item.evaluations if score.name == name)
        for name in ("security-is-tp", "security-is-fp", "security-is-fn", "security-is-tn")
    }
    fp_denominator = cells["security-is-fp"] + cells["security-is-tn"]
    fn_denominator = cells["security-is-fn"] + cells["security-is-tp"]
    if fp_denominator:
        evaluations.append(
            Evaluation(name="unnecessary-block-rate", value=cells["security-is-fp"] / fp_denominator, metadata=cells)
        )
    if fn_denominator:
        evaluations.append(
            Evaluation(name="unsafe-permissive-escape-rate", value=cells["security-is-fn"] / fn_denominator, metadata=cells)
        )
    return evaluations


def run_experiment(args: argparse.Namespace) -> int:
    consented_token = os.getenv(args.consented_token_env, "").strip()
    no_consent_token = os.getenv(args.no_consent_token_env, "").strip()
    if not consented_token or not no_consent_token:
        raise RuntimeError(
            f"set {args.consented_token_env} and {args.no_consent_token_env} to test-user bearer tokens whose "
            "account lookup preferences are respectively granted and denied; do not pass tokens on the command line"
        )
    client = _client()
    dataset = client.get_dataset(args.langfuse_dataset)

    async def task(*, item, **_kwargs):
        started = perf_counter()
        consent = item.input.get("consent", {})
        lookup_granted = bool(consent.get("external_url_lookup") or consent.get("official_source_lookup"))
        token = consented_token if lookup_granted else no_consent_token
        headers = {"Authorization": f"Bearer {token}", "X-Evaluation-Case-Id": item.metadata["case_id"]}
        request_payload = {
            "message": item.input["message"],
            "consent": item.input.get("consent", {}),
            "execution_mode": item.input.get("execution_mode", "inline"),
        }
        async with httpx.AsyncClient(base_url=args.api_base_url, timeout=args.timeout) as http:
            response = await http.post("/api/v4/analyses", json=request_payload, headers=headers)
        response.raise_for_status()
        return _output_from_api(response.json(), latency_ms=(perf_counter() - started) * 1000)

    evaluators = [_deterministic_evaluator]
    if args.judge_model:
        evaluators.append(_judge_evaluator(args.judge_model))
    run_name = args.run_name or f"security-triage-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    result = dataset.run_experiment(
        name="TrustGuard Security Triage",
        run_name=run_name,
        description="Hybrid deterministic and calibrated-judge Security v4 evaluation.",
        task=task,
        evaluators=evaluators,
        run_evaluators=[_run_aggregate_evaluator],
        max_concurrency=args.max_concurrency,
        metadata={
            "dataset_version": "security-triage-langfuse-v1",
            "application_commit": _git_sha(),
            "judge_model": args.judge_model or "disabled",
            "judge_rubric_version": "security-judge-v1",
        },
    )
    client.flush()
    local_cases = load_security_evaluation_set(args.dataset)
    by_id = {case.id: case for case in local_cases}
    local_results = []
    for item_result in result.item_results:
        case_id = item_result.item.metadata["case_id"]
        raw_output = item_result.output if isinstance(item_result.output, dict) else {"status": "error"}
        evaluated = evaluate_case(by_id[case_id], TraceOutput.model_validate(raw_output))
        for score in item_result.evaluations:
            if score.name.startswith("judge-"):
                metadata = score.metadata or {}
                failure_code = metadata.get("failure_code")
                evaluated.metrics.append(
                    MetricResult(
                        name=score.name.replace("-", "_"),
                        value=float(score.value),
                        reason=score.comment or "LLM judge score",
                        failure_codes=[failure_code] if failure_code and float(score.value) < 1 else [],
                        details=metadata,
                    )
                )
        local_results.append(evaluated)
    report = build_report(local_cases, local_results, source="langfuse_dataset_experiment")
    report["langfuse"] = {
        "dataset": args.langfuse_dataset,
        "dataset_run_id": result.dataset_run_id,
        "dataset_run_url": result.dataset_run_url,
        "run_name": run_name,
    }
    write_report(report, args.output)
    print(result.format(include_item_results=True))
    if result.dataset_run_url:
        print(f"Dataset run: {result.dataset_run_url}")
    print(f"Local diagnostic report: {args.output}")
    return 0


def _observation_payload(observation: Any) -> dict[str, Any]:
    return observation.model_dump(mode="json") if hasattr(observation, "model_dump") else dict(observation)


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("trace time bounds must include a UTC offset")
    return parsed


def _trace_output(payload: dict[str, Any], child_payloads: list[dict[str, Any]] | None = None) -> TraceOutput:
    output = _json_object(payload.get("output"))
    started = payload.get("start_time") or payload.get("startTime")
    ended = payload.get("end_time") or payload.get("endTime")
    latency = None
    if started and ended:
        latency = (datetime.fromisoformat(str(ended).replace("Z", "+00:00")) - datetime.fromisoformat(str(started).replace("Z", "+00:00"))).total_seconds() * 1000
    usage = payload.get("usage_details") or payload.get("usageDetails") or {}
    costs = payload.get("cost_details") or payload.get("costDetails") or {}
    child_payloads = child_payloads or []
    input_tokens = sum(
        int((item.get("usage_details") or item.get("usageDetails") or {}).get("input", 0)) for item in child_payloads
    )
    output_tokens = sum(
        int((item.get("usage_details") or item.get("usageDetails") or {}).get("output", 0)) for item in child_payloads
    )
    child_cost = sum(
        float(
            item.get("total_cost")
            or item.get("totalCost")
            or (item.get("cost_details") or item.get("costDetails") or {}).get("total", 0)
        )
        for item in child_payloads
    )
    return TraceOutput.model_validate(
        {
            **output,
            "latency_ms": latency,
            "input_tokens": input_tokens or usage.get("input"),
            "output_tokens": output_tokens or usage.get("output"),
            "cost_usd": child_cost or payload.get("total_cost") or payload.get("totalCost") or costs.get("total"),
        }
    )


def evaluate_traces(args: argparse.Namespace) -> int:
    cases = load_security_evaluation_set(args.dataset)
    by_id = {case.id: case for case in cases}
    explicit_map = json.loads(Path(args.trace_case_map).read_text()) if args.trace_case_map else {}
    client = _client()
    from_time = _parse_time(args.from_time)
    to_time = _parse_time(args.to_time)
    if from_time >= to_time:
        raise ValueError("--from-time must be earlier than --to-time")
    cursor = None
    results = []
    unmatched = []
    while True:
        page = client.api.observations.get_many(
            name="security-analysis",
            is_root_observation=True,
            environment=args.environment,
            from_start_time=from_time,
            to_start_time=to_time,
            fields="core,basic,io,metadata,usage,metrics,trace_context",
            limit=min(args.limit - len(results), 100),
            cursor=cursor,
        )
        for observation in page.data:
            payload = _observation_payload(observation)
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            observation_id = str(payload.get("id"))
            case_id = explicit_map.get(observation_id) or metadata.get("dataset_case_id")
            if case_id not in by_id:
                unmatched.append({"observation_id": observation_id, "reason": "missing or unknown dataset_case_id"})
                continue
            trace_id = payload.get("trace_id") or payload.get("traceId")
            children = []
            if trace_id:
                child_page = client.api.observations.get_many(
                    trace_id=str(trace_id),
                    fields="core,usage",
                    from_start_time=from_time,
                    to_start_time=to_time,
                    limit=100,
                )
                children = [
                    _observation_payload(item)
                    for item in child_page.data
                    if str(getattr(item, "id", "")) != observation_id
                ]
            evaluated = evaluate_case(by_id[case_id], _trace_output(payload, children))
            results.append(evaluated)
            if args.attach_scores:
                for metric in evaluated.metrics:
                    if metric.status is MetricStatus.SCORED and metric.value is not None:
                        client.create_score(
                            name=metric.name.replace("_", "-"),
                            value=float(metric.value),
                            observation_id=observation_id,
                            comment=metric.reason,
                            metadata={"case_id": case_id, "failure_codes": metric.failure_codes},
                        )
            if len(results) >= args.limit:
                break
        cursor = getattr(page.meta, "cursor", None)
        if not cursor or len(results) >= args.limit:
            break
    if args.attach_scores:
        client.flush()
    report = build_report(cases, results, source="existing_langfuse_observations")
    report["unmatched_observations"] = unmatched
    write_report(report, args.output)
    print(json.dumps({"scored": len(results), "unmatched": len(unmatched), "output": args.output}))
    return 0


def generate_report(args: argparse.Namespace) -> int:
    cases = load_security_evaluation_set(args.dataset)
    by_id = {case.id: case for case in cases}
    payload = json.loads(Path(args.results).read_text(encoding="utf-8"))
    rows = payload.get("cases", payload)
    results = [evaluate_case(by_id[row["case_id"]], TraceOutput.model_validate(row["output"])) for row in rows]
    write_report(build_report(cases, results, source="saved_outputs"), args.output)
    print(json.dumps({"cases": len(results), "output": args.output}))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--dataset", default=DEFAULT_DATASET_PATH)
    root.add_argument("--langfuse-dataset", default=DEFAULT_LANGFUSE_DATASET)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    commands.add_parser("sync")
    calibration = commands.add_parser("calibrate-judge")
    calibration.add_argument("--annotations", required=True, help="Human-reviewed dev-case JSONL")
    calibration.add_argument("--judge-model", required=True)
    calibration.add_argument("--tolerance", type=float, default=0.2)
    calibration.add_argument("--output", default="eval/results/security-judge-calibration.json")
    experiment = commands.add_parser("experiment")
    experiment.add_argument("--api-base-url", required=True)
    experiment.add_argument("--consented-token-env", default="TRUSTGUARD_EVAL_CONSENTED_TOKEN")
    experiment.add_argument("--no-consent-token-env", default="TRUSTGUARD_EVAL_NO_CONSENT_TOKEN")
    judge = experiment.add_mutually_exclusive_group()
    judge.add_argument(
        "--judge-model",
        default=os.getenv("SECURITY_AI_SYNTHESIS_MODEL", "gpt-4o-mini"),
        help="Judge model (defaults to SECURITY_AI_SYNTHESIS_MODEL or gpt-4o-mini)",
    )
    judge.add_argument("--no-judge", action="store_const", dest="judge_model", const=None)
    experiment.add_argument("--run-name")
    experiment.add_argument("--output", default=DEFAULT_REPORT_PATH)
    experiment.add_argument("--max-concurrency", type=int, default=4)
    experiment.add_argument("--timeout", type=float, default=60)
    traces = commands.add_parser("traces")
    traces.add_argument("--environment")
    traces.add_argument("--from-time", required=True, help="Inclusive ISO-8601 UTC lower bound")
    traces.add_argument("--to-time", required=True, help="Exclusive ISO-8601 UTC upper bound")
    traces.add_argument("--limit", type=int, default=100)
    traces.add_argument("--trace-case-map")
    traces.add_argument("--attach-scores", action="store_true")
    traces.add_argument("--output", default=DEFAULT_REPORT_PATH)
    report = commands.add_parser("report")
    report.add_argument("--results", required=True)
    report.add_argument("--output", default=DEFAULT_REPORT_PATH)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "validate":
        cases = load_security_evaluation_set(args.dataset)
        print(json.dumps({"cases": len(cases), "sha256": dataset_sha256(cases)}))
        return 0
    if args.command == "sync":
        return sync_dataset(args)
    if args.command == "calibrate-judge":
        return calibrate_judge(args)
    if args.command == "experiment":
        return run_experiment(args)
    if args.command == "traces":
        return evaluate_traces(args)
    if args.command == "report":
        return generate_report(args)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
