"""Call the real OpenAI model while keeping external security tools deterministic.

Usage:
    python -m scripts.smoke_test_openai_agent
    python -m scripts.smoke_test_openai_agent --message "Nội dung cần kiểm tra"
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime

from src.agents import build_graph
from src.agents.tools.fakes import FakeBlacklistRepository, FakeClaimRetriever, FakeUrlScanner
from src.config import get_settings
from src.models import DomainIntelligenceResult, UrlScanResult, Verdict
from src.services.llm import get_llm


class SmokeDomainIntelligence:
    """Offline domain-intelligence adapter used by the v2 workflow."""

    async def lookup(self, domain: str) -> DomainIntelligenceResult:
        return DomainIntelligenceResult(
            provider="smoke-fake-domain-intelligence",
            domain=domain,
            signals=["unverified_domain"],
            observed_at=datetime.now(UTC),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke-test all GPT-4o-mini nodes without calling real security providers."
    )
    parser.add_argument(
        "--message",
        default="Bạn đã trúng quà. Đăng nhập ngay tại https://unknown.example/login để nhận.",
        help="Message sent to the agent (avoid real credentials or sensitive data).",
    )
    parser.add_argument(
        "--no-consent",
        action="store_true",
        help="Do not allow the fake URL reputation scan.",
    )
    return parser.parse_args()


async def run(message: str, consent: bool) -> None:
    settings = get_settings()
    key = settings.openai_api_key.strip()
    if not key or key == "sk-your-key-here":
        raise SystemExit("OPENAI_API_KEY is missing or still uses the .env.example placeholder.")
    if settings.model_name != "gpt-4o-mini":
        raise SystemExit(f"MODEL_NAME must be gpt-4o-mini, got {settings.model_name!r}.")

    observed_at = datetime.now(UTC)
    scanner = FakeUrlScanner(
        {
            "smoke": UrlScanResult(
                provider="smoke-fake-url-reputation",
                normalized_url="https://unknown.example/login",
                verdict=Verdict.SUSPICIOUS,
                redirect_chain=[],
                signals=["credential_path"],
                observed_at=observed_at,
            )
        },
        "smoke",
    )
    retriever = FakeClaimRetriever({"smoke": []}, "smoke")
    # Build the injectable v2 agent directly so every security-provider call
    # remains deterministic while the LLM nodes use the configured OpenAI model.
    graph = build_graph(
        llm=get_llm(),
        url_scanner=scanner,
        domain_intelligence=SmokeDomainIntelligence(),
        claim_retriever=retriever,
        blacklist=FakeBlacklistRepository(),
    )
    result = await graph.ainvoke(
        {
            "message": message,
            "consent_to_scan_urls": consent,
            "max_tool_calls": 6,
        }
    )

    llm_errors = result.get("llm_errors", [])
    payload = {
        "real_openai_call_succeeded": result.get("llm_model") == "gpt-4o-mini" and not llm_errors,
        "llm_model": result.get("llm_model"),
        "context": result.get("llm_context"),
        "emotion": result.get("llm_emotion"),
        "sender_intent": result.get("llm_sender_intent"),
        "suspected_scam_intent": result.get("llm_suspected_scam_intent"),
        "scam_indicators": result.get("llm_scam_indicators", []),
        "tool_plan": result.get("llm_tool_plan", []),
        "investigation_plan": [step.model_dump(mode="json") for step in result.get("investigation_plan", [])],
        "url_findings": [finding.model_dump(mode="json") for finding in result.get("url_findings", [])],
        "domain_findings": [finding.model_dump(mode="json") for finding in result.get("domain_findings", [])],
        "risk_score": result.get("risk_score"),
        "risk_level": getattr(result.get("risk_level"), "value", result.get("risk_level")),
        "verdict": getattr(result.get("verdict"), "value", result.get("verdict")),
        "recommended_action": getattr(
            result.get("recommended_action"), "value", result.get("recommended_action")
        ),
        "summary": result.get("summary"),
        "reasons": result.get("reasons", []),
        "limitations": result.get("limitations", []),
        "llm_errors": llm_errors,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if not payload["real_openai_call_succeeded"]:
        raise SystemExit("OpenAI smoke test failed; inspect llm_errors and limitations above.")


def main() -> None:
    args = parse_args()
    asyncio.run(run(args.message, not args.no_consent))


if __name__ == "__main__":
    main()
