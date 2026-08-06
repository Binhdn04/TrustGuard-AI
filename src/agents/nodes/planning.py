from __future__ import annotations

from src.agents.state import WorkflowState


def _attempt_key(tool: str, target: str) -> str:
    return f"{tool}:{target}"


def plan_next_tool(state: WorkflowState) -> dict:
    used = state.get("tool_calls_used", 0)
    maximum = state.get("max_tool_calls", 6)
    if used >= maximum:
        limitations = list(state.get("limitations", []))
        limitations.append("Đã dùng hết ngân sách gọi công cụ.")
        return {"next_tool": "assess", "limitations": list(dict.fromkeys(limitations))}

    attempts = state.get("tool_attempts", {})
    scanned = {item.normalized_url for item in state.get("url_findings", [])}
    searched_claims = {key.removeprefix("verify_claim:") for key in attempts if key.startswith("verify_claim:")}

    # LLM chooses priority only. Code retains consent, SSRF, retry, budget and
    # completeness enforcement, and appends omitted applicable tools.
    preferred = list(state.get("llm_tool_plan", []))
    for required in ("url_scanner", "claim_retriever"):
        if required not in preferred:
            preferred.append(required)
    for tool in preferred:
        if tool == "url_scanner" and state.get("consent_to_scan_urls", False):
            for url in state.get("normalized_urls", []):
                key = _attempt_key("scan_url", url)
                if url not in state.get("blocked_urls", []) and url not in scanned and attempts.get(key, 0) < 2:
                    return {"next_tool": "scan_url", "tool_target": url}
        if tool == "claim_retriever":
            for claim in state.get("claims", []):
                if claim not in searched_claims:
                    return {"next_tool": "verify_claim", "tool_target": claim}
    return {"next_tool": "assess", "tool_target": "assessment"}


def route_planned_tool(state: WorkflowState) -> str:
    return state.get("next_tool", "assess")
