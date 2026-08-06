from __future__ import annotations

from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import urlsplit

from src.agents.state import WorkflowState
from src.models import InvestigationStep, InvestigationStepStatus, InvestigationTool

_TERMINAL_STATUSES = {
    InvestigationStepStatus.COMPLETED,
    InvestigationStepStatus.SKIPPED,
    InvestigationStepStatus.FAILED,
}


def step_id_for(tool: InvestigationTool | str, target: str) -> str:
    """Return a stable, opaque id without exposing planner reasoning."""
    tool_value = getattr(tool, "value", tool)
    digest = sha256(f"{tool_value}\0{target}".encode()).hexdigest()[:12]
    return f"step-{digest}"


def ensure_step(
    plan: list[InvestigationStep],
    *,
    tool: InvestigationTool,
    target: str,
    reason_code: str,
    depends_on: list[str] | None = None,
    status: InvestigationStepStatus = InvestigationStepStatus.PENDING,
) -> InvestigationStep:
    """Add a step once and preserve its current status on replanning."""
    identifier = step_id_for(tool, target)
    for step in plan:
        if step.step_id == identifier:
            return step
    step = InvestigationStep(
        step_id=identifier,
        tool=tool,
        target=target,
        reason_code=reason_code,
        depends_on=depends_on or [],
        status=status,
    )
    plan.append(step)
    return step


def transition_step(
    plan: list[InvestigationStep],
    step_id: str,
    status: InvestigationStepStatus,
) -> list[InvestigationStep]:
    """Idempotently transition a step; terminal states cannot be overwritten."""
    updated: list[InvestigationStep] = []
    found = False
    for step in plan:
        if step.step_id != step_id:
            updated.append(step)
            continue
        found = True
        if step.status == status or step.status in _TERMINAL_STATUSES:
            updated.append(step)
            continue
        allowed = (
            (step.status is InvestigationStepStatus.PENDING and status is InvestigationStepStatus.RUNNING)
            or (
                step.status is InvestigationStepStatus.PENDING
                and status in {InvestigationStepStatus.SKIPPED, InvestigationStepStatus.FAILED}
            )
            or (step.status is InvestigationStepStatus.RUNNING and status in _TERMINAL_STATUSES)
            or (step.status is InvestigationStepStatus.RUNNING and status is InvestigationStepStatus.PENDING)
        )
        updated.append(step.model_copy(update={"status": status}) if allowed else step)
    if not found:
        raise KeyError(f"unknown investigation step: {step_id}")
    return updated


def domain_target(url: str) -> str | None:
    """Return a normalized host; the domain adapter owns PSL/eTLD+1 handling."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    try:
        ip_address(host)
    except ValueError:
        return host
    return None


def build_investigation_plan(state: WorkflowState) -> list[InvestigationStep]:
    """Merge mandatory policy steps and planner proposals into one safe plan."""
    plan = [step.model_copy(deep=True) for step in state.get("investigation_plan", [])]
    local = ensure_step(
        plan,
        tool=InvestigationTool.LOCAL_RULES,
        target="message",
        reason_code="input_validation",
        status=InvestigationStepStatus.COMPLETED,
    )

    blacklist_by_domain: dict[str, InvestigationStep] = {}
    for url in state.get("normalized_urls", []):
        domain = domain_target(url)
        if domain and domain not in blacklist_by_domain:
            blacklist_by_domain[domain] = ensure_step(
                plan,
                tool=InvestigationTool.BLACKLIST_LOOKUP,
                target=domain,
                reason_code="url_present",
                depends_on=[local.step_id],
                status=InvestigationStepStatus.COMPLETED,
            )

    proposed = state.get("llm_tool_plan", [])
    priorities = [item.get("tool") for item in proposed]
    for required in ("url_scanner", "domain_intelligence", "claim_retriever"):
        if required not in priorities:
            priorities.append(required)

    consent = state.get("consent_to_scan_urls") is True
    blocked = set(state.get("blocked_urls", []))
    blacklisted = set(state.get("blacklisted_domains", []))
    for tool_name in priorities:
        if tool_name == "url_scanner":
            for url in state.get("normalized_urls", []):
                dependency = blacklist_by_domain.get(domain_target(url) or "")
                ensure_step(
                    plan,
                    tool=InvestigationTool.URL_SCANNER,
                    target=url,
                    reason_code="url_reputation_needed",
                    depends_on=[dependency.step_id] if dependency else [local.step_id],
                    status=(
                        InvestigationStepStatus.PENDING
                        if consent and url not in blocked and domain_target(url) not in blacklisted
                        else InvestigationStepStatus.SKIPPED
                    ),
                )
        elif tool_name == "domain_intelligence":
            seen_domains: set[str] = set()
            for url in state.get("normalized_urls", []):
                domain = domain_target(url)
                if not domain or domain in seen_domains:
                    continue
                seen_domains.add(domain)
                dependency = blacklist_by_domain.get(domain)
                ensure_step(
                    plan,
                    tool=InvestigationTool.DOMAIN_INTELLIGENCE,
                    target=domain,
                    reason_code="domain_age_needed",
                    depends_on=[dependency.step_id] if dependency else [local.step_id],
                    status=(
                        InvestigationStepStatus.PENDING
                        if consent
                        and domain not in blacklisted
                        and not any(
                            url in blocked for url in state.get("normalized_urls", []) if domain_target(url) == domain
                        )
                        else InvestigationStepStatus.SKIPPED
                    ),
                )
        elif tool_name == "claim_retriever":
            for claim in state.get("claims", []):
                ensure_step(
                    plan,
                    tool=InvestigationTool.CLAIM_RETRIEVER,
                    target=claim,
                    reason_code="claim_requires_verification",
                    depends_on=[local.step_id],
                )
    return plan


def plan_next_tool(state: WorkflowState) -> dict:
    """Route only ready, pending work; budget and terminal state stop the loop."""
    plan = state.get("investigation_plan", [])
    used = state.get("tool_calls_used", 0)
    maximum = state.get("max_tool_calls", 6)
    if used >= maximum:
        limitations = list(state.get("limitations", []))
        limitations.append("Đã dùng hết ngân sách gọi công cụ.")
        return {"next_tool": "assess", "limitations": list(dict.fromkeys(limitations))}

    statuses = {step.step_id: step.status for step in plan}
    ready = [
        step
        for step in plan
        if step.status is InvestigationStepStatus.PENDING
        and all(statuses.get(dependency) is InvestigationStepStatus.COMPLETED for dependency in step.depends_on)
    ]
    return {"next_tool": "execute" if ready else "assess"}


def route_planned_tool(state: WorkflowState) -> str:
    return state.get("next_tool", "assess")


__all__ = [
    "build_investigation_plan",
    "domain_target",
    "ensure_step",
    "plan_next_tool",
    "step_id_for",
    "transition_step",
]
