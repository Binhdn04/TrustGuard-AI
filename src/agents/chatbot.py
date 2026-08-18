from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from src.agents.security_risk import assess_security_risk
from src.models import ScopeDecisionV4, SecurityTriageCreateRequestV4
from src.services.security_triage import SecurityTriageScopeService

_SYSTEM_PROMPT = """Bạn là TrustGuard, một trợ lý hội thoại về an toàn số.

Hãy trò chuyện tự nhiên và hữu ích bằng ngôn ngữ của người dùng. Khi người dùng đưa nội dung, URL,
email hoặc tình huống để hỏi có lừa đảo/phishing/giả mạo hay không, bạn BẮT BUỘC gọi tool
`check_scam` trước khi trả lời. Không gọi tool cho chào hỏi hoặc hội thoại thông thường.

Chỉ diễn giải kết quả tool; không tự bịa việc đã quét URL, tra blacklist hay xác minh nguồn bên ngoài.
Không khẳng định SAFE khi bằng chứng chưa đủ. Nếu dữ liệu còn thiếu, hỏi ngắn gọn một câu để lấy nội
dung tin nhắn, URL, người gửi hoặc hành động được yêu cầu. Không làm general fact-check ngoài mục đích
đánh giá scam. Ưu tiên hướng dẫn an toàn tức thời nếu có yêu cầu chuyển tiền, mật khẩu hoặc OTP.
"""


def _scam_result(content: str) -> dict[str, Any]:
    """Run the canonical local security scope and risk policy for chatbot tool use."""
    scoped = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=content))
    if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE:
        scoped = assess_security_risk(scoped)

    context = scoped.security_context
    return {
        "scope_decision": scoped.scope_decision.value,
        "scope_reasons": scoped.scope_reasons,
        "risk": scoped.risk.value if scoped.risk is not None else None,
        "score": scoped.score,
        "confidence": scoped.confidence,
        "threat_type": scoped.threat_type.value if scoped.threat_type is not None else None,
        "scenario": context.scenario.value if context is not None else None,
        "requested_action": context.requested_action.value if context and context.requested_action else None,
        "signals": {
            "credential_request": bool(context and context.credential_request),
            "otp_request": bool(context and context.otp_request),
            "payment_request": bool(context and context.payment_request),
            "urgency": bool(context and context.urgency),
            "impersonation": bool(context and context.impersonation_signals),
            "url_count": len(context.urls) if context else 0,
        },
        "recommended_actions": [item.value for item in scoped.recommended_actions],
        "explanation": scoped.explanation,
        "follow_up_question": scoped.follow_up_question,
        "boundary_message": scoped.boundary_message,
        "limitations": scoped.limitations,
        "inspection_level": "local_policy_only",
    }


@tool
def check_scam(content: str) -> str:
    """Check user-provided text or URLs for scam, phishing, impersonation, and risky-action signals.

    Use this tool whenever the user asks whether a message, URL, sender, payment request, login request,
    or OTP request may be fraudulent. Pass the complete user-provided suspicious content unchanged.
    The result is a local policy assessment and does not claim an external URL reputation scan.
    """
    return json.dumps(_scam_result(content), ensure_ascii=False)


def _text_content(message: AIMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
        return "\n".join(part for part in parts if part).strip()
    return str(content).strip()


def build_chatbot_node(llm: Any | None = None):
    """Build a GPT-first chat node with bounded, explicit tool execution and no answer fallback."""

    async def chat(state: dict[str, Any]) -> dict[str, Any]:
        active_llm = llm
        if active_llm is None:
            from src.config import get_settings
            from src.services.llm import get_llm

            settings = get_settings()
            if not settings.openai_api_key.strip():
                raise RuntimeError("OPENAI_API_KEY is required for the GPT chatbot; fallback is disabled")
            active_llm = get_llm()

        model = active_llm.bind_tools([check_scam])
        messages: list[Any] = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=state.get("query", "")),
        ]
        tool_results: list[dict[str, Any]] = []

        for _ in range(4):
            answer = await model.ainvoke(messages)
            messages.append(answer)
            calls = list(getattr(answer, "tool_calls", []) or [])
            if not calls:
                response = _text_content(answer)
                if not response:
                    raise RuntimeError("GPT returned an empty chatbot response")
                return {
                    "response": response,
                    "analysis": json.dumps(
                        {"model": "gpt", "tools_called": ["check_scam"] * len(tool_results)},
                        ensure_ascii=False,
                    ),
                    "metadata": {"tool_results": tool_results},
                }

            for call in calls:
                if call.get("name") != check_scam.name:
                    raise RuntimeError(f"GPT requested unsupported tool: {call.get('name')}")
                # This policy-only tool is synchronous and CPU-local. Calling it
                # directly also avoids dispatching sensitive message content to a
                # generic executor context.
                result_text = check_scam.invoke(call.get("args", {}))
                result = json.loads(result_text)
                tool_results.append(result)
                messages.append(ToolMessage(content=result_text, tool_call_id=call["id"]))

        raise RuntimeError("GPT exceeded the maximum tool-calling turns")

    return chat


__all__ = ["build_chatbot_node", "check_scam"]
