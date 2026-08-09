from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, date, datetime
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from src.agents.fact_check import ExtractedClaim
from src.agents.state import WorkflowState

LLM_MODEL = "gpt-4o-mini"
AllowedTool = Literal["url_scanner", "domain_intelligence", "claim_retriever"]
logger = logging.getLogger(__name__)


class _StrictOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExtractedClaimDraft(_StrictOutput):
    text: str = Field(min_length=1, max_length=1000)
    language: str = Field(default="vi", min_length=2, max_length=35)
    is_temporal: bool = False
    claim_date_start: date | None = None
    claim_date_end: date | None = None


class MessageAnalysis(_StrictOutput):
    context: str = Field(min_length=1, max_length=500)
    dominant_emotion: Literal["neutral", "urgency", "fear", "greed", "curiosity", "trust", "unknown"]
    sender_intent: Literal[
        "informational",
        "promotion",
        "credential_harvest",
        "financial_request",
        "impersonation",
        "coercion",
        "unknown",
    ]
    suspected_scam_intent: bool
    scam_indicators: list[str] = Field(max_length=8)
    # Strings remain accepted for frozen v2 structured-output fixtures.
    claims: list[str | ExtractedClaimDraft] = Field(max_length=5)


class PlannedTool(_StrictOutput):
    tool: AllowedTool
    target: str = Field(min_length=1, max_length=500)
    reason_code: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")


class ToolPlan(_StrictOutput):
    tools: list[PlannedTool] = Field(max_length=3)


class AssessmentReview(_StrictOutput):
    agrees_with_deterministic_assessment: bool
    evidence_indexes: list[int] = Field(max_length=8)
    missing_information: list[str] = Field(max_length=5)
    narrative: str = Field(min_length=1, max_length=700)


class GroundedReason(_StrictOutput):
    evidence_index: int
    text: str = Field(min_length=1, max_length=500)


class GroundedResponse(_StrictOutput):
    summary: str = Field(min_length=1, max_length=700)
    reasons: list[GroundedReason] = Field(max_length=6)
    limitations: list[str] = Field(max_length=6)


async def _invoke_structured(llm: Any, schema: type[_StrictOutput], messages: list[Any]):
    runnable = llm.with_structured_output(schema)
    result = await runnable.ainvoke(messages)
    return result if isinstance(result, schema) else schema.model_validate(result)


class _LlmBudgetExceededError(RuntimeError):
    pass


class _LlmInvocationFailedError(RuntimeError):
    def __init__(self, usage: dict[str, int | float]) -> None:
        self.usage = usage
        super().__init__("LLM invocation failed")


def _estimated_tokens(messages: list[Any]) -> int:
    # A conservative tokenizer-independent reservation. It prevents an LLM
    # call before the configured cap is crossed; provider usage can replace
    # this estimate when the LLM boundary exposes normalized metadata.
    characters = sum(len(str(getattr(message, "content", ""))) for message in messages)
    return max(1, (characters + 3) // 4) + 256


async def _invoke_budgeted(
    llm: Any,
    schema: type[_StrictOutput],
    messages: list[Any],
    state: WorkflowState,
):
    calls = state.get("llm_calls_used", 0)
    tokens = state.get("llm_tokens_used", 0)
    cost = state.get("llm_cost_used_usd", 0.0)
    reserved_tokens = _estimated_tokens(messages)
    reserved_cost = reserved_tokens * 0.000001
    if (
        calls >= state.get("max_llm_calls", 4)
        or tokens + reserved_tokens > state.get("max_llm_tokens", 16_384)
        or cost + reserved_cost > state.get("max_llm_cost_usd", float("inf"))
    ):
        raise _LlmBudgetExceededError
    usage = {
        "llm_calls_used": calls + 1,
        "llm_tokens_used": tokens + reserved_tokens,
        "llm_cost_used_usd": cost + reserved_cost,
    }
    try:
        invocation = _invoke_structured(llm, schema, messages)
        deadline = state.get("deadline_at")
        if deadline is not None:
            remaining = max(0.0, (deadline - datetime.now(UTC)).total_seconds())
            result = await asyncio.wait_for(invocation, timeout=remaining)
        else:
            result = await invocation
    except Exception as exc:
        raise _LlmInvocationFailedError(usage) from exc
    return result, usage


def _failure_update(
    state: WorkflowState,
    stage: str,
    *,
    budget: bool = False,
    usage: dict[str, int | float] | None = None,
) -> dict:
    errors = list(state.get("llm_errors", []))
    errors.append(stage)
    limitations = list(state.get("limitations", []))
    limitations.append(
        f"LLM không hoàn tất bước {stage}"
        f"{' do hết budget' if budget else ''}; hệ thống dùng logic deterministic thay thế."
    )
    return {"llm_errors": errors, "limitations": list(dict.fromkeys(limitations)), **(usage or {})}


def _claim_is_grounded(claim: str, message: str) -> bool:
    claim_tokens = {token for token in re.findall(r"\w+", claim.casefold()) if len(token) > 2}
    message_tokens = set(re.findall(r"\w+", message.casefold()))
    return bool(claim_tokens) and len(claim_tokens & message_tokens) / len(claim_tokens) >= 0.6


def build_analyze_message_node(llm: Any | None):
    async def analyze_message(state: WorkflowState) -> dict:
        if llm is None:
            return {}
        try:
            messages = [
                SystemMessage(
                    content=(
                        "Bạn phân tích tin nhắn mà người dùng dán để kiểm tra lừa đảo. "
                        "Đánh giá ý đồ có khả năng thuộc về NGƯỜI GỬI tin nhắn, không quy kết người dùng. "
                        "Chỉ trích xuất tối đa năm claim có trong input; không thêm sự kiện hoặc bằng chứng. "
                        "Mỗi claim object gồm text, language, is_temporal và claim_date_start/end ISO nếu có. "
                        "Cảm xúc là kỹ thuật tác động nổi bật trong nội dung. Trả structured output."
                    )
                ),
                HumanMessage(content=state.get("message", "")),
            ]
            result, usage = await _invoke_budgeted(
                llm,
                MessageAnalysis,
                messages,
                state,
            )
        except _LlmBudgetExceededError:
            return _failure_update(state, "phân tích ngữ nghĩa", budget=True)
        except _LlmInvocationFailedError as exc:
            return _failure_update(state, "phân tích ngữ nghĩa", usage=exc.usage)
        except Exception:
            return _failure_update(state, "phân tích ngữ nghĩa")

        claims = list(state.get("claims", []))
        extracted = list(state.get("extracted_claims", []))
        by_text = {item.normalized_text: item for item in extracted}
        for draft in result.claims:
            claim = draft if isinstance(draft, str) else draft.text
            cleaned = claim.strip()
            if cleaned and cleaned not in claims and _claim_is_grounded(cleaned, state.get("message", "")):
                claims.append(cleaned)
            if cleaned and _claim_is_grounded(cleaned, state.get("message", "")):
                metadata = draft if isinstance(draft, ExtractedClaimDraft) else None
                try:
                    item = ExtractedClaim.from_text(
                        cleaned,
                        language=metadata.language if metadata else "vi",
                        claim_date_start=metadata.claim_date_start if metadata else None,
                        claim_date_end=metadata.claim_date_end if metadata else None,
                        is_temporal=metadata.is_temporal if metadata else None,
                    )
                    by_text[item.normalized_text] = item
                except ValueError:
                    continue
        return {
            "claims": claims[:5],
            "extracted_claims": list(by_text.values())[:5],
            "llm_context": result.context,
            "llm_emotion": result.dominant_emotion,
            "llm_sender_intent": result.sender_intent,
            "llm_suspected_scam_intent": result.suspected_scam_intent,
            "llm_scam_indicators": result.scam_indicators,
            "llm_model": LLM_MODEL,
            **usage,
        }

    return analyze_message


def build_plan_tools_node(llm: Any | None):
    async def plan_tools(state: WorkflowState) -> dict:
        if llm is None:
            return {}
        payload = {
            "context": state.get("llm_context"),
            "sender_intent": state.get("llm_sender_intent"),
            "urls": state.get("normalized_urls", []),
            "claims": state.get("claims", []),
            "consent_to_scan_urls": state.get("consent_to_scan_urls", False),
            "blocked_urls": state.get("blocked_urls", []),
            "allowed_tools": ["url_scanner", "domain_intelligence", "claim_retriever"],
        }
        try:
            result, usage = await _invoke_budgeted(
                llm,
                ToolPlan,
                [
                    SystemMessage(
                        content=(
                            "Lập thứ tự tool để thu thập evidence. Mỗi mục chỉ có tool, target và reason_code. "
                            "Chỉ chọn từ allowed_tools và target có trong input. "
                            "Không chọn url_scanner khi thiếu consent hoặc URL đã bị chặn. "
                            "Không xem suy luận LLM là evidence và không tự kết luận verdict."
                        )
                    ),
                    HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
                ],
                state,
            )
        except _LlmBudgetExceededError:
            return _failure_update(state, "lập kế hoạch tool", budget=True)
        except _LlmInvocationFailedError as exc:
            return _failure_update(state, "lập kế hoạch tool", usage=exc.usage)
        except Exception:
            return _failure_update(state, "lập kế hoạch tool")

        # The schema enforces the allowlist. The executor intentionally ignores
        # model-supplied targets when constructing executable work and derives
        # them again from normalized state.
        tools: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in result.tools:
            key = (item.tool, item.target)
            if key not in seen:
                seen.add(key)
                tools.append(item.model_dump())
        return {"llm_tool_plan": tools, **usage}

    return plan_tools


def build_review_assessment_node(llm: Any | None):
    async def review_assessment(state: WorkflowState) -> dict:
        if llm is None:
            return {}
        evidence = [
            {
                "index": index,
                "type": item.type.value,
                "source": item.source,
                "title": item.title,
                "finding": item.finding,
            }
            for index, item in enumerate(state.get("evidence", []))
        ]
        payload = {
            "semantic_context": state.get("llm_context"),
            "scam_indicators": state.get("llm_scam_indicators", []),
            "deterministic_assessment": {
                "score": state.get("risk_score"),
                "level": getattr(state.get("risk_level"), "value", state.get("risk_level")),
                "verdict": getattr(state.get("verdict"), "value", state.get("verdict")),
            },
            "evidence": evidence,
            "limitations": state.get("limitations", []),
        }
        try:
            result, usage = await _invoke_budgeted(
                llm,
                AssessmentReview,
                [
                    SystemMessage(
                        content=(
                            "Đóng vai reviewer an toàn. Giải thích assessment chỉ bằng evidence được cung cấp. "
                            "Không sửa score/verdict, không tạo evidence, và chỉ tham chiếu index tồn tại. "
                            "Nếu evidence thiếu hoặc mâu thuẫn, ghi vào missing_information."
                        )
                    ),
                    HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
                ],
                state,
            )
        except _LlmBudgetExceededError:
            return _failure_update(state, "review đánh giá", budget=True)
        except _LlmInvocationFailedError as exc:
            return _failure_update(state, "review đánh giá", usage=exc.usage)
        except Exception:
            return _failure_update(state, "review đánh giá")

        valid_indexes = [index for index in result.evidence_indexes if 0 <= index < len(evidence)]
        return {
            "llm_assessment": result.narrative,
            "llm_assessment_agrees": result.agrees_with_deterministic_assessment,
            "llm_evidence_indexes": valid_indexes,
            "llm_missing_information": result.missing_information,
            **usage,
        }

    return review_assessment


def build_generate_response_node(llm: Any | None):
    async def generate_response(state: WorkflowState) -> dict:
        if llm is None:
            return {}
        evidence = [
            {"index": index, "title": item.title, "finding": item.finding, "source": item.source}
            for index, item in enumerate(state.get("evidence", []))
        ]
        payload = {
            "context": state.get("llm_context"),
            "assessment_review": state.get("llm_assessment"),
            "missing_information": state.get("llm_missing_information", []),
            "verdict": getattr(state.get("verdict"), "value", state.get("verdict")),
            "risk_level": getattr(state.get("risk_level"), "value", state.get("risk_level")),
            "recommended_action": getattr(state.get("recommended_action"), "value", state.get("recommended_action")),
            "evidence": evidence,
            "limitations": state.get("limitations", []),
        }
        try:
            result, usage = await _invoke_budgeted(
                llm,
                GroundedResponse,
                [
                    SystemMessage(
                        content=(
                            "Viết phản hồi tiếng Việt ngắn, dễ hiểu, không gây hoảng sợ. "
                            "Mỗi reason phải mang evidence_index của evidence hỗ trợ nó; không nói an toàn "
                            "khi thiếu dữ liệu. Nếu không có evidence, để reasons rỗng. "
                            "Giữ nguyên verdict, risk level và action do hệ thống cung cấp."
                        )
                    ),
                    HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
                ],
                state,
            )
        except _LlmBudgetExceededError:
            return _failure_update(state, "tạo phản hồi", budget=True)
        except _LlmInvocationFailedError as exc:
            return _failure_update(state, "tạo phản hồi", usage=exc.usage)
        except Exception:
            return _failure_update(state, "tạo phản hồi")

        valid_reasons = [reason for reason in result.reasons if 0 <= reason.evidence_index < len(evidence)]
        indexes = [reason.evidence_index for reason in valid_reasons]
        if not valid_reasons and evidence:
            # Reject an ungrounded response and keep the deterministic explanation.
            return _failure_update(state, "kiểm tra grounding phản hồi")
        limitations = list(state.get("limitations", [])) + result.limitations
        return {
            "summary": result.summary,
            "reasons": [reason.text for reason in valid_reasons] or state.get("reasons", []),
            "limitations": list(dict.fromkeys(item for item in limitations if item.strip())),
            "llm_response_evidence_indexes": indexes,
            **usage,
        }

    return generate_response


__all__ = [
    "AssessmentReview",
    "GroundedReason",
    "GroundedResponse",
    "ExtractedClaimDraft",
    "LLM_MODEL",
    "MessageAnalysis",
    "PlannedTool",
    "ToolPlan",
    "build_analyze_message_node",
    "build_generate_response_node",
    "build_plan_tools_node",
    "build_review_assessment_node",
]
