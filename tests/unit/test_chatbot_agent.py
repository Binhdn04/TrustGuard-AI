from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from src.agents.chatbot import check_scam
from src.agents.graph import build_chatbot_graph


class _SequencedToolCallingModel:
    def __init__(self, responses: list[AIMessage]) -> None:
        self.responses = list(responses)
        self.bound_tools = []
        self.requests = []

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self

    async def ainvoke(self, messages):
        self.requests.append(list(messages))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_chatbot_answers_normal_conversation_without_tool_call() -> None:
    model = _SequencedToolCallingModel([AIMessage(content="Chào bạn, tôi có thể giúp kiểm tra dấu hiệu lừa đảo.")])

    result = await build_chatbot_graph(llm=model).ainvoke({"query": "Xin chào"})

    assert result["response"].startswith("Chào bạn")
    assert result["metadata"]["tool_results"] == []
    assert [item.name for item in model.bound_tools] == ["check_scam"]
    assert len(model.requests) == 1


@pytest.mark.asyncio
async def test_chatbot_uses_structured_context_as_untrusted_data() -> None:
    model = _SequencedToolCallingModel([AIMessage(content="Bạn không nên gửi mã OTP đó.")])

    result = await build_chatbot_graph(llm=model).ainvoke(
        {
            "query": "Tại sao vậy?",
            "context": json.dumps(
                {
                    "schema": "security-chat-context-v1",
                    "security_context": {"otp_request": True},
                    "current_assessment": {"risk": "HIGH_RISK"},
                }
            ),
        }
    )

    assert "OTP" in result["response"]
    human_messages = [message.content for message in model.requests[0] if isinstance(message, HumanMessage)]
    assert human_messages[-1] == "Tại sao vậy?"
    assert "security-chat-context-v1" in human_messages[-2]


@pytest.mark.asyncio
async def test_chatbot_executes_check_scam_before_synthesizing_answer() -> None:
    model = _SequencedToolCallingModel(
        [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "check_scam",
                        "args": {"content": "HR yêu cầu chuyển tiền ngay để đóng phí hồ sơ"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="Đây là dấu hiệu rủi ro cao. Bạn không nên chuyển tiền."),
        ]
    )

    result = await build_chatbot_graph(llm=model).ainvoke(
        {"query": "HR yêu cầu chuyển tiền ngay để đóng phí hồ sơ, có lừa đảo không?"}
    )

    assert "không nên chuyển tiền" in result["response"]
    tool_result = result["metadata"]["tool_results"][0]
    assert tool_result["risk"] == "HIGH_RISK"
    assert tool_result["signals"]["payment_request"] is True
    assert tool_result["inspection_level"] == "local_policy_only"
    tool_messages = [message for message in model.requests[1] if isinstance(message, ToolMessage)]
    assert len(tool_messages) == 1
    assert json.loads(tool_messages[0].content)["threat_type"] == "RECRUITMENT_SCAM"


def test_check_scam_tool_does_not_claim_safe_for_unsupported_general_question() -> None:
    result = json.loads(check_scam.invoke({"content": "Đội nào sẽ vô địch World Cup?"}))

    assert result["scope_decision"] == "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
    assert result["risk"] is None
    assert result["inspection_level"] == "local_policy_only"
