import pytest

import src.agents.graph as graph_module
from src.agents.graph import agent
from src.agents.nodes.extraction import classify_input, extract_indicators
from src.agents.nodes.llm import build_analyze_message_node


@pytest.mark.asyncio
async def test_agent_basic_flow():
    result = await agent.ainvoke({"query": "Hello"})
    assert "response" in result


@pytest.mark.asyncio
async def test_agent_state_structure():
    result = await agent.ainvoke({"query": "Test query"})
    assert isinstance(result, dict)
    assert "query" in result


def test_extract_indicators_removes_repeated_urls_in_one_pass():
    state = {"message": ("Thông báo example.com/path, yêu cầu xác nhận tại example.com/path ngay hôm nay")}
    state.update(classify_input(state))

    result = extract_indicators(state)

    assert result["extracted_urls"] == ["example.com/path"]
    assert result["claims"] == ["Thông báo yêu cầu xác nhận tại ngay hôm nay"]


@pytest.mark.asyncio
async def test_planning_loop_stops_when_tool_node_makes_no_progress(monkeypatch):
    async def stalled_tool_node(_state):
        return {}

    monkeypatch.setattr(graph_module, "build_scan_urls_node", lambda *_args: stalled_tool_node)
    monkeypatch.setattr(
        graph_module,
        "plan_next_tool",
        lambda _state: {"next_tool": "scan_url", "tool_target": "https://example.com"},
    )
    planning_loop = graph_module._build_planning_loop_node(None, None, None)

    result = await planning_loop({"tool_calls_used": 0})

    assert result["next_tool"] == "assess"
    assert result["tool_calls_used"] == 0
    assert "không ghi nhận tiến độ" in result["limitations"][0]


@pytest.mark.asyncio
async def test_invalid_structured_output_uses_deterministic_fallback():
    class Runnable:
        async def ainvoke(self, _messages):
            return {"context": "missing all other required fields"}

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    analyze = build_analyze_message_node(Llm())

    result = await analyze({"message": "Thông báo yêu cầu xác nhận ngay hôm nay"})

    assert result["llm_errors"] == ["phân tích ngữ nghĩa"]
    assert "deterministic" in result["limitations"][0]
