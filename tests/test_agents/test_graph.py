import pytest

import src.agents.graph as graph_module
from src.agents.graph import agent
from src.agents.nodes.extraction import classify_input, extract_indicators
from src.agents.nodes.llm import _english_verification_query, build_analyze_message_node
from src.agents.nodes.rules import NO_VERIFIABLE_INPUT_LIMITATION


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


def test_extract_indicators_keeps_standalone_health_claim_as_fallback():
    state = {"message": "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư"}
    state.update(classify_input(state))

    result = extract_indicators(state)

    assert result["claims"] == ["Uống nước chanh mỗi ngày có thể chữa khỏi ung thư"]


def test_english_verification_query_restores_scope_time_and_source_qualifiers():
    result = _english_verification_query(
        "Vietnam will completely ban motorbikes starting in 2027.",
        "Vietnam motorbike ban",
    )

    assert result == "Vietnam motorbike ban 2027 nationwide official sources"


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


@pytest.mark.asyncio
async def test_llm_claim_removes_stale_no_verifiable_input_limitation():
    class Runnable:
        async def ainvoke(self, _messages):
            return {
                "context": "Khẳng định về tác dụng chữa bệnh của nước chanh.",
                "dominant_emotion": "neutral",
                "sender_intent": "informational",
                "suspected_scam_intent": False,
                "scam_indicators": [],
                "claims": [
                    {
                        "text": "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư.",
                        "language": "vi",
                        "is_temporal": False,
                        "claim_date_start": None,
                        "claim_date_end": None,
                        "search_query_en": "Drinking lemon water every day can cure cancer.",
                        "search_query_alt_en": "lemon water cure cancer official medical evidence",
                    }
                ],
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    analyze = build_analyze_message_node(Llm())
    result = await analyze(
        {
            "message": "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư.",
            "limitations": [NO_VERIFIABLE_INPUT_LIMITATION, "Một giới hạn khác."],
        }
    )

    assert result["claims"] == ["Uống nước chanh mỗi ngày có thể chữa khỏi ung thư."]
    assert result["limitations"] == ["Một giới hạn khác."]
    assert [(item.text, item.language) for item in result["extracted_claims"][0].query_variants] == [
        ("Uống nước chanh mỗi ngày có thể chữa khỏi ung thư.", "vi"),
        ("Drinking lemon water every day can cure cancer.", "en"),
        ("lemon water cure cancer official medical evidence", "en"),
    ]


@pytest.mark.asyncio
async def test_english_vietnam_claim_adds_qualified_english_and_local_queries():
    class Runnable:
        async def ainvoke(self, _messages):
            return {
                "context": "A claim about a future transport policy in Vietnam.",
                "dominant_emotion": "neutral",
                "sender_intent": "informational",
                "suspected_scam_intent": False,
                "scam_indicators": [],
                "claims": [
                    {
                        "text": "Vietnam will completely ban motorbikes starting in 2027.",
                        "language": "English",
                        "is_temporal": True,
                        "claim_date_start": "2027-01-01",
                        "claim_date_end": None,
                        "search_query_en": None,
                        "search_query_alt_en": "Vietnam motorbike ban",
                        "search_query_vi": "Việt Nam cấm hoàn toàn xe máy từ năm 2027",
                    }
                ],
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    result = await build_analyze_message_node(Llm())(
        {"message": "Vietnam will completely ban motorbikes starting in 2027."}
    )

    assert [(item.text, item.language) for item in result["extracted_claims"][0].query_variants] == [
        ("Vietnam will completely ban motorbikes starting in 2027.", "en"),
        ("Vietnam motorbike ban 2027 nationwide official sources", "en"),
        ("Việt Nam cấm hoàn toàn xe máy từ năm 2027 nguồn chính thức", "vi"),
    ]
