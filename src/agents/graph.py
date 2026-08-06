from langgraph.graph import END, StateGraph

from src.agents.nodes.example_node import analyze_node, respond_node
from src.agents.state import LegacyAgentState


def should_continue(state: LegacyAgentState) -> str:
    """Route based on whether an error occurred during analysis."""
    if state.get("error"):
        return END
    return "respond"


def build_graph() -> StateGraph:
    graph = StateGraph(LegacyAgentState)

    # Add nodes
    graph.add_node("analyze", analyze_node)
    graph.add_node("respond", respond_node)

    # Add edges
    graph.set_entry_point("analyze")
    graph.add_conditional_edges("analyze", should_continue)
    graph.add_edge("respond", END)

    return graph.compile()


<<<<<<< Updated upstream
agent = build_graph()
=======
def build_openai_graph(**kwargs):
    """Build the production graph; remains offline when no API key is configured."""
    from src.agents.tools.integration import build_provider_adapters
    from src.config import get_settings
    from src.services.llm import get_llm

    settings = get_settings()
    llm = get_llm() if settings.openai_api_key else None
    owned_adapters = build_provider_adapters(settings)
    for name, adapter in owned_adapters.items():
        kwargs.setdefault(name, adapter)
    graph = build_graph(llm=llm, **kwargs)
    # Keep application-owned resources reachable so the ASGI lifespan can
    # deterministically close their connection pools.
    graph._owned_adapters = tuple(owned_adapters.values())
    return graph


async def close_graph_resources(graph) -> None:
    """Close provider clients created while building a production graph."""
    for adapter in getattr(graph, "_owned_adapters", ()):
        close = getattr(adapter, "aclose", None)
        if close is not None:
            await close()


# Backward compatibility for the existing `/chat` endpoint and starter tests.
agent = build_legacy_graph()

__all__ = [
    "agent",
    "build_graph",
    "build_legacy_graph",
    "build_openai_graph",
    "close_graph_resources",
]
>>>>>>> Stashed changes
