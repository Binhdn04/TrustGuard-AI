from src.services.official_evidence_planner import (
    EvidenceEdge,
    EvidenceRetrievalPlanner,
    RetrievalDirection,
)


def test_candidate_source_is_expanded_before_another_search() -> None:
    planner = EvidenceRetrievalPlanner(
        entity="Example University",
        campaign="Future Learning With AI",
        resource_url="https://forms.example/form/ABC-123",
    )

    first = planner.next_frontier()
    assert first is not None
    assert first.edge is EvidenceEdge.ENTITY_OFFICIAL_IDENTITY
    assert first.direction is RetrievalDirection.CLAIM_CENTRIC
    assert first.queries == ('Example University "Future Learning With AI"', "Example University")

    assert planner.observe_candidates(["https://www.example.edu/news/ai"])
    planner.complete_frontier(first, new_evidence=True)
    second = planner.next_frontier()
    assert second is not None
    assert second.direction is RetrievalDirection.SOURCE_CENTRIC
    assert second.candidate_urls == ("https://www.example.edu/news/ai",)


def test_reverse_resource_frontier_uses_exact_url_and_identifier_after_claim_miss() -> None:
    planner = EvidenceRetrievalPlanner(
        entity="Example University",
        campaign="Future Learning With AI",
        resource_url="https://forms.example/form/ABC-123",
    )
    claim = planner.next_frontier()
    assert claim is not None
    planner.complete_frontier(claim, new_evidence=False)

    reverse = planner.next_frontier()
    assert reverse is not None
    assert reverse.edge is EvidenceEdge.CAMPAIGN_EXACT_RESOURCE
    assert reverse.direction is RetrievalDirection.RESOURCE_CENTRIC
    assert reverse.queries == (
        "https://forms.example/form/ABC-123",
        "forms.example ABC-123",
    )


def test_stops_after_two_frontiers_without_new_evidence_and_never_repeats_work() -> None:
    planner = EvidenceRetrievalPlanner(entity="Example University", resource_url="https://forms.example/x/ABC")
    first = planner.next_frontier()
    assert first is not None
    planner.complete_frontier(first, new_evidence=False)
    second = planner.next_frontier()
    assert second is not None
    planner.complete_frontier(second, new_evidence=False)
    assert planner.next_frontier() is None
    assert planner.stop_reason == "consecutive_retrievals_no_new_evidence"
