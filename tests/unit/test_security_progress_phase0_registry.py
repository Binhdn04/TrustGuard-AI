from src.services.security_progress import (
    PROGRESS_EVENT_QUEUE_MAXSIZE,
    PROGRESS_QUIESCE_TIMEOUT_SECONDS,
    PROGRESS_STAGE_ALLOWLIST,
    SecurityProgressStage,
)


def test_phase0_progress_stage_allowlist_is_coarse_and_closed() -> None:
    assert PROGRESS_STAGE_ALLOWLIST == {
        "running",
        "understanding",
        "scope_gate",
        "incident_response",
        "investigation",
        "official_link_verification",
        "security_memory_lookup",
        "risk_assessment",
        "assistant_response",
    }
    assert set(SecurityProgressStage) == set(PROGRESS_STAGE_ALLOWLIST)
    assert (
        not {
            "dns",
            "rdap",
            "redirect_check",
            "url_reputation",
            "web_search",
        }
        & PROGRESS_STAGE_ALLOWLIST
    )


def test_phase0_reporter_bounds_are_static_and_cover_all_coarse_events() -> None:
    assert PROGRESS_EVENT_QUEUE_MAXSIZE == 32
    assert PROGRESS_EVENT_QUEUE_MAXSIZE >= 1 + (len(PROGRESS_STAGE_ALLOWLIST) * 2)
    assert PROGRESS_QUIESCE_TIMEOUT_SECONDS == 1.0
