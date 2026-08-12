import pytest
from pydantic import ValidationError

from src.config import Settings


def test_production_rejects_demo_auth() -> None:
    with pytest.raises(ValidationError, match="DEMO_AUTH_ENABLED must be false"):
        Settings(app_env="production", demo_auth_enabled=True, _env_file=None)


def test_production_allows_demo_auth_to_be_disabled() -> None:
    settings = Settings(app_env="production", demo_auth_enabled=False, _env_file=None)

    assert settings.demo_auth_enabled is False


def test_wave1_reputation_policy_is_bounded() -> None:
    settings = Settings(
        google_web_risk_api_key="web-risk",
        virustotal_api_key="virus-total",
        reputation_secondary_call_budget=0,
        _env_file=None,
    )
    assert settings.google_web_risk_api_key == "web-risk"
    assert settings.reputation_secondary_call_budget == 0
    with pytest.raises(ValidationError):
        Settings(reputation_max_attempts=0, _env_file=None)


def test_post_processing_reserve_must_fit_analysis_deadline() -> None:
    with pytest.raises(ValidationError, match="POST_PROCESSING_RESERVE_SECONDS"):
        Settings(analysis_deadline_seconds=10, post_processing_reserve_seconds=10, _env_file=None)
