import pytest
from pydantic import ValidationError

from src.config import Settings


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "demo_auth_enabled": False,
        "database_url": "postgresql://app:password@db.example/trustguard",
        "redis_url": "rediss://redis.example/0",
        "database_encryption_key": "database-encryption-secret-000001",
        "oidc_issuer": "https://identity.example/",
        "oidc_audience": "https://api.example",
        "cors_origins": "https://app.example",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_rejects_demo_auth() -> None:
    with pytest.raises(ValidationError, match="DEMO_AUTH_ENABLED must be false"):
        production_settings(demo_auth_enabled=True)


def test_production_allows_demo_auth_to_be_disabled() -> None:
    settings = production_settings()

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


def test_live_provider_profile_requires_only_security_v4_providers() -> None:
    settings = Settings(
        live_providers_required=True,
        virustotal_api_key="virus-total",
        openai_api_key="",
        _env_file=None,
    )

    assert settings.openai_api_key == ""


def test_live_provider_profile_does_not_require_google_web_risk() -> None:
    settings = Settings(
        live_providers_required=True,
        google_web_risk_api_key="",
        virustotal_api_key="virus-total",
        _env_file=None,
    )

    assert settings.security_live_provider_requirements()["VIRUSTOTAL_API_KEY"] == "virus-total"
    assert "GOOGLE_WEB_RISK_API_KEY" not in settings.security_live_provider_requirements()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"database_url": "sqlite:///./data/app.db"}, "PostgreSQL"),
        ({"redis_url": "memory://local"}, "Redis"),
        ({"oidc_issuer": "http://identity.example"}, "HTTPS"),
        ({"database_encryption_key": "replace-with-a-secret"}, "DATABASE_ENCRYPTION_KEY"),
        ({"cors_origins": "http://localhost:3000"}, "CORS_ORIGINS"),
    ],
)
def test_production_rejects_insecure_runtime_dependencies(override, message) -> None:
    with pytest.raises(ValidationError, match=message):
        production_settings(**override)


def test_production_cutover_requires_frozen_legacy_and_live_providers() -> None:
    with pytest.raises(ValidationError, match="LEGACY_API_WRITES_ENABLED"):
        production_settings(security_release_profile="cutover")

    with pytest.raises(ValidationError, match="source discovery"):
        production_settings(
            security_release_profile="cutover",
            legacy_api_writes_enabled=False,
        )

    with pytest.raises(ValidationError, match="LIVE_PROVIDERS_REQUIRED"):
        production_settings(
            security_release_profile="cutover",
            legacy_api_writes_enabled=False,
            source_discovery_enabled=False,
            source_provisional_enabled=False,
            source_auto_promotion_enabled=False,
        )


def test_production_cutover_accepts_complete_security_profile() -> None:
    settings = production_settings(
        security_release_profile="cutover",
        legacy_api_writes_enabled=False,
        source_discovery_enabled=False,
        source_provisional_enabled=False,
        source_auto_promotion_enabled=False,
        live_providers_required=True,
        google_web_risk_api_key="web-risk",
        virustotal_api_key="virus-total",
    )

    assert settings.security_release_profile == "cutover"
