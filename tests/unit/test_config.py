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


def test_production_async_api_allows_a_separate_durable_worker() -> None:
    settings = production_settings(
        security_async_execution_enabled=True,
        run_durable_worker=False,
        openai_api_key="configured-test-provider-key",
    )

    assert settings.enabled_security_capabilities()["security_async_execution"] is True


def test_wave1_reputation_policy_is_bounded() -> None:
    settings = Settings(
        virustotal_api_key="virus-total",
        reputation_secondary_call_budget=0,
        _env_file=None,
    )
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
        bkns_whois_api_key="",
        openai_api_key="",
        _env_file=None,
    )

    assert settings.openai_api_key == ""
    assert settings.bkns_whois_api_key == ""


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


def test_production_cutover_requires_live_providers() -> None:
    with pytest.raises(ValidationError, match="LIVE_PROVIDERS_REQUIRED"):
        production_settings(security_release_profile="cutover")


def test_production_cutover_accepts_complete_security_profile() -> None:
    settings = production_settings(
        security_release_profile="cutover",
        live_providers_required=True,
        virustotal_api_key="virus-total",
    )

    assert settings.security_release_profile == "cutover"


def test_trusted_proxy_ips_must_be_ip_addresses_or_cidrs() -> None:
    settings = Settings(trusted_proxy_ips="10.0.0.1, 2001:db8::/32", _env_file=None)

    assert settings.trusted_proxy_ips == "10.0.0.1,2001:db8::/32"
    with pytest.raises(ValidationError, match="TRUSTED_PROXY_IPS"):
        Settings(trusted_proxy_ips="proxy.example", _env_file=None)
