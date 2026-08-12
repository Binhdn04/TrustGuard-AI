from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    app_name: str = "AI20K Agent"
    app_env: Literal["development", "production", "test"] = "development"
    app_port: int = Field(default=8000, ge=1, le=65535)
    app_host: str = "0.0.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    cors_origins: str = "http://localhost:3000"

    # LLM
    openai_api_key: str = ""
    model_name: str = "gpt-4o-mini"
    llm_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    llm_timeout_seconds: float = Field(default=30.0, gt=0.0)
    llm_max_retries: int = Field(default=2, ge=0)

    # Provider adapters
    provider_timeout_seconds: float = Field(default=10.0, gt=0.0)
    jina_timeout_seconds: float = Field(default=20.0, gt=0.0, le=60.0)
    google_web_risk_api_key: str = ""
    virustotal_api_key: str = ""
    reputation_secondary_enabled: bool = True
    reputation_max_network_calls: int = Field(default=4, ge=1, le=20)
    google_safe_browsing_api_key: str = ""
    google_fact_check_api_key: str = ""
    tavily_api_key: str = ""
    jina_api_key: str = ""
    embedding_model: str = "text-embedding-3-small"
    live_providers_required: bool = False
    analysis_deadline_seconds: float = Field(default=30.0, gt=0.0, le=120.0)
    fact_check_timeout_seconds: float = Field(default=30.0, gt=0.0, le=90.0)
    post_processing_reserve_seconds: float = Field(default=10.0, ge=0.0, le=60.0)
    max_provider_cost_usd: float = Field(default=0.05, gt=0.0, le=10.0)
    max_claim_concurrency: int = Field(default=3, ge=1, le=3)
    flashrank_model: str = "ms-marco-MultiBERT-L-12"
    flashrank_cache_dir: str = "./data/flashrank"
    reputation_max_attempts: int = Field(default=2, ge=1, le=5)
    reputation_circuit_failure_threshold: int = Field(default=3, ge=1, le=20)
    reputation_secondary_call_budget: int = Field(default=1, ge=0, le=5)

    # Demo auth
    demo_auth_enabled: bool = True
    demo_user_token: str = "dev-user-token"
    demo_admin_token: str = "dev-admin-token"

    # Database
    database_url: str = "sqlite:///./data/app.db"
    database_encryption_key: str = "development-only-change-me"
    security_database_path: str = Field(
        default="./data/security.db",
        validation_alias=AliasChoices("SECURITY_DATABASE_PATH", "BLACKLIST_DATABASE_PATH"),
    )
    redis_url: str = "redis://localhost:6379/0"

    # OIDC (Auth0 is the hosted default; tests can inject an authenticator)
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_admin_role: str = "security_admin"
    oidc_roles_claim: str = "roles"
    websocket_ticket_ttl_seconds: int = Field(default=60, ge=10, le=300)

    # Abuse controls. Admin traffic has a separate, lower-volume bucket.
    user_rate_limit_per_minute: int = Field(default=120, ge=1)
    admin_rate_limit_per_minute: int = Field(default=60, ge=1)
    job_lease_seconds: int = Field(default=60, ge=5, le=3600)
    run_durable_worker: bool = True

    # Signed artifact access and retention. Access tokens are derived and are
    # never stored in PostgreSQL.
    artifact_signing_key: str = "development-artifact-signing-key"
    artifact_access_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    artifact_retention_days: int = Field(default=30, ge=1, le=365)
    artifact_storage_dir: str = "./data/artifacts"

    # Vector Store
    chroma_persist_dir: str = "./data/chroma"

    @model_validator(mode="after")
    def reject_demo_auth_in_production(self) -> "Settings":
        if self.app_env == "production" and self.demo_auth_enabled:
            raise ValueError("DEMO_AUTH_ENABLED must be false in production")
        if self.live_providers_required:
            required = {
                "OPENAI_API_KEY": self.openai_api_key,
                "GOOGLE_FACT_CHECK_API_KEY": self.google_fact_check_api_key,
                "GOOGLE_WEB_RISK_API_KEY": self.google_web_risk_api_key,
                "VIRUSTOTAL_API_KEY": self.virustotal_api_key,
                "TAVILY_API_KEY": self.tavily_api_key,
                "JINA_API_KEY": self.jina_api_key,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError("Live provider profile is missing: " + ", ".join(missing))
        if self.post_processing_reserve_seconds >= self.analysis_deadline_seconds:
            raise ValueError("POST_PROCESSING_RESERVE_SECONDS must be smaller than ANALYSIS_DEADLINE_SECONDS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
