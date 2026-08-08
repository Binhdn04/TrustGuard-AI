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
    google_web_risk_api_key: str = ""
    virustotal_api_key: str = ""
    reputation_secondary_enabled: bool = True
    reputation_max_network_calls: int = Field(default=4, ge=1, le=20)
    google_safe_browsing_api_key: str = ""
    google_fact_check_api_key: str = ""

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

    # Vector Store
    chroma_persist_dir: str = "./data/chroma"

    @model_validator(mode="after")
    def reject_demo_auth_in_production(self) -> "Settings":
        if self.app_env == "production" and self.demo_auth_enabled:
            raise ValueError("DEMO_AUTH_ENABLED must be false in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
