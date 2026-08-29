import re
from functools import lru_cache
from ipaddress import ip_network
from typing import Literal
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_CHROME_EXTENSION_ORIGIN = re.compile(r"chrome-extension://[a-p]{32}")


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
    chrome_extension_origins: str = ""

    # LLM
    openai_api_key: str = ""
    model_name: str = "gpt-4o-mini"
    llm_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    llm_timeout_seconds: float = Field(default=30.0, gt=0.0)
    llm_max_retries: int = Field(default=2, ge=0)

    # Langfuse tracing is opt-in. Sanitized content capture remains separately
    # gated so a deployment cannot start exporting message content by accident.
    langfuse_tracing_enabled: bool = False
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_base_url: str = "https://cloud.langfuse.com"
    langfuse_sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    langfuse_debug: bool = False
    langfuse_capture_sanitized_content: bool = False

    # Security assistant runtime. AI stages default on but remain independently
    # gated as operational kill switches; policy remains deterministic.
    security_ai_understanding_enabled: bool = True
    security_ai_planning_enabled: bool = True
    security_ai_explanation_enabled: bool = True
    security_async_execution_enabled: bool = False
    security_memory_retrieval_enabled: bool = False
    security_admin_copilot_enabled: bool = True
    security_page_capture_enabled: bool = False
    security_page_capture_timeout_seconds: float = Field(default=12.0, gt=0.0, le=30.0)
    security_page_capture_max_image_bytes: int = Field(default=2_000_000, ge=100_000, le=5_000_000)
    security_page_capture_max_concurrency: int = Field(default=2, ge=1, le=4)
    security_page_capture_viewport_width: int = Field(default=1280, ge=640, le=1920)
    security_page_capture_viewport_height: int = Field(default=720, ge=480, le=1080)
    security_page_capture_jpeg_quality: int = Field(default=72, ge=40, le=90)
    security_official_verification_mode: Literal["off", "shadow", "visible", "enforced"] = "visible"
    security_domain_familiarity_mode: Literal["off", "visible", "enforced"] = "off"
    security_admin_copilot_rate_limit_per_minute: int = Field(default=5, ge=1, le=60)
    security_ai_max_calls_per_turn: int = Field(default=8, ge=1, le=12)
    security_ai_timeout_seconds: float = Field(default=15.0, gt=0.0, le=15.0)
    security_ai_turn_deadline_seconds: float = Field(default=60.0, gt=0.0, le=120.0)
    security_ai_max_retries: int = Field(default=1, ge=0, le=2)
    security_ai_small_model: str = Field(default="gpt-4o-mini", min_length=1)
    security_ai_synthesis_model: str = Field(default="gpt-4o-mini", min_length=1)
    security_ai_small_input_cost_per_million_usd: float = Field(default=0.15, gt=0.0)
    security_ai_small_output_cost_per_million_usd: float = Field(default=0.60, gt=0.0)
    security_ai_synthesis_input_cost_per_million_usd: float = Field(default=0.15, gt=0.0)
    security_ai_synthesis_output_cost_per_million_usd: float = Field(default=0.60, gt=0.0)

    # Provider adapters
    provider_timeout_seconds: float = Field(default=10.0, gt=0.0)
    bkns_whois_api_key: str = ""
    virustotal_api_key: str = ""
    cloudflare_radar_api_token: str = ""
    reputation_secondary_enabled: bool = True
    reputation_max_network_calls: int = Field(default=4, ge=1, le=20)
    google_safe_browsing_api_key: str = ""
    tavily_api_key: str = ""
    embedding_model: str = "text-embedding-3-small"
    live_providers_required: bool = False
    analysis_deadline_seconds: float = Field(default=60.0, gt=0.0, le=120.0)
    post_processing_reserve_seconds: float = Field(default=10.0, ge=0.0, le=60.0)
    max_provider_cost_usd: float = Field(default=0.05, gt=0.0, le=10.0)
    max_claim_concurrency: int = Field(default=3, ge=1, le=3)
    source_discovery_enabled: bool = False
    source_provisional_enabled: bool = False
    source_auto_promotion_enabled: bool = False
    reputation_max_attempts: int = Field(default=2, ge=1, le=5)
    reputation_circuit_failure_threshold: int = Field(default=3, ge=1, le=20)
    reputation_secondary_call_budget: int = Field(default=1, ge=0, le=5)
    security_investigation_max_external_calls: int = Field(default=16, ge=1, le=100)
    security_investigation_max_retries: int = Field(default=1, ge=0, le=3)
    security_investigation_deadline_seconds: float = Field(default=20.0, gt=0.0, le=120.0)
    security_conversation_retention_days: int = Field(default=30, ge=1, le=365)
    security_release_profile: Literal["pre_cutover", "cutover"] = "pre_cutover"

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
    # This applies before authentication. When the app is deployed behind a
    # reverse proxy, configure only proxy addresses/CIDRs that are controlled
    # by the deployment; untrusted forwarding headers are ignored.
    ip_rate_limit_per_minute: int = Field(default=240, ge=1)
    trusted_proxy_ips: str = ""
    user_rate_limit_per_minute: int = Field(default=120, ge=1)
    admin_rate_limit_per_minute: int = Field(default=60, ge=1)
    job_lease_seconds: int = Field(default=60, ge=5, le=3600)
    run_durable_worker: bool = True

    # Retention for minimized analysis content and security payloads.
    content_retention_days: int = Field(default=30, ge=1, le=365)

    def security_live_provider_requirements(self) -> dict[str, str]:
        required = {
            "VIRUSTOTAL_API_KEY": self.virustotal_api_key,
        }
        return required

    def enabled_security_capabilities(self) -> dict[str, bool]:
        provider_ready = self.security_ai_provider_configuration_valid()
        # The API process can enqueue durable work while the consumer runs in a
        # separate service.  ``run_durable_worker`` controls only whether this
        # process starts a consumer; requiring it here would hide async from a
        # correctly configured API + worker deployment.
        durable_ready = self.security_async_execution_enabled and self.database_url.startswith(
            ("postgresql://", "postgresql+asyncpg://")
        )
        return {
            "security_ai_understanding": self.security_ai_understanding_enabled and provider_ready,
            "security_ai_planning": self.security_ai_planning_enabled and provider_ready,
            "security_ai_explanation": self.security_ai_explanation_enabled and provider_ready,
            "security_async_execution": durable_ready,
            "security_memory_retrieval": self.security_memory_retrieval_enabled,
            "security_admin_copilot": self.security_admin_copilot_enabled and provider_ready,
            "security_page_capture": self.security_page_capture_enabled,
            "official_link_verification": self.security_official_verification_mode != "off",
            "official_web_search_ready": (
                self.security_official_verification_mode != "off" and bool(self.tavily_api_key.strip())
            ),
            "domain_familiarity": self.security_domain_familiarity_mode != "off",
            "domain_popularity_lookup_ready": (
                self.security_domain_familiarity_mode != "off" and bool(self.cloudflare_radar_api_token.strip())
            ),
        }

    def security_ai_provider_configuration_valid(self) -> bool:
        """Return whether the locally verifiable OpenAI configuration is usable."""
        return bool(
            self.openai_api_key.strip()
            and self.security_ai_small_model.strip()
            and self.security_ai_synthesis_model.strip()
        )

    def langfuse_configuration_valid(self) -> bool:
        return bool(
            self.langfuse_tracing_enabled
            and self.langfuse_public_key.strip()
            and self.langfuse_secret_key.strip()
            and self.langfuse_base_url.strip()
        )

    @field_validator("security_ai_small_model", "security_ai_synthesis_model")
    @classmethod
    def validate_security_ai_model_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Security AI model names must not be blank")
        return value

    @field_validator("trusted_proxy_ips")
    @classmethod
    def validate_trusted_proxy_ips(cls, value: str) -> str:
        entries = [entry.strip() for entry in value.split(",") if entry.strip()]
        for entry in entries:
            try:
                ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError("TRUSTED_PROXY_IPS must contain comma-separated IP addresses or CIDRs") from exc
        return ",".join(entries)

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, value: str) -> str:
        origins = [entry.strip().rstrip("/") for entry in value.split(",") if entry.strip()]
        if not origins:
            raise ValueError("CORS_ORIGINS must contain at least one exact web origin")
        for origin in origins:
            parsed = urlparse(origin)
            if (
                origin == "*"
                or parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("CORS_ORIGINS must contain comma-separated exact HTTP(S) origins")
        return ",".join(dict.fromkeys(origins))

    @field_validator("chrome_extension_origins")
    @classmethod
    def validate_chrome_extension_origins(cls, value: str) -> str:
        origins = [entry.strip().rstrip("/") for entry in value.split(",") if entry.strip()]
        for origin in origins:
            if _CHROME_EXTENSION_ORIGIN.fullmatch(origin) is None:
                raise ValueError(
                    "CHROME_EXTENSION_ORIGINS must contain exact chrome-extension://<32-character-id> origins"
                )
        return ",".join(dict.fromkeys(origins))

    def browser_origins(self) -> list[str]:
        return [
            *self.cors_origins.split(","),
            *(origin for origin in self.chrome_extension_origins.split(",") if origin),
        ]

    def browser_origin_allowed(self, origin: str | None) -> bool:
        return origin is not None and origin in self.browser_origins()

    @staticmethod
    def _placeholder_or_short_secret(value: str) -> bool:
        lowered = value.strip().lower()
        markers = ("development", "change-me", "replace-with", "placeholder", "example-secret")
        return len(value.strip()) < 32 or any(marker in lowered for marker in markers)

    @model_validator(mode="after")
    def validate_runtime_profile(self) -> "Settings":
        if self.app_env == "production":
            if self.demo_auth_enabled:
                raise ValueError("DEMO_AUTH_ENABLED must be false in production")
            if not self.database_url.startswith(("postgresql://", "postgresql+asyncpg://")):
                raise ValueError("DATABASE_URL must use PostgreSQL in production")
            if not self.redis_url.startswith(("redis://", "rediss://")):
                raise ValueError("REDIS_URL must use Redis in production")
            if not self.oidc_issuer or not self.oidc_audience:
                raise ValueError("OIDC_ISSUER and OIDC_AUDIENCE are required in production")
            if urlparse(self.oidc_issuer).scheme != "https":
                raise ValueError("OIDC_ISSUER must use HTTPS in production")
            if self._placeholder_or_short_secret(self.database_encryption_key):
                raise ValueError("DATABASE_ENCRYPTION_KEY must be a non-placeholder secret of at least 32 characters")
            origins = self.cors_origins.split(",")
            if not origins or any(origin == "*" or urlparse(origin).scheme != "https" for origin in origins):
                raise ValueError("CORS_ORIGINS must contain explicit HTTPS origins in production")
            if self.security_release_profile == "cutover":
                if not self.live_providers_required:
                    raise ValueError("LIVE_PROVIDERS_REQUIRED must be true for production cutover")
            if self.langfuse_tracing_enabled and urlparse(self.langfuse_base_url).scheme != "https":
                raise ValueError("LANGFUSE_BASE_URL must use HTTPS when tracing is enabled in production")
        if self.langfuse_tracing_enabled and not self.langfuse_configuration_valid():
            raise ValueError(
                "LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, and LANGFUSE_BASE_URL are required "
                "when LANGFUSE_TRACING_ENABLED is true"
            )
        if self.live_providers_required:
            required = self.security_live_provider_requirements()
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError("Live provider profile is missing: " + ", ".join(missing))
        ai_enabled = any(
            (
                self.security_ai_understanding_enabled,
                self.security_ai_planning_enabled,
                self.security_ai_explanation_enabled,
                self.security_admin_copilot_enabled,
            )
        )
        if self.app_env == "production" and ai_enabled and not self.security_ai_provider_configuration_valid():
            raise ValueError(
                "Valid OPENAI_API_KEY and Security AI model configuration are required "
                "when a production Security AI flag is enabled"
            )
        if self.post_processing_reserve_seconds >= self.analysis_deadline_seconds:
            raise ValueError("POST_PROCESSING_RESERVE_SECONDS must be smaller than ANALYSIS_DEADLINE_SECONDS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
