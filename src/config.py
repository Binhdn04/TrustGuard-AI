from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
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

    # Demo authentication. Production must replace this with an identity
    # provider and set DEMO_AUTH_ENABLED=false.
    demo_auth_enabled: bool = True
    demo_user_token: str = "dev-user-token"
    demo_admin_token: str = "dev-admin-token"

    # LLM
    openai_api_key: str = ""
    model_name: str = "gpt-4o-mini"
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_timeout_seconds: float = Field(default=15.0, gt=0.0, le=60.0)
    llm_max_retries: int = Field(default=1, ge=0, le=3)

    # Database
    database_url: str = "sqlite:///./data/app.db"
    redis_url: str = "redis://localhost:6379/0"

    # Vector Store
    chroma_persist_dir: str = "./data/chroma"

    @model_validator(mode="after")
    def reject_demo_auth_in_production(self) -> "Settings":
        if self.app_env == "production" and self.demo_auth_enabled:
            raise ValueError("demo authentication must be disabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
