import pytest
from pydantic import ValidationError

from src.config import Settings


def test_production_rejects_demo_auth() -> None:
    with pytest.raises(ValidationError, match="DEMO_AUTH_ENABLED must be false"):
        Settings(app_env="production", demo_auth_enabled=True, _env_file=None)


def test_production_allows_demo_auth_to_be_disabled() -> None:
    settings = Settings(app_env="production", demo_auth_enabled=False, _env_file=None)

    assert settings.demo_auth_enabled is False
