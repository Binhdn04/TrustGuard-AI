from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.config import Settings
from src.core.errors import PlatformError
from src.models import ErrorCode


class UserRole(StrEnum):
    USER = "user"
    SECURITY_ADMIN = "security_admin"


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    role: UserRole


class DemoTokenAuthenticator:
    """Small development-only auth boundary that can be replaced by OIDC."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def authenticate(self, authorization: str | None) -> Principal:
        if not self._settings.demo_auth_enabled:
            raise PlatformError(
                status_code=503,
                code=ErrorCode.INTERNAL_ERROR,
                message="Authentication provider is not configured.",
                retryable=False,
            )
        if not authorization or not authorization.startswith("Bearer "):
            raise PlatformError(
                status_code=403,
                code=ErrorCode.FORBIDDEN,
                message="A valid bearer token is required.",
                retryable=False,
            )

        token = authorization.removeprefix("Bearer ").strip()
        if token == self._settings.demo_user_token:
            return Principal(user_id="demo-user", role=UserRole.USER)
        if token == self._settings.demo_admin_token:
            return Principal(user_id="demo-security-admin", role=UserRole.SECURITY_ADMIN)
        raise PlatformError(
            status_code=403,
            code=ErrorCode.FORBIDDEN,
            message="The bearer token is invalid.",
            retryable=False,
        )


def require_security_admin(principal: Principal) -> None:
    if principal.role is not UserRole.SECURITY_ADMIN:
        raise PlatformError(
            status_code=403,
            code=ErrorCode.FORBIDDEN,
            message="Security admin role is required.",
            retryable=False,
        )
