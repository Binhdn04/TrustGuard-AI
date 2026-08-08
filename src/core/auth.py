from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

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


class OIDCAuthenticator:
    """Validate an asymmetric OIDC access token against issuer JWKS.

    PyJWKClient caches signing keys and refreshes them after rotation. Tokens
    are never logged or persisted by this boundary.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.oidc_issuer or not settings.oidc_audience:
            raise ValueError("OIDC issuer and audience are required")
        try:
            import jwt
        except ImportError as exc:  # pragma: no cover - deployment dependency guard
            raise RuntimeError("PyJWT[crypto] is required for OIDC authentication") from exc
        self._jwt = jwt
        self._settings = settings
        jwks_url = settings.oidc_jwks_url or f"{settings.oidc_issuer.rstrip('/')}/.well-known/jwks.json"
        self._keys = jwt.PyJWKClient(jwks_url, cache_keys=True)

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer_token(authorization)
        try:
            signing_key = self._keys.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._settings.oidc_audience,
                issuer=self._settings.oidc_issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except self._jwt.PyJWTError as exc:
            raise _invalid_bearer() from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise _invalid_bearer()
        roles = _claim_values(claims.get(self._settings.oidc_roles_claim)) | _claim_values(
            claims.get(f"{self._settings.oidc_audience.rstrip('/')}/roles")
        )
        role = UserRole.SECURITY_ADMIN if self._settings.oidc_admin_role in roles else UserRole.USER
        return Principal(user_id=subject, role=role)


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise _invalid_bearer()
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise _invalid_bearer()
    return token


def _claim_values(value: object) -> set[str]:
    if isinstance(value, str):
        return {item for item in value.split() if item}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _invalid_bearer() -> PlatformError:
    return PlatformError(
        status_code=403,
        code=ErrorCode.FORBIDDEN,
        message="The bearer token is invalid.",
        retryable=False,
    )


class ConfiguredAuthenticator:
    def __init__(self, settings: Settings) -> None:
        self._delegate = DemoTokenAuthenticator(settings) if settings.demo_auth_enabled else OIDCAuthenticator(settings)

    def authenticate(self, authorization: str | None) -> Principal:
        return self._delegate.authenticate(authorization)

    async def authenticate_async(self, authorization: str | None) -> Principal:
        if isinstance(self._delegate, DemoTokenAuthenticator):
            return self._delegate.authenticate(authorization)
        # JWKS discovery and key rotation may perform blocking HTTP inside PyJWT.
        return await asyncio.to_thread(self._delegate.authenticate, authorization)


def require_security_admin(principal: Principal) -> None:
    if principal.role is not UserRole.SECURITY_ADMIN:
        raise PlatformError(
            status_code=403,
            code=ErrorCode.FORBIDDEN,
            message="Security admin role is required.",
            retryable=False,
        )
