from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace

import pytest

from src.config import Settings
from src.core.auth import OIDCAuthenticator, Principal, UserRole, require_security_admin
from src.core.errors import PlatformError

ISSUER = "https://tenant.example/"
AUDIENCE = "https://api.trustguard.example"
ROLES_CLAIM = f"{AUDIENCE}/roles"


class FakePyJWTError(Exception):
    pass


class FakePyJWKClient:
    def __init__(self, _jwks_url: str, *, cache_keys: bool) -> None:
        assert cache_keys is True

    def get_signing_key_from_jwt(self, _token: str) -> SimpleNamespace:
        return SimpleNamespace(key=object())


@pytest.fixture
def oidc_authenticator(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[OIDCAuthenticator, Callable[..., str]]:
    token_claims: dict[str, dict[str, object]] = {}
    fake_jwt = ModuleType("jwt")
    fake_jwt.PyJWTError = FakePyJWTError  # type: ignore[attr-defined]
    fake_jwt.PyJWKClient = FakePyJWKClient  # type: ignore[attr-defined]

    def decode(
        token: str,
        _key: object,
        *,
        algorithms: list[str],
        audience: str,
        issuer: str,
        options: dict[str, list[str]],
    ) -> dict[str, object]:
        assert algorithms == ["RS256", "ES256"]
        claims = token_claims.get(token)
        if claims is None:
            raise FakePyJWTError("unknown token")
        if claims.get("iss") != issuer or claims.get("aud") != audience:
            raise FakePyJWTError("issuer or audience mismatch")
        if any(required not in claims for required in options["require"]):
            raise FakePyJWTError("required claim missing")
        expiry = claims.get("exp")
        if not isinstance(expiry, datetime) or expiry <= datetime.now(UTC):
            raise FakePyJWTError("token expired")
        return claims

    fake_jwt.decode = decode  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "jwt", fake_jwt)
    authenticator = OIDCAuthenticator(
        Settings(
            demo_auth_enabled=False,
            oidc_issuer=ISSUER,
            oidc_audience=AUDIENCE,
            oidc_roles_claim=ROLES_CLAIM,
            oidc_admin_role="security_admin",
        )
    )

    def issue_token(**overrides: object) -> str:
        now = datetime.now(UTC)
        claims: dict[str, object] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "auth0|user-1",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        }
        claims.update(overrides)
        token = f"token-{len(token_claims)}"
        token_claims[token] = claims
        return token

    return authenticator, issue_token


def test_oidc_maps_namespaced_security_admin_role(
    oidc_authenticator: tuple[OIDCAuthenticator, Callable[..., str]],
) -> None:
    authenticator, issue_token = oidc_authenticator
    token = issue_token(**{ROLES_CLAIM: ["security_admin"]})

    principal = authenticator.authenticate(f"Bearer {token}")

    assert principal == Principal(user_id="auth0|user-1", role=UserRole.SECURITY_ADMIN)


@pytest.mark.parametrize(
    "roles",
    [None, [], ["user"], ["unrecognized_role"]],
)
def test_oidc_defaults_non_admin_accounts_to_user(
    oidc_authenticator: tuple[OIDCAuthenticator, Callable[..., str]],
    roles: list[str] | None,
) -> None:
    authenticator, issue_token = oidc_authenticator
    extra = {} if roles is None else {ROLES_CLAIM: roles}
    token = issue_token(**extra)

    principal = authenticator.authenticate(f"Bearer {token}")

    assert principal == Principal(user_id="auth0|user-1", role=UserRole.USER)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://wrong-tenant.example/"},
        {"aud": "https://wrong-api.example"},
        {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        {"sub": ""},
    ],
)
def test_oidc_rejects_invalid_identity_claims(
    oidc_authenticator: tuple[OIDCAuthenticator, Callable[..., str]],
    overrides: dict[str, object],
) -> None:
    authenticator, issue_token = oidc_authenticator
    token = issue_token(**overrides)

    with pytest.raises(PlatformError) as exc_info:
        authenticator.authenticate(f"Bearer {token}")

    assert exc_info.value.status_code == 403


def test_security_admin_guard_rejects_user() -> None:
    with pytest.raises(PlatformError) as exc_info:
        require_security_admin(Principal(user_id="auth0|user-1", role=UserRole.USER))

    assert exc_info.value.status_code == 403


def test_security_admin_guard_accepts_admin() -> None:
    require_security_admin(Principal(user_id="auth0|admin-1", role=UserRole.SECURITY_ADMIN))
