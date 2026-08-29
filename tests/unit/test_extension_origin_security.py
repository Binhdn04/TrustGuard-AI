from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from src.api import security_v4
from src.api.dependencies import get_ticket_manager
from src.config import Settings, get_settings
from src.core.auth import Principal, UserRole
from src.main import app
from src.services.realtime import MemoryTicketStore, TicketGrant, WebSocketTicketManager

EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
EXTENSION_ORIGIN = f"chrome-extension://{EXTENSION_ID}"
UNAPPROVED_EXTENSION_ORIGIN = f"chrome-extension://{'b' * 32}"


class FakeTicketManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def consume(self, ticket: str, analysis_id) -> None:
        self.calls.append((ticket, analysis_id))
        return None


class FakeWebSocket:
    def __init__(self, origin: str | None, tickets: FakeTicketManager) -> None:
        self.headers = {} if origin is None else {"origin": origin}
        self.app = SimpleNamespace(dependency_overrides={get_ticket_manager: lambda: tickets})
        self.closed: tuple[int, str] | None = None

    async def close(self, *, code: int, reason: str) -> None:
        self.closed = (code, reason)


def test_extension_origins_are_exact_normalized_and_separate_from_web_origins() -> None:
    settings = Settings(
        cors_origins="http://localhost:3000/, https://app.example",
        chrome_extension_origins=f"{EXTENSION_ORIGIN}/,{EXTENSION_ORIGIN}",
        _env_file=None,
    )

    assert settings.cors_origins == "http://localhost:3000,https://app.example"
    assert settings.chrome_extension_origins == EXTENSION_ORIGIN
    assert settings.browser_origins() == [
        "http://localhost:3000",
        "https://app.example",
        EXTENSION_ORIGIN,
    ]
    assert settings.browser_origin_allowed(EXTENSION_ORIGIN) is True
    assert settings.browser_origin_allowed(f"{EXTENSION_ORIGIN}/") is False
    assert settings.browser_origin_allowed(None) is False


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "",
        "https://user:password@app.example",
        "https://app.example/path",
        "https://app.example?query=1",
        "https://app.example#fragment",
        EXTENSION_ORIGIN,
    ],
)
def test_web_origin_configuration_rejects_non_exact_values(origin: str) -> None:
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(cors_origins=origin, _env_file=None)


def test_application_cors_middleware_uses_combined_browser_origins() -> None:
    cors_middleware = next(middleware for middleware in app.user_middleware if middleware.cls.__name__ == "CORSMiddleware")

    assert cors_middleware.kwargs["allow_origins"] == get_settings().browser_origins()


@pytest.mark.asyncio
async def test_http_cors_preflight_allows_only_exact_extension_origin() -> None:
    settings = Settings(chrome_extension_origins=EXTENSION_ORIGIN, _env_file=None)
    application = FastAPI()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.browser_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        approved = await client.options(
            "/api/v4/capabilities",
            headers={"Origin": EXTENSION_ORIGIN, "Access-Control-Request-Method": "GET"},
        )
        rejected = await client.options(
            "/api/v4/capabilities",
            headers={"Origin": UNAPPROVED_EXTENSION_ORIGIN, "Access-Control-Request-Method": "GET"},
        )

    assert approved.status_code == 200
    assert approved.headers["access-control-allow-origin"] == EXTENSION_ORIGIN
    assert rejected.status_code == 400
    assert "access-control-allow-origin" not in rejected.headers


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "chrome-extension://*",
        "chrome-extension://short-id",
        f"chrome-extension://{EXTENSION_ID.upper()}",
        f"{EXTENSION_ORIGIN}/path",
        f"{EXTENSION_ORIGIN}?query=1",
        f"{EXTENSION_ORIGIN}#fragment",
        f"https://{EXTENSION_ID}",
    ],
)
def test_extension_origin_configuration_rejects_non_exact_values(origin: str) -> None:
    with pytest.raises(ValidationError, match="CHROME_EXTENSION_ORIGINS"):
        Settings(chrome_extension_origins=origin, _env_file=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("origin", [None, "https://attacker.example", UNAPPROVED_EXTENSION_ORIGIN])
async def test_websocket_rejects_missing_or_unapproved_origin_before_consuming_ticket(
    monkeypatch: pytest.MonkeyPatch,
    origin: str | None,
) -> None:
    tickets = FakeTicketManager()
    websocket = FakeWebSocket(origin, tickets)
    settings = Settings(chrome_extension_origins=EXTENSION_ORIGIN, _env_file=None)
    monkeypatch.setattr(security_v4, "get_settings", lambda: settings)

    await security_v4.security_analysis_stream_v4(
        cast(WebSocket, websocket),
        uuid4(),
        ticket="single-use-private-ticket",
        cursor=None,
    )

    assert websocket.closed == (4403, "WebSocket origin is not allowed.")
    assert tickets.calls == []


@pytest.mark.asyncio
async def test_websocket_allows_exact_extension_origin_to_reach_ticket_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tickets = FakeTicketManager()
    websocket = FakeWebSocket(EXTENSION_ORIGIN, tickets)
    settings = Settings(chrome_extension_origins=EXTENSION_ORIGIN, _env_file=None)
    monkeypatch.setattr(security_v4, "get_settings", lambda: settings)
    analysis_id = uuid4()

    await security_v4.security_analysis_stream_v4(
        cast(WebSocket, websocket),
        analysis_id,
        ticket="single-use-private-ticket",
        cursor=None,
    )

    assert tickets.calls == [("single-use-private-ticket", analysis_id)]
    assert websocket.closed == (4403, "Invalid or expired WebSocket ticket.")


@pytest.mark.asyncio
async def test_websocket_ticket_is_analysis_bound_single_use_and_rejects_expiry() -> None:
    principal = Principal("owner-1", UserRole.USER)
    first_analysis = uuid4()
    second_analysis = uuid4()
    manager = WebSocketTicketManager(MemoryTicketStore(), ttl_seconds=60)

    assert await manager.consume("", first_analysis) is None

    mismatched, _ = await manager.issue(first_analysis, principal)
    assert await manager.consume(mismatched, second_analysis) is None
    assert await manager.consume(mismatched, first_analysis) is None

    valid, _ = await manager.issue(first_analysis, principal)
    assert await manager.consume(valid, first_analysis) == principal
    assert await manager.consume(valid, first_analysis) is None

    class ExpiredStore:
        grant: TicketGrant | None = None

        async def put(self, digest: str, grant: TicketGrant, ttl_seconds: int) -> None:
            del digest, ttl_seconds
            self.grant = replace(grant, expires_at=datetime.now(UTC) - timedelta(seconds=1))

        async def pop(self, digest: str) -> TicketGrant | None:
            del digest
            grant, self.grant = self.grant, None
            return grant if grant is not None and grant.expires_at > datetime.now(UTC) else None

        async def close(self) -> None:
            self.grant = None

    expired_manager = WebSocketTicketManager(ExpiredStore(), ttl_seconds=60)
    expired, _ = await expired_manager.issue(first_analysis, principal)
    assert await expired_manager.consume(expired, first_analysis) is None
