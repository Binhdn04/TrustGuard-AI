from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from src.agents.tools.errors import ToolCallError, UnsafeUrlError

Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(record[4][0] for record in records))


@dataclass(frozen=True)
class SsrfPolicy:
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allowed_ports: frozenset[int] = frozenset({80, 443})
    max_redirects: int = 5
    max_response_bytes: int = 1_000_000


class SsrfGuard:
    """Reject URLs that can reach local, private, metadata, or special networks."""

    _blocked_hosts = frozenset({"localhost", "metadata.google.internal", "metadata.azure.internal"})

    def __init__(self, *, resolver: Resolver = system_resolver, policy: SsrfPolicy | None = None) -> None:
        self._resolver = resolver
        self.policy = policy or SsrfPolicy()

    async def validate(self, url: str) -> str:
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
        except ValueError as exc:
            raise UnsafeUrlError("URL has an invalid port") from exc
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold().rstrip(".")
        if scheme not in self.policy.allowed_schemes or not host:
            raise UnsafeUrlError("Only absolute HTTP(S) URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise UnsafeUrlError("URLs containing credentials are not allowed")
        if port not in self.policy.allowed_ports:
            raise UnsafeUrlError(f"Port {port} is not allowed")
        if host in self._blocked_hosts or host.endswith(".localhost"):
            raise UnsafeUrlError(f"Host {host} is blocked")
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addresses = await self._resolver(host, port)
            except (OSError, socket.gaierror) as exc:
                raise ToolCallError("url_scanner", "DNS_ERROR", "Could not resolve URL host", retryable=True) from exc
        if not addresses:
            raise ToolCallError("url_scanner", "DNS_ERROR", "URL host resolved to no addresses", retryable=True)
        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(raw_address.split("%", 1)[0])
            except ValueError as exc:
                raise UnsafeUrlError("DNS returned an invalid address") from exc
            if not address.is_global:
                raise UnsafeUrlError(f"Host resolves to a non-public address ({address})")
        return url


class GuardedHttpClient:
    """Small HTTP boundary that revalidates DNS after every redirect."""

    def __init__(self, client: httpx.AsyncClient, guard: SsrfGuard | None = None) -> None:
        self._client = client
        self._guard = guard or SsrfGuard()

    async def get(self, url: str, **kwargs: object) -> tuple[httpx.Response, list[str]]:
        current = url
        chain = [url]
        for redirect_number in range(self._guard.policy.max_redirects + 1):
            await self._guard.validate(current)
            response = await self._client.get(current, follow_redirects=False, **kwargs)
            location = response.headers.get("location")
            if response.is_redirect and location:
                if redirect_number >= self._guard.policy.max_redirects:
                    raise ToolCallError("url_scanner", "TOO_MANY_REDIRECTS", "Redirect limit exceeded")
                current = urljoin(current, location)
                chain.append(current)
                continue
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > self._guard.policy.max_response_bytes:
                raise ToolCallError("url_scanner", "RESPONSE_TOO_LARGE", "Provider response is too large")
            if len(response.content) > self._guard.policy.max_response_bytes:
                raise ToolCallError("url_scanner", "RESPONSE_TOO_LARGE", "Provider response is too large")
            return response, chain
        raise ToolCallError("url_scanner", "TOO_MANY_REDIRECTS", "Redirect limit exceeded")
