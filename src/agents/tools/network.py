from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

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


@dataclass(frozen=True)
class ValidatedTarget:
    """A URL together with the DNS answers that passed the SSRF policy."""

    url: str
    host: str
    port: int
    addresses: tuple[str, ...]

    def pinned_url(self, address: str) -> str:
        parsed = urlsplit(self.url)
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        literal = f"[{ip}]" if ip.version == 6 else str(ip)
        default_port = 443 if parsed.scheme.casefold() == "https" else 80
        authority = literal if self.port == default_port else f"{literal}:{self.port}"
        return urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, parsed.fragment))

    @property
    def host_header(self) -> str:
        default_port = 443 if urlsplit(self.url).scheme.casefold() == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == default_port else f"{host}:{self.port}"


class SsrfGuard:
    """Reject URLs that can reach local, private, metadata, or special networks."""

    _blocked_hosts = frozenset({"localhost", "metadata.google.internal", "metadata.azure.internal"})

    def __init__(self, *, resolver: Resolver = system_resolver, policy: SsrfPolicy | None = None) -> None:
        self._resolver = resolver
        self.policy = policy or SsrfPolicy()

    async def validate(self, url: str) -> ValidatedTarget:
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
        return ValidatedTarget(url=url, host=host, port=port, addresses=tuple(addresses))


class GuardedHttpClient:
    """Small HTTP boundary that revalidates DNS after every redirect."""

    def __init__(self, client: httpx.AsyncClient, guard: SsrfGuard | None = None) -> None:
        self._client = client
        self._guard = guard or SsrfGuard()

    async def get(self, url: str, **kwargs: object) -> tuple[httpx.Response, list[str]]:
        current = url
        chain = [url]
        visited = {url}
        request_headers = dict(kwargs.pop("headers", {}) or {})
        request_extensions = dict(kwargs.pop("extensions", {}) or {})
        kwargs.pop("follow_redirects", None)
        for redirect_number in range(self._guard.policy.max_redirects + 1):
            try:
                target = await self._guard.validate(current)
            except ToolCallError as exc:
                exc.network_calls = redirect_number
                raise
            # Connect to the exact DNS answer that was checked.  The original
            # hostname is retained for HTTP routing and TLS SNI/certificate
            # verification, eliminating the validation/request DNS race.
            headers = request_headers.copy()
            headers["host"] = target.host_header
            extensions = request_extensions.copy()
            # httpcore/anyio expects the SNI hostname as text and performs its
            # own IDNA/ASCII encoding. Passing bytes reaches TLSStream.wrap()
            # and crashes with ``bytes has no attribute encode``.
            extensions["sni_hostname"] = target.host
            request = self._client.build_request(
                "GET",
                target.pinned_url(target.addresses[0]),
                headers=headers,
                extensions=extensions,
                **kwargs,
            )
            # ``AsyncClient.get`` eagerly buffers the complete response. Use
            # streaming so the byte limit is enforced while data arrives.
            response = await self._client.send(request, stream=True, follow_redirects=False)
            location = response.headers.get("location")
            if response.is_redirect and location:
                await response.aclose()
                if redirect_number >= self._guard.policy.max_redirects:
                    raise ToolCallError("url_scanner", "TOO_MANY_REDIRECTS", "Redirect limit exceeded")
                current = urljoin(current, location)
                if current in visited:
                    error = ToolCallError("redirect_resolver", "REDIRECT_LOOP", "Redirect chain contains a loop")
                    error.network_calls = redirect_number + 1
                    raise error
                visited.add(current)
                chain.append(current)
                continue
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    advertised_size = int(content_length)
                except ValueError as exc:
                    await response.aclose()
                    raise ToolCallError(
                        "url_scanner", "PROVIDER_ERROR", "Response has an invalid content length"
                    ) from exc
                if advertised_size > self._guard.policy.max_response_bytes:
                    await response.aclose()
                    raise ToolCallError("url_scanner", "RESPONSE_TOO_LARGE", "Provider response is too large")
            body = bytearray()
            try:
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > self._guard.policy.max_response_bytes:
                        raise ToolCallError("url_scanner", "RESPONSE_TOO_LARGE", "Provider response is too large")
                    body.extend(chunk)
            finally:
                await response.aclose()
            response_headers = response.headers.copy()
            response_headers.pop("content-encoding", None)
            response_headers.pop("content-length", None)
            response_headers.pop("transfer-encoding", None)
            bounded_response = httpx.Response(
                response.status_code,
                headers=response_headers,
                content=bytes(body),
                request=request,
                extensions=response.extensions,
            )
            return bounded_response, chain
        raise ToolCallError("url_scanner", "TOO_MANY_REDIRECTS", "Redirect limit exceeded")
