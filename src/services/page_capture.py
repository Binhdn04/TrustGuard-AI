from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import unquote, urlsplit

from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.network import SsrfGuard


class PageCaptureError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass(frozen=True)
class PageCaptureResult:
    content: bytes
    media_type: str
    final_url: str


class PageRenderer(Protocol):
    async def render(self, url: str) -> PageCaptureResult: ...

    async def aclose(self) -> None: ...


RouteGuard = Callable[[str, str], Awaitable[bool]]

_BLOCKED_RESOURCE_TYPES = frozenset({"media", "eventsource", "websocket", "texttrack"})
_BLOCKED_DOWNLOAD_SUFFIXES = frozenset(
    {
        ".7z",
        ".apk",
        ".appx",
        ".bat",
        ".bz2",
        ".cab",
        ".cmd",
        ".com",
        ".deb",
        ".dmg",
        ".doc",
        ".docm",
        ".docx",
        ".exe",
        ".gz",
        ".img",
        ".iso",
        ".jar",
        ".jsb",
        ".msi",
        ".msix",
        ".pkg",
        ".ppt",
        ".pptm",
        ".pptx",
        ".ps1",
        ".rar",
        ".rpm",
        ".scr",
        ".tar",
        ".vbs",
        ".vhd",
        ".vhdx",
        ".xls",
        ".xlsm",
        ".xlsx",
        ".xz",
        ".zip",
    }
)


def _looks_like_download(url: str) -> bool:
    path = unquote(urlsplit(url).path).casefold()
    return any(path.endswith(suffix) for suffix in _BLOCKED_DOWNLOAD_SUFFIXES)


class PlaywrightPageRenderer:
    """Render a bounded viewport in a fresh, unauthenticated browser context."""

    def __init__(
        self,
        *,
        route_guard: RouteGuard,
        timeout_seconds: float,
        viewport_width: int,
        viewport_height: int,
        jpeg_quality: int,
        max_image_bytes: int,
        isolate_process: bool = True,
    ) -> None:
        self._route_guard = route_guard
        self._timeout_seconds = timeout_seconds
        self._timeout_ms = int(timeout_seconds * 1000)
        self._viewport = {"width": viewport_width, "height": viewport_height}
        self._jpeg_quality = jpeg_quality
        self._max_image_bytes = max_image_bytes
        self._isolate_process = isolate_process

    async def render(self, url: str) -> PageCaptureResult:
        if self._isolate_process:
            return await asyncio.to_thread(self._render_in_subprocess, url)
        return await self._render_locally(url)

    def _render_in_subprocess(self, url: str) -> PageCaptureResult:
        payload = json.dumps(
            {
                "url": url,
                "timeout_seconds": self._timeout_seconds,
                "viewport_width": self._viewport["width"],
                "viewport_height": self._viewport["height"],
                "jpeg_quality": self._jpeg_quality,
                "max_image_bytes": self._max_image_bytes,
            }
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "src.services.page_capture_worker"],
                input=payload,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds + 2.0,
                check=False,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            raise PageCaptureError(
                "PROVIDER_TIMEOUT",
                "Page capture timed out.",
                retryable=True,
            ) from exc
        except OSError as exc:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The page capture process could not be started.",
                retryable=True,
            ) from exc

        if completed.returncode != 0:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The destination page could not be captured.",
                retryable=True,
            )
        try:
            response = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The page capture process returned an invalid response.",
                retryable=True,
            ) from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            code = response.get("code", "CAPTURE_FAILED") if isinstance(response, dict) else "CAPTURE_FAILED"
            message = (
                response.get("message", "The destination page could not be captured.")
                if isinstance(response, dict)
                else "The destination page could not be captured."
            )
            retryable = bool(response.get("retryable", True)) if isinstance(response, dict) else True
            raise PageCaptureError(str(code), str(message), retryable=retryable)
        try:
            content = base64.b64decode(response["content_base64"], validate=True)
            media_type = str(response["media_type"])
            final_url = str(response["final_url"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The page capture process returned an invalid response.",
                retryable=True,
            ) from exc
        if media_type != "image/jpeg" or not final_url:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The page capture process returned an invalid response.",
                retryable=True,
            )
        return PageCaptureResult(content=content, media_type=media_type, final_url=final_url)

    async def _render_locally(self, url: str) -> PageCaptureResult:
        try:
            from playwright.async_api import Error as PlaywrightError
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - depends on deployment image
            raise PageCaptureError(
                "NOT_CONFIGURED",
                "Page capture runtime is not installed.",
            ) from exc

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-background-networking",
                        "--disable-component-update",
                        "--disable-default-apps",
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-sync",
                        "--no-first-run",
                    ],
                )
                try:
                    context = await browser.new_context(
                        accept_downloads=False,
                        bypass_csp=False,
                        ignore_https_errors=False,
                        java_script_enabled=True,
                        permissions=[],
                        service_workers="block",
                        viewport=self._viewport,
                    )
                    page = await context.new_page()
                    page.set_default_navigation_timeout(self._timeout_ms)
                    page.set_default_timeout(self._timeout_ms)

                    async def guard_route(route) -> None:
                        request = route.request
                        if await self._route_guard(request.url, request.resource_type):
                            await route.continue_()
                        else:
                            await route.abort("blockedbyclient")

                    async def cancel_download(download) -> None:
                        await download.cancel()

                    async def close_popup(popup) -> None:
                        await popup.close()

                    page.on("download", cancel_download)
                    page.on("popup", close_popup)
                    await context.route("**/*", guard_route)
                    await page.goto(url, wait_until="domcontentloaded", timeout=self._timeout_ms)
                    await page.wait_for_timeout(350)
                    final_url = page.url
                    if not await self._route_guard(final_url, "document"):
                        raise PageCaptureError("SSRF_BLOCKED", "The final page URL is not allowed.")
                    content = await page.screenshot(
                        type="jpeg",
                        quality=self._jpeg_quality,
                        full_page=False,
                        animations="disabled",
                        caret="hide",
                    )
                    return PageCaptureResult(content=content, media_type="image/jpeg", final_url=final_url)
                finally:
                    await browser.close()
        except PageCaptureError:
            raise
        except PlaywrightTimeoutError as exc:
            raise PageCaptureError(
                "PROVIDER_TIMEOUT",
                "Page capture timed out.",
                retryable=True,
            ) from exc
        except PlaywrightError as exc:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The destination page could not be captured.",
                retryable=True,
            ) from exc
        except (NotImplementedError, OSError) as exc:
            raise PageCaptureError(
                "CAPTURE_FAILED",
                "The page capture runtime is unavailable.",
                retryable=True,
            ) from exc

    async def aclose(self) -> None:
        # Each request owns and closes its isolated browser instance.
        return None


class PageCaptureService:
    def __init__(
        self,
        renderer: PageRenderer | None = None,
        *,
        guard: SsrfGuard | None = None,
        timeout_seconds: float = 12.0,
        max_image_bytes: int = 2_000_000,
        max_concurrency: int = 2,
        viewport_width: int = 1280,
        viewport_height: int = 720,
        jpeg_quality: int = 72,
        isolate_renderer_process: bool = True,
    ) -> None:
        self._guard = guard or SsrfGuard()
        self._timeout_seconds = timeout_seconds
        self._max_image_bytes = max_image_bytes
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._renderer = renderer or PlaywrightPageRenderer(
            route_guard=self._allow_request,
            timeout_seconds=timeout_seconds,
            viewport_width=viewport_width,
            viewport_height=viewport_height,
            jpeg_quality=jpeg_quality,
            max_image_bytes=max_image_bytes,
            isolate_process=isolate_renderer_process,
        )

    async def _allow_request(self, url: str, resource_type: str) -> bool:
        if resource_type in _BLOCKED_RESOURCE_TYPES or _looks_like_download(url):
            return False
        scheme = urlsplit(url).scheme.casefold()
        if scheme in {"data", "blob"}:
            return True
        if scheme not in {"http", "https"}:
            return False
        try:
            await self._guard.validate(url)
        except (UnsafeUrlError, ToolCallError, ValueError):
            return False
        return True

    async def capture(self, url: str) -> PageCaptureResult:
        if _looks_like_download(url):
            raise PageCaptureError("INVALID_TARGET", "Downloadable files cannot be captured.")
        try:
            await self._guard.validate(url)
        except UnsafeUrlError as exc:
            raise PageCaptureError("SSRF_BLOCKED", str(exc)) from exc
        except ToolCallError as exc:
            raise PageCaptureError(exc.error.code, exc.error.message, retryable=exc.error.retryable) from exc
        async with self._semaphore:
            try:
                async with asyncio.timeout(self._timeout_seconds + 3.0):
                    result = await self._renderer.render(url)
            except TimeoutError as exc:
                raise PageCaptureError(
                    "PROVIDER_TIMEOUT",
                    "Page capture timed out.",
                    retryable=True,
                ) from exc
        if not await self._allow_request(result.final_url, "document"):
            raise PageCaptureError("SSRF_BLOCKED", "The final page URL is not allowed.")
        if not result.content or len(result.content) > self._max_image_bytes:
            raise PageCaptureError("RESPONSE_TOO_LARGE", "Captured image exceeded the allowed size.")
        return result

    async def aclose(self) -> None:
        await self._renderer.aclose()


__all__ = [
    "PageCaptureError",
    "PageCaptureResult",
    "PageCaptureService",
    "PageRenderer",
    "PlaywrightPageRenderer",
]
