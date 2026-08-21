from __future__ import annotations

import base64
import json
import subprocess

import pytest

from src.agents.tools.network import SsrfGuard
from src.services.page_capture import (
    PageCaptureError,
    PageCaptureResult,
    PageCaptureService,
    PlaywrightPageRenderer,
)


class FakeRenderer:
    def __init__(self, result: PageCaptureResult) -> None:
        self.result = result
        self.urls: list[str] = []

    async def render(self, url: str) -> PageCaptureResult:
        self.urls.append(url)
        return self.result

    async def aclose(self) -> None:
        return None


async def public_resolver(_host: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


@pytest.mark.asyncio
async def test_page_capture_returns_bounded_private_image() -> None:
    renderer = FakeRenderer(PageCaptureResult(b"jpeg", "image/jpeg", "https://example.com/landing"))
    service = PageCaptureService(
        renderer,
        guard=SsrfGuard(resolver=public_resolver),
        max_image_bytes=10,
    )

    result = await service.capture("https://example.com/")

    assert result.content == b"jpeg"
    assert renderer.urls == ["https://example.com/"]


@pytest.mark.asyncio
async def test_page_capture_rejects_private_targets_before_renderer() -> None:
    renderer = FakeRenderer(PageCaptureResult(b"jpeg", "image/jpeg", "http://127.0.0.1/"))
    service = PageCaptureService(renderer)

    with pytest.raises(PageCaptureError, match="non-public") as captured:
        await service.capture("http://127.0.0.1/")

    assert captured.value.code == "SSRF_BLOCKED"
    assert renderer.urls == []


@pytest.mark.asyncio
async def test_page_capture_rejects_oversized_images() -> None:
    renderer = FakeRenderer(PageCaptureResult(b"too-large", "image/jpeg", "https://example.com/"))
    service = PageCaptureService(
        renderer,
        guard=SsrfGuard(resolver=public_resolver),
        max_image_bytes=4,
    )

    with pytest.raises(PageCaptureError) as captured:
        await service.capture("https://example.com/")

    assert captured.value.code == "RESPONSE_TOO_LARGE"


@pytest.mark.asyncio
async def test_page_capture_rejects_download_targets_before_renderer() -> None:
    renderer = FakeRenderer(PageCaptureResult(b"jpeg", "image/jpeg", "https://example.com/payload.exe"))
    service = PageCaptureService(
        renderer,
        guard=SsrfGuard(resolver=public_resolver),
    )

    with pytest.raises(PageCaptureError) as captured:
        await service.capture("https://example.com/download/PAYLOAD%2EEXE?source=message")

    assert captured.value.code == "INVALID_TARGET"
    assert renderer.urls == []


@pytest.mark.asyncio
async def test_page_capture_blocks_active_streams_and_download_subresources() -> None:
    service = PageCaptureService(
        FakeRenderer(PageCaptureResult(b"jpeg", "image/jpeg", "https://example.com/")),
        guard=SsrfGuard(resolver=public_resolver),
    )

    assert await service._allow_request("https://example.com/socket", "websocket") is False
    assert await service._allow_request("https://example.com/archive.zip", "fetch") is False
    assert await service._allow_request("https://example.com/challenge.js", "script") is True


@pytest.mark.asyncio
async def test_playwright_renderer_uses_private_worker_protocol(monkeypatch) -> None:
    calls: list[tuple[list[str], str]] = []

    def run_worker(command, **kwargs):
        calls.append((command, kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "ok": True,
                    "media_type": "image/jpeg",
                    "final_url": "https://example.com/landing",
                    "content_base64": base64.b64encode(b"jpeg").decode(),
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("src.services.page_capture.subprocess.run", run_worker)

    async def allow_request(_url: str, _resource_type: str) -> bool:
        return True

    renderer = PlaywrightPageRenderer(
        route_guard=allow_request,
        timeout_seconds=12,
        viewport_width=1280,
        viewport_height=720,
        jpeg_quality=72,
        max_image_bytes=2_000_000,
    )
    result = await renderer.render("https://example.com/private-path")

    assert result.content == b"jpeg"
    assert calls[0][0][-1] == "src.services.page_capture_worker"
    assert "https://example.com/private-path" not in calls[0][0]
    assert json.loads(calls[0][1])["url"] == "https://example.com/private-path"


@pytest.mark.asyncio
async def test_playwright_renderer_maps_worker_errors(monkeypatch) -> None:
    def run_worker(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "ok": False,
                    "code": "PROVIDER_TIMEOUT",
                    "message": "Page capture timed out.",
                    "retryable": True,
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("src.services.page_capture.subprocess.run", run_worker)

    async def allow_request(_url: str, _resource_type: str) -> bool:
        return True

    renderer = PlaywrightPageRenderer(
        route_guard=allow_request,
        timeout_seconds=12,
        viewport_width=1280,
        viewport_height=720,
        jpeg_quality=72,
        max_image_bytes=2_000_000,
    )

    with pytest.raises(PageCaptureError) as captured:
        await renderer.render("https://example.com/")

    assert captured.value.code == "PROVIDER_TIMEOUT"
    assert captured.value.retryable is True
