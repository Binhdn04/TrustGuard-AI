from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from src.agents.tools.advanced import PlaywrightScreenshotRenderer
from src.agents.tools.models import ToolResultStatus
from src.services.platform_wave2 import ArtifactRecord


class ScreenshotArtifactRepository(Protocol):
    async def register_artifact(self, artifact: ArtifactRecord) -> None: ...


class ScreenshotCaptureCoordinator:
    """Capture a public URL in a fresh browser context and retain only PNG bytes.

    The renderer boundary performs SSRF validation before navigation and after
    redirects. This coordinator never persists DOM, visible text, cookies, or
    form data.
    """

    def __init__(
        self,
        repository: ScreenshotArtifactRepository,
        storage_root: str,
        *,
        retention_days: int = 30,
        timeout_seconds: float = 8,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self._repository = repository
        self._storage_root = Path(storage_root).resolve()
        self._retention_days = retention_days
        self._timeout_seconds = timeout_seconds
        self._max_bytes = max_bytes

    async def capture(self, analysis_id: UUID, owner_id: str, normalized_url: str) -> bool:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False

        artifact_id = uuid4()
        storage_key = f"screenshots/{analysis_id}/{artifact_id}.png"
        destination = (self._storage_root / storage_key).resolve()
        if not destination.is_relative_to(self._storage_root):
            return False

        async def capture_page(url: str, **options):
            download_attempted = False
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        accept_downloads=bool(options.get("accept_downloads", False)),
                        storage_state=options.get("storage_state"),
                        service_workers="block",
                    )
                    try:
                        revalidate = options.get("revalidate")

                        async def validate_request(route) -> None:
                            scheme = urlsplit(route.request.url).scheme.lower()
                            if scheme in {"data", "blob"}:
                                await route.continue_()
                                return
                            if scheme not in {"http", "https"} or revalidate is None:
                                await route.abort()
                                return
                            try:
                                await revalidate(route.request.url)
                            except Exception:
                                await route.abort()
                                return
                            await route.continue_()

                        await context.route("**/*", validate_request)
                        page = await context.new_page()

                        def mark_download(_download) -> None:
                            nonlocal download_attempted
                            download_attempted = True

                        page.on("download", mark_download)
                        response = await page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=int(self._timeout_seconds * 1000),
                        )
                        image = await page.screenshot(type="png", full_page=False)
                        return {
                            "image": image,
                            "final_url": page.url,
                            "visible_text": "",
                            "signals": [f"http_status:{response.status}"] if response else [],
                            "download_attempted": download_attempted,
                        }
                    finally:
                        await context.close()
                finally:
                    await browser.close()

        async def store(image: bytes) -> UUID:
            if not image or len(image) > self._max_bytes:
                raise ValueError("screenshot artifact exceeds the allowed size")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(".tmp")
            try:
                with temporary.open("xb") as handle:
                    handle.write(image)
                os.replace(temporary, destination)
                now = datetime.now(UTC)
                artifact = ArtifactRecord(
                    artifact_id=artifact_id,
                    analysis_id=analysis_id,
                    owner_id=owner_id,
                    storage_key=storage_key,
                    media_type="image/png",
                    size_bytes=len(image),
                    sha256=sha256(image).hexdigest(),
                    created_at=now,
                    expires_at=now + timedelta(days=self._retention_days),
                )
                await self._repository.register_artifact(artifact)
                return artifact_id
            except Exception:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise

        renderer = PlaywrightScreenshotRenderer(
            capture_page,
            store,
            timeout_seconds=self._timeout_seconds,
        )
        result = await renderer.render(normalized_url)
        return result.status is ToolResultStatus.SUCCESS


__all__ = ["ScreenshotCaptureCoordinator"]
