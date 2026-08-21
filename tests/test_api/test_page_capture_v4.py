from __future__ import annotations

import pytest

from src.api.dependencies import get_page_capture_service
from src.config import get_settings
from src.main import app
from src.services.page_capture import PageCaptureResult

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


class FakeCaptureService:
    def __init__(self) -> None:
        self.targets: list[str] = []

    async def capture(self, target: str) -> PageCaptureResult:
        self.targets.append(target)
        return PageCaptureResult(b"jpeg-image", "image/jpeg", target)


@pytest.mark.asyncio
async def test_owner_can_capture_only_a_url_from_their_analysis_with_fresh_consent(client) -> None:
    created = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra giúp tôi https://example.com/login có đáng tin không"},
    )
    assert created.status_code == 200
    analysis_id = created.json()["analysis_id"]
    capture = FakeCaptureService()
    settings = get_settings()
    previous = settings.security_page_capture_enabled
    settings.security_page_capture_enabled = True
    app.dependency_overrides[get_page_capture_service] = lambda: capture
    try:
        missing_consent = await client.post(
            f"/api/v4/analyses/{analysis_id}/page-capture",
            headers=USER_HEADERS,
            json={"url_index": 0},
        )
        invalid_index = await client.post(
            f"/api/v4/analyses/{analysis_id}/page-capture",
            headers=USER_HEADERS,
            json={"url_index": 1, "external_url_lookup": True},
        )
        forbidden = await client.post(
            f"/api/v4/analyses/{analysis_id}/page-capture",
            headers=ADMIN_HEADERS,
            json={"url_index": 0, "external_url_lookup": True},
        )
        response = await client.post(
            f"/api/v4/analyses/{analysis_id}/page-capture",
            headers=USER_HEADERS,
            json={"url_index": 0, "external_url_lookup": True},
        )
    finally:
        app.dependency_overrides.pop(get_page_capture_service, None)
        settings.security_page_capture_enabled = previous

    assert missing_consent.status_code == 422
    assert invalid_index.status_code == 422
    assert forbidden.status_code == 403
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["cache-control"] == "private, no-store, max-age=0"
    assert response.content == b"jpeg-image"
    assert capture.targets == ["https://example.com/login"]
