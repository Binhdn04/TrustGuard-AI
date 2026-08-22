from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any

from src.services.page_capture import PageCaptureError, PageCaptureService

_MAX_REQUEST_BYTES = 65_536


def _number(payload: dict[str, Any], name: str, *, minimum: float, maximum: float) -> float:
    value = payload.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"Invalid {name}")
    number = float(value)
    if number < minimum or number > maximum:
        raise ValueError(f"Invalid {name}")
    return number


async def _capture(payload: dict[str, Any]) -> dict[str, Any]:
    url = payload.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("Invalid URL")
    timeout_seconds = _number(payload, "timeout_seconds", minimum=1.0, maximum=60.0)
    viewport_width = int(_number(payload, "viewport_width", minimum=320, maximum=2560))
    viewport_height = int(_number(payload, "viewport_height", minimum=240, maximum=1440))
    jpeg_quality = int(_number(payload, "jpeg_quality", minimum=20, maximum=95))
    max_image_bytes = int(_number(payload, "max_image_bytes", minimum=1_000, maximum=20_000_000))
    service = PageCaptureService(
        timeout_seconds=timeout_seconds,
        max_image_bytes=max_image_bytes,
        max_concurrency=1,
        viewport_width=viewport_width,
        viewport_height=viewport_height,
        jpeg_quality=jpeg_quality,
        isolate_renderer_process=False,
    )
    try:
        result = await service.capture(url)
    finally:
        await service.aclose()
    return {
        "ok": True,
        "media_type": result.media_type,
        "final_url": result.final_url,
        "content_base64": base64.b64encode(result.content).decode("ascii"),
    }


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if len(raw) > _MAX_REQUEST_BYTES:
            raise ValueError("Capture request is too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Capture request must be an object")
        response = asyncio.run(_capture(payload))
    except PageCaptureError as exc:
        response = {
            "ok": False,
            "code": exc.code,
            "message": exc.message,
            "retryable": exc.retryable,
        }
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        response = {
            "ok": False,
            "code": "INVALID_TARGET",
            "message": "The page capture request is invalid.",
            "retryable": False,
        }
    except Exception:
        response = {
            "ok": False,
            "code": "CAPTURE_FAILED",
            "message": "The destination page could not be captured.",
            "retryable": True,
        }
    sys.stdout.write(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
