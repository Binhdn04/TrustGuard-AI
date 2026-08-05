from __future__ import annotations

from src.models import ToolError


class ToolCallError(RuntimeError):
    """Adapter failure with a stable, workflow-friendly error payload."""

    def __init__(self, tool: str, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.error = ToolError(tool=tool, code=code, message=message, retryable=retryable)


class UnsafeUrlError(ToolCallError):
    def __init__(self, message: str) -> None:
        super().__init__("url_scanner", "SSRF_BLOCKED", message, retryable=False)
