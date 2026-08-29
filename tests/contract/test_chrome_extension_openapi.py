from pathlib import Path

from scripts.export_extension_openapi import EXTENSION_OPERATIONS, serialize_extension_openapi

SNAPSHOT = Path(__file__).parents[2] / "extension" / "contracts" / "openapi-v4.json"


def test_chrome_extension_openapi_snapshot_has_required_v4_operations() -> None:
    expected = {
        ("/api/v4/analyses", "post"),
        ("/api/v4/analyses/{analysis_id}", "get"),
        ("/api/v4/analyses/{analysis_id}/events", "get"),
        ("/api/v4/capabilities", "get"),
        ("/api/v4/ws-tickets", "post"),
    }
    assert EXTENSION_OPERATIONS == expected


def test_chrome_extension_openapi_snapshot_does_not_drift() -> None:
    assert SNAPSHOT.read_text(encoding="utf-8") == serialize_extension_openapi()
