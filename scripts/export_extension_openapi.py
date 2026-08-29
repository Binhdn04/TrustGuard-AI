from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.main import app  # noqa: E402

EXTENSION_OPERATIONS = {
    ("/api/v4/analyses", "post"),
    ("/api/v4/analyses/{analysis_id}", "get"),
    ("/api/v4/analyses/{analysis_id}/events", "get"),
    ("/api/v4/capabilities", "get"),
    ("/api/v4/ws-tickets", "post"),
}


def _schema_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        reference = value.get("$ref")
        prefix = "#/components/schemas/"
        if isinstance(reference, str) and reference.startswith(prefix):
            references.add(reference.removeprefix(prefix))
        for child in value.values():
            references.update(_schema_references(child))
    elif isinstance(value, list):
        for child in value:
            references.update(_schema_references(child))
    return references


def extension_openapi_document() -> dict[str, Any]:
    source = app.openapi()
    paths: dict[str, dict[str, Any]] = {}
    for path, method in sorted(EXTENSION_OPERATIONS):
        operation = source["paths"][path][method]
        paths.setdefault(path, {})[method] = deepcopy(operation)

    source_schemas = source["components"]["schemas"]
    pending = _schema_references(paths)
    schemas: dict[str, Any] = {}
    while pending:
        name = pending.pop()
        if name in schemas:
            continue
        schema = deepcopy(source_schemas[name])
        schemas[name] = schema
        pending.update(_schema_references(schema) - schemas.keys())

    return {
        "openapi": source["openapi"],
        "info": {
            "title": "TrustGuard Chrome Extension API",
            "version": source["info"]["version"],
        },
        "paths": paths,
        "components": {"schemas": dict(sorted(schemas.items()))},
    }


def serialize_extension_openapi() -> str:
    return json.dumps(extension_openapi_document(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the Chrome Extension subset of the TrustGuard v4 OpenAPI.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialize_extension_openapi(), encoding="utf-8")


if __name__ == "__main__":
    main()
