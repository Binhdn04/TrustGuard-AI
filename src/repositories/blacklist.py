from __future__ import annotations

import asyncio
import ipaddress
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


def normalize_domain(domain: str) -> str:
    candidate = domain.strip().casefold().rstrip(".")
    if "://" in candidate or "/" in candidate or "@" in candidate:
        raise ValueError("domain must be a hostname, not a URL")
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc
    if not normalized or len(normalized) > 253:
        raise ValueError("domain is required and must not exceed 253 characters")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        labels = normalized.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError("domain is invalid")
        if any(not all(char.isalnum() or char == "-" for char in label) for label in labels):
            raise ValueError("domain is invalid")
    return normalized


class SQLiteBlacklistRepository:
    """Persistent blacklist whose writes require an audited approved decision."""

    def __init__(self, database: str | Path) -> None:
        self._database = str(database)
        if self._database != ":memory:":
            Path(self._database).parent.mkdir(parents=True, exist_ok=True)
        # This repository is scoped to one event-loop thread.  Retaining
        # SQLite's thread check prevents accidental cross-thread connection
        # sharing, which an asyncio.Lock cannot make safe.
        self._connection = sqlite3.connect(self._database)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lock = asyncio.Lock()
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS admin_decisions (
                decision_id TEXT PRIMARY KEY,
                reviewer_id TEXT NOT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                action TEXT NOT NULL CHECK (action IN ('add_to_blacklist', 'none')),
                note TEXT NOT NULL,
                decided_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blacklist (
                domain TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL UNIQUE,
                added_at TEXT NOT NULL,
                FOREIGN KEY (decision_id) REFERENCES admin_decisions(decision_id)
            );
            """
        )
        self._connection.commit()

    async def record_decision(
        self,
        *,
        decision_id: str,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
    ) -> None:
        values = (decision_id.strip(), reviewer_id.strip(), decision, action, note.strip())
        if not all(values):
            raise ValueError("all decision audit fields are required")
        if decision not in {"approved", "rejected"} or action not in {"add_to_blacklist", "none"}:
            raise ValueError("invalid decision or action")
        if action == "add_to_blacklist" and decision != "approved":
            raise ValueError("blacklist action requires an approved decision")
        async with self._lock:
            self._connection.execute(
                "INSERT INTO admin_decisions VALUES (?, ?, ?, ?, ?, ?)",
                (*values, datetime.now(UTC).isoformat()),
            )
            self._connection.commit()

    async def contains(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        async with self._lock:
            row = self._connection.execute("SELECT 1 FROM blacklist WHERE domain = ?", (normalized,)).fetchone()
        return row is not None

    async def add_approved(self, domain: str, decision_id: str) -> None:
        normalized = normalize_domain(domain)
        decision_id = decision_id.strip()
        if not decision_id:
            raise ValueError("decision_id is required")
        async with self._lock:
            row = self._connection.execute(
                "SELECT decision, action FROM admin_decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
            if row != ("approved", "add_to_blacklist"):
                raise PermissionError("an audited approved blacklist decision is required")
            try:
                self._connection.execute(
                    "INSERT INTO blacklist(domain, decision_id, added_at) VALUES (?, ?, ?)",
                    (normalized, decision_id, datetime.now(UTC).isoformat()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise ValueError("domain or decision is already recorded") from exc

    async def close(self) -> None:
        async with self._lock:
            self._connection.close()
