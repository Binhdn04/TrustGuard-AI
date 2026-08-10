#!/usr/bin/env python3
"""Restart-safe Wave 1 importer for the legacy SQLite development database."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from src.models import AnalysisCreateRequest, AnalysisEvent, AnalysisResponse

IMPORTER_NAME = "sqlite-wave1-v1"


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class SQLiteWave1Importer:
    def __init__(self, sqlite_path: Path, pool, encryption_key: str, batch_size: int = 100) -> None:
        self.path = sqlite_path.resolve(strict=True)
        self.pool = pool
        self.encryption_key = encryption_key
        self.batch_size = batch_size
        self.source_fingerprint = fingerprint(self.path)

    async def run(self) -> dict[str, int]:
        async with self.pool.acquire() as pg:
            complete = await pg.fetchval(
                """SELECT completed_at IS NOT NULL FROM schema_imports
                   WHERE importer_name=$1 AND source_fingerprint=$2""",
                IMPORTER_NAME,
                self.source_fingerprint,
            )
            if complete:
                return {"analyses": 0, "events": 0, "already_complete": 1}
            await pg.execute(
                """INSERT INTO schema_imports(importer_name,source_fingerprint,started_at)
                   VALUES($1,$2,$3) ON CONFLICT(importer_name,source_fingerprint) DO NOTHING""",
                IMPORTER_NAME,
                self.source_fingerprint,
                datetime.now(UTC),
            )

        uri = f"file:{self.path}?mode=ro"
        sqlite = sqlite3.connect(uri, uri=True)
        sqlite.row_factory = sqlite3.Row
        counts = {"analyses": 0, "events": 0, "quarantined": 0}
        errors: dict[str, int] = {}
        try:
            rows = sqlite.execute(
                "SELECT analysis_id,owner_id,request_json,response_json,created_at FROM analyses ORDER BY rowid"
            )
            while batch := rows.fetchmany(self.batch_size):
                async with self.pool.acquire() as pg, pg.transaction():
                    for row in batch:
                        try:
                            analysis_id = UUID(row["analysis_id"])
                            request = AnalysisCreateRequest.model_validate_json(row["request_json"])
                            response = AnalysisResponse.model_validate_json(row["response_json"])
                            if response.analysis_id != analysis_id:
                                raise ValueError("analysis_id_mismatch")
                            created_at = datetime.fromisoformat(row["created_at"]).astimezone(UTC)
                        except Exception as exc:
                            code = type(exc).__name__
                            errors[code] = errors.get(code, 0) + 1
                            counts["quarantined"] += 1
                            continue
                        request_json = request.model_dump_json()
                        inserted = await pg.fetchval(
                            """INSERT INTO analyses(
                                  id,owner_id,input_ciphertext,input_hash,consent,status,response,
                                  case_status,scoring_version,created_at,updated_at,completed_at
                               ) VALUES($1,$2,pgp_sym_encrypt($3,$4),$5,$6,$7::jsonb,$8,$9,$10,$10,$11)
                               ON CONFLICT(id) DO NOTHING RETURNING 1""",
                            analysis_id,
                            row["owner_id"],
                            request_json,
                            self.encryption_key,
                            hashlib.sha256(request_json.encode()).hexdigest(),
                            request.consent_to_scan_urls,
                            response.status.value,
                            response.model_dump_json(),
                            response.case_status.value if response.case_status else None,
                            response.scoring_version,
                            created_at,
                            response.completed_at,
                        )
                        counts["analyses"] += int(bool(inserted))
                        event_rows = sqlite.execute(
                            "SELECT event_json FROM analysis_events WHERE analysis_id=? ORDER BY event_id",
                            (str(analysis_id),),
                        ).fetchall()
                        for sequence, event_row in enumerate(event_rows, 1):
                            try:
                                event = AnalysisEvent.model_validate_json(event_row["event_json"])
                            except Exception as exc:
                                code = type(exc).__name__
                                errors[code] = errors.get(code, 0) + 1
                                continue
                            event_inserted = await pg.fetchval(
                                """INSERT INTO analysis_events(
                                      event_id,analysis_id,sequence,event_type,payload,occurred_at
                                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)
                                   ON CONFLICT(analysis_id,sequence) DO NOTHING RETURNING 1""",
                                uuid4(),
                                analysis_id,
                                sequence,
                                "step_transition" if event.step_id else "analysis_status",
                                event.model_dump_json(),
                                event.occurred_at,
                            )
                            counts["events"] += int(bool(event_inserted))
                        if response.status.value in {"queued", "running"}:
                            job_id = uuid4()
                            now = datetime.now(UTC)
                            await pg.execute(
                                """INSERT INTO analysis_jobs(
                                      id,analysis_id,kind,status,max_attempts,available_at,
                                      idempotency_key,created_at,updated_at
                                   ) VALUES($1,$2,'analyze','queued',3,$3,$4,$3,$3)
                                   ON CONFLICT(idempotency_key) DO NOTHING""",
                                job_id,
                                analysis_id,
                                now,
                                f"analysis:{analysis_id}:analyze:v1",
                            )
                            await pg.execute(
                                """INSERT INTO outbox(
                                      id,aggregate_type,aggregate_id,event_type,payload,
                                      idempotency_key,created_at
                                   ) VALUES($1,'analysis',$2,'analysis.queued',$3::jsonb,$4,$5)
                                   ON CONFLICT(idempotency_key) DO NOTHING""",
                                uuid4(),
                                analysis_id,
                                json.dumps({"analysis_id": str(analysis_id), "job_id": str(job_id)}),
                                f"analysis:{analysis_id}:queued:v1",
                                now,
                            )
                        # Semantic round-trip validation before this batch commits.
                        persisted = await pg.fetchval("SELECT response FROM analyses WHERE id=$1", analysis_id)
                        if (
                            AnalysisResponse.model_validate(_json_value(persisted)).model_dump()
                            != response.model_dump()
                        ):
                            raise ValueError("semantic_roundtrip_failed")
        finally:
            sqlite.close()

        async with self.pool.acquire() as pg:
            await pg.execute(
                """UPDATE schema_imports SET completed_at=$3,row_counts=$4::jsonb,error_summary=$5::jsonb
                   WHERE importer_name=$1 AND source_fingerprint=$2""",
                IMPORTER_NAME,
                self.source_fingerprint,
                datetime.now(UTC),
                json.dumps(counts),
                json.dumps(errors),
            )
        return counts


def _json_value(value):
    return json.loads(value) if isinstance(value, str) else value


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sqlite_path", type=Path)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--encryption-key", required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    import asyncpg

    pool = await asyncpg.create_pool(args.database_url)
    try:
        result = await SQLiteWave1Importer(args.sqlite_path, pool, args.encryption_key, args.batch_size).run()
        print(json.dumps(result, sort_keys=True))
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
