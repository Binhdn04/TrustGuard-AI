from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.script import ScriptDirectory

from src.models import BrandRecordV4, TrustLifecycleV4, WhitelistRecordV4, WhitelistScopeV4
from src.repositories.postgres import PostgresPlatformRepository

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def repository() -> PostgresPlatformRepository:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.fail("TEST_DATABASE_URL is required for PostgreSQL integration tests")
    instance = PostgresPlatformRepository(database_url, "integration-encryption-key-at-least-32")
    try:
        yield instance
    finally:
        await instance.close()


@pytest.mark.asyncio
async def test_database_is_migrated_to_the_repository_head(repository: PostgresPlatformRepository) -> None:
    assert await repository.healthcheck() is True
    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        database_heads = {
            row["version_num"] for row in await connection.fetch("SELECT version_num FROM alembic_version")
        }
    migration_heads = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())

    assert database_heads == migration_heads


@pytest.mark.asyncio
async def test_brand_disable_is_single_winner_and_immutably_audited(
    repository: PostgresPlatformRepository,
) -> None:
    now = datetime.now(UTC)
    suffix = uuid4().hex
    brand = BrandRecordV4(
        name=f"Integration Brand {suffix}",
        official_domains=[f"{suffix}.example.test"],
        provenance="integration-test",
        effective_from=now,
        reviewer_id="integration-admin",
        created_at=now,
    )
    await repository.create_brand(brand)

    results = await asyncio.gather(
        repository.disable_brand(str(brand.brand_id), "reviewer-one", now + timedelta(seconds=1)),
        repository.disable_brand(str(brand.brand_id), "reviewer-two", now + timedelta(seconds=2)),
    )

    disabled = [result for result in results if result is not None]
    assert len(disabled) == 1
    assert disabled[0].lifecycle is TrustLifecycleV4.DISABLED
    assert disabled[0].supersedes == brand.brand_id
    assert brand.brand_id not in {
        item.brand_id for item in await repository.list_active_brands(now + timedelta(minutes=1))
    }

    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        audit = await connection.fetch(
            """SELECT action,reviewer_id FROM security_trust_audit
               WHERE resource_id=$1 OR resource_id=$2 ORDER BY occurred_at""",
            brand.brand_id,
            disabled[0].brand_id,
        )
    assert [(row["action"], row["reviewer_id"]) for row in audit] == [
        ("created", "integration-admin"),
        ("disabled", disabled[0].reviewer_id),
    ]


@pytest.mark.asyncio
async def test_whitelist_lifecycle_round_trips_through_postgres(repository: PostgresPlatformRepository) -> None:
    now = datetime.now(UTC)
    record = WhitelistRecordV4(
        indicator=f"{uuid4().hex}.example.test",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="integration-test",
        effective_from=now,
        reviewer_id="integration-admin",
        created_at=now,
    )

    await repository.create_whitelist(record)
    assert record.whitelist_id in {
        item.whitelist_id for item in await repository.list_active_whitelist(now + timedelta(seconds=1))
    }

    disabled = await repository.disable_whitelist(
        str(record.whitelist_id),
        "integration-reviewer",
        now + timedelta(seconds=2),
    )

    assert disabled is not None
    assert disabled.lifecycle is TrustLifecycleV4.DISABLED
    assert record.whitelist_id not in {
        item.whitelist_id for item in await repository.list_active_whitelist(now + timedelta(minutes=1))
    }
