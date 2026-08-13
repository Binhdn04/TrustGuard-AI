from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from src.models import SecurityConversationSummaryV4, SecurityConversationV4
from src.repositories.blacklist import SQLiteBlacklistRepository


@pytest.mark.asyncio
async def test_sqlite_conversation_retention_removes_summary_and_turns(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    now = datetime.now(UTC)
    record = SecurityConversationV4(
        conversation_id=uuid4(),
        active_analysis_id=uuid4(),
        summary=SecurityConversationSummaryV4(),
        context_version=1,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=1),
    )
    await repository.save_security_conversation("owner", record, expected_version=None)

    removed = await repository.expire_security_conversations(now + timedelta(days=2))

    assert removed == 1
    assert await repository.load_security_conversation(str(record.conversation_id)) is None
    turn_count = repository._connection.execute(  # noqa: SLF001 - persistence contract assertion
        "SELECT count(*) FROM security_conversation_turns WHERE conversation_id=?",
        (str(record.conversation_id),),
    ).fetchone()[0]
    assert turn_count == 0
