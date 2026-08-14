import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Test configuration must be established before importing the application.
# Otherwise pydantic-settings reads the developer .env and unit/API tests can
# accidentally connect to local PostgreSQL, Redis, or observability services.
_TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="trustguard-tests-"))
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{(_TEST_DATA_DIR / 'app.db').as_posix()}"
os.environ["SECURITY_DATABASE_PATH"] = str(_TEST_DATA_DIR / "security.db")
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGSMITH_TRACING"] = "false"

from src.main import app  # noqa: E402 - test environment must precede application import


@pytest_asyncio.fixture
async def client():
    """Async HTTP client for testing API endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_llm():
    """Mock LLM to avoid calling OpenAI during tests.

    Usage in test:
        def test_something(mock_llm):
            # LLM calls will return mock response instead of hitting OpenAI
            ...
    """
    mock = AsyncMock()
    mock.ainvoke.return_value = AsyncMock(content="Mocked LLM response")
    return mock
