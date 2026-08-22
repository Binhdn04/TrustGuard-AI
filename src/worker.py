from __future__ import annotations

import asyncio
import signal

from src.api.dependencies import (
    close_security_analysis_service,
    close_security_trust_services,
    start_durable_worker,
    stop_durable_worker,
)
from src.config import get_settings
from src.core.logging import configure_structured_logging
from src.observability.langfuse import close_langfuse_observability


async def run() -> None:
    settings = get_settings()
    configure_structured_logging(settings.log_level)
    if not settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")):
        raise RuntimeError("The durable worker requires PostgreSQL")
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stopping.set)
    await start_durable_worker()
    try:
        await stopping.wait()
    finally:
        await stop_durable_worker()
        await close_security_analysis_service()
        await close_security_trust_services()
        close_langfuse_observability()


if __name__ == "__main__":
    asyncio.run(run())
