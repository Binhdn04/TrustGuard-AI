from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, Request

from src.agents.graph import build_openai_graph
from src.config import get_settings
from src.core.auth import DemoTokenAuthenticator, Principal
from src.repositories import SQLiteBlacklistRepository
from src.services.analysis import AnalysisService
from src.services.processor import LangGraphAnalysisProcessor


@lru_cache
def get_analysis_service() -> AnalysisService:
    settings = get_settings()
    blacklist = SQLiteBlacklistRepository(settings.security_database_path)
    graph = build_openai_graph(blacklist=blacklist)
    processor = LangGraphAnalysisProcessor(graph)
    return AnalysisService(blacklist=blacklist, processor=processor)


async def resolve_analysis_service(request: Request) -> AnalysisService:
    override = request.app.dependency_overrides.get(get_analysis_service)
    if override is None:
        return get_analysis_service()
    service = override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def close_analysis_service() -> None:
    if get_analysis_service.cache_info().currsize == 0:
        return
    service = get_analysis_service()
    get_analysis_service.cache_clear()
    await service.aclose()


async def get_principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    return DemoTokenAuthenticator(get_settings()).authenticate(authorization)


AnalysisServiceDependency = Annotated[AnalysisService, Depends(resolve_analysis_service)]
PrincipalDependency = Annotated[Principal, Depends(get_principal)]
