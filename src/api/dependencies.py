from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header

from src.config import get_settings
from src.core.auth import DemoTokenAuthenticator, Principal
from src.services.analysis import AnalysisService


@lru_cache
def get_analysis_service() -> AnalysisService:
    return AnalysisService()


def get_principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    return DemoTokenAuthenticator(get_settings()).authenticate(authorization)


AnalysisServiceDependency = Annotated[AnalysisService, Depends(get_analysis_service)]
PrincipalDependency = Annotated[Principal, Depends(get_principal)]
