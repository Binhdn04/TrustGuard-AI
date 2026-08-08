"""Persistence interfaces and implementations will live in this package."""

from src.repositories.blacklist import SQLiteBlacklistRepository, normalize_domain
from src.repositories.fact_check import JsonFactCheckRepository
from src.repositories.postgres import PostgresPlatformRepository

__all__ = [
    "JsonFactCheckRepository",
    "PostgresPlatformRepository",
    "SQLiteBlacklistRepository",
    "normalize_domain",
]
