from __future__ import annotations

from datetime import UTC, datetime

from src.agents.security_trust import canonical_whitelist_url
from src.core.auth import Principal, require_security_admin
from src.models import (
    BrandCreateRequestV4,
    BrandRecordV4,
    WhitelistCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories.blacklist import normalize_domain


class SecurityTrustAdminService:
    def __init__(self, repository) -> None:
        self._repository = repository

    async def create_brand(self, request: BrandCreateRequestV4, principal: Principal) -> BrandRecordV4:
        require_security_admin(principal)
        try:
            domains = list(dict.fromkeys(normalize_domain(item) for item in request.official_domains))
        except ValueError as exc:
            from src.core.errors import PlatformError
            from src.models import ErrorCode

            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="An official brand domain is invalid.",
                retryable=False,
            ) from exc
        record = BrandRecordV4(
            **request.model_dump(exclude={"official_domains"}),
            official_domains=domains,
            reviewer_id=principal.user_id,
            created_at=datetime.now(UTC),
        )
        await self._repository.create_brand(record)
        return record

    async def disable_brand(self, brand_id: str, principal: Principal) -> BrandRecordV4:
        require_security_admin(principal)
        record = await self._repository.disable_brand(brand_id, principal.user_id, datetime.now(UTC))
        if record is None:
            from src.core.errors import PlatformError
            from src.models import ErrorCode

            raise PlatformError(
                status_code=404, code=ErrorCode.NOT_FOUND, message="Brand was not found.", retryable=False
            )
        return record

    async def create_whitelist(
        self, request: WhitelistCreateRequestV4, principal: Principal
    ) -> WhitelistRecordV4:
        require_security_admin(principal)
        indicator = request.indicator
        try:
            if request.scope is WhitelistScopeV4.DOMAIN:
                indicator = normalize_domain(indicator)
            elif request.scope is WhitelistScopeV4.URL:
                indicator = canonical_whitelist_url(indicator) or ""
                if not indicator:
                    raise ValueError("URL is not canonicalizable")
            else:
                indicator = indicator.casefold().strip()
        except ValueError as exc:
            from src.core.errors import PlatformError
            from src.models import ErrorCode

            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="Whitelist indicator is invalid for its scope.",
                retryable=False,
            ) from exc
        record = WhitelistRecordV4(
            **request.model_dump(exclude={"indicator"}),
            indicator=indicator,
            reviewer_id=principal.user_id,
            created_at=datetime.now(UTC),
        )
        await self._repository.create_whitelist(record)
        return record

    async def disable_whitelist(self, whitelist_id: str, principal: Principal) -> WhitelistRecordV4:
        require_security_admin(principal)
        record = await self._repository.disable_whitelist(whitelist_id, principal.user_id, datetime.now(UTC))
        if record is None:
            from src.core.errors import PlatformError
            from src.models import ErrorCode

            raise PlatformError(
                status_code=404, code=ErrorCode.NOT_FOUND, message="Whitelist entry was not found.", retryable=False
            )
        return record

    async def list_brands(self, principal: Principal) -> list[BrandRecordV4]:
        require_security_admin(principal)
        return await self._repository.list_brands()

    async def list_whitelist(self, principal: Principal) -> list[WhitelistRecordV4]:
        require_security_admin(principal)
        return await self._repository.list_whitelist()


__all__ = ["SecurityTrustAdminService"]
