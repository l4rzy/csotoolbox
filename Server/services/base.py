from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


@dataclass
class CachePolicy:
    should_cache: bool
    ttl: Optional[int] = None
    maxsize: Optional[int] = None


class TunnelService(ABC):
    @property
    @abstractmethod
    def service_type(self) -> ServiceType: ...

    async def validate(self, payload: str) -> str | None:
        return None

    async def cache_key(self, payload: str, options: TunnelOptions) -> str | None:
        return None

    def cache_policy(self, result: object) -> CachePolicy:
        if isinstance(result, ServiceResult):
            if result.error is not None:
                return CachePolicy(should_cache=False)
            return CachePolicy(should_cache=True)
        if not isinstance(result, dict):
            return CachePolicy(should_cache=result is not None)
        if result.get("error") is not None:
            return CachePolicy(should_cache=False)
        return CachePolicy(should_cache=True)

    def http_error_response(
        self, code: int, service_name: str
    ) -> ServiceResult | None:
        if 200 <= code < 300:
            return None
        if code == 404:
            return make_error(
                ErrorType.NOT_FOUND_ERROR,
                f"Object was not found on {service_name}, code = 404",
            )
        if code == 429:
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR,
                "Service rate limited",
            )
        if code in (401, 403):
            return make_error(
                ErrorType.AUTH_ERROR,
                f"Authentication failed for {service_name}, code = {code}",
            )
        return make_error(
            ErrorType.UPSTREAM_SERVICE_ERROR,
            f"server is working but {service_name} didn't respond, code = {code}",
        )

    @abstractmethod
    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult: ...

    async def handle_v1(self, payload: str, options: TunnelOptions) -> ServiceResult:
        return await self.handle(payload, options)

    async def handle_v2(self, payload: str, options: TunnelOptions) -> ServiceResult:
        return await self.handle(payload, options)
