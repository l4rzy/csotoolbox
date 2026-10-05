import json
import logging
import threading
from typing import Awaitable, Callable

from cachetools import TTLCache

from infrastructure.models import TunnelOptions, ServiceResult
from infrastructure.utils import hash_str
from services.base import TunnelService


logger = logging.getLogger()


class TimedCache:
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 1000):
        self._cache = TTLCache(maxsize=max_size, ttl=ttl_seconds)
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value):
        with self._lock:
            self._cache[key] = value

    async def execute(
        self,
        svc: TunnelService,
        payload: str,
        options: TunnelOptions,
        handler: Callable[[str, TunnelOptions], Awaitable[ServiceResult]],
        api_version: int = 1,
    ) -> tuple[str, bool]:
        opts_json = json.dumps(options.model_dump()) if options else "{}"
        default_key = hash_str(f"{svc.service_type}:{payload}:{opts_json}")
        base_key = (await svc.cache_key(payload, options)) or default_key
        cache_key = hash_str(f"v{api_version}:{base_key}")
        force = options.force or False

        if not force:
            cached_val = self.get(cache_key)
            if cached_val is not None:
                logger.info(f"Cache HIT: service={svc.service_type}, payload={payload}")
                return cached_val, True
            logger.info(f"Cache MISS: service={svc.service_type}, payload={payload}")
        else:
            logger.info(f"Cache BYPASS (force=True): service={svc.service_type}, payload={payload}")

        result = await handler(payload, options)

        if isinstance(result, ServiceResult):
            result_str = json.dumps(result.model_dump())
        else:
            result_str = json.dumps(result) if isinstance(result, dict) else str(result)

        policy = svc.cache_policy(result)
        if policy.should_cache and self.get(cache_key) is None:
            self.set(cache_key, result_str)

        return result_str, False
