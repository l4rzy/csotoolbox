import logging
import threading
import time


logger = logging.getLogger(__name__)


class ApiKeyRotator:
    def __init__(self, keys):
        self.keys = keys if isinstance(keys, list) else []
        if not self.keys:
            logger.warning(
                "No API keys configured — all requests to this service will fail."
            )
        self._index = 0
        self._lock = threading.Lock()
        self._bad_keys: dict[str, float] = {}

    def get_next(self) -> str | None:
        with self._lock:
            if not self.keys:
                return None

            now = time.time()
            active_keys = [
                k
                for k in self.keys
                if k not in self._bad_keys or now > self._bad_keys[k]
            ]

            if not active_keys:
                active_keys = self.keys

            key = active_keys[self._index % len(active_keys)]
            self._index += 1
            return key

    def mark_bad(self, key: str, duration_seconds: int = 300):
        with self._lock:
            if key in self.keys:
                self._bad_keys[key] = time.time() + duration_seconds
