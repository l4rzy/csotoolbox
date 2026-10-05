import json
import logging

from infrastructure.constants import API_MALWAREBAZAAR
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult, _HASH_RE
from services.base import TunnelService
from infrastructure.http_client import aiohttp_post_form
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


logger = logging.getLogger()


class BazaarService(TunnelService):
    def __init__(self, rotator):
        self._rotator = rotator

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.BAZAAR

    async def validate(self, payload: str) -> str | None:
        if not _HASH_RE.match(payload.strip()):
            return "Invalid hash format — expected MD5, SHA1, or SHA256"

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        key = self._rotator.get_next()
        if key is None:
            return make_error(
                ErrorType.AUTH_ERROR, "No MalwareBazaar API keys configured."
            )

        headers = [f"Auth-Key: {key}"]
        form_data = {"query": "get_info", "hash": payload.strip()}

        body = None
        try:
            code, body_bytes = await aiohttp_post_form(
                API_MALWAREBAZAAR, form_data, headers
            )

            if code in (401, 403, 429):
                self._rotator.mark_bad(key)
                logger.warning(
                    f"MalwareBazaar key returned HTTP {code}, temporarily disabling: {key[:8]}..."
                )

            if 200 <= code < 300:
                body = body_bytes
            else:
                err = self.http_error_response(code, self.service_type.value)
                if err:
                    body = err
                else:
                    logger.error(f"MalwareBazaar request returned HTTP {code}")
        except Exception as e:
            logger.error(f"MalwareBazaar connection error: {e}")

        if body is None:
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR,
                f"server is working but {self.service_type.value} didn't respond",
            )

        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="ignore")
            try:
                payload_dict = json.loads(body_str)
            except Exception:
                return ServiceResult(payload={"raw": body_str}, error=None)

            query_status = payload_dict.get("query_status")
            if query_status == "hash_not_found":
                return make_error(
                    ErrorType.NOT_FOUND_ERROR,
                    f"Hash not found in MalwareBazaar",
                )
            if query_status != "ok":
                return make_error(
                    ErrorType.UPSTREAM_SERVICE_ERROR,
                    f"MalwareBazaar returned: {query_status}",
                )

            data = payload_dict.get("data")
            if isinstance(data, list) and len(data) > 0:
                result = data[0]
                # remediate inconsistency issue with vendor_intel = [] when empty and {} when having values
                if isinstance(result, dict) and isinstance(
                    result.get("vendor_intel"), list
                ):
                    result["vendor_intel"] = {}
                return ServiceResult(payload=result, error=None)
            return make_error(
                ErrorType.NOT_FOUND_ERROR,
                f"No data found for hash: {payload}",
            )
        return body
