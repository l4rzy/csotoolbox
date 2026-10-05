import json
import logging
from urllib.parse import urlparse, urlunparse

from infrastructure.constants import API_THREATFOX
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult, _HASH_RE
from services.base import TunnelService
from infrastructure.http_client import aiohttp_post_json
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


logger = logging.getLogger()


def _classify_payload(payload: str) -> tuple[str, dict]:
    """Determine ThreatFox query type and build the JSON body."""
    stripped = payload.strip()

    # Hash -> search_hash
    if _HASH_RE.match(stripped):
        return "hash", {"query": "search_hash", "hash": stripped}

    # IP -> exact match
    import ipaddress

    try:
        ipaddress.ip_address(stripped)
        return "ip", {
            "query": "search_ioc",
            "search_term": stripped,
            "exact_match": True,
        }
    except ValueError:
        pass

    # URL -> strip query params, fuzzy match
    if stripped.lower().startswith(("http://", "https://")):
        parsed = urlparse(stripped)
        clean_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, None, None, None)
        )
        return "url", {
            "query": "search_ioc",
            "search_term": clean_url,
            "exact_match": False,
        }

    # Domain -> fuzzy match
    return "domain", {
        "query": "search_ioc",
        "search_term": stripped,
        "exact_match": False,
    }


class ThreatFoxService(TunnelService):
    def __init__(self, rotator):
        self._rotator = rotator

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.THREATFOX

    async def validate(self, payload: str) -> str | None:
        if not payload.strip():
            return "No IOC provided for ThreatFox query."

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        key = self._rotator.get_next()
        if key is None:
            return make_error(ErrorType.AUTH_ERROR, "No ThreatFox API keys configured.")

        ioc_type, json_data = _classify_payload(payload)
        headers = [f"Auth-Key: {key}"]

        body = None
        try:
            code, body_bytes = await aiohttp_post_json(
                API_THREATFOX, json_data, headers
            )

            if code in (401, 403, 429):
                self._rotator.mark_bad(key)
                logger.warning(
                    f"ThreatFox key returned HTTP {code}, temporarily disabling: {key[:8]}..."
                )

            if 200 <= code < 300:
                body = body_bytes
            else:
                err = self.http_error_response(code, self.service_type.value)
                if err:
                    body = err
                else:
                    logger.error(f"ThreatFox request returned HTTP {code}")
        except Exception as e:
            logger.error(f"ThreatFox connection error: {e}")

        if body is None:
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR,
                f"Server is working but {self.service_type.value} didn't respond",
            )

        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="ignore")
            try:
                payload_dict = json.loads(body_str)
            except Exception:
                return ServiceResult(payload={"raw": body_str}, error=None)

            query_status = payload_dict.get("query_status")
            if query_status in ("no_result", "hash_not_found"):
                return make_error(
                    ErrorType.NOT_FOUND_ERROR,
                    f"No results found on ThreatFox for: {payload}",
                )
            if query_status != "ok":
                return make_error(
                    ErrorType.UPSTREAM_SERVICE_ERROR,
                    f"ThreatFox returned: {query_status}",
                )

            data = payload_dict.get("data")
            if isinstance(data, list) and len(data) > 0:
                return ServiceResult(
                    payload={"ioc_type": ioc_type, "results": data}, error=None
                )
            if isinstance(data, dict):
                return ServiceResult(
                    payload={"ioc_type": ioc_type, "results": data}, error=None
                )
            return make_error(
                ErrorType.NOT_FOUND_ERROR,
                f"No data found on ThreatFox for: {payload}",
            )
        return body
