import json
import logging
from urllib.parse import quote

from infrastructure.constants import API_VIRUSTOTAL_SEARCH
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch
from infrastructure.utils import make_error, extract_host
from infrastructure.errors import ErrorType


logger = logging.getLogger()


class VirusTotalService(TunnelService):
    def __init__(self, rotator):
        self._rotator = rotator

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.VIRUSTOTAL

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        key = self._rotator.get_next()
        if key is None:
            return make_error(
                ErrorType.AUTH_ERROR, "No VirusTotal API keys configured."
            )
        url = f"{API_VIRUSTOTAL_SEARCH}?query={quote(extract_host(payload), safe='')}"
        headers = ["Accept: application/json", f"x-apikey: {key}"]

        body = None
        try:
            code, body_bytes = await aiohttp_fetch(url, headers)

            if code in (401, 403, 429):
                self._rotator.mark_bad(key)
                logger.warning(
                    f"VirusTotal key returned HTTP {code}, temporarily disabling: {key[:8]}..."
                )

            if 200 <= code < 300:
                body = body_bytes
            else:
                err = self.http_error_response(code, self.service_type.value)
                if err:
                    body = err
                else:
                    logger.error(f"VirusTotal request to {url} returned HTTP {code}")
        except Exception as e:
            logger.error(f"VirusTotal connection error to {url}: {e}")

        if body is None:
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR,
                f"server is working but {self.service_type.value} didn't respond",
            )

        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="ignore")
            try:
                payload_dict = json.loads(body_str)
                parsed_ok = True
            except Exception:
                payload_dict = {"raw": body_str}
                parsed_ok = False
            if parsed_ok and isinstance(payload_dict, dict):
                data_val = payload_dict.get("data")
                if data_val is None or data_val == []:
                    return make_error(
                        ErrorType.NOT_FOUND_ERROR, "Object was not found on VirusTotal"
                    )
            return ServiceResult(payload=payload_dict, error=None)
        return body
