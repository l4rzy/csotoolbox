import logging
import secrets
from typing import Tuple

from infrastructure.constants import API_MAC_VENDOR
from infrastructure.models import ServiceType, TunnelOptions, _MAC_RE, ServiceResult
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch


logger = logging.getLogger()


def _randomize_mac(mac: str) -> str:
    """Keep the first 36 bits (OUI + 12), randomize the remaining 12 bits."""
    sep = ":" if ":" in mac else "-"
    mac_digits = mac.replace(":", "").replace("-", "")
    prefix = mac_digits[:9]
    suffix = f"{secrets.randbits(12):03x}"
    raw = prefix + suffix
    return sep.join(raw[i : i + 2] for i in range(0, 12, 2))


async def _mac_vendor_fetch(mac_addr: str) -> Tuple[int, str]:
    url = API_MAC_VENDOR.format(mac_addr=mac_addr)
    code, body_bytes = await aiohttp_fetch(url)
    return code, body_bytes.decode("utf-8", errors="ignore").strip()


class MacService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.MAC

    async def validate(self, payload: str) -> str | None:
        if not payload.strip():
            return "No MAC address provided."
        if not _MAC_RE.match(payload.strip()):
            return "Invalid MAC address format"

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        mac_addr = _randomize_mac(payload.strip())
        vendor = "Unknown"
        try:
            code, text = await _mac_vendor_fetch(mac_addr)
            if code == 200:
                vendor = text
        except Exception as e:
            logger.error(f"MAC lookup error: {e}")
        return ServiceResult(payload={"vendor": vendor}, error=None)
