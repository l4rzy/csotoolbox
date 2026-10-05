import json
import logging

from infrastructure.constants import API_SHODAN_CVE
from infrastructure.models import ServiceType, TunnelOptions, _CVE_RE, ServiceResult
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


logger = logging.getLogger()


async def query_shodan_cve(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    url = API_SHODAN_CVE.format(cve_id=cve_id)

    data = None
    try:
        code, body_bytes = await aiohttp_fetch(url, ["Accept: application/json"])
        body_str = body_bytes.decode("utf-8", errors="ignore")

        if code == 200:
            try:
                data = json.loads(body_str)
            except Exception as e:
                logger.error(f"Error decoding/parsing JSON from Shodan: {e}")
        elif code == 404:
            data = {"error": ErrorType.NOT_FOUND_ERROR}
        else:
            logger.error(f"Shodan returned HTTP status {code}")
    except Exception as e:
        logger.error(f"Error querying Shodan: {e}")

    if data is None:
        return {
            "error": ErrorType.UPSTREAM_SERVICE_ERROR,
            "message": "server is working but shodan didn't respond",
        }

    if isinstance(data, dict) and data.get("error") == "NotFoundError":
        return {
            "error": ErrorType.NOT_FOUND_ERROR,
            "message": "Object was not found on shodan, code = 404",
        }

    cvss_score = data.get("cvss_v3") or data.get("cvss") or data.get("cvss_v2") or 0.0
    assigner = ""
    if data.get("euvd"):
        assigner = data["euvd"].get("assigner", "")
    summary = data.get("summary", "No description available.")
    if data.get("epss") is not None:
        summary += f"\n\nEPSS: {data['epss']:.2%} (percentile: {data.get('ranking_epss', 0):.2%})"
    if data.get("kev"):
        summary += "\n\n! KNOWN EXPLOITED VULNERABILITY (CISA KEV)"

    mapped = {
        "id": cve_id,
        "Published": data.get("published_time", ""),
        "Modified": "",
        "summary": summary,
        "cvss": cvss_score,
        "access": {
            "authentication": "UNKNOWN",
            "complexity": "UNKNOWN",
            "vector": "UNKNOWN",
        },
        "impact": {
            "availability": "UNKNOWN",
            "confidentiality": "UNKNOWN",
            "integrity": "UNKNOWN",
        },
        "assigner": assigner,
        "epss": data.get("epss"),
        "kev": data.get("kev", False),
        "ransomware_campaign": data.get("ransomware_campaign"),
        "references": data.get("references", []),
        "cpes": data.get("cpes", []),
    }

    return mapped


class ShodanCveService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.SHODAN

    async def validate(self, payload: str) -> str | None:
        if not payload:
            return "No CVE ID provided."
        cve_id = payload.strip().upper()
        if not _CVE_RE.match(cve_id):
            return f"Invalid CVE ID format: {cve_id}"

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        cve_id = payload.strip().upper()
        result = await query_shodan_cve(cve_id)
        if isinstance(result, dict) and "error" in result:
            return make_error(result["error"], result.get("message", result["error"]))
        return ServiceResult(payload=result, error=None)
