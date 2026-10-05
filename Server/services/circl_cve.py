import json
import logging
import html
import re

from infrastructure.constants import API_CIRCL_CVE
from infrastructure.models import ServiceType, TunnelOptions, _CVE_RE, ServiceResult
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


logger = logging.getLogger()


async def query_circl_cve(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    url = API_CIRCL_CVE.format(cve_id=cve_id)

    data = None
    try:
        code, body_bytes = await aiohttp_fetch(url)
        body_str = body_bytes.decode("utf-8", errors="ignore")

        if code == 200:
            try:
                data = json.loads(body_str)
            except Exception as e:
                logger.error(f"Error decoding/parsing JSON from CIRCL: {e}")
        elif code == 404:
            data = {"error": ErrorType.NOT_FOUND_ERROR}
        elif code == 429:
            data = {
                "error": ErrorType.UPSTREAM_SERVICE_ERROR,
                "message": "Service rate limited",
            }
        else:
            logger.error(f"CIRCL returned HTTP status {code}")
    except Exception as e:
        logger.error(f"Error querying CIRCL: {e}")

    if data is None:
        return {
            "error": ErrorType.UPSTREAM_SERVICE_ERROR,
            "message": "Server is working but circl didn't respond",
        }

    if isinstance(data, dict) and data.get("error") == "NotFoundError":
        return {
            "error": ErrorType.NOT_FOUND_ERROR,
            "message": "Object was not found on circl, code = 404",
        }

    mapped = {
        "id": cve_id,
        "Published": "",
        "Modified": "",
        "summary": "No description available.",
        "cvss": 0.0,
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
        "assigner": "",
    }

    cve_meta = data.get("cveMetadata", {})
    mapped["id"] = cve_meta.get("cveId", cve_id)
    mapped["Published"] = cve_meta.get("datePublished", "")
    mapped["Modified"] = cve_meta.get("dateUpdated", "")

    containers = data.get("containers", {})
    if "cna" in containers:
        cna = containers["cna"]

        descriptions = cna.get("descriptions", [])
        summary_val = ""
        for d in descriptions:
            if d.get("lang", "").startswith("en"):
                summary_val = d.get("value", "")
                break
        if not summary_val and descriptions:
            summary_val = descriptions[0].get("value", "")
        if summary_val:
            summary_val = re.sub(r"<.*?>", "", summary_val)
            summary_val = html.unescape(summary_val)
            paragraphs = summary_val.split("\n\n")
            clean_paragraphs = []
            for p in paragraphs:
                lines = [line.strip() for line in p.split("\n") if line.strip()]
                clean_p = " ".join(lines)
                while "  " in clean_p:
                    clean_p = clean_p.replace("  ", " ")
                if clean_p.strip():
                    clean_paragraphs.append(clean_p.strip())
            summary_val = "\n\n".join(clean_paragraphs)
            mapped["summary"] = summary_val

        mapped["assigner"] = cna.get("providerMetadata", {}).get("shortName", "")

        metrics = cna.get("metrics", [])
        cvss_score = 0.0
        vector_str = ""
        for m in metrics:
            for cvss_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2"]:
                if cvss_key in m:
                    cvss_data = m[cvss_key]
                    cvss_score = cvss_data.get("baseScore", cvss_score)
                    vector_str = cvss_data.get("vectorString", vector_str)
                    break
            if cvss_score > 0.0:
                break

        mapped["cvss"] = cvss_score

        if vector_str:
            parts = vector_str.split("/")
            kv = {}
            for p in parts:
                if ":" in p:
                    k, v = p.split(":", 1)
                    kv[k.upper()] = v.upper()

            access = mapped["access"]
            impact = mapped["impact"]

            if "AV" in kv:
                av_map = {
                    "N": "NETWORK",
                    "A": "ADJACENT_NETWORK",
                    "L": "LOCAL",
                    "P": "PHYSICAL",
                }
                access["vector"] = av_map.get(kv["AV"], kv["AV"])
            if "AC" in kv:
                ac_map = {"L": "LOW", "H": "HIGH", "M": "MEDIUM"}
                access["complexity"] = ac_map.get(kv["AC"], kv["AC"])
            if "PR" in kv:
                pr_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
                access["authentication"] = pr_map.get(kv["PR"], kv["PR"])
            elif "AU" in kv:
                au_map = {
                    "N": "NONE",
                    "S": "SINGLE_INSTANCE",
                    "M": "MULTIPLE_INSTANCES",
                }
                access["authentication"] = au_map.get(kv["AU"], kv["AU"])

            for metric, key in [
                ("C", "confidentiality"),
                ("I", "integrity"),
                ("A", "availability"),
            ]:
                if metric in kv:
                    c_map = {
                        "H": "HIGH",
                        "L": "LOW",
                        "N": "NONE",
                        "P": "PARTIAL",
                        "C": "COMPLETE",
                    }
                    impact[key] = c_map.get(kv[metric], kv[metric])

    return mapped


class CirclCveService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.CIRCLCVE

    async def validate(self, payload: str) -> str | None:
        if not payload:
            return "No CVE ID provided."
        cve_id = payload.strip().upper()
        if not _CVE_RE.match(cve_id):
            return f"Invalid CVE ID format: {cve_id}"

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        cve_id = payload.strip().upper()
        result = await query_circl_cve(cve_id)
        if isinstance(result, dict) and "error" in result:
            return make_error(result["error"], result.get("message", result["error"]))
        return ServiceResult(payload=result, error=None)
