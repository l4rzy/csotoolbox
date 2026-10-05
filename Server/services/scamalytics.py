import json
import logging
import re
from urllib.parse import quote

from infrastructure.constants import API_SCAMALYTICS, API_IPAPI
from infrastructure.maxmind_geoip import MaxMindGeoIPReader, build_geoip_from_mmdb
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch
from infrastructure.utils import make_error


logger = logging.getLogger()


def _get_credentials(config):
    cfg = config.get("scamalytics")
    if cfg and isinstance(cfg, list) and len(cfg) > 0:
        entry = cfg[0]
        user = entry.get("user", "")
        key = entry.get("key", "")
        if user and key:
            return user, key
    return None, None


async def _ip_api_lookup(ip: str) -> dict | None:
    url = API_IPAPI.format(ip=ip)
    code, body = await aiohttp_fetch(url)
    if code != 200:
        return None
    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None
    if data.get("status") != "success":
        return None

    geoip = {}
    if data.get("countryCode"):
        geoip["ip_country_code"] = data["countryCode"]
    if data.get("country"):
        geoip["ip_country_name"] = data["country"]
    if data.get("regionName"):
        geoip["ip_state_name"] = data["regionName"]
    if data.get("city"):
        geoip["ip_city"] = data["city"]
    if data.get("zip"):
        geoip["ip_postcode"] = data["zip"]
    if data.get("lat") is not None and data.get("lon") is not None:
        geoip["ip_geolocation"] = f"{data['lat']},{data['lon']}"
    if data.get("timezone"):
        geoip["ip_time_zone"] = data["timezone"]
    if data.get("isp"):
        geoip["isp_name"] = data["isp"]
    if data.get("org"):
        geoip["org_name"] = data["org"]

    as_field = data.get("as", "")
    if as_field:
        m = re.match(r"^AS(\d+)\s*(.*)", as_field)
        if m:
            asn = m.group(1)
            as_name = m.group(2).strip()
            if asn:
                geoip["asn"] = asn
            if as_name:
                geoip["as_name"] = as_name

    return geoip


def _sanitize_premium(obj):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str) and v.strip().startswith("PREMIUM FIELD"):
                obj[k] = ""
            elif isinstance(v, (dict, list)):
                _sanitize_premium(v)
    elif isinstance(obj, list):
        for item in obj:
            _sanitize_premium(item)


async def scamalytics_lookup(ip: str, config, extra: bool = False, geoip_reader: MaxMindGeoIPReader | None = None) -> ServiceResult:
    user, key = _get_credentials(config)
    if not user or not key:
        return make_error("ConfigError", "Scamalytics API credentials not configured.")

    url = API_SCAMALYTICS.format(
        user=quote(user, safe=""), key=quote(key, safe=""), ip=quote(ip, safe="")
    )

    code, body_bytes = await aiohttp_fetch(url)
    if code != 200:
        return make_error(
            "ThirdPartyError",
            f"server is working but scamalytics didn't respond, code = {code}",
        )

    try:
        data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        _sanitize_premium(data)
    except json.JSONDecodeError as e:
        return {
            "payload": None,
            "error": {
                "type": "ParseError",
                "message": f"Failed to parse Scamalytics response: {e}",
            },
        }

    payload = {}

    ext = data.get("external_datasources", {})

    if extra:
        payload["scamalytics"] = data.get("scamalytics", {})
        payload["external_datasources"] = ext
    else:
        scam = data.get("scamalytics", {})
        is_blacklisted_external = scam.pop("is_blacklisted_external", None)
        scam.pop("credits", None)
        scam.pop("exec", None)
        payload["scamalytics"] = scam

        geoip_priority = ["dbip", "ip2proxy_lite", "maxmind_geolite2", "ipinfo"]
        geoip_fields = [
            "ip_country_code",
            "ip_country_name",
            "ip_state_name",
            "ip_district_name",
            "ip_city",
            "ip_postcode",
            "ip_geolocation",
            "ip_geoname_id",
            "ip_location_accuracy_km",
            "ip_metro_code",
            "ip_time_zone",
            "asn",
            "as_name",
            "isp_name",
            "org_name",
            "domain",
            "ip_continent_code",
            "ip_continent_name",
            "ip_range_from",
            "ip_range_to",
            "as_domain",
            "connection_type",
        ]

        geoip = {}
        source_used = None

        # 1. ip-api.com (highest priority)
        ip_api_geoip = await _ip_api_lookup(ip)
        if ip_api_geoip:
            geoip.update(ip_api_geoip)
            source_used = "ip_api"

        # 2. local MaxMind (fill missing)
        if geoip_reader is not None:
            local_geoip = build_geoip_from_mmdb(ip, geoip_reader)
            if local_geoip:
                for k, v in local_geoip.items():
                    if k != "datasource_name" and (k not in geoip or not geoip.get(k)):
                        geoip[k] = v
                if source_used is None:
                    source_used = "maxmind_geolite2_local"

        # 3. Scamalytics external datasources (fill remaining)
        scam_contributed = False
        for field in geoip_fields:
            if field not in geoip or not geoip.get(field):
                for src in geoip_priority:
                    src_obj = ext.get(src)
                    if src_obj and field in src_obj and src_obj[field]:
                        value = src_obj[field]
                        if isinstance(value, str) and value.strip():
                            geoip[field] = value
                            scam_contributed = True
                            break

        if source_used is None and scam_contributed:
            source_used = "scamalytics_datasources"

        if source_used is not None:
            geoip["datasource_name"] = source_used

        if geoip:
            payload["geoip"] = geoip

        # Security: consolidated blacklists and proxies
        security = {}

        blacklists = {}
        if is_blacklisted_external is not None:
            security["is_blacklisted_external"] = is_blacklisted_external

        blacklists["ip2proxy"] = bool(
            ext.get("ip2proxy_lite", {}).get("ip_blacklisted")
        )
        blacklists["firehol"] = bool(ext.get("firehol", {}).get("ip_blacklisted_30"))
        blacklists["ipsum"] = bool(ext.get("ipsum", {}).get("ip_blacklisted"))
        blacklists["spamhaus"] = bool(
            ext.get("spamhaus_drop", {}).get("ip_blacklisted")
        )

        x4bnet_obj = ext.get("x4bnet", {})
        blacklists["spambot"] = bool(x4bnet_obj.get("is_blacklisted_spambot"))

        if blacklists:
            security["blacklists"] = blacklists

        proxies = {}
        proxy = scam.get("scamalytics_proxy", {})
        for field in ("is_datacenter", "is_vpn"):
            if field in proxy:
                proxies[field] = proxy[field]
        if "is_tor" in x4bnet_obj:
            proxies["is_tor"] = x4bnet_obj["is_tor"]

        ip2proxy_lite = ext.get("ip2proxy_lite", {})
        if "proxy_type" in ip2proxy_lite:
            proxies["proxy_type"] = ip2proxy_lite["proxy_type"]
        if "usage_type" in ip2proxy_lite:
            proxies["usage_type"] = ip2proxy_lite["usage_type"]

        if proxies:
            security["proxies"] = proxies

        if security:
            payload["security"] = security

    if payload.get("scamalytics", {}).get("status") != "ok":
        return make_error("ApiError", "Scamalytics API error, contact your admin")

    return ServiceResult(payload=payload, error=None)


class ScamalyticsService(TunnelService):
    def __init__(self, config, geoip_reader: MaxMindGeoIPReader | None = None):
        self._config = config
        self._geoip_reader = geoip_reader

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.SCAMALYTICS

    async def validate(self, payload: str) -> str | None:
        if not payload.strip():
            return "No IP address provided for Scamalytics lookup."

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        extra = options.extra if options else False
        return await scamalytics_lookup(payload.strip(), self._config, extra, self._geoip_reader)
