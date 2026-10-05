import asyncio
import json
import logging
import os
import time as _time

from cachetools import TTLCache
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from infrastructure.models import (
    ServiceType,
    TunnelOptions,
    TunnelRequestV1,
    TunnelResponseV1,
    TunnelResponseV1Metadata,
)
from infrastructure import constants as _constants
from infrastructure.constants import (
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
    RATE_LIMIT_TRACKED_CLIENTS_MAX,
    MAX_REQUEST_BODY_BYTES,
    TIMEOUT_SERVICE_DEFAULT,
    VERSION_MAJOR,
    VERSION_MINOR,
    VERSION_BUILD,
    VERSION_DATE,
)
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType
from infrastructure.cache import TimedCache
from infrastructure.config_loader import YamlConfigParser
from infrastructure.key_rotator import ApiKeyRotator
from infrastructure.ipdb import IPDBInfo
from infrastructure.maxmind_geoip import MaxMindGeoIPReader
from infrastructure.geoip_updater import GeoIPUpdater
from services.ocr import OcrService
from services.bazaar import BazaarService
from services.threatfox import ThreatFoxService
from infrastructure.http_client import close_session
from infrastructure.executors import shutdown_executors
from services.base import TunnelService
from services.ipdb import IpdbService
from services.dns import DnsService
from services.whois import WhoisService
from services.rdap import RdapService
from services.mac import MacService
from services.circl_cve import CirclCveService
from services.shodan_cve import ShodanCveService
from services.scamalytics import ScamalyticsService
from services.abuseipdb import AbuseIpDbService
from services.virustotal import VirusTotalService


logger = logging.getLogger()

# FastAPI
app = FastAPI(title="CSO Toolbox", redoc_url=None)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    err = make_error(ErrorType.INTERNAL_ERROR, f"Route not found: {request.method} {request.url.path}")
    v1 = TunnelResponseV1(
        metadata=TunnelResponseV1Metadata(),
        payload=None,
        error=err.error,
    )
    return PlainTextResponse(json.dumps(v1.model_dump()), status_code=404)


@app.exception_handler(Exception)
async def internal_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    err = make_error(ErrorType.INTERNAL_ERROR, f"Internal server error: {exc}")
    v1 = TunnelResponseV1(
        metadata=TunnelResponseV1Metadata(),
        payload=None,
        error=err.error,
    )
    return PlainTextResponse(json.dumps(v1.model_dump()), status_code=500)


@app.on_event("startup")
async def startup_event():
    await geoip_updater.start()

@app.on_event("shutdown")
async def shutdown_event():
    await geoip_updater.stop()
    geoip_reader.close()
    await close_session()
    shutdown_executors()


@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                err_res = make_error(
                    "PayloadTooLarge",
                    f"Request body exceeds the maximum allowed size of {MAX_REQUEST_BODY_BYTES} bytes.",
                )
                return PlainTextResponse(
                    json.dumps(err_res.model_dump()),
                    status_code=413,
                )
        except ValueError:
            pass  # malformed header — let it through to normal parsing
    return await call_next(request)


_request_timestamps = TTLCache(maxsize=RATE_LIMIT_TRACKED_CLIENTS_MAX, ttl=RATE_LIMIT_WINDOW)
_rate_limit_lock = asyncio.Lock()


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # User-Agent validation
    user_agent = request.headers.get("user-agent", "")
    if not user_agent.startswith("CSO Toolbox Client"):
        err_res = make_error(
            "AuthError", "This API is restricted to CSO Toolbox Client only."
        )
        return PlainTextResponse(
            json.dumps(err_res.model_dump()),
            status_code=403,
        )

    client = request.client.host if request.client else "unknown"
    now = _time.time()
    async with _rate_limit_lock:
        timestamps = [
            t for t in _request_timestamps.get(client, []) if now - t < RATE_LIMIT_WINDOW
        ]
        if len(timestamps) >= RATE_LIMIT_MAX:
            _request_timestamps[client] = timestamps
            err_res = make_error("RateLimit", "Too many requests. Try again later.")
            return PlainTextResponse(
                json.dumps(err_res.model_dump()),
                status_code=429,
            )
        timestamps.append(now)
        _request_timestamps[client] = timestamps
    return await call_next(request)


# Infrastructure init
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ipdb_info = IPDBInfo(os.path.join(SCRIPT_DIR, "data", "ipdb.csv"))
config = YamlConfigParser(os.path.join(SCRIPT_DIR, "data", "config.yaml"))
config.load()
cache = TimedCache()
abuseipdb_rotator = ApiKeyRotator(config.get("abuseipdb"))
virustotal_rotator = ApiKeyRotator(config.get("virustotal"))
bazaar_rotator = ApiKeyRotator(config.get("abusech"))
threatfox_rotator = ApiKeyRotator(config.get("abusech"))

geoip_reader = MaxMindGeoIPReader(os.path.join(SCRIPT_DIR, "data", "GeoLite2-City.mmdb"))
geoip_updater = GeoIPUpdater(os.path.join(SCRIPT_DIR, "data", "GeoLite2-City.mmdb"), geoip_reader)

# Service registry with version support
_services: dict[tuple[ServiceType, int], TunnelService] = {}


def register_service(svc: TunnelService, api_version: int = 1):
    _services[(svc.service_type, api_version)] = svc


def get_service(
    service_type: ServiceType, api_version: int = 1
) -> TunnelService | None:
    svc = _services.get((service_type, api_version))
    return svc or _services.get((service_type, 1))


register_service(IpdbService(ipdb_info))
register_service(DnsService(ipdb_info))
register_service(WhoisService())
register_service(RdapService())
register_service(MacService())
register_service(CirclCveService())
register_service(ShodanCveService())
register_service(ScamalyticsService(config, geoip_reader))
register_service(AbuseIpDbService(abuseipdb_rotator))
register_service(VirusTotalService(virustotal_rotator))
register_service(OcrService())
register_service(BazaarService(bazaar_rotator))
register_service(ThreatFoxService(threatfox_rotator))


async def _get_health():
    return {
        "health": "ok",
        "version": f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_BUILD}.{_constants.VERSION_REVISION} ({VERSION_DATE})",
        "ocr_backend": "OpenVINO",
        "service_timeout": TIMEOUT_SERVICE_DEFAULT,
    }


@app.get("/api/v1/health")
async def get_health_v1():
    return await _get_health()


_UPDATES_DIR = os.path.join(SCRIPT_DIR, "updates")


async def _check_update(platform: str, version: str):
    manifest_path = os.path.join(_UPDATES_DIR, "latest.json")
    if not os.path.exists(manifest_path):
        return {
            "update_available": False,
            "version": version,
            "message": "No updates available",
        }

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception:
        return {
            "update_available": False,
            "version": version,
            "message": "Failed to read update manifest",
        }

    latest_ver = manifest.get("version")
    if not latest_ver:
        return {
            "update_available": False,
            "version": version,
            "message": "No update configured",
        }

    try:
        client_parts = [int(x) for x in version.split(".")]
        latest_parts = [int(x) for x in str(latest_ver).split(".")]
    except ValueError:
        return {
            "update_available": False,
            "version": version,
            "message": "Invalid version format",
        }

    # Pad shorter list with zeros for comparison
    while len(client_parts) < len(latest_parts):
        client_parts.append(0)
    while len(latest_parts) < len(client_parts):
        latest_parts.append(0)

    is_newer = latest_parts > client_parts
    if not is_newer:
        return {
            "update_available": False,
            "version": version,
            "message": "You are up to date",
        }

    platform_info = manifest.get("platforms", {}).get(platform)
    if not platform_info:
        return {
            "update_available": False,
            "version": version,
            "message": f"Platform '{platform}' is not supported for this release",
        }

    return {
        "update_available": True,
        "version": latest_ver,
        "release_notes": manifest.get("release_notes", ""),
        "filename": platform_info.get("filename"),
        "sha256": platform_info.get("sha256"),
        "size": platform_info.get("size", 0),
    }


@app.get("/api/v1/update/check/{platform}/{version}")
async def check_update_v1(platform: str, version: str):
    return await _check_update(platform, version)


async def _download_update(platform: str):
    manifest_path = os.path.join(_UPDATES_DIR, "latest.json")
    if not os.path.exists(manifest_path):
        return PlainTextResponse("Update manifest not found", status_code=404)
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception:
        return PlainTextResponse("Invalid update manifest", status_code=500)

    p = manifest.get("platforms", {}).get(platform)
    if not p:
        return PlainTextResponse(f"Platform not supported: {platform}", status_code=404)

    safe_name = os.path.basename(p.get("filename", ""))
    if not safe_name:
        return PlainTextResponse("Invalid filename in manifest", status_code=500)
    file_path = os.path.join(_UPDATES_DIR, safe_name)
    if not os.path.exists(file_path):
        return PlainTextResponse("Update file not found", status_code=404)

    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=p.get("filename"),
    )


@app.get("/api/v1/download/{platform}")
async def download_update_v1(platform: str):
    return await _download_update(platform)


async def _execute_tunnel(
    service_type: ServiceType,
    payload: str,
    options: TunnelOptions,
    api_version: int = 1,
) -> tuple[str, bool]:
    svc = get_service(service_type, api_version)
    if not svc:
        return json.dumps(
            make_error(
                ErrorType.UNKNOWN_SERVICE, f"Unknown service: {service_type}"
            ).model_dump()
        ), False

    handler = svc.handle_v2 if api_version >= 2 else svc.handle_v1

    if service_type != ServiceType.OCR:
        payload = payload.strip()
    options = options or TunnelOptions()

    # Validation
    err = await svc.validate(payload)
    if err:
        return json.dumps(make_error(ErrorType.VALIDATION_ERROR, err).model_dump()), False

    try:
        timeout = (
            options.timeout
            if options.timeout and options.timeout > 0
            else TIMEOUT_SERVICE_DEFAULT
        )
        return await asyncio.wait_for(
            cache.execute(svc, payload, options, handler, api_version=api_version),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning(f"Service {service_type} timed out after {timeout}s")
        return json.dumps(
            make_error(
                ErrorType.TIMEOUT_ERROR,
                f"Service {service_type} did not respond within {timeout} seconds",
            ).model_dump()
        ), False
    except Exception as e:
        logger.error(f"Error handling {service_type}: {e}")
        return json.dumps(make_error(ErrorType.INTERNAL_ERROR, str(e)).model_dump()), False


@app.post("/api/v1/tunnel/{service}", response_class=PlainTextResponse)
async def handle_tunnel_v1(service: str, target: TunnelRequestV1):
    try:
        service_type = ServiceType(service)
    except ValueError:
        return json.dumps(
            make_error(
                ErrorType.UNKNOWN_SERVICE, f"Unknown service: {service}"
            ).model_dump()
        )

    logger.info(
        f"Tunnel request payload: service={service_type}, payload={target.payload}, "
        f"force={target.options.force if target.options else False}"
    )

    result_str, was_cached = await _execute_tunnel(
        service_type,
        target.payload or "",
        target.options or TunnelOptions(),
        api_version=1,
    )

    # Wrap in v1 envelope with metadata
    try:
        inner = json.loads(result_str)
        v1 = TunnelResponseV1(
            metadata=TunnelResponseV1Metadata(cached=was_cached),
            payload=inner.get("payload"),
            error=inner.get("error"),
        )
        return json.dumps(v1.model_dump())
    except Exception:
        return PlainTextResponse(result_str, status_code=500)


@app.post("/api/v2/tunnel/{service}", response_class=PlainTextResponse)
async def handle_tunnel_v2(service: str, target: TunnelRequestV1):
    try:
        service_type = ServiceType(service)
    except ValueError:
        return json.dumps(
            make_error(
                ErrorType.UNKNOWN_SERVICE, f"Unknown service: {service}"
            ).model_dump()
        )

    logger.info(
        f"Tunnel request payload: service={service_type}, payload={target.payload}, "
        f"force={target.options.force if target.options else False}"
    )

    result_str, was_cached = await _execute_tunnel(
        service_type,
        target.payload or "",
        target.options or TunnelOptions(),
        api_version=2,
    )

    try:
        inner = json.loads(result_str)
        v2 = TunnelResponseV1(
            metadata=TunnelResponseV1Metadata(cached=was_cached, version="2"),
            payload=inner.get("payload"),
            error=inner.get("error"),
        )
        return json.dumps(v2.model_dump())
    except Exception:
        return PlainTextResponse(result_str, status_code=500)
