import json
import logging
import ipaddress
from urllib.parse import quote

from infrastructure.models import (
    ServiceType,
    TunnelOptions,
    RdapDomain,
    RdapIp,
    RdapEvent,
    RdapEntity,
    RdapNameServer,
    ServiceResult,
)
from services.base import TunnelService
from infrastructure.http_client import aiohttp_fetch
from infrastructure.utils import extract_host, hash_str, make_error, get_root_domain
from infrastructure.errors import ErrorType


logger = logging.getLogger()


def _redact(obj):
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_redact(v) for v in obj]
    elif isinstance(obj, str) and len(obj) > 512:
        return "<REDACTED>"
    return obj


def _parse_and_redact(raw: str) -> dict:
    parsed = json.loads(raw)
    return _redact(parsed)


def _parse_vcard(vcard_array: list) -> dict:
    """Extract fn, email, tel, adr from a jCard/vCardArray structure."""
    result: dict[str, str] = {"fn": "", "email": "", "tel": "", "adr": ""}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result
    props = vcard_array[1] if isinstance(vcard_array[1], list) else []
    for prop in props:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name = prop[0]
        value = prop[3]
        if name == "fn":
            result["fn"] = str(value) if isinstance(value, str) else ""
        elif name == "email":
            result["email"] = str(value) if isinstance(value, str) else ""
        elif name == "tel":
            raw = value
            if isinstance(raw, str):
                result["tel"] = raw
            elif isinstance(raw, list):
                result["tel"] = str(raw[0]) if raw else ""
        elif name == "adr":
            if isinstance(value, dict) and "label" in value:
                result["adr"] = value["label"]
            elif isinstance(value, list):
                parts = [str(p) for p in value if p]
                result["adr"] = ", ".join(parts)
    return result


def _normalize_entities(raw_entities: list) -> list[RdapEntity]:
    entities: list[RdapEntity] = []
    for ent in raw_entities:
        if not isinstance(ent, dict):
            continue
        vcard = _parse_vcard(ent.get("vcardArray", []))
        entities.append(
            RdapEntity(
                handle=ent.get("handle", ""),
                roles=ent.get("roles", []),
                fn=vcard["fn"],
                email=vcard["email"],
                tel=vcard["tel"],
                adr=vcard["adr"],
            )
        )
        # Flatten nested entities (e.g., abuse contact inside registrar)
        for sub in ent.get("entities", []):
            if isinstance(sub, dict):
                sub_vcard = _parse_vcard(sub.get("vcardArray", []))
                entities.append(
                    RdapEntity(
                        handle=sub.get("handle", ""),
                        roles=sub.get("roles", []),
                        fn=sub_vcard["fn"],
                        email=sub_vcard["email"],
                        tel=sub_vcard["tel"],
                        adr=sub_vcard["adr"],
                    )
                )
    return entities


def _normalize_events(raw_events: list) -> list[RdapEvent]:
    events: list[RdapEvent] = []
    for ev in raw_events:
        if isinstance(ev, dict):
            events.append(
                RdapEvent(
                    action=ev.get("eventAction", ""),
                    date=ev.get("eventDate", ""),
                )
            )
    return events


def _normalize_rdap(raw: dict) -> RdapDomain | RdapIp:
    obj_class = raw.get("objectClassName", "")
    if obj_class == "domain":
        raw_ns = raw.get("nameservers", [])
        nameservers = [
            RdapNameServer(ldh_name=ns["ldhName"])
            for ns in raw_ns
            if isinstance(ns, dict) and "ldhName" in ns
        ]
        return RdapDomain(
            handle=raw.get("handle", ""),
            ldh_name=raw.get("ldhName", ""),
            unicode_name=raw.get("unicodeName"),
            statuses=raw.get("status", []),
            events=_normalize_events(raw.get("events", [])),
            entities=_normalize_entities(raw.get("entities", [])),
            nameservers=nameservers,
            secure_dns=raw.get("secureDNS", {}).get("delegationSigned")
            if isinstance(raw.get("secureDNS"), dict)
            else None,
        )
    else:
        cidrs = []
        for c in raw.get("cidr0_cidrs", []):
            if isinstance(c, dict):
                prefix = c.get("v4prefix", c.get("v6prefix", ""))
                length = c.get("length", "")
                cidrs.append(f"{prefix}/{length}" if length else prefix)
        return RdapIp(
            handle=raw.get("handle", ""),
            ip_version=raw.get("ipVersion", ""),
            start_address=raw.get("startAddress", ""),
            end_address=raw.get("endAddress", ""),
            name=raw.get("name"),
            type=raw.get("type"),
            country=raw.get("country"),
            statuses=raw.get("status", []),
            events=_normalize_events(raw.get("events", [])),
            entities=_normalize_entities(raw.get("entities", [])),
            cidrs=cidrs,
            port43=raw.get("port43"),
        )


def _parse_and_normalize(body: bytes) -> ServiceResult | None:
    raw = body.decode("utf-8", errors="ignore")
    try:
        rdap_json = _parse_and_redact(raw)
    except Exception:
        try:
            rdap_json = json.loads(raw)
        except Exception:
            rdap_json = None
    if rdap_json is None:
        return None
    normalized = _normalize_rdap(rdap_json)
    return ServiceResult(payload=normalized.model_dump(), error=None)


class RdapService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.RDAP

    async def cache_key(self, payload: str, options: TunnelOptions) -> str | None:
        query = extract_host(payload)
        opts_json = json.dumps(options.model_dump()) if options else "{}"
        return hash_str(f"{ServiceType.RDAP}:{query}:{opts_json}")

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        query = extract_host(payload)
        try:
            ipaddress.ip_address(query)
            url = f"https://www.rdap.net/ip/{quote(query, safe='')}"
            is_ip = True
        except ValueError:
            url = f"https://www.rdap.net/domain/{quote(query, safe='')}"
            is_ip = False

        try:
            code, body = await aiohttp_fetch(url, ["Accept: application/rdap+json"])

            if code in (401, 403):
                return make_error(
                    ErrorType.AUTH_ERROR,
                    f"Authentication failed for RDAP, code = {code}",
                )
            if code not in (200, 404):
                return make_error(
                    ErrorType.UPSTREAM_SERVICE_ERROR,
                    f"Server is working but RDAP didn't respond, code = {code}",
                )

            if code == 200:
                result = _parse_and_normalize(body)
                if result:
                    return result
                return make_error(
                    ErrorType.NOT_FOUND_ERROR, f"No RDAP data found for '{query}'."
                )

            # code == 404: FLD fallback for domain queries
            if not is_ip:
                root_domain = get_root_domain(query)
                if root_domain != query:
                    fb_code, fb_body = await aiohttp_fetch(
                        f"https://www.rdap.net/domain/{quote(root_domain, safe='')}",
                        ["Accept: application/rdap+json"],
                    )
                    if fb_code == 200:
                        result = _parse_and_normalize(fb_body)
                        if result:
                            return result

            return make_error(
                ErrorType.NOT_FOUND_ERROR, f"Object was not found on RDAP, code = 404"
            )
        except Exception as e:
            logger.error(f"RDAP lookup error for {query}: {e}")
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR, f"RDAP lookup error: {str(e)}"
            )
