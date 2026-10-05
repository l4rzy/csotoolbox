import asyncio
import ipaddress
import json
import logging
import re as _re
from datetime import datetime

from infrastructure.models import (
    ServiceType,
    TunnelOptions,
    _DOMAIN_RE,
    ServiceResult,
)
from infrastructure.utils import extract_host, get_root_domain, make_error, hash_str
from infrastructure.constants import TIMEOUT_SERVICE_DEFAULT
from infrastructure.errors import ErrorType
from services.base import TunnelService


_WHOIS_NOT_FOUND_INDICATORS = [
    "not found",
    "no match for",
    "no entries found",
    "no data found",
    "query returned 0 objects",
    "no object found",
    "domain not found",
]


logger = logging.getLogger()


# IP WHOIS markers
_IP_WHOIS_MARKERS = (
    "inetnum:",
    "netrange:",
    "inet6num:",
    "route:",
    "origin:",
    "organisation:",
    "orgname:",
    "netname:",
    "nethandle:",
    "cidr:",
)

# Domain field aliases
_DOMAIN_KEYS = ("domain name", "domain", "domain_name")
_REGISTRAR_KEYS = ("registrar", "registrar name", "sponsoring registrar")
_REGISTRAR_ID_KEYS = ("registrar iana id", "registrar id", "iana id")
_REGISTRAR_URL_KEYS = ("registrar url", "registrar website", "referral url")
_REGISTRY_ID_KEYS = ("registry domain id", "domain id")
_REGISTRANT_ORG_KEYS = ("registrant organization", "registrant org")
_REGISTRANT_NAME_KEYS = ("registrant name", "registrant")
_REGISTRANT_EMAIL_KEYS = ("registrant email", "registrant contact email")
_REGISTRANT_PHONE_KEYS = ("registrant phone", "registrant contact phone")
_ADMIN_ORG_KEYS = (
    "admin organization",
    "admin org",
    "admin contact organization",
    "administrative contact organization",
)
_ADMIN_NAME_KEYS = ("admin name", "admin contact name", "administrative contact name")
_ADMIN_EMAIL_KEYS = (
    "admin email",
    "admin contact email",
    "administrative contact email",
)
_ADMIN_PHONE_KEYS = (
    "admin phone",
    "admin contact phone",
    "administrative contact phone",
)
_TECH_ORG_KEYS = ("tech organization", "tech org", "technical contact organization")
_TECH_NAME_KEYS = ("tech name", "tech contact name", "technical contact name")
_TECH_EMAIL_KEYS = ("tech email", "tech contact email", "technical contact email")
_TECH_PHONE_KEYS = ("tech phone", "tech contact phone", "technical contact phone")
_CREATED_KEYS = (
    "creation date",
    "created",
    "registered",
    "creation_date",
    "registered on",
    "created on",
    "registration date",
    "registered date",
    "registered at",
)
_EXPIRY_KEYS = (
    "registry expiry date",
    "expiration date",
    "expires",
    "expiry date",
    "registry_expiry_date",
    "registrar registration expiration date",
    "paid-till",
)
_UPDATED_KEYS = (
    "updated date",
    "last updated",
    "changed",
    "updated_date",
    "last-update",
    "modified",
    "last modified",
    "last updated on",
)
_ABUSE_EMAIL_KEYS = (
    "registrar abuse contact email",
    "abuse email",
    "registrar abuse email",
    "abuse complaints email",
    "abuse contact email",
)
_ABUSE_PHONE_KEYS = (
    "registrar abuse contact phone",
    "abuse phone",
    "registrar abuse phone",
    "abuse complaints phone",
    "abuse contact phone",
)
_DNSSEC_KEYS = ("dnssec", "dnssec delegation")
_STATUS_KEYS = ("domain status", "status", "domain_status", "state")
_NAMESERVER_KEYS = (
    "name server",
    "name servers",
    "nameserver",
    "nameservers",
    "nserver",
    "ns",
)


def normalize_date(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    for suffix in (" UTC", " GMT", " EST", " PST", " CET", " EET", " JST"):
        if raw.endswith(suffix):
            raw = raw[: -len(suffix)]
            break
    raw = _re.sub(r" [+-]\d{2}:\d{2}$", "", raw)
    raw = raw.rstrip("Z").rstrip("z").rstrip("+").rstrip("-").strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y",
        "%B %d %Y",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y. %m. %d.",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    try:
        ts = int(raw)
        if 1_000_000_000 < ts < 10_000_000_000:
            dt = datetime.utcfromtimestamp(ts)
        elif 10_000_000_000_000 < ts < 10_000_000_000_000_000:
            dt = datetime.utcfromtimestamp(ts / 1000)
        else:
            return raw
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        pass
    return raw


def _make_empty_result() -> dict:
    return {
        "domain_name": "",
        "registrar": "",
        "registrar_iana_id": "",
        "registrar_url": "",
        "registry_domain_id": "",
        "registrant": "",
        "registrant_name": "",
        "registrant_email": "",
        "registrant_phone": "",
        "admin_org": "",
        "admin_name": "",
        "admin_email": "",
        "admin_phone": "",
        "tech_org": "",
        "tech_name": "",
        "tech_email": "",
        "tech_phone": "",
        "created_date": "",
        "expiration_date": "",
        "updated_date": "",
        "abuse_email": "",
        "abuse_phone": "",
        "dnssec": "",
        "statuses": [],
        "nameservers": [],
    }


def _is_ip_whois(text: str) -> bool:
    return any(marker in text[:2048].lower() for marker in _IP_WHOIS_MARKERS)


def _parse_ip_whois(text: str) -> dict:
    data = _make_empty_result()
    current_key = None
    ip_country = ""

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "%", ";")):
            current_key = None
            continue

        if ":" in stripped:
            parts = stripped.split(":", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            current_key = key
        elif current_key and (line[0] in (" ", "\t") if line else False):
            val = stripped
        else:
            current_key = None
            continue

        if not val:
            continue

        if current_key in ("inetnum", "netrange", "inet6num", "cidr", "route"):
            if not data["domain_name"]:
                data["domain_name"] = val
        elif current_key in ("netname", "nethandle"):
            if not data["registrar"]:
                data["registrar"] = val
        elif current_key in ("organisation", "orgname", "owner", "org-name", "org"):
            data["registrant"] = val
        elif current_key == "country":
            ip_country = val
        elif current_key == "descr":
            if not data["tech_org"]:
                data["tech_org"] = val
            elif val not in data["tech_org"]:
                data["tech_org"] += f"; {val}"
        elif current_key in ("abuse-mailbox", "orgabuseemail"):
            if not data["abuse_email"]:
                data["abuse_email"] = val
        elif current_key in ("abuse-c", "orgabusehandle"):
            if not data["abuse_phone"]:
                data["abuse_phone"] = val
        elif current_key in ("created", "created_date", "registration"):
            if not data["created_date"]:
                data["created_date"] = normalize_date(val)
        elif current_key in ("last-modified", "changed", "updated"):
            if not data["updated_date"]:
                data["updated_date"] = normalize_date(val)
        elif current_key == "remarks":
            pass
        elif current_key == "status":
            if val not in data["statuses"]:
                data["statuses"].append(val)

    if ip_country and data["registrant"]:
        data["registrant"] = f"{data['registrant']}, {ip_country}"
    elif ip_country:
        data["registrant"] = ip_country
    return data


def _parse_domain_whois(text: str) -> dict:
    data = _make_empty_result()
    current_primary_key = None

    def _set(dst_key: str, v: str) -> None:
        if not data[dst_key]:
            data[dst_key] = v

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "%", ";")):
            current_primary_key = None
            continue

        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            current_primary_key = key
        elif current_primary_key and raw_line and raw_line[0] in (" ", "\t"):
            val = line
            if current_primary_key in _REGISTRANT_ORG_KEYS:
                data["registrant"] = f"{data['registrant']} {val}".strip()
            elif current_primary_key in _REGISTRANT_NAME_KEYS:
                data["registrant_name"] = f"{data['registrant_name']} {val}".strip()
            elif current_primary_key in _ADMIN_ORG_KEYS:
                data["admin_org"] = f"{data['admin_org']} {val}".strip()
            elif current_primary_key in _TECH_ORG_KEYS:
                data["tech_org"] = f"{data['tech_org']} {val}".strip()
            elif current_primary_key in _REGISTRAR_KEYS:
                data["registrar"] = f"{data['registrar']} {val}".strip()
            elif current_primary_key == "abuse-mailbox":
                data["abuse_email"] = f"{data['abuse_email']} {val}".strip()
            continue
        else:
            current_primary_key = None
            continue

        if not val:
            continue

        if key in _DOMAIN_KEYS:
            _set("domain_name", val)
        elif key in _REGISTRAR_KEYS:
            _set("registrar", val)
        elif key in _REGISTRAR_ID_KEYS:
            _set("registrar_iana_id", val)
        elif key in _REGISTRAR_URL_KEYS:
            _set("registrar_url", val)
        elif key in _REGISTRY_ID_KEYS:
            _set("registry_domain_id", val)
        elif key in _REGISTRANT_ORG_KEYS:
            _set("registrant", val)
        elif key in _REGISTRANT_NAME_KEYS:
            _set("registrant_name", val)
        elif key in _REGISTRANT_EMAIL_KEYS:
            _set("registrant_email", val)
        elif key in _REGISTRANT_PHONE_KEYS:
            _set("registrant_phone", val)
        elif key in _ADMIN_ORG_KEYS:
            _set("admin_org", val)
        elif key in _ADMIN_NAME_KEYS:
            _set("admin_name", val)
        elif key in _ADMIN_EMAIL_KEYS:
            _set("admin_email", val)
        elif key in _ADMIN_PHONE_KEYS:
            _set("admin_phone", val)
        elif key in _TECH_ORG_KEYS:
            _set("tech_org", val)
        elif key in _TECH_NAME_KEYS:
            _set("tech_name", val)
        elif key in _TECH_EMAIL_KEYS:
            _set("tech_email", val)
        elif key in _TECH_PHONE_KEYS:
            _set("tech_phone", val)
        elif key in _CREATED_KEYS:
            _set("created_date", normalize_date(val))
        elif key in _EXPIRY_KEYS:
            _set("expiration_date", normalize_date(val))
        elif key in _UPDATED_KEYS:
            _set("updated_date", normalize_date(val))
        elif key in _ABUSE_EMAIL_KEYS:
            _set("abuse_email", val)
        elif key in _ABUSE_PHONE_KEYS:
            _set("abuse_phone", val)
        elif key in _DNSSEC_KEYS:
            _set("dnssec", val)
        elif key in _STATUS_KEYS:
            status_val = val.split("http", 1)[0].strip()
            if status_val not in data["statuses"]:
                data["statuses"].append(status_val)
        elif key in _NAMESERVER_KEYS:
            ns_val = val.lower()
            if " " in ns_val:
                ns_val, _ = (
                    ns_val.split(" ", 1) if not ns_val[0].isdigit() else (ns_val, "")
                )
            if ns_val and ns_val not in data["nameservers"]:
                data["nameservers"].append(ns_val)

    return data


def parse_whois(text: str) -> dict:
    if not text:
        return _make_empty_result()
    if _is_ip_whois(text):
        return _parse_ip_whois(text)
    return _parse_domain_whois(text)


_IANA_SERVER = "whois.iana.org"
_WHOIS_PORT = 43


async def _is_safe_whois_server(server: str, timeout: int = TIMEOUT_SERVICE_DEFAULT) -> bool:
    """Reject referral servers that resolve to a private/loopback/link-local address."""
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo(server, _WHOIS_PORT), timeout=timeout)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip_obj = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return False
    return True


async def _query_whois_server(
    server: str, query: str, timeout: int = TIMEOUT_SERVICE_DEFAULT
) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, _WHOIS_PORT),
            timeout=timeout,
        )
        writer.write((query + "\r\n").encode("ascii"))
        await writer.drain()

        data = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
            except asyncio.TimeoutError:
                break
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


async def _get_referral_server(
    query: str, is_ip: bool, timeout: int = TIMEOUT_SERVICE_DEFAULT
) -> str:
    text = await _query_whois_server(_IANA_SERVER, query, timeout=timeout)
    default_server = "whois.ripe.net" if is_ip else "whois.verisign-grs.com"
    for line in text.split("\n"):
        line = line.strip()
        if line.lower().startswith("whois:"):
            server = line.split(":", 1)[1].strip()
            if server:
                if await _is_safe_whois_server(server, timeout=timeout):
                    return server
                logger.warning(f"Ignoring unsafe WHOIS referral server: {server}")
            break
    return default_server


async def query_whois_async(query: str, timeout: int = TIMEOUT_SERVICE_DEFAULT) -> str:
    domain = query.strip()
    is_ip = False
    try:
        ipaddress.IPv4Address(domain)
        is_ip = True
    except Exception:
        try:
            ipaddress.IPv6Address(domain)
            is_ip = True
        except Exception:
            pass
    if not is_ip and domain.startswith("-"):
        return "Error: Invalid domain input"
    server = await _get_referral_server(domain, is_ip, timeout=timeout)
    return await _query_whois_server(server, domain, timeout=timeout)


class WhoisService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.WHOIS

    def _has_data(self, parsed: dict) -> bool:
        filled = sum(
            1
            for v in (
                parsed.get(k, "")
                for k in ("domain_name", "registrar", "registrant", "created_date")
            )
            if v
        )
        return filled >= 2 and "error" not in parsed

    async def validate(self, payload: str) -> str | None:
        if not payload:
            return "No domain or IP provided for WHOIS query."

    async def cache_key(self, payload: str, options: TunnelOptions) -> str | None:
        query_val = payload.strip()
        domain = query_val
        try:
            ipaddress.IPv4Address(domain)
        except Exception:
            try:
                ipaddress.IPv6Address(domain)
            except Exception:
                domain = extract_host(domain)
        opts_json = json.dumps(options.model_dump()) if options else "{}"
        return hash_str(f"{ServiceType.WHOIS}:{domain}:{opts_json}")

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        query_val = payload
        domain = query_val.strip()
        is_ip = False
        try:
            ipaddress.IPv4Address(domain)
            is_ip = True
        except Exception:
            try:
                ipaddress.IPv6Address(domain)
                is_ip = True
            except Exception:
                pass

        if not is_ip:
            domain = extract_host(domain)

        if not is_ip:
            try:
                ipaddress.ip_address(domain)
                return make_error(
                    ErrorType.VALIDATION_ERROR,
                    f"WHOIS does not support IP addresses: {domain}",
                )
            except ValueError:
                pass

        if not is_ip and (domain.startswith("-") or not _DOMAIN_RE.match(domain)):
            return make_error(
                ErrorType.VALIDATION_ERROR, f"Invalid domain format: {domain}"
            )

        whois_timeout = options.timeout or TIMEOUT_SERVICE_DEFAULT

        async def query_domain_whois(dom):
            parsed = {}
            try:
                whois_text = await query_whois_async(dom, timeout=whois_timeout)
                text_lower = whois_text.lower()
                if any(ind in text_lower for ind in _WHOIS_NOT_FOUND_INDICATORS):
                    parsed = {
                        "error": ErrorType.NOT_FOUND_ERROR,
                        "message": "Object was not found on WHOIS",
                    }
                else:
                    parsed = parse_whois(whois_text)
            except Exception as e:
                logger.error(f"WHOIS lookup for {dom} failed: {e}")
                parsed = {
                    "error": ErrorType.UPSTREAM_SERVICE_ERROR,
                    "message": "server is working but whois didn't respond",
                }
            return parsed

        parsed_data = await query_domain_whois(domain)
        if not self._has_data(parsed_data):
            root_dom = get_root_domain(domain)
            if root_dom != domain:
                parsed_root = await query_domain_whois(root_dom)
                if self._has_data(parsed_root):
                    parsed_data = parsed_root

        if "error" in parsed_data and len(parsed_data) <= 2:
            return make_error(
                parsed_data["error"], parsed_data.get("message", "unknown error")
            )
        return ServiceResult(payload=parsed_data, error=None)
