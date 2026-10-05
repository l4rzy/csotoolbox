import asyncio
import ipaddress
import json
import logging
import re
from dataclasses import dataclass

from infrastructure.utils import get_root_domain, extract_host, hash_str
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from infrastructure.constants import (
    TIMEOUT_SERVICE_DEFAULT,
    DNS_PCOMPUTER_DOMAIN,
    DNS_PCOMPUTER_PATTERN,
)
from infrastructure.executors import DNS_EXECUTOR
from infrastructure.errors import ErrorType
from infrastructure.utils import make_error
from services.base import TunnelService


logger = logging.getLogger()

_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

_RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


@dataclass
class DnsQueryResult:
    records: list
    nameserver: str = ""
    error: str | None = None


@dataclass
class DnsResolveOptions:
    query: str
    reverse: bool = False
    use_custom_dns: bool = True
    is_url: bool = False
    timeout: int | None = None
    is_internal: bool = False


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in net for net in _RFC1918)
    except Exception:
        return False


def _get_dns_resolver(use_custom: bool, is_internal: bool = False):
    import dns.resolver
    from infrastructure.constants import (
        DNS_CUSTOM_NAMESERVERS,
        DNS_INTERNAL_NAMESERVERS,
    )

    if is_internal:
        if not DNS_INTERNAL_NAMESERVERS:
            return dns.resolver.Resolver()
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DNS_INTERNAL_NAMESERVERS
        return resolver
    if use_custom:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DNS_CUSTOM_NAMESERVERS
        return resolver
    return dns.resolver.Resolver()


def _query_single(host: str, rtype: str, opts: DnsResolveOptions) -> DnsQueryResult:
    """Resolve one record type synchronously (runs in thread pool per query)."""
    import dns.resolver

    resolver = _get_dns_resolver(opts.use_custom_dns, is_internal=opts.is_internal)
    try:
        answers = resolver.resolve(host, rtype, lifetime=opts.timeout)
        records = []
        for rdata in answers:
            val = str(rdata)
            if rtype == "TXT" and not val.startswith('"'):
                val = f'"{val}"'
            records.append({"type": rtype, "value": val})
        return DnsQueryResult(records=records, nameserver=answers.nameserver)
    except dns.resolver.NXDOMAIN:
        return DnsQueryResult(records=[], error="NXDOMAIN")
    except dns.resolver.NoNameservers:
        return DnsQueryResult(records=[], error="SERVFAIL")
    except Exception:
        return DnsQueryResult(records=[], error="ERROR")


async def resolve_dns_records_async(opts: DnsResolveOptions) -> dict:
    """Async DNS lookup — all record types queried concurrently via a dedicated executor."""
    import dns.reversename

    loop = asyncio.get_running_loop()
    host = opts.query.strip()

    result = {
        "host": host,
        "isResolvable": False,
        "nameservers": [],
        "reverse": opts.reverse,
        "records": [],
    }

    if opts.reverse:
        try:
            is_private = _is_private_ip(host)
            rev_resolver = _get_dns_resolver(
                opts.use_custom_dns and not is_private, is_internal=is_private
            )
            rev_name = dns.reversename.from_address(host)
            answers = await loop.run_in_executor(DNS_EXECUTOR, rev_resolver.resolve, rev_name, "PTR")
            ptrs = [str(rdata) for rdata in answers]
            if ptrs:
                result["isResolvable"] = True
                result["records"] = [{"type": "PTR", "value": ptrs[0]}]
            result["nameservers"] = [answers.nameserver]
        except Exception:
            if "rev_resolver" in locals():
                result["nameservers"] = [rev_resolver.nameservers[0]]
    else:
        tasks = [
            loop.run_in_executor(DNS_EXECUTOR, _query_single, host, rt, opts)
            for rt in _RTYPES
        ]
        tasks.append(
            loop.run_in_executor(DNS_EXECUTOR, _query_single, f"_dmarc.{host}", "TXT", opts)
        )
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        records = []
        nameservers: set[str] = set()
        error_types: set[str] = set()
        for res in all_results:
            if isinstance(res, DnsQueryResult):
                records.extend(res.records)
                if res.nameserver:
                    nameservers.add(res.nameserver)
                if res.error:
                    error_types.add(res.error)

        if records:
            result["records"] = records
            result["isResolvable"] = True
        elif opts.is_url:
            root_domain = get_root_domain(host)
            if root_domain != host:
                tasks2 = [
                    loop.run_in_executor(DNS_EXECUTOR, _query_single, root_domain, rt, opts)
                    for rt in _RTYPES
                ]
                root_results = await asyncio.gather(*tasks2, return_exceptions=True)
                records2 = []
                for res in root_results:
                    if isinstance(res, DnsQueryResult):
                        records2.extend(res.records)
                        if res.nameserver:
                            nameservers.add(res.nameserver)
                        if res.error:
                            error_types.add(res.error)
                if records2:
                    result["host"] = root_domain
                    result["records"] = records2
                    result["isResolvable"] = True

        if not records and not opts.reverse and error_types:
            result["dns_error"] = (
                "NXDOMAIN"
                if "NXDOMAIN" in error_types
                else "SERVFAIL"
                if "SERVFAIL" in error_types
                else "ERROR"
            )

        if nameservers:
            result["nameservers"] = list(nameservers)

    return result


class DnsService(TunnelService):
    def __init__(self, ipdb_info=None):
        self._ipdb = ipdb_info

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.DNS

    async def cache_key(self, payload: str, options: TunnelOptions) -> str | None:
        host = extract_host(payload)
        opts_json = json.dumps(options.model_dump()) if options else "{}"
        return hash_str(f"{ServiceType.DNS}:{host}:{opts_json}")

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        host = extract_host(payload)
        reverse = options.reverse if options and options.reverse is not None else False
        use_custom_dns = (
            options.use_custom_dns
            if options and options.use_custom_dns is not None
            else True
        )

        if not reverse:
            try:
                ipaddress.ip_address(host)
                reverse = True
            except ValueError:
                pass

        is_internal = False
        if not reverse and re.fullmatch(DNS_PCOMPUTER_PATTERN, host):
            host = f"{host}.{DNS_PCOMPUTER_DOMAIN}"
            is_internal = True

        dns_timeout = options.timeout or TIMEOUT_SERVICE_DEFAULT
        opts = DnsResolveOptions(
            query=host,
            reverse=reverse,
            use_custom_dns=use_custom_dns,
            is_url=(host != payload),
            timeout=dns_timeout,
            is_internal=is_internal,
        )
        res_dict = await resolve_dns_records_async(opts)

        dns_error = res_dict.pop("dns_error", None)
        if dns_error:
            host_display = res_dict.get("host") or host
            if dns_error == "NXDOMAIN":
                return make_error(
                    ErrorType.NOT_FOUND_ERROR,
                    f"DNS domain not found: {host_display} (NXDOMAIN)",
                )
            return make_error(
                ErrorType.UPSTREAM_SERVICE_ERROR,
                f"DNS resolution failed: {host_display} ({dns_error})",
            )

        if (reverse or is_internal) and self._ipdb:
            ipdb_ip = host
            if not reverse:
                ipdb_ip = next(
                    (
                        rec["value"]
                        for rec in res_dict.get("records", [])
                        if rec["type"] in ("A", "AAAA")
                    ),
                    None,
                )
            if ipdb_ip:
                try:
                    res_dict["ipdb"] = await self._ipdb.query(ipdb_ip)
                except Exception:
                    pass
        return ServiceResult(payload=res_dict, error=None)
