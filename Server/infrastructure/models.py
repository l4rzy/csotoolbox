import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ServiceType(str, Enum):
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    CIRCLCVE = "circl"
    SHODAN = "shodan"
    IPDB = "ipdb"
    WHOIS = "whois"
    RDAP = "rdap"
    DNS = "dns"
    OCR = "ocr"
    MAC = "mac"
    SCAMALYTICS = "scamalytics"
    BAZAAR = "bazaar"
    THREATFOX = "threatfox"


class TunnelOptions(BaseModel):
    force: Optional[bool] = False
    reverse: Optional[bool] = None
    use_custom_dns: Optional[bool] = None
    extra: Optional[bool] = False
    timeout: Optional[int] = None


class TunnelRequestV1(BaseModel):
    payload: Optional[str] = ""
    options: Optional[TunnelOptions] = TunnelOptions()


class TunnelError(BaseModel):
    type: str
    message: str


class ServiceResult(BaseModel):
    payload: Optional[dict] = None
    error: Optional[TunnelError] = None


class TunnelResponseV1Metadata(BaseModel):
    version: str = "1"
    cached: bool = False


class TunnelResponseV1(BaseModel):
    metadata: TunnelResponseV1Metadata = TunnelResponseV1Metadata()
    payload: Optional[dict] = None
    error: Optional[TunnelError] = None


# Regex validators
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")
_HASH_RE = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


class RdapEvent(BaseModel):
    action: str = ""
    date: str = ""


class RdapEntity(BaseModel):
    handle: str = ""
    roles: list[str] = []
    fn: str = ""
    email: str = ""
    tel: str = ""
    adr: str = ""


class RdapNameServer(BaseModel):
    ldh_name: str = ""


class RdapDomain(BaseModel):
    handle: str = ""
    ldh_name: str = ""
    unicode_name: str | None = None
    statuses: list[str] = []
    events: list[RdapEvent] = []
    entities: list[RdapEntity] = []
    nameservers: list[RdapNameServer] = []
    secure_dns: bool | None = None


class RdapIp(BaseModel):
    handle: str = ""
    ip_version: str = ""
    start_address: str = ""
    end_address: str = ""
    name: str | None = None
    type: str | None = None
    country: str | None = None
    statuses: list[str] = []
    events: list[RdapEvent] = []
    entities: list[RdapEntity] = []
    cidrs: list[str] = []
    port43: str | None = None
