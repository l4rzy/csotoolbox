import os


# =============================================================================
# Application-wide constants
# =============================================================================

# Default HTTP User-Agent header value for all HTTP requests
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
)

# Custom DNS resolver nameservers (primary, fallback)
DNS_CUSTOM_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
DNS_INTERNAL_NAMESERVERS = [
    address.strip()
    for address in os.getenv("CSOTOOLBOX_INTERNAL_DNS", "").split(",")
    if address.strip()
]

# Third-party API URL templates
API_CIRCL_CVE = "https://vulnerability.circl.lu/api/cve/{cve_id}"
API_SHODAN_CVE = "https://cvedb.shodan.io/cve/{cve_id}"
API_ABUSEIPDB_CHECK = (
    "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose&maxAgeInDays=90"
)
API_VIRUSTOTAL_SEARCH = "https://www.virustotal.com/api/v3/search"
API_MAC_VENDOR = "https://api.macvendors.com/{mac_addr}"
API_SCAMALYTICS = "https://api11.scamalytics.com/v3/{user}/?key={key}&ip={ip}"
API_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
API_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
API_IPAPI = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

# Rate limiting
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 60  # max requests per window per client
RATE_LIMIT_TRACKED_CLIENTS_MAX = 10000  # hard cap on distinct client IPs tracked at once

# Request body size limit
MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024  # 8 MB — generous for a resized base64 screenshot

# Cache
CACHE_TTL_SECONDS = 3600
CACHE_MAX_SIZE = 1000

# OCR engine configuration
OCR_MAX_SIDE = 840

# PComputer DNS
DNS_PCOMPUTER_DOMAIN = os.getenv("CSOTOOLBOX_PCOMPUTER_DOMAIN", "example.invalid")
DNS_PCOMPUTER_PATTERN = r"(PCOMP|pcomp)(-|_)([0-9]{7})(?![0-9])"

# Service timeout
TIMEOUT_SERVICE_DEFAULT = 5  # seconds

# Version
VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_BUILD = 0
VERSION_REVISION = "DEV"
VERSION_DATE = "2026 October 5"
