import hashlib
from urllib.parse import urlsplit
from tld import get_fld


def extract_host(query: str) -> str:
    """Extract hostname from a URL, email, host:port, or bare host/IP."""
    stripped = query.strip()
    if not stripped:
        return stripped

    if not stripped.startswith("//"):
        lower = stripped.lower()
        if not lower.startswith(("http://", "https://", "ftp://")):
            stripped = f"//{stripped}"

    parsed = urlsplit(stripped)
    return parsed.hostname if parsed.hostname else query.strip()


def hash_str(item_str: str) -> str:
    return hashlib.sha256(item_str.encode()).hexdigest()


def get_root_domain(host: str) -> str:
    try:
        return get_fld(f"http://{host}", fail_silently=False)
    except Exception:
        return host


from infrastructure.models import ServiceResult, TunnelError


def make_error(error_type: str, message: str) -> ServiceResult:
    return ServiceResult(
        payload=None, error=TunnelError(type=error_type, message=message)
    )
