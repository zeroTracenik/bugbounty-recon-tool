import re
import ssl
from typing import Set, Optional
import aiohttp

# RFC 1123 compliant domain regex matching
SUBDOMAIN_REGEX_TEMPLATE = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+{domain}"

def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

class BaseSource:
    name: str = "base"
    requires_key: bool = False

    def __init__(self, api_keys: Optional[dict] = None):
        self.api_keys = api_keys or {}

    def sanitize(self, candidate: str, domain: str) -> Optional[str]:
        if not candidate:
            return None
        candidate = candidate.strip().lower()
        # Remove schemes
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1]
        # Remove paths / queries
        if "/" in candidate:
            candidate = candidate.split("/", 1)[0]
        # Remove ports
        if ":" in candidate:
            candidate = candidate.split(":", 1)[0]
        # Remove wildcard prefix and leading dots
        candidate = candidate.lstrip("*.@_ \t\r\n")
        candidate = candidate.rstrip(".")

        # Must end with domain
        if candidate == domain or candidate.endswith("." + domain):
            # Check characters validity: alphanumeric, hyphens, dots
            if re.match(r"^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$", candidate):
                # Ensure no double dots or invalid label length
                labels = candidate.split(".")
                if all(1 <= len(l) <= 63 for l in labels):
                    return candidate
        return None

    def extract_from_text(self, text: str, domain: str) -> Set[str]:
        escaped_domain = re.escape(domain)
        pattern = re.compile(rf"\b([a-zA-Z0-9_\-\*]+\.{escaped_domain})\b", re.IGNORECASE)
        found = set()
        for match in pattern.finditer(text):
            raw = match.group(1)
            # handle cases like *.sub.domain or sub1,sub2.domain
            for part in raw.split("\n"):
                clean = self.sanitize(part, domain)
                if clean:
                    found.add(clean)
        return found

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        raise NotImplementedError
