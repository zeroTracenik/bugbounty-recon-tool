from typing import Set
import aiohttp
from .base import BaseSource

class SecurityTrailsSource(BaseSource):
    name = "securitytrails"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        api_key = self.api_keys.get("securitytrails")
        if not api_key:
            return subdomains

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    subs = data.get("subdomains", [])
                    for sub in subs:
                        full = f"{sub}.{domain}"
                        clean = self.sanitize(full, domain)
                        if clean:
                            subdomains.add(clean)
        except Exception:
            pass
        return subdomains
