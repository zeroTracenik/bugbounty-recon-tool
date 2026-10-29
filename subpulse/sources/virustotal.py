from typing import Set
import aiohttp
from .base import BaseSource

class VirusTotalSource(BaseSource):
    name = "virustotal"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return subdomains

        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        headers = {
            "x-apikey": api_key,
            "User-Agent": "Mozilla/5.0"
        }
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    items = data.get("data", [])
                    for item in items:
                        sub_id = item.get("id", "")
                        clean = self.sanitize(sub_id, domain)
                        if clean:
                            subdomains.add(clean)
        except Exception:
            pass
        return subdomains
