from typing import Set
import aiohttp
from .base import BaseSource

class AlienVaultSource(BaseSource):
    name = "alienvault"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"User-Agent": "Mozilla/5.0"}
        api_key = self.api_keys.get("alienvault")
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    records = data.get("passive_dns", [])
                    for rec in records:
                        hostname = rec.get("hostname", "")
                        clean = self.sanitize(hostname, domain)
                        if clean:
                            subdomains.add(clean)
        except Exception:
            pass
        return subdomains
