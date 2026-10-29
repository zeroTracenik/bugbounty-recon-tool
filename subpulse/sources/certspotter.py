from typing import Set
import aiohttp
from .base import BaseSource

class CertSpotterSource(BaseSource):
    name = "certspotter"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for item in data:
                            dns_names = item.get("dns_names", [])
                            for dns_name in dns_names:
                                clean = self.sanitize(dns_name, domain)
                                if clean:
                                    subdomains.add(clean)
        except Exception:
            pass
        return subdomains
