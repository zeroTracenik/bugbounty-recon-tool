from typing import Set
import aiohttp
from .base import BaseSource

class AnubisSource(BaseSource):
    name = "anubis"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for sub in data:
                            clean = self.sanitize(str(sub), domain)
                            if clean:
                                subdomains.add(clean)
        except Exception:
            pass
        return subdomains
