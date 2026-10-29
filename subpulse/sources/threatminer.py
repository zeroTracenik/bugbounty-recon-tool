from typing import Set
import aiohttp
from .base import BaseSource

class ThreatMinerSource(BaseSource):
    name = "threatminer"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    if isinstance(results, list):
                        for sub in results:
                            clean = self.sanitize(str(sub), domain)
                            if clean:
                                subdomains.add(clean)
        except Exception:
            pass
        return subdomains
