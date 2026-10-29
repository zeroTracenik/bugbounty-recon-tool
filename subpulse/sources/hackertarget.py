from typing import Set
import aiohttp
from .base import BaseSource

class HackerTargetSource(BaseSource):
    name = "hackertarget"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    if "error" not in text.lower():
                        for line in text.splitlines():
                            parts = line.split(",")
                            if parts:
                                clean = self.sanitize(parts[0], domain)
                                if clean:
                                    subdomains.add(clean)
        except Exception:
            pass
        return subdomains
