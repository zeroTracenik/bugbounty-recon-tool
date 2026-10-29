from typing import Set
import aiohttp
from .base import BaseSource

class DigitorusSource(BaseSource):
    name = "digitorus"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://certificatedetails.com/{domain}"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    subdomains.update(self.extract_from_text(text, domain))
        except Exception:
            pass
        return subdomains
