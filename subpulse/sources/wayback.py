from typing import Set
import aiohttp
from .base import BaseSource

class WaybackSource(BaseSource):
    name = "wayback"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=5000"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list) and len(data) > 1:
                        # Skip header row
                        for row in data[1:]:
                            if row and len(row) > 0:
                                raw_url = str(row[0])
                                # Extract hostname
                                if "://" in raw_url:
                                    host = raw_url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                                    clean = self.sanitize(host, domain)
                                    if clean:
                                        subdomains.add(clean)
        except Exception:
            pass
        return subdomains
