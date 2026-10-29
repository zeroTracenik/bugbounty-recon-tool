from typing import Set
import aiohttp
from .base import BaseSource

class UrlScanSource(BaseSource):
    name = "urlscan"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    for res in results:
                        page = res.get("page", {})
                        ptr = page.get("domain", "")
                        clean = self.sanitize(ptr, domain)
                        if clean:
                            subdomains.add(clean)
                        # Also check task domain
                        task_domain = res.get("task", {}).get("domain", "")
                        clean_task = self.sanitize(task_domain, domain)
                        if clean_task:
                            subdomains.add(clean_task)
        except Exception:
            pass
        return subdomains
