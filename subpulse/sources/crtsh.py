import json
from typing import Set
import aiohttp
from .base import BaseSource

class CrtshSource(BaseSource):
    name = "crtsh"

    async def enumerate(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains = set()
        urls = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://crt.sh/?q={domain}&output=json"
        ]

        for url in urls:
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="ignore")
                        try:
                            data = json.loads(text)
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for raw in name_value.split("\n"):
                                    clean = self.sanitize(raw, domain)
                                    if clean:
                                        subdomains.add(clean)
                        except Exception:
                            # Fallback to regex extraction
                            subdomains.update(self.extract_from_text(text, domain))
                        if subdomains:
                            break
            except Exception:
                continue

        return subdomains
