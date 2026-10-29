import asyncio
import re
from typing import List, Optional
import aiohttp
from .resolver import SubdomainRecord

TITLE_REGEX = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

class AsyncHttpProber:
    def __init__(self, concurrency: int = 50, timeout: float = 5.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def probe_single(self, record: SubdomainRecord, session: aiohttp.ClientSession):
        async with self.semaphore:
            # Try HTTPS first, then fallback to HTTP
            for proto in ["https", "http"]:
                url = f"{proto}://{record.subdomain}"
                try:
                    async with session.get(
                        url,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers={"User-Agent": "Mozilla/5.0"}
                    ) as resp:
                        record.http_status = resp.status
                        record.http_server = resp.headers.get("Server", "")
                        try:
                            # Read first 8KB to extract title
                            body_chunk = await resp.content.read(8192)
                            text = body_chunk.decode("utf-8", errors="ignore")
                            match = TITLE_REGEX.search(text)
                            if match:
                                record.http_title = match.group(1).strip().replace("\n", " ").replace("\r", " ")
                        except Exception:
                            pass
                        # Found a working response
                        return
                except Exception:
                    continue

    async def probe_all(self, records: List[SubdomainRecord]):
        tcp_conn = aiohttp.TCPConnector(ssl=False, limit=0)
        async with aiohttp.ClientSession(connector=tcp_conn) as session:
            tasks = [self.probe_single(rec, session) for rec in records]
            await asyncio.gather(*tasks, return_exceptions=True)
