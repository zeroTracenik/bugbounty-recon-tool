import asyncio
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict
import dns.asyncresolver
import dns.resolver
from .config import DEFAULT_RESOLVERS, DEFAULT_DNS_TIMEOUT
from .wildcard import WildcardDetector

@dataclass
class SubdomainRecord:
    subdomain: str
    is_alive: bool = False
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)
    is_wildcard: bool = False
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None

class FastAsyncResolver:
    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = DEFAULT_DNS_TIMEOUT,
        concurrency: int = 150,
        wildcard_detector: Optional[WildcardDetector] = None,
    ):
        self.nameservers = nameservers or DEFAULT_RESOLVERS
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.wildcard_detector = wildcard_detector

        # Configure async resolver
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2

    async def resolve_single(self, host: str, source: str = "dns") -> SubdomainRecord:
        record = SubdomainRecord(subdomain=host)
        if source:
            record.sources.add(source)

        async with self.semaphore:
            # Query A record
            try:
                ans_a = await self.resolver.resolve(host, "A")
                for rdata in ans_a:
                    record.ips.append(rdata.to_text())
            except Exception:
                pass

            # Query AAAA record
            try:
                ans_aaaa = await self.resolver.resolve(host, "AAAA")
                for rdata in ans_aaaa:
                    record.ips.append(rdata.to_text())
            except Exception:
                pass

            # Query CNAME record
            try:
                ans_cname = await self.resolver.resolve(host, "CNAME")
                for rdata in ans_cname:
                    record.cnames.append(rdata.to_text().rstrip("."))
            except Exception:
                pass

        if record.ips or record.cnames:
            record.is_alive = True
            if self.wildcard_detector and self.wildcard_detector.filter_wildcard(set(record.ips), set(record.cnames)):
                record.is_wildcard = True

        return record

    async def resolve_batch(
        self,
        subdomains: List[str],
        source_map: Optional[Dict[str, Set[str]]] = None,
        progress_callback=None
    ) -> List[SubdomainRecord]:
        tasks = []
        source_map = source_map or {}

        async def _wrap_resolve(host: str):
            srcs = source_map.get(host, set())
            rec = await self.resolve_single(host)
            rec.sources.update(srcs)
            if progress_callback:
                progress_callback(rec)
            return rec

        for sub in subdomains:
            tasks.append(_wrap_resolve(sub))

        return await asyncio.gather(*tasks, return_exceptions=False)
