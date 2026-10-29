import uuid
import asyncio
from typing import Set, Tuple, List, Optional
import dns.asyncresolver
import dns.resolver

class WildcardDetector:
    """
    Detects wildcard DNS configurations to eliminate false positives
    during active resolution and DNS brute forcing.
    """
    def __init__(self, domain: str, resolver: dns.asyncresolver.Resolver, sample_count: int = 4):
        self.domain = domain
        self.resolver = resolver
        self.sample_count = sample_count
        self.is_wildcard: bool = False
        self.wildcard_ips: Set[str] = set()
        self.wildcard_cnames: Set[str] = set()

    async def detect(self) -> Tuple[bool, Set[str]]:
        """
        Sends random high-entropy DNS queries to check if wildcard is active.
        """
        resolved_ip_counts: dict = {}
        resolved_cnames: Set[str] = set()

        tasks = []
        test_hosts = []
        for _ in range(self.sample_count):
            rand_prefix = f"subpulse-wc-{uuid.uuid4().hex[:12]}"
            test_host = f"{rand_prefix}.{self.domain}"
            test_hosts.append(test_host)
            tasks.append(self._probe_host(test_host))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, tuple):
                ips, cnames = res
                for ip in ips:
                    resolved_ip_counts[ip] = resolved_ip_counts.get(ip, 0) + 1
                resolved_cnames.update(cnames)

        # If more than 50% of random non-existent queries resolve, it's a wildcard
        threshold = max(2, self.sample_count // 2)
        wildcard_detected_ips = {ip for ip, count in resolved_ip_counts.items() if count >= threshold}

        if wildcard_detected_ips:
            self.is_wildcard = True
            self.wildcard_ips = wildcard_detected_ips
            self.wildcard_cnames = resolved_cnames
            return True, self.wildcard_ips

        self.is_wildcard = False
        return False, set()

    async def _probe_host(self, host: str) -> Tuple[Set[str], Set[str]]:
        ips = set()
        cnames = set()
        try:
            ans = await self.resolver.resolve(host, "A")
            for rdata in ans:
                ips.add(rdata.to_text())
        except Exception:
            pass

        try:
            ans_cname = await self.resolver.resolve(host, "CNAME")
            for rdata in ans_cname:
                cnames.add(rdata.to_text().rstrip("."))
        except Exception:
            pass

        return ips, cnames

    def filter_wildcard(self, ips: Set[str], cnames: Optional[Set[str]] = None) -> bool:
        """
        Returns True if the resolved host is a WILDCARD false positive (should be dropped).
        Returns False if the host has genuine distinct records.
        """
        if not self.is_wildcard or not ips:
            return False

        # If every resolved IP is in the wildcard IP set, it's a wildcard false positive
        if ips.issubset(self.wildcard_ips):
            return True

        # Check CNAME match if present
        if cnames and self.wildcard_cnames:
            if cnames.issubset(self.wildcard_cnames):
                return True

        return False
