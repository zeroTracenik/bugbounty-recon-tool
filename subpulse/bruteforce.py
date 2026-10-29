import os
from pathlib import Path
from typing import List, Set, Optional, Callable
from .resolver import FastAsyncResolver, SubdomainRecord
from .wildcard import WildcardDetector

DEFAULT_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "subdomains.txt"

def load_wordlist(custom_path: Optional[str] = None) -> List[str]:
    path = Path(custom_path) if custom_path else DEFAULT_WORDLIST_PATH
    words = []
    if path.exists() and path.is_file():
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for w in words:
        if w not in seen:
            seen.add(w)
            deduped.append(w)
    return deduped

class SubdomainBruteforcer:
    def __init__(
        self,
        domain: str,
        resolver: FastAsyncResolver,
        wildcard_detector: Optional[WildcardDetector] = None,
        custom_wordlist: Optional[str] = None,
    ):
        self.domain = domain
        self.resolver = resolver
        self.wildcard_detector = wildcard_detector
        self.wordlist = load_wordlist(custom_wordlist)

    async def run(
        self,
        progress_callback: Optional[Callable[[SubdomainRecord], None]] = None
    ) -> List[SubdomainRecord]:
        candidates = [f"{w}.{self.domain}" for w in self.wordlist]
        discovered: List[SubdomainRecord] = []

        def _on_resolved(record: SubdomainRecord):
            if record.is_alive and not record.is_wildcard:
                discovered.append(record)
                if progress_callback:
                    progress_callback(record)

        # Batch resolve all candidates
        await self.resolver.resolve_batch(
            candidates,
            source_map={c: {"bruteforce"} for c in candidates},
            progress_callback=_on_resolved
        )

        return discovered
