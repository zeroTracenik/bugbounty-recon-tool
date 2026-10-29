import re
from typing import Set, List

COMMON_WORDS = [
    "dev", "development", "staging", "stage", "stg", "prod", "production",
    "test", "testing", "qa", "uat", "demo", "beta", "alpha", "preview",
    "api", "v1", "v2", "v3", "app", "web", "mobile", "portal", "admin",
    "corp", "internal", "intranet", "private", "secure", "vpn", "gateway",
    "cloud", "auth", "login", "sso", "identity", "oauth", "account",
    "node", "srv", "server", "host", "edge", "cdn", "static", "assets",
    "data", "db", "sql", "redis", "elastic", "k8s", "cluster", "hub"
]

NUMBER_PATTERNS = [
    ("1", "2"), ("01", "02"), ("2", "3"), ("1", "01"), ("0", "1")
]

class PermutationEngine:
    def __init__(self, domain: str, max_generated: int = 5000):
        self.domain = domain
        self.max_generated = max_generated

    def generate(self, discovered_subdomains: Set[str]) -> Set[str]:
        """
        Generates smart permutations and mutations based on discovered subdomains.
        """
        generated = set()

        # Extract subdomain prefixes (e.g. 'api' from 'api.target.com')
        base_labels = set()
        for sub in discovered_subdomains:
            if sub == self.domain or not sub.endswith("." + self.domain):
                continue
            prefix = sub[: -len(self.domain) - 1]
            labels = prefix.split(".")
            for l in labels:
                if l and len(l) < 30:
                    base_labels.add(l)
                    # Also split words by hyphen or underscore
                    subparts = re.split(r"[-_]", l)
                    for part in subparts:
                        if part and len(part) >= 2:
                            base_labels.add(part)

        if not base_labels:
            base_labels = {"api", "dev", "app", "admin", "test", "stage"}

        # 1. Hyphenated Prefix & Suffix Alterations
        for label in base_labels:
            if len(generated) >= self.max_generated:
                break
            for word in COMMON_WORDS[:25]:
                # Suffix: label-word.domain
                cand1 = f"{label}-{word}.{self.domain}"
                generated.add(cand1)
                # Prefix: word-label.domain
                cand2 = f"{word}-{label}.{self.domain}"
                generated.add(cand2)
                # Direct concat: labelword.domain
                cand3 = f"{label}{word}.{self.domain}"
                generated.add(cand3)

        # 2. Number mutations (e.g., api1 -> api2, srv01 -> srv02)
        for label in base_labels:
            if len(generated) >= self.max_generated:
                break
            match = re.search(r"\d+$", label)
            if match:
                num_str = match.group()
                prefix_part = label[: -len(num_str)]
                try:
                    num_val = int(num_str)
                    for delta in [-1, 1, 2, 3]:
                        new_num = num_val + delta
                        if new_num >= 0:
                            new_label = f"{prefix_part}{new_num:0{len(num_str)}d}"
                            generated.add(f"{new_label}.{self.domain}")
                except Exception:
                    pass
            else:
                # Append 1, 2, 01
                generated.add(f"{label}1.{self.domain}")
                generated.add(f"{label}2.{self.domain}")
                generated.add(f"{label}01.{self.domain}")

        # Exclude already discovered subdomains
        return generated - discovered_subdomains
