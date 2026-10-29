import os
import json
from pathlib import Path

# Trusted, ultra-fast public DNS resolvers
DEFAULT_RESOLVERS = [
    "1.1.1.1",        # Cloudflare primary
    "1.0.0.1",        # Cloudflare secondary
    "8.8.8.8",        # Google primary
    "8.8.4.4",        # Google secondary
    "9.9.9.9",        # Quad9 primary
    "149.112.112.112",# Quad9 secondary
    "208.67.222.222", # OpenDNS primary
    "208.67.220.220", # OpenDNS secondary
]

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

DEFAULT_TIMEOUT = 12
DEFAULT_CONCURRENCY = 150
DEFAULT_DNS_TIMEOUT = 3.0

def get_config_dir() -> Path:
    home = Path.home()
    config_dir = home / ".config" / "subpulse"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir

def load_api_keys() -> dict:
    """
    Loads API keys from config file if available:
    ~/.config/subpulse/config.json or ./subpulse_config.json
    """
    keys = {
        "virustotal": "",
        "securitytrails": "",
        "shodan": "",
        "alienvault": "",
        "chaos": "",
        "censys_id": "",
        "censys_secret": "",
        "github": "",
    }
    candidates = [
        Path("subpulse_config.json"),
        get_config_dir() / "config.json"
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        keys.update(data)
                        break
            except Exception:
                pass
    return keys
