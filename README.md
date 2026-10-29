# SubPulse ⚡
> **Advanced, High-Yield, and Ultra-Fast Subdomain Enumeration & Intelligence Engine**

SubPulse is a state-of-the-art subdomain discovery tool designed to combine the **speed of Subfinder**, the **depth of OWASP Amass**, and the **active precision of AlterX/MassDNS** into a single cohesive engine.

---

## 🚀 Key Features

| Capability | Feature Description |
| :--- | :--- |
| **High Yield (More Subdomains)** | Simultaneously leverages **14+ passive OSINT engines**, certificate transparency logs, web archives, DNS registries, and search APIs. |
| **Active Brute-Forcing** | Ships with a curated, high-yield dictionary of **1,500+ top real-world subdomain prefixes** (`api`, `dev`, `portal`, `k8s`, `auth`, `corp`, etc.) or custom wordlists. |
| **Smart Permutations (AlterX Style)** | Automatically mutates and permutes discovered subdomains (`dev-api`, `api-v1`, `staging-internal`) to discover hidden, unindexed hosts. |
| **Wildcard Detection & Filtering** | Queries random high-entropy labels to detect catch-all wildcard DNS and **filters out false positives automatically**. |
| **Ultra-Fast Async DNS Engine** | Multi-threaded asynchronous UDP resolver supporting Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), and OpenDNS (`208.67.222.222`). |
| **Integrated HTTP/HTTPS Probing** | Optionally probes discovered targets for HTTP response codes (200, 403, etc.), page titles, and web server banners (`nginx`, `envoy`, `cloudflare`). |
| **Pipeline Ready (`-silent`)** | Formatted for clean UNIX/PowerShell piping to downstream tools like `httpx`, `naabu`, `nuclei`, and `nmap`. |
| **Multiple Output Formats** | Rich visual tables in console, raw TXT, structured JSON, and CSV exports. |

---

## 🛠️ Cross-Platform Installation

SubPulse is 100% cross-platform with **zero bloat** (only 3 ubiquitous lightweight dependencies: `aiohttp`, `dnspython`, `rich`). All files use standard UNIX LF line endings and standard POSIX shebangs.

### 🐉 On Kali Linux / Debian / Ubuntu / Parrot OS

#### Option A: Direct via APT (Fastest & avoids PEP 668 external environment blocks)
```bash
sudo apt update
sudo apt install -y python3-aiohttp python3-dnspython python3-rich
chmod +x subpulse.py
./subpulse.py -h
```

#### Option B: Via Pip / Pipx
```bash
# Using pipx (Recommended on modern Kali / Debian 12+)
pipx install .

# Or using standard pip / virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 🪟 On Windows & 🍎 macOS

```bash
# Clone or open directory
pip install -r requirements.txt

# Run directly
python subpulse.py -d example.com
```

---

## 📖 Quick Start & Examples

### 1. Fast Passive Discovery
Enumerate all passive sources concurrently in seconds:
```bash
python subpulse.py -d example.com
```

### 2. Active DNS Verification & Live IP Resolution
Filter out dead/unresolvable domains and capture active A/AAAA/CNAME records:
```bash
python subpulse.py -d example.com -active -o alive_subdomains.txt
```

### 3. Maximum Coverage (Passive + Built-in Brute Force + Permutations)
Combine passive OSINT, high-speed brute forcing, and alteration generation:
```bash
python subpulse.py -d example.com -b -p -active -oJ results.json
```

### 4. Custom Wordlist Active Brute-Forcing
```bash
python subpulse.py -d example.com -b -w /path/to/wordlist.txt -a
```

### 5. HTTP/HTTPS Probing (Status Code, Title & Server)
```bash
python subpulse.py -d example.com -active --probe -oCSV report.csv
```

### 6. Pipeline Friendly (Silent Mode)
Pipe directly to tools like `httpx` or `nuclei`:
```bash
python subpulse.py -d example.com -silent | httpx -title -status-code
```

### 7. Multi-Target Scanning
Scan multiple domains from a text file:
```bash
python subpulse.py -dL targets.txt -active -o all_active.txt
```

---

## ⚙️ Command-Line Reference

```text
usage: subpulse [-h] [-d DOMAIN] [-dL LIST] [-s SOURCES] [-list-sources] [-a]
                [-b] [-w WORDLIST] [-p] [--probe] [-t THREADS] [-r RESOLVERS]
                [--dns-timeout DNS_TIMEOUT] [--http-timeout HTTP_TIMEOUT]
                [--no-wildcard] [-o OUTPUT] [-oJ JSON] [-oCSV CSV] [-silent]

Target Options:
  -d, --domain DOMAIN     Target domain (e.g. example.com)
  -dL, --list LIST        File containing list of domains to scan

Enumeration Modes:
  -s, --sources SOURCES   Comma-separated passive sources to use (default: all)
  -list-sources           Display list of all available passive sources
  -a, --active            Active DNS verification (filter dead subdomains & resolve IPs)
  -b, --bruteforce        Active DNS brute-forcing with curated high-yield wordlist
  -w, --wordlist FILE     Path to custom wordlist for brute forcing
  -p, --permute           Smart alteration & mutation engine (Amass/AlterX style)
  --probe                 HTTP/HTTPS probing (Status code, Page Title, Server banner)

Performance & DNS:
  -t, --threads INT       Concurrency worker pool size (default: 150)
  -r, --resolvers LIST    Comma-separated DNS resolvers or resolvers file path
  --dns-timeout FLOAT     DNS query timeout in seconds (default: 2.5)
  --http-timeout FLOAT    HTTP probe timeout in seconds (default: 5.0)
  --no-wildcard           Disable wildcard DNS detection and filtering

Output Options:
  -o, --output FILE       Save discovered subdomains to text file (one per line)
  -oJ, --json FILE        Save detailed structured results to JSON file
  -oCSV, --csv FILE       Save structured results to CSV file
  -silent                 Output only subdomains to stdout (pipeable)
```

---

## 🌐 Supported Passive Sources

Run `python subpulse.py -list-sources` to view all sources:
- **crt.sh** (Certificate Transparency logs)
- **CertSpotter** (SSLMate CT log stream)
- **HackerTarget** (DNS host search)
- **URLScan.io** (Scan archive API)
- **Subdomain Center** (Subdomain directory API)
- **RapidDNS** (Rapid DNS database)
- **Wayback Machine** (Internet Archive CDX API)
- **ThreatMiner** (Threat intelligence host data)
- **AlienVault OTX** (Passive DNS indicators)
- **Anubis** (JLDC Subdomain database)
- **SiteDossier** (Parent domain topology)
- **Digitorus** (Certificate search engine)
- **VirusTotal** (Passive DNS / API)
- **SecurityTrails** (Domain intelligence)

---

## 🔑 Optional API Keys Configuration

SubPulse works out-of-the-box without requiring any API keys. If you have API keys for extra threat intelligence feeds, copy `subpulse_config.json.example` to `subpulse_config.json` (or place in `~/.config/subpulse/config.json`):

```json
{
  "alienvault": "YOUR_OTX_KEY",
  "virustotal": "YOUR_VT_KEY",
  "securitytrails": "YOUR_SECURITYTRAILS_KEY",
  "shodan": "YOUR_SHODAN_KEY"
}
```

---

## 🛡️ License
MIT License. Built for authorized reconnaissance, bug bounty hunting, security auditing, and penetration testing.
