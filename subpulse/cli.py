import argparse
import asyncio
import sys
import time
import signal
from typing import List, Set, Dict
from pathlib import Path
import aiohttp

# Ignore broken pipe errors on Linux/Unix when piping output (e.g. to head or httpx)
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

from .config import DEFAULT_RESOLVERS, DEFAULT_CONCURRENCY, load_api_keys
from .sources import ALL_SOURCES, get_sources
from .resolver import FastAsyncResolver, SubdomainRecord
from .wildcard import WildcardDetector
from .bruteforce import SubdomainBruteforcer
from .permutations import PermutationEngine
from .http_prober import AsyncHttpProber
from .output import (
    print_banner,
    print_info,
    print_success,
    print_warning,
    print_error,
    display_results_table,
    export_results,
    console
)

async def run_passive_sources(
    domain: str,
    sources: list,
    silent: bool = False
) -> Dict[str, Set[str]]:
    """
    Executes all passive sources concurrently.
    """
    subdomain_sources: Dict[str, Set[str]] = {}
    tcp_conn = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=tcp_conn) as session:
        async def _query_source(src):
            try:
                found = await src.enumerate(session, domain)
                if not silent and found:
                    print_info(f"Source [bold cyan]{src.name}[/bold cyan] found [bold green]{len(found)}[/bold green] subdomains", silent)
                return src.name, found
            except Exception as e:
                return src.name, set()

        tasks = [_query_source(src) for src in sources]
        results = await asyncio.gather(*tasks)

        for src_name, found_set in results:
            for sub in found_set:
                if sub not in subdomain_sources:
                    subdomain_sources[sub] = set()
                subdomain_sources[sub].add(src_name)

    return subdomain_sources

async def process_domain(domain: str, args, api_keys: dict):
    start_time = time.time()
    silent = args.silent
    domain = domain.strip().lower().lstrip(".").rstrip(".")

    print_info(f"Target Domain: [bold cyan]{domain}[/bold cyan]", silent)

    # 1. Resolvers configuration
    resolvers = DEFAULT_RESOLVERS
    if args.resolvers:
        if Path(args.resolvers).is_file():
            with open(args.resolvers, "r") as f:
                resolvers = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            resolvers = [r.strip() for r in args.resolvers.split(",") if r.strip()]

    # 2. Wildcard Detection
    wildcard_detector = None
    if not args.no_wildcard:
        tmp_resolver = FastAsyncResolver(nameservers=resolvers, timeout=args.dns_timeout)
        wildcard_detector = WildcardDetector(domain, tmp_resolver.resolver)
        print_info("Testing for Wildcard DNS...", silent)
        is_wildcard, wc_ips = await wildcard_detector.detect()
        if is_wildcard:
            print_warning(f"Wildcard DNS detected! IPs: {', '.join(wc_ips)}. Filtering enabled.", silent)
        else:
            print_info("No Wildcard DNS detected.", silent)

    # Fast Async Resolver with wildcard filter
    resolver = FastAsyncResolver(
        nameservers=resolvers,
        timeout=args.dns_timeout,
        concurrency=args.threads,
        wildcard_detector=wildcard_detector
    )

    # 3. Passive Enumeration
    enabled_srcs = [s.strip().lower() for s in args.sources.split(",")] if args.sources else None
    sources = get_sources(api_keys=api_keys, enabled_sources=enabled_srcs)
    print_info(f"Running passive discovery across [bold]{len(sources)}[/bold] sources...", silent)

    subdomain_sources = await run_passive_sources(domain, sources, silent=silent)
    passive_count = len(subdomain_sources)
    print_success(f"Passive discovery identified [bold green]{passive_count}[/bold green] unique subdomains.", silent)

    records_map: Dict[str, SubdomainRecord] = {}
    for sub, srcs in subdomain_sources.items():
        records_map[sub] = SubdomainRecord(subdomain=sub, sources=srcs)

    # 4. Active Wordlist Brute Force (if requested)
    if args.bruteforce:
        print_info("Starting active DNS brute forcing...", silent)
        bruteforcer = SubdomainBruteforcer(
            domain=domain,
            resolver=resolver,
            wildcard_detector=wildcard_detector,
            custom_wordlist=args.wordlist
        )
        print_info(f"Loaded wordlist with [bold]{len(bruteforcer.wordlist)}[/bold] prefixes.", silent)

        def _on_bf_found(rec: SubdomainRecord):
            if silent:
                print(rec.subdomain)
            else:
                console.print(f"[bold green]+[/bold green] [cyan]{rec.subdomain}[/cyan] -> [dim]{', '.join(rec.ips)}[/dim]")

        bf_results = await bruteforcer.run(progress_callback=_on_bf_found if not silent else None)
        print_success(f"Bruteforce discovered [bold green]{len(bf_results)}[/bold green] valid subdomains.", silent)
        for rec in bf_results:
            if rec.subdomain in records_map:
                records_map[rec.subdomain].is_alive = True
                records_map[rec.subdomain].ips = rec.ips
                records_map[rec.subdomain].cnames = rec.cnames
                records_map[rec.subdomain].sources.add("bruteforce")
            else:
                records_map[rec.subdomain] = rec

    # 5. Smart Permutations / Mutations (if requested)
    if args.permute:
        known_subs = set(records_map.keys())
        if known_subs:
            print_info(f"Generating permutations from {len(known_subs)} discovered subdomains...", silent)
            engine = PermutationEngine(domain)
            mutations = engine.generate(known_subs)
            print_info(f"Resolving [bold]{len(mutations)}[/bold] permutation candidates...", silent)

            async def _check_mutation(candidate: str):
                rec = await resolver.resolve_single(candidate, source="permutation")
                if rec.is_alive and not rec.is_wildcard:
                    if not silent:
                        console.print(f"[bold green]+ [MUTATION][/bold green] [cyan]{rec.subdomain}[/cyan] -> [dim]{', '.join(rec.ips)}[/dim]")
                    records_map[rec.subdomain] = rec

            tasks = [_check_mutation(c) for c in mutations]
            await asyncio.gather(*tasks)

    # 6. Active Resolution / Verification
    final_records: List[SubdomainRecord] = []
    if args.active:
        print_info(f"Resolving all [bold]{len(records_map)}[/bold] candidates to verify active hosts...", silent)
        sub_list = list(records_map.keys())
        src_map = {k: v.sources for k, v in records_map.items()}

        resolved_records = await resolver.resolve_batch(sub_list, source_map=src_map)
        for rec in resolved_records:
            if rec.is_alive and not rec.is_wildcard:
                final_records.append(rec)
    else:
        final_records = list(records_map.values())

    # 7. HTTP Probing (if requested)
    if args.probe:
        alive_records = [r for r in final_records if r.is_alive or not args.active]
        print_info(f"Probing HTTP/HTTPS services for [bold]{len(alive_records)}[/bold] subdomains...", silent)
        prober = AsyncHttpProber(concurrency=args.threads // 2, timeout=args.http_timeout)
        await prober.probe_all(alive_records)

    # Sort records alphabetically
    final_records.sort(key=lambda r: r.subdomain)

    # 8. Output and Reporting
    elapsed = time.time() - start_time

    if silent:
        for r in final_records:
            try:
                sys.stdout.write(f"{r.subdomain}\n")
                sys.stdout.flush()
            except (BrokenPipeError, IOError):
                sys.exit(0)
    else:
        display_results_table(final_records)
        console.print(f"\n[bold green]Scan Completed in {elapsed:.2f} seconds![/bold green]")
        console.print(f"[bold cyan]Total Subdomains Discovered:[/bold cyan] [bold white]{len(final_records)}[/bold white]")
        if args.active or args.bruteforce:
            alive_count = sum(1 for r in final_records if r.is_alive)
            console.print(f"[bold green]Active (Alive) Subdomains:[/bold green] [bold white]{alive_count}[/bold white]")

    # Export to requested formats
    export_results(
        final_records,
        txt_path=args.output,
        json_path=args.json,
        csv_path=args.csv,
        silent=silent
    )

def main():
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="subpulse",
        description="SubPulse: Advanced, Ultra-Fast Subdomain Enumeration & Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  subpulse -d example.com
  subpulse -d example.com -active -o alive_subs.txt
  subpulse -d example.com -b -p -active -oJ output.json
  subpulse -d example.com -silent | httpx
  subpulse -dL domains.txt -active -oCSV report.csv
        """
    )

    group_target = parser.add_argument_group("Target Options")
    group_target.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    group_target.add_argument("-dL", "--list", help="File containing list of domains to scan")

    group_enum = parser.add_argument_group("Enumeration Modes")
    group_enum.add_argument("-s", "--sources", help="Comma-separated passive sources to use (default: all)")
    group_enum.add_argument("-list-sources", action="store_true", help="List all available passive sources")
    group_enum.add_argument("-a", "--active", action="store_true", help="Active DNS verification (filter dead subdomains & resolve IPs)")
    group_enum.add_argument("-b", "--bruteforce", action="store_true", help="Active DNS brute forcing using curated high-yield wordlist")
    group_enum.add_argument("-w", "--wordlist", help="Path to custom wordlist for brute forcing")
    group_enum.add_argument("-p", "--permute", action="store_true", help="Smart alteration & mutation engine (Amass/AlterX style)")
    group_enum.add_argument("--probe", action="store_true", help="HTTP/HTTPS probing (Status code, Page Title, Server banner)")

    group_perf = parser.add_argument_group("Performance & DNS")
    group_perf.add_argument("-t", "--threads", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrency worker pool size (default: {DEFAULT_CONCURRENCY})")
    group_perf.add_argument("-r", "--resolvers", help="Comma-separated DNS resolvers or file path")
    group_perf.add_argument("--dns-timeout", type=float, default=2.5, help="DNS query timeout in seconds (default: 2.5)")
    group_perf.add_argument("--http-timeout", type=float, default=5.0, help="HTTP probe timeout in seconds (default: 5.0)")
    group_perf.add_argument("--no-wildcard", action="store_true", help="Disable wildcard DNS detection and filtering")

    group_out = parser.add_argument_group("Output Options")
    group_out.add_argument("-o", "--output", help="Save discovered subdomains to text file")
    group_out.add_argument("-oJ", "--json", help="Save detailed results to JSON file")
    group_out.add_argument("-oCSV", "--csv", help="Save detailed results to CSV file")
    group_out.add_argument("-silent", action="store_true", help="Output only subdomains to stdout (pipeable)")

    args = parser.parse_args()

    if args.list_sources:
        print_banner()
        console.print("[bold yellow]Available Passive Sources:[/bold yellow]\n")
        for src in ALL_SOURCES:
            console.print(f" - [bold cyan]{src.name}[/bold cyan]")
        sys.exit(0)

    if not args.domain and not args.list:
        print_banner()
        parser.print_help()
        sys.exit(1)

    print_banner(silent=args.silent)

    api_keys = load_api_keys()

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        p = Path(args.list)
        if p.is_file():
            with open(p, "r") as f:
                domains.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])
        else:
            print_error(f"Target list file not found: {args.list}")
            sys.exit(1)

    for dom in domains:
        try:
            asyncio.run(process_domain(dom, args, api_keys))
        except (KeyboardInterrupt, SystemExit):
            if not args.silent:
                print_warning("\nScan terminated.")
            sys.exit(0)
        except BrokenPipeError:
            sys.exit(0)

if __name__ == "__main__":
    main()
