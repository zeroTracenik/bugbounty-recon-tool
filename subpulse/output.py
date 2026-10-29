import json
import csv
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .resolver import SubdomainRecord

console = Console()

BANNER = r"""
 [bold cyan] ____        _     ____        _             [/bold cyan]
 [bold cyan]/ ___| _   _| |__ |  _ \ _   _| |___  ___   [/bold cyan]
 [bold cyan]\___ \| | | | '_ \| |_) | | | | / __|/ _ \  [/bold cyan]
 [bold cyan] ___) | |_| | |_) |  __/| |_| | \__ \  __/  [/bold cyan]
 [bold cyan]|____/ \__,_|_.__/|_|    \__,_|_|___/\___|  [/bold cyan]
 [dim]High-Speed Subdomain Discovery & Recon Engine v1.0[/dim]
"""

def print_banner(silent: bool = False):
    if not silent:
        console.print(BANNER)

def print_info(msg: str, silent: bool = False):
    if not silent:
        console.print(f"[bold blue][*][/bold blue] {msg}")

def print_success(msg: str, silent: bool = False):
    if not silent:
        console.print(f"[bold green][+][/bold green] {msg}")

def print_warning(msg: str, silent: bool = False):
    if not silent:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")

def print_error(msg: str, silent: bool = False):
    if not silent:
        console.print(f"[bold red][-][/bold red] {msg}")

def display_results_table(records: List[SubdomainRecord]):
    table = Table(title="[bold green]Discovered Subdomains Summary[/bold green]", show_header=True, header_style="bold magenta")
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("IP Addresses", style="green")
    table.add_column("CNAME", style="yellow")
    table.add_column("HTTP", justify="center")
    table.add_column("Title / Banner", style="dim")
    table.add_column("Sources", style="blue")

    for rec in records:
        status_text = "[green]ALIVE[/green]" if rec.is_alive else "[dim]PASSIVE[/dim]"
        if rec.is_wildcard:
            status_text = "[yellow]WILDCARD[/yellow]"

        ips_text = ", ".join(rec.ips[:3]) if rec.ips else "-"
        if len(rec.ips) > 3:
            ips_text += f" (+{len(rec.ips)-3})"

        cname_text = ", ".join(rec.cnames[:2]) if rec.cnames else "-"
        http_text = f"[green]{rec.http_status}[/green]" if rec.http_status else "-"
        title_text = (rec.http_title[:35] + "...") if (rec.http_title and len(rec.http_title) > 35) else (rec.http_title or "-")
        sources_text = ",".join(sorted(list(rec.sources))[:3])

        table.add_row(
            rec.subdomain,
            status_text,
            ips_text,
            cname_text,
            http_text,
            title_text,
            sources_text
        )

    console.print(table)

def export_results(
    records: List[SubdomainRecord],
    txt_path: Optional[str] = None,
    json_path: Optional[str] = None,
    csv_path: Optional[str] = None,
    silent: bool = False
):
    if txt_path:
        with open(txt_path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(f"{rec.subdomain}\n")
        print_success(f"Saved {len(records)} subdomains to [bold]{txt_path}[/bold]", silent)

    if json_path:
        data = []
        for rec in records:
            data.append({
                "subdomain": rec.subdomain,
                "is_alive": rec.is_alive,
                "is_wildcard": rec.is_wildcard,
                "ips": rec.ips,
                "cnames": rec.cnames,
                "http_status": rec.http_status,
                "http_title": rec.http_title,
                "http_server": rec.http_server,
                "sources": list(rec.sources)
            })
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print_success(f"Saved JSON export to [bold]{json_path}[/bold]", silent)

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain", "Alive", "Wildcard", "IPs", "CNAMEs", "HTTP_Status", "HTTP_Title", "HTTP_Server", "Sources"])
            for rec in records:
                writer.writerow([
                    rec.subdomain,
                    rec.is_alive,
                    rec.is_wildcard,
                    ";".join(rec.ips),
                    ";".join(rec.cnames),
                    rec.http_status or "",
                    rec.http_title or "",
                    rec.http_server or "",
                    ";".join(rec.sources)
                ])
        print_success(f"Saved CSV export to [bold]{csv_path}[/bold]", silent)
