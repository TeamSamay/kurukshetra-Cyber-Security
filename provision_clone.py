#!/usr/bin/env python3
"""
Kurukshetra Company Server Clone Provisioner (CLI).
Usage:
  python provision_clone.py --company "Acme Corp" --domain acme.com
  python provision_clone.py --company "TechStart" --domain techstart.io --list
"""

import sys
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from honeypot.clone.provisioner import CloneProvisioner

console = Console(legacy_windows=False)


def main():
    parser = argparse.ArgumentParser(description="Provision a sanitized company honeypot clone")
    parser.add_argument("--company", "-c", help="Company name (e.g. Acme Corp)")
    parser.add_argument("--domain", "-d", help="Company domain (e.g. acme.com)")
    parser.add_argument("--backend", default="https://kurukshetra-backend.onrender.com", help="Threat intel backend URL")
    parser.add_argument("--services", default="ssh,web,api", help="Comma-separated services")
    parser.add_argument("--list", action="store_true", help="List all clone profiles")
    args = parser.parse_args()

    prov = CloneProvisioner()

    if args.list:
        profiles = prov.list_profiles()
        if not profiles:
            console.print("[yellow]No clone profiles yet. Run with --company and --domain.[/yellow]")
            return
        table = Table(title="Company Clone Profiles")
        table.add_column("Clone ID", style="cyan")
        table.add_column("Company")
        table.add_column("Hostname", style="green")
        table.add_column("Status")
        for p in profiles:
            table.add_row(p.get("clone_id", ""), p.get("company_name", ""), p.get("hostname", ""), p.get("status", ""))
        console.print(table)
        return

    if not args.company or not args.domain:
        parser.error("--company and --domain required (or use --list)")

    console.print(Panel(
        f"[bold]Company:[/bold] {args.company}\n"
        f"[bold]Domain:[/bold] {args.domain}\n"
        f"[bold]Backend:[/bold] {args.backend}",
        title="[bold cyan]Provisioning Sanitized Server Clone[/bold cyan]",
    ))

    profile = prov.provision(
        company_name=args.company,
        domain=args.domain,
        services=[s.strip() for s in args.services.split(",")],
        backend_url=args.backend,
    )

    console.print(f"\n[bold green]✓ Clone provisioned:[/bold green] {profile.clone_id}")
    console.print(f"  Hostname:  [cyan]{profile.hostname}[/cyan]")
    console.print(f"  Web Title: {profile.web_title}")
    console.print(f"  Sanitized: [green]{profile.sanitized}[/green]")
    console.print(f"\n[dim]Restart honeypot to apply: python main.py[/dim]")
    console.print(f"[dim]Or Docker: docker-compose up --build[/dim]")


if __name__ == "__main__":
    main()
