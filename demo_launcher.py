#!/usr/bin/env python3
"""
Kurukshetra Full Demo Launcher — one command for hackathon judges.
Runs: provision clone → start honeypot check → fire attack simulation → verify backend.

Usage:
  python demo_launcher.py                          # local demo against Render backend
  python demo_launcher.py --target 34.x.x.x        # GCP VM honeypot IP
  python demo_launcher.py --company "Hackathon Corp" --domain hackathon.local
"""

import sys
import os
import argparse
import time
import subprocess

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console(legacy_windows=False)

BACKEND_DEFAULT = "https://kurukshetra-backend.onrender.com"


def step(title: str):
    console.print(f"\n[bold cyan]▶ {title}[/bold cyan]")


def check_backend(url: str) -> bool:
    try:
        r = httpx.get(f"{url.rstrip('/')}/health", timeout=15)
        return r.status_code == 200
    except Exception as e:
        console.print(f"[red]Backend unreachable: {e}[/red]")
        return False


def provision_company(company: str, domain: str, backend: str):
    from honeypot.clone.provisioner import CloneProvisioner
    profile = CloneProvisioner().provision(company_name=company, domain=domain, backend_url=backend)
    console.print(f"[green]Clone ready:[/green] {profile.hostname} ({profile.clone_id})")
    return profile


def run_attacks(target: str, ssh_port: int, web_port: int, scenario: str):
    cmd = [
        sys.executable, "attack.py",
        "--target", target,
        "--scenario", scenario,
        "--ssh-port", str(ssh_port),
        "--web-port", str(web_port),
    ]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))


def verify_dashboard(backend: str):
    base = backend.rstrip("/")
    with httpx.Client(timeout=20) as client:
        summary = client.get(f"{base}/api/dashboard/summary").json()
        attacks = client.get(f"{base}/api/attacks").json()
    console.print(Panel(
        f"Total Events:    {summary.get('total_events', 0)}\n"
        f"Active Sessions: {summary.get('active_sessions', 0)}\n"
        f"Total IOCs:      {summary.get('total_iocs', 0)}\n"
        f"Attack Sessions: {len(attacks) if isinstance(attacks, list) else 0}",
        title="[bold green]Live Backend Telemetry[/bold green]",
    ))


def main():
    parser = argparse.ArgumentParser(description="Kurukshetra full hackathon demo launcher")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Honeypot IP (GCP VM external IP)")
    parser.add_argument("--backend", default=BACKEND_DEFAULT, help="Render backend URL")
    parser.add_argument("--company", default="Hackathon Corp", help="Demo company for clone provision")
    parser.add_argument("--domain", default="hackathon.local", help="Demo domain")
    parser.add_argument("--scenario", default="mixed", choices=["ssh", "web", "api", "mixed"])
    parser.add_argument("--skip-attack", action="store_true", help="Only provision + verify backend")
    parser.add_argument("--skip-clone", action="store_true", help="Skip clone provisioning")
    args = parser.parse_args()

    console.print(Panel(
        "[bold]KURUKSHETRA — Full Demo Pipeline[/bold]\n"
        "Clone → Honeypot → Attack → Backend → SOC Dashboard",
        style="cyan",
    ))

    step("1/4 — Verify Render backend")
    if not check_backend(args.backend):
        console.print("[red]Abort: start backend on Render first.[/red]")
        sys.exit(1)
    console.print("[green]Backend online ✓[/green]")

    if not args.skip_clone:
        step("2/4 — Provision company server clone")
        provision_company(args.company, args.domain, args.backend)

    if not args.skip_attack:
        step("3/4 — Run controlled attacker simulation")
        console.print("[yellow]Ensure honeypot is running: python main.py  OR  docker compose up[/yellow]")
        time.sleep(2)
        try:
            run_attacks(args.target, 2222, 8080, args.scenario)
        except Exception as e:
            console.print(f"[red]Attack sim failed (is honeypot up?): {e}[/red]")

    step("4/4 — Verify telemetry on backend")
    time.sleep(3)
    try:
        verify_dashboard(args.backend)
    except Exception as e:
        console.print(f"[yellow]Could not fetch dashboard stats: {e}[/yellow]")

    console.print("\n[bold green]Demo pipeline complete![/bold green]")
    console.print("[dim]Open SOC dashboard → click Simulate Attack → Live Attacks tab[/dim]")


if __name__ == "__main__":
    main()
