"""
Main Honeypot Server Orchestrator.
Spins up SSH, Web, and API deception services alongside the backend telemetry dispatcher.
"""

import sys
import os

# Ensure UTF-8 stream handling on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import time
import signal
import asyncio
import threading
import uvicorn
from rich.console import Console
from rich.panel import Panel

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeypot.config.settings import settings
from honeypot.common.backend_client import backend_client
from honeypot.common.telemetry import emit_event
from honeypot.clone.provisioner import CloneProvisioner
from honeypot.ssh.ssh_server import ssh_honeypot
from honeypot.web.web_server import web_app

console = Console(legacy_windows=False)

BANNER = r"""
 [bold cyan]██╗  ██╗██╗   ██╗██████╗ ██╗   ██╗██╗  ██╗███████╗██╗  ██╗████████╗██████╗  █████╗ [/bold cyan]
 [bold cyan]██║ ██╔╝██║   ██║██╔══██╗██║   ██║██║ ██╔╝██╔════╝██║  ██║╚══██╔══╝██╔══██╗██╔══██╗[/bold cyan]
 [bold cyan]█████╔╝ ██║   ██║██████╔╝██║   ██║█████╔╝ ███████╗███████║   ██║   ██████╔╝███████║[/bold cyan]
 [bold cyan]██╔═██╗ ██║   ██║██╔══██╗██║   ██║██╔═██╗ ╚════██║██╔══██║   ██║   ██╔══██╗██╔══██║[/bold cyan]
 [bold cyan]██║  ██╗╚██████╔╝██║  ██║╚██████╔╝██║  ██╗███████║██║  ██║   ██║   ██║  ██║██║  ██║[/bold cyan]
 [bold cyan]╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝[/bold cyan]
 [bold yellow]         ADAPTIVE CYBER DECEPTION & THREAT INTELLIGENCE PLATFORM[/bold yellow]
 [bold green]           -- MEMBER 1: HONEYPOT SERVER / DECEPTION TELEMETRY --[/bold green]
"""


def display_welcome_banner():
    console.print(BANNER)
    info_text = (
        f"[bold white]Host Target IP :[/bold white] [bold cyan]{settings.HONEYPOT_TARGET_IP}[/bold cyan]\n"
        f"[bold white]SSH Service    :[/bold white] [bold green]Port {settings.SSH_PORT}[/bold green] (Interactive Emulated Bash)\n"
        f"[bold white]Web & API Svc  :[/bold white] [bold green]Port {settings.WEB_PORT}[/bold green] (SSO Portal & REST Deception)\n"
        f"[bold white]Backend Relay  :[/bold white] [bold yellow]{settings.full_backend_events_url}[/bold yellow]\n"
        f"[bold white]Local Logs     :[/bold white] [bold magenta]{settings.EVENTS_JSONL_FILE}[/bold magenta]\n"
        f"[bold white]Active Decoys  :[/bold white] fake-credentials, fake-config, fake-users, fake-backup, fake-admin"
    )
    console.print(Panel(info_text, title="[bold green]Deception Layer Initialized[/bold green]", expand=False))


def run_server():
    # 0. Apply active company clone profile (if provisioned)
    active_clone = CloneProvisioner().apply_to_settings()
    if active_clone:
        console.print(Panel(
            f"[bold white]Clone ID   :[/bold white] [cyan]{active_clone.clone_id}[/cyan]\n"
            f"[bold white]Company    :[/bold white] {active_clone.company_name}\n"
            f"[bold white]Hostname   :[/bold white] [green]{active_clone.hostname}[/green]\n"
            f"[bold white]Sanitized  :[/bold white] [green]Yes — synthetic decoys only[/green]",
            title="[bold yellow]Company Clone Active[/bold yellow]",
            expand=False,
        ))

    display_welcome_banner()

    # 1. Start Backend Dispatcher Worker
    backend_client.start()

    # 2. Start SSH Honeypot
    ssh_honeypot.start(blocking=False)

    # 3. Emit Honeypot Initialization Event
    emit_event(
        service="honeypot",
        event_type="honeypot_started",
        event=f"Honeypot services started (SSH:{settings.SSH_PORT}, WEB/API:{settings.WEB_PORT})",
        source_ip="127.0.0.1",
        session_id="SYSTEM-BOOT",
        metadata={
            "internal_probe": True,
            "ssh_port": settings.SSH_PORT,
            "web_port": settings.WEB_PORT,
            "backend_url": settings.full_backend_events_url,
            "hostname": settings.HONEYPOT_HOSTNAME,
        }
    )

    # 4. Start FastAPI Uvicorn Server (Web & API Honeypot)
    config = uvicorn.Config(
        app=web_app,
        host=settings.HONEYPOT_HOST,
        port=settings.WEB_PORT,
        log_level="warning",  # Keep console clean for our custom telemetry logger
    )
    server = uvicorn.Server(config)

    def handle_exit(signum, frame):
        console.print("\n[bold red][!] Stopping Honeypot services gracefully...[/bold red]")
        ssh_honeypot.stop()
        backend_client.stop(wait_empty=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        server.run()
    finally:
        ssh_honeypot.stop()
        backend_client.stop(wait_empty=True)


if __name__ == "__main__":
    run_server()
