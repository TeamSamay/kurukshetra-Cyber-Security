"""
API Attack Scenario (Member 2).
Performs API Surface Enumeration -> JWT Extraction -> Decoy API Endpoint Exploitation.
"""

import time
import httpx
from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel

from attacker_simulator.scenarios.base import BaseScenario

console = Console(legacy_windows=False)


class APIAttackScenario(BaseScenario):
    """
    Simulates REST API fuzzing, JWT token harvesting, and microservice telemetry triggering.
    """
    def __init__(self, target_host: str, web_port: int = 8080, delay: float = 0.3):
        super().__init__(target_host=target_host, web_port=web_port, delay=delay)
        self.base_url = f"http://{target_host}:{web_port}"

    def run(self) -> Dict[str, Any]:
        console.print(Panel(
            f"[bold yellow]Scenario: REST API Surface Enumeration & Data Exfiltration[/bold yellow]\n"
            f"Target: [cyan]{self.base_url}/api[/cyan]",
            title="[bold yellow]MEMBER 2 ATTACK VECTOR[/bold yellow]",
            expand=False
        ))

        self.stats["start_time"] = time.time()
        headers = {
            "User-Agent": "Kurukshetra-API-Fuzzer/2.0 (Parrot OS ThreatSim)",
            "Accept": "application/json"
        }

        with httpx.Client(base_url=self.base_url, headers=headers, timeout=5.0) as client:
            
            # Step 1: Discover API surface via Swagger/OpenAPI
            console.print("[bold yellow][*] Phase 1: Querying OpenAPI / Swagger documentation...[/bold yellow]")
            self.stats["probes_sent"] += 1
            try:
                r = client.get("/api/swagger.json")
                self.stats["success_responses"] += 1
                paths = list(r.json().get("paths", {}).keys())
                console.print(f"  [green][+] GET /api/swagger.json -> HTTP {r.status_code}[/green]")
                console.print(f"    [dim]Discovered Endpoints: {paths}[/dim]")
            except Exception as e:
                self.stats["error_responses"] += 1
                console.print(f"  [red][!] Failed /api/swagger.json: {e}[/red]")
            self.sleep()

            # Step 2: Acquire Authentication Bearer Token
            console.print("\n[bold yellow][*] Phase 2: Calling POST /api/login for JWT Bearer Token...[/bold yellow]")
            self.stats["probes_sent"] += 1
            token = ""
            try:
                r = client.post("/api/login", json={"username": "admin", "password": "supersecretpassword"})
                self.stats["success_responses"] += 1
                token = r.json().get("access_token", "")
                console.print(f"  [green][+] Acquired Token: [/green][dim]{token[:45]}...[/dim]")
            except Exception as e:
                self.stats["error_responses"] += 1
                console.print(f"  [red][!] Failed POST /api/login: {e}[/red]")
            self.sleep()

            # Step 3: Query Protected API Decoy Endpoints
            console.print("\n[bold yellow][*] Phase 3: Exploiting Deception API Endpoints...[/bold yellow]")
            auth_headers = {"Authorization": f"Bearer {token}"} if token else {}
            
            api_targets = [
                ("/api/users", "GET", "Synthetic Corporate Employee Registry"),
                ("/api/admin", "GET", "High-Privilege Cluster Configuration"),
                ("/api/config", "GET", "Production Secrets & Database Strings"),
                ("/api/v1/health", "GET", "Microservice Health & Uptime Node"),
            ]

            for ep, method, desc in api_targets:
                self.stats["probes_sent"] += 1
                self.stats["decoys_triggered"] += 1
                try:
                    r = client.get(ep, headers=auth_headers)
                    self.stats["success_responses"] += 1
                    snippet = r.text[:65].replace("\n", " ")
                    console.print(f"  [bold red]⚡ [API DECOY HIT] {method} {ep} ({desc}) -> HTTP {r.status_code}[/bold red]")
                    console.print(f"    [dim]Response: {snippet}...[/dim]")
                except Exception as e:
                    self.stats["error_responses"] += 1
                self.sleep()

        self.stats["end_time"] = time.time()
        console.print("\n[bold green][+] API attack scenario concluded successfully![/bold green]")
        return self.stats
