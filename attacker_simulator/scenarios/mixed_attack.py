"""
Mixed Attack Scenario (Member 2 - Master Demo Scenario).
Simulates a multi-vector APT attack campaign chaining Web Recon, API Exploitation, SSH Infiltration, and Decoy Harvesting.
"""

import time
from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from attacker_simulator.scenarios.base import BaseScenario
from attacker_simulator.scenarios.web_attack import WebAttackScenario
from attacker_simulator.scenarios.api_attack import APIAttackScenario
from attacker_simulator.scenarios.ssh_attack import SSHAttackScenario

console = Console(legacy_windows=False)


class MixedAttackScenario(BaseScenario):
    """
    Orchestrates an end-to-end cyber attack campaign against all Honeypot surfaces.
    """
    def __init__(self, target_host: str, ssh_port: int = 2222, web_port: int = 8080, delay: float = 0.3):
        super().__init__(target_host=target_host, ssh_port=ssh_port, web_port=web_port, delay=delay)

    def run(self) -> Dict[str, Any]:
        console.print(Panel(
            f"[bold red]╔═══════════════════════════════════════════════════════════════╗[/bold red]\n"
            f"[bold red]║     KURUKSHETRA 2.0: FULL MULTI-VECTOR ATTACK SIMULATION      ║[/bold red]\n"
            f"[bold red]╚═══════════════════════════════════════════════════════════════╝[/bold red]\n"
            f"Target Honeypot: [bold cyan]{self.target_host}[/bold cyan]\n"
            f"Services Under Attack: [yellow]Web/API (Port {self.web_port}) + SSH (Port {self.ssh_port})[/yellow]\n"
            f"Objective: Generate high-fidelity telemetry across all deception layers.",
            title="[bold yellow]APT-2026 THREAT SIMULATOR[/bold yellow]",
            expand=False
        ))

        self.stats["start_time"] = time.time()

        # Step 1: Web Scenario
        console.print("\n[bold magenta]══════════════ STAGE 1: WEB RECONNAISSANCE ══════════════[/bold magenta]")
        web_sim = WebAttackScenario(target_host=self.target_host, web_port=self.web_port, delay=self.delay)
        web_stats = web_sim.run()

        # Step 2: API Scenario
        console.print("\n[bold yellow]══════════════ STAGE 2: API ENUMERATION & HARVESTING ══════════════[/bold yellow]")
        api_sim = APIAttackScenario(target_host=self.target_host, web_port=self.web_port, delay=self.delay)
        api_stats = api_sim.run()

        # Step 3: SSH Infiltration Scenario
        console.print("\n[bold red]══════════════ STAGE 3: SSH INFILTRATION & HOST RECON ══════════════[/bold red]")
        ssh_sim = SSHAttackScenario(target_host=self.target_host, ssh_port=self.ssh_port, delay=self.delay)
        ssh_stats = ssh_sim.run()

        self.stats["end_time"] = time.time()

        # Aggregate metrics
        self.stats["probes_sent"] = web_stats["probes_sent"] + api_stats["probes_sent"] + ssh_stats["probes_sent"]
        self.stats["success_responses"] = web_stats["success_responses"] + api_stats["success_responses"] + ssh_stats["success_responses"]
        self.stats["error_responses"] = web_stats["error_responses"] + api_stats["error_responses"] + ssh_stats["error_responses"]
        self.stats["decoys_triggered"] = web_stats["decoys_triggered"] + api_stats["decoys_triggered"] + ssh_stats["decoys_triggered"]

        # Final Summary Table
        table = Table(title="Attack Simulation Telemetry Generated")
        table.add_column("Vector / Phase", style="cyan")
        table.add_column("Probes Sent", style="yellow")
        table.add_column("Decoys Triggered", style="bold red")
        table.add_column("Status", style="bold green")

        table.add_row("Web Application Recon", str(web_stats["probes_sent"]), str(web_stats["decoys_triggered"]), "SUCCESS")
        table.add_row("REST API Exfiltration", str(api_stats["probes_sent"]), str(api_stats["decoys_triggered"]), "SUCCESS")
        table.add_row("SSH Host Exploitation", str(ssh_stats["probes_sent"]), str(ssh_stats["decoys_triggered"]), "SUCCESS")
        table.add_row("TOTAL / CAMPAIGN", str(self.stats["probes_sent"]), str(self.stats["decoys_triggered"]), "TELEMETRY DISPATCHED")

        console.print("\n")
        console.print(table)
        console.print(Panel(
            f"[bold green]✓ Live network attack successfully completed![/bold green]\n"
            f"Telemetry has been converted by Honeypot and dispatched to Backend API.",
            expand=False
        ))

        return self.stats
