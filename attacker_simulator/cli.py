"""
Attacker Simulator Command-Line Interface (Member 2).
Usage:
  python attack.py --target 10.113.202.185 --scenario mixed
  python attack.py --target 10.113.202.185 --scenario ssh
  python attack.py --target 10.113.202.185 --scenario web
  python attack.py --target 10.113.202.185 --scenario api
"""

import sys
import os
import time
import argparse
from rich.console import Console
from rich.panel import Panel

# Ensure project root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# UTF-8 stream handling
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False)

from attacker_simulator.scenarios.ssh_attack import SSHAttackScenario
from attacker_simulator.scenarios.web_attack import WebAttackScenario
from attacker_simulator.scenarios.api_attack import APIAttackScenario
from attacker_simulator.scenarios.mixed_attack import MixedAttackScenario

BANNER = r"""
[bold red]
 ▄▄▄       ▄▄▄█████▓ ▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███  
▒████▄     ▓  ██▒ ▓▒ ▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄   ▒ ▓██░ ▒░ ▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██  ░ ▓██▓ ░  ░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
 ▓█   ▓██▒   ▒██▒ ░    ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░   ▒ ░░      ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░     ░         ░      ▒   ▒▒ ░  ░  ▒    ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
  ░   ▒      ░         ░        ░   ▒   ░         ░ ░░ ░    ░     ░░   ░ 
      ░  ░                          ░  ░░ ░       ░  ░      ░  ░   ░     
                                        ░                                
[/bold red]
[bold yellow]   KURUKSHETRA 2.0 — CONTROLLED ATTACKER SIMULATOR (MEMBER 2)[/bold yellow]
[dim]   Generates controlled, high-interaction deception traffic against Honeypot[/dim]
"""


def main():
    parser = argparse.ArgumentParser(
        description="Kurukshetra 2.0 Controlled Attacker Simulator (Member 2)"
    )
    parser.add_argument(
        "--target", "-t",
        default="127.0.0.1",
        help="Target Honeypot IP address (e.g. 10.113.202.185 or 192.168.x.x)"
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=["ssh", "web", "api", "mixed", "stealth", "aggressive"],
        default="mixed",
        help="Attack scenario to execute against Honeypot"
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=2222,
        help="Honeypot SSH Port (default: 2222)"
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8080,
        help="Honeypot Web/API Port (default: 8080)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="Delay in seconds between attack probes (default: 0.3s)"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously in a loop for live hackathon SOC dashboard demo"
    )

    args = parser.parse_args()

    console.print(BANNER)
    console.print(Panel(
        f"[bold white]Target Honeypot :[/bold white] [bold cyan]{args.target}[/bold cyan]\n"
        f"[bold white]Scenario        :[/bold white] [bold yellow]{args.scenario.upper()}[/bold yellow]\n"
        f"[bold white]SSH Service Port:[/bold white] [green]{args.ssh_port}[/green]\n"
        f"[bold white]Web/API Port    :[/bold white] [green]{args.web_port}[/green]\n"
        f"[bold white]Probe Delay     :[/bold white] [cyan]{args.delay}s[/cyan]\n"
        f"[bold white]Continuous Loop :[/bold white] [{'green' if args.loop else 'dim'}]{args.loop}[/]",
        title="[bold green]Simulation Parameters[/bold green]",
        expand=False
    ))

    # Determine delay modifier
    delay = args.delay
    if args.scenario == "stealth":
        delay = 1.5
    elif args.scenario == "aggressive":
        delay = 0.05

    def execute_once():
        if args.scenario in ("ssh",):
            sim = SSHAttackScenario(target_host=args.target, ssh_port=args.ssh_port, delay=delay)
            sim.run()
        elif args.scenario in ("web",):
            sim = WebAttackScenario(target_host=args.target, web_port=args.web_port, delay=delay)
            sim.run()
        elif args.scenario in ("api",):
            sim = APIAttackScenario(target_host=args.target, web_port=args.web_port, delay=delay)
            sim.run()
        else:  # mixed, stealth, aggressive
            sim = MixedAttackScenario(target_host=args.target, ssh_port=args.ssh_port, web_port=args.web_port, delay=delay)
            sim.run()

    iteration = 1
    while True:
        if args.loop:
            console.print(f"\n[bold yellow]>>> CAMPAIGN ITERATION #{iteration} <<<[/bold yellow]")
        
        execute_once()

        if not args.loop:
            break

        iteration += 1
        console.print(f"\n[dim]Pausing 5 seconds before next campaign cycle...[/dim]")
        time.sleep(5)


if __name__ == "__main__":
    main()
