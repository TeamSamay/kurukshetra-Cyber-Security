"""
SSH Attack Scenario (Member 2).
Performs SSH Brute-force -> Interactive Infiltration -> Decoy Snooping -> Privilege Escalation Probe.
"""

import time
import socket
from typing import Dict, Any, List, Tuple
import paramiko
from rich.console import Console
from rich.panel import Panel
from rich.progress import track

from attacker_simulator.scenarios.base import BaseScenario

console = Console(legacy_windows=False)


class SSHAttackScenario(BaseScenario):
    """
    Simulates a sophisticated SSH threat actor reconnaissance sequence.
    """
    def __init__(self, target_host: str, ssh_port: int = 2222, delay: float = 0.4):
        super().__init__(target_host=target_host, ssh_port=ssh_port, delay=delay)
        
        self.wordlist: List[Tuple[str, str]] = [
            ("guest", "guest"),
            ("user", "user123"),
            ("support", "support2026"),
            ("devops", "devops_internal"),
            ("admin", "admin123"),
            ("root", "toor"),  # Successful entry
        ]

        self.recon_commands = [
            ("whoami", "Check active user identity"),
            ("id", "Inspect user privileges and group memberships"),
            ("uname -a", "Determine OS version & kernel build"),
            ("hostname -I", "Identify internal network interfaces"),
            ("pwd", "Check current working directory"),
            ("ls -la /root", "List sensitive files in root directory"),
            ("cat /etc/passwd", "Enumerate system user accounts"),
            ("ps aux", "List active system processes and services"),
            ("netstat -tuln", "Discover listening internal ports"),
            ("cat /root/fake-credentials.txt", "[DECOY] Probe infrastructure root credentials"),
            ("cat /opt/backups/fake-backup.sql", "[DECOY] Probe database backup dump"),
            ("cat /var/www/html/fake-config.php", "[DECOY] Probe production database secrets"),
            ("sudo -l", "Attempt privilege escalation sudo check"),
            ("history", "Examine previous bash command history"),
            ("exit", "Terminate attacker session"),
        ]

    def run(self) -> Dict[str, Any]:
        console.print(Panel(
            f"[bold red]Scenario: SSH Reconnaissance & Deception Trap Exploration[/bold red]\n"
            f"Target: [cyan]{self.target_host}:{self.ssh_port}[/cyan]",
            title="[bold yellow]MEMBER 2 ATTACK VECTOR[/bold yellow]",
            expand=False
        ))

        self.stats["start_time"] = time.time()

        # Step 1: Simulated Dictionary Attack / Brute Force
        console.print("[bold yellow][*] Phase 1: Initiating SSH dictionary credential attack...[/bold yellow]")
        for user, pwd in self.wordlist[:-1]:
            self.stats["probes_sent"] += 1
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                console.print(f"  [dim]› Probing credential pair: {user}:{pwd}[/dim]")
                client.connect(self.target_host, port=self.ssh_port, username=user, password=pwd, timeout=3)
                client.close()
                self.stats["success_responses"] += 1
            except Exception:
                self.stats["error_responses"] += 1
            self.sleep()

        # Step 2: Establish Interactive Shell
        success_user, success_pwd = self.wordlist[-1]
        console.print(f"\n[bold green][+] Phase 2: Exploiting valid credential pair ({success_user}:{success_pwd})...[/bold green]")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.target_host,
                port=self.ssh_port,
                username=success_user,
                password=success_pwd,
                timeout=5
            )
            console.print("[bold green][+] SSH Channel Established! Spawning PTY shell...[/bold green]\n")

            channel = client.invoke_shell()
            time.sleep(1.0)

            # Step 3: Execute Reconnaissance & Decoy Command Sequence
            console.print("[bold cyan][*] Phase 3: Executing APT Post-Exploitation Reconnaissance Sequence...[/bold cyan]")
            
            for cmd, desc in self.recon_commands:
                self.stats["probes_sent"] += 1
                if "[DECOY]" in desc:
                    self.stats["decoys_triggered"] += 1
                    console.print(f"  [bold red]⚡ [ALERT TRIGGER] {desc} -> [/bold red][white]{cmd}[/white]")
                else:
                    console.print(f"  [cyan]› {desc}: [/cyan][bold white]{cmd}[/bold white]")

                channel.send(cmd + "\n")
                time.sleep(0.35)

                if channel.recv_ready():
                    raw_resp = channel.recv(4096).decode("utf-8", errors="ignore")
                    lines = [l.strip() for l in raw_resp.splitlines() if l.strip()]
                    if len(lines) > 1:
                        snippet = lines[1][:75]
                        console.print(f"    [dim]Output: {snippet}...[/dim]")

                self.sleep()

            client.close()
            self.stats["success_responses"] += 1
            console.print("\n[bold green][+] SSH attack scenario concluded successfully![/bold green]")

        except Exception as e:
            console.print(f"[bold red][!] SSH connection failed: {e}[/bold red]")
            self.stats["error_responses"] += 1

        self.stats["end_time"] = time.time()
        return self.stats
