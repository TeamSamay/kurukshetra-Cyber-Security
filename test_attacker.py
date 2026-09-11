"""
Attacker Simulator (Member 2 Testing Tool).
Simulates realistic cyber attack scenarios against the Honeypot Server:
  1. SSH Brute Force & Interactive Shell Reconnaissance
  2. Decoy Resource Snooping (fake-credentials, fake-backup, fake-config, fake-users)
  3. Web Portal Scanning, Login Probing, and Hidden Route Discovery
  4. REST API Endpoint Exploitation & Secret Extraction
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
import socket
import argparse
import httpx
import paramiko
from rich.console import Console
from rich.panel import Panel

console = Console(legacy_windows=False)


def simulate_ssh_attack(host: str = "127.0.0.1", port: int = 2222):
    console.print(Panel(f"[bold red]Scenario 1: SSH Brute Force & Reconnaissance[/bold red]\nTarget: {host}:{port}", expand=False))
    
    # 1. Failed SSH Attempts
    failed_logins = [("root", "wrongpassword123"), ("devops", "badpass")]
    for user, pwd in failed_logins:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            console.print(f"[yellow][*] Attempting SSH login with {user}:{pwd}...[/yellow]")
            client.connect(host, port=port, username=user, password=pwd, timeout=4)
            client.close()
        except Exception:
            console.print(f"[green][+] Auth attempt recorded (Expected rejection)[/green]")

    # 2. Successful SSH Session & Decoy Exploration
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        console.print(f"[bold yellow][*] Establishing interactive SSH shell as root:toor...[/bold yellow]")
        client.connect(host, port=port, username="root", password="toor", timeout=5)
        
        channel = client.invoke_shell()
        time.sleep(1)

        commands = [
            "whoami",
            "id",
            "uname -a",
            "ls -la",
            "cat /etc/passwd",
            "cat /root/fake-credentials.txt",   # Decoy 1
            "cat /opt/backups/fake-backup.sql", # Decoy 2
            "cat /var/www/html/fake-config.php", # Decoy 3
            "exit"
        ]

        for cmd in commands:
            console.print(f"[cyan]  > Running simulated command: {cmd}[/cyan]")
            channel.send(cmd + "\n")
            time.sleep(0.4)
            # Read response
            if channel.recv_ready():
                resp = channel.recv(4096).decode("utf-8", errors="ignore")
                lines = [l for l in resp.splitlines() if l.strip()]
                if len(lines) > 1:
                    console.print(f"[dim]    Output: {lines[1][:80]}...[/dim]")

        client.close()
        console.print("[bold green][+] SSH Attack scenario completed successfully![/bold green]\n")
    except Exception as e:
        console.print(f"[bold red][!] SSH connection failed: {e}[/bold red]\n")


def simulate_web_attack(host: str = "127.0.0.1", port: int = 8080):
    console.print(Panel(f"[bold magenta]Scenario 2: Web Reconnaissance & Decoy Harvesting[/bold magenta]\nTarget: http://{host}:{port}", expand=False))
    base_url = f"http://{host}:{port}"

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        # 1. Crawl robots.txt
        console.print("[yellow][*] Probing /robots.txt for hidden admin/decoy endpoints...[/yellow]")
        r = client.get("/robots.txt")
        console.print(f"    Status: {r.status_code}, Found disallow entries")

        # 2. Probe Login Portal
        console.print("[yellow][*] Probing /login with brute force attempts...[/yellow]")
        r_fail = client.post("/login", data={"username": "attacker", "password": "password123"})
        console.print(f"    POST /login (attacker:password123) -> HTTP {r_fail.status_code}")

        r_admin = client.post("/login", data={"username": "admin", "password": "supersecretpassword"}, follow_redirects=True)
        console.print(f"    POST /login (admin:supersecretpassword) -> HTTP {r_admin.status_code} (Redirected to Admin Console)")

        # 3. Harvest Web Decoys
        decoys = ["/fake-config", "/fake-users", "/fake-backup", "/fake-credentials", "/.env"]
        for d in decoys:
            console.print(f"[cyan][*] Probing sensitive decoy endpoint: {d}...[/cyan]")
            r_decoy = client.get(d)
            snippet = r_decoy.text[:60].replace("\n", " ")
            console.print(f"    HTTP {r_decoy.status_code} | Sample Payload: [dim]{snippet}...[/dim]")

    console.print("[bold green][+] Web Attack scenario completed successfully![/bold green]\n")


def simulate_api_attack(host: str = "127.0.0.1", port: int = 8080):
    console.print(Panel(f"[bold yellow]Scenario 3: API Enumeration & Credential Theft[/bold yellow]\nTarget: http://{host}:{port}/api", expand=False))
    base_url = f"http://{host}:{port}"

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        # 1. Inspect Swagger
        console.print("[yellow][*] Querying /api/swagger.json for API surface...[/yellow]")
        r_swag = client.get("/api/swagger.json")
        console.print(f"    HTTP {r_swag.status_code} | Endpoints discovered: {list(r_swag.json().get('paths', {}).keys())}")

        # 2. Authenticate against API
        console.print("[yellow][*] POST /api/login for Bearer token...[/yellow]")
        r_login = client.post("/api/login", json={"username": "admin", "password": "adminpassword"})
        token = r_login.json().get("access_token", "")
        console.print(f"    HTTP {r_login.status_code} | Acquired Token: [dim]{token[:40]}...[/dim]")

        # 3. Query API Decoys
        api_endpoints = ["/api/users", "/api/admin", "/api/config", "/api/v1/health"]
        for ep in api_endpoints:
            console.print(f"[cyan][*] Calling API endpoint: {ep}...[/cyan]")
            r = client.get(ep, headers={"Authorization": f"Bearer {token}"})
            console.print(f"    HTTP {r.status_code} | Response snippet: [dim]{r.text[:65]}...[/dim]")

    console.print("[bold green][+] API Attack scenario completed successfully![/bold green]\n")


def simulate_advanced_threat_learning(host: str = "127.0.0.1", port: int = 8080):
    console.print(Panel(f"[bold red]Scenario 4: Advanced Exploitation & Tool Fingerprinting Test[/bold red]\nTarget: http://{host}:{port}", expand=False))
    base_url = f"http://{host}:{port}"

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        # 1. Simulate Sqlmap SQL Injection attack
        console.print("[yellow][*] Simulating Sqlmap automated SQLi payload against /login...[/yellow]")
        r_sqli = client.post(
            "/login",
            data={"username": "admin' UNION SELECT null, database(), user() --", "password": "' OR '1'='1"},
            headers={"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}
        )
        console.print(f"    SQLi Probe status: HTTP {r_sqli.status_code}")

        # 2. Simulate Hydra Brute-Force tool User-Agent
        console.print("[yellow][*] Simulating Hydra brute force probe...[/yellow]")
        r_hydra = client.post(
            "/api/login",
            json={"username": "root", "password": "password123"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; Hydra/9.5)"}
        )
        console.print(f"    Hydra probe status: HTTP {r_hydra.status_code}")

        # 3. Query Live Threat Intelligence from Honeypot
        console.print("\n[bold cyan][*] Querying Honeypot Learned Attacker Intelligence (/api/threat-intel)...[/bold cyan]")
        try:
            r_intel = client.get("/api/threat-intel")
            if r_intel.status_code == 200:
                intel_data = r_intel.json()
                console.print(f"    [green]Total Attackers Tracked: {intel_data.get('total_attackers_tracked')}[/green]")
                for atk in intel_data.get("attackers", []):
                    console.print(f"    [bold yellow]• Attacker IP/Session:[/bold yellow] {atk.get('identifier')} | [bold red]Risk:[/bold red] {atk.get('risk_score')}/100")
                    console.print(f"      [cyan]Skill Level:[/cyan] {atk.get('skill_level')} | [cyan]Intent:[/cyan] {atk.get('intent')}")
                    console.print(f"      [magenta]Detected Tools:[/magenta] {atk.get('detected_tools')}")
                    console.print(f"      [blue]MITRE Techniques:[/blue] {[t['technique_id'] + ': ' + t['name'] for t in atk.get('mitre_techniques', [])]}")
        except Exception as e:
            console.print(f"[dim red]Threat intel query failed: {e}[/dim red]")


def main():
    parser = argparse.ArgumentParser(description="Kurukshetra Attacker Simulator (Member 2 Tool)")
    parser.add_argument("--host", default="127.0.0.1", help="Target Honeypot IP/Host")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Honeypot SSH Port")
    parser.add_argument("--web-port", type=int, default=8080, help="Honeypot Web/API Port")
    parser.add_argument("--target", choices=["all", "ssh", "web", "api", "threat"], default="all", help="Attack scenario to run")
    args = parser.parse_args()

    console.print(f"[bold cyan]=== Kurukshetra Honeypot Attacker Simulation Suite ===[/bold cyan]")
    console.print(f"Target: {args.host} (SSH:{args.ssh_port}, Web/API:{args.web_port})\n")

    if args.target in ("all", "ssh"):
        simulate_ssh_attack(args.host, args.ssh_port)
    if args.target in ("all", "web"):
        simulate_web_attack(args.host, args.web_port)
    if args.target in ("all", "api"):
        simulate_api_attack(args.host, args.web_port)
    if args.target in ("all", "threat"):
        simulate_advanced_threat_learning(args.host, args.web_port)

    console.print("[bold green]=== All Simulation Scenarios Completed! ===[/bold green]")


if __name__ == "__main__":
    main()

