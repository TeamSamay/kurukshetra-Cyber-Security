"""
Threat Intelligence Report Generator (Kurukshetra 2.0).
Analyzes honeypot telemetry from logs/events.jsonl and generates an executive
SOC Threat Intelligence & Forensics Report with MITRE ATT&CK mappings and Risk Scoring.
"""

import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(legacy_windows=False)


def analyze_telemetry(log_file: str = "logs/events.jsonl") -> Dict[str, Any]:
    """Reads telemetry events and performs forensic threat intelligence analysis."""
    events: List[Dict[str, Any]] = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass

    # Aggregations
    total_events = len(events)
    attackers = {}
    services = {}
    event_types = {}
    decoys_tripped = []
    files_tampered = []
    commands_executed = []
    auth_attempts = []

    # MITRE ATT&CK Mapping matrix
    mitre_mappings = set()

    for evt in events:
        svc = evt.get("service", "unknown")
        etype = evt.get("event_type", "unknown")
        src_ip = evt.get("source_ip", "unknown")
        session_id = evt.get("session_id", "unknown")
        payload = evt.get("event", "")
        metadata = evt.get("metadata", {})

        # Services & Types
        services[svc] = services.get(svc, 0) + 1
        event_types[etype] = event_types.get(etype, 0) + 1

        # Attacker tracking
        if src_ip not in attackers:
            attackers[src_ip] = {
                "ip": src_ip,
                "sessions": set(),
                "event_count": 0,
                "services": set(),
                "risk_score": 0,
                "first_seen": evt.get("timestamp"),
                "last_seen": evt.get("timestamp"),
            }
        attackers[src_ip]["sessions"].add(session_id)
        attackers[src_ip]["services"].add(svc)
        attackers[src_ip]["event_count"] += 1
        attackers[src_ip]["last_seen"] = evt.get("timestamp")

        # Specific threat detections
        if "auth" in etype:
            auth_attempts.append({"ip": src_ip, "user": metadata.get("username", "unknown"), "payload": payload})
            attackers[src_ip]["risk_score"] += 15
            mitre_mappings.add("T1110 - Brute Force / Credential Stuffing")

        if "command" in etype:
            commands_executed.append({"ip": src_ip, "command": payload, "session": session_id})
            attackers[src_ip]["risk_score"] += 10
            mitre_mappings.add("T1059.004 - Command and Scripting Interpreter (Unix Shell)")
            mitre_mappings.add("T1082 - System Information Discovery")

        if "decoy" in etype:
            decoys_tripped.append({"ip": src_ip, "resource": metadata.get("resource", "decoy"), "target": metadata.get("probed_target", payload)})
            attackers[src_ip]["risk_score"] += 30
            mitre_mappings.add("T1552 - Unsecured Credentials & Sensitive Files Access")

        if "file_created" in etype or "file_modified" in etype or "file_deleted" in etype:
            files_tampered.append({"ip": src_ip, "action": etype, "path": metadata.get("path", payload)})
            attackers[src_ip]["risk_score"] += 25
            mitre_mappings.add("T1105 - Ingress Tool Transfer / File Tampering")

        if "http" in etype and ("admin" in payload or "config" in payload or ".env" in payload):
            mitre_mappings.add("T1595 - Active Scanning / Vulnerability Reconnaissance")

    # Normalize risk scores (cap at 100)
    for ip, data in attackers.items():
        data["risk_score"] = min(100, max(20, data["risk_score"]))
        data["severity"] = "CRITICAL" if data["risk_score"] >= 75 else ("HIGH" if data["risk_score"] >= 50 else "MEDIUM")
        data["sessions"] = list(data["sessions"])
        data["services"] = list(data["services"])

    # Overall Platform Risk
    max_risk = max([d["risk_score"] for d in attackers.values()]) if attackers else 0
    overall_severity = "CRITICAL" if max_risk >= 75 else ("HIGH" if max_risk >= 50 else ("MEDIUM" if max_risk > 20 else "LOW"))

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_events": total_events,
        "overall_risk_score": max_risk,
        "overall_severity": overall_severity,
        "unique_attackers": len(attackers),
        "attackers": attackers,
        "service_breakdown": services,
        "event_type_breakdown": event_types,
        "decoys_tripped": decoys_tripped,
        "files_tampered": files_tampered,
        "commands_executed": commands_executed[-20:],
        "auth_attempts": auth_attempts[-20:],
        "mitre_mappings": sorted(list(mitre_mappings)),
    }


def generate_html_report(report_data: Dict[str, Any], output_path: str = "reports/threat_intelligence_report.html") -> str:
    """Renders a stunning executive cyber threat intelligence report HTML."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    attacker_rows = ""
    for ip, at in report_data["attackers"].items():
        badge_cls = "badge-crit" if at["severity"] == "CRITICAL" else "badge-high"
        attacker_rows += f"""
        <tr>
            <td><strong style="color:#38bdf8;">{ip}</strong></td>
            <td><span class="badge {badge_cls}">{at['severity']} ({at['risk_score']}/100)</span></td>
            <td>{len(at['sessions'])} Sessions</td>
            <td>{at['event_count']} Events</td>
            <td>{', '.join(at['services']).upper()}</td>
            <td><small>{at['last_seen']}</small></td>
        </tr>
        """

    mitre_items = "".join([f"<li class='mitre-item'><strong>{m.split(' - ')[0]}</strong>: {m.split(' - ')[1]}</li>" for m in report_data["mitre_mappings"]])
    
    decoy_rows = ""
    for d in report_data["decoys_tripped"][-10:]:
        decoy_rows += f"<tr><td><code>{d['ip']}</code></td><td><span class='badge badge-crit'>{d['resource']}</span></td><td><code>{d['target']}</code></td></tr>"

    file_rows = ""
    for f in report_data["files_tampered"][-10:]:
        file_rows += f"<tr><td><code>{f['ip']}</code></td><td><strong>{f['action']}</strong></td><td><code>{f['path']}</code></td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kurukshetra 2.0 — Executive Cyber Threat Intelligence Report</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card: #151d30;
            --border: #23304b;
            --blue: #38bdf8;
            --red: #f43f5e;
            --green: #10b981;
            --yellow: #fbbf24;
            --text: #f3f4f6;
            --dim: #94a3b8;
        }}
        * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 32px; margin: 0; line-height: 1.5; }}
        .header {{ display: flex; justify-content: space-between; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }}
        h1 {{ margin: 0; color: var(--blue); font-size: 1.8rem; }}
        .meta-text {{ color: var(--dim); font-size: 0.9rem; margin-top: 4px; }}
        .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
        .card-title {{ color: var(--dim); font-size: 0.8rem; text-transform: uppercase; font-weight: 700; margin-bottom: 8px; }}
        .card-num {{ font-size: 2.2rem; font-weight: 800; color: #fff; }}
        
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 28px; }}
        th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); text-align: left; font-size: 0.9rem; }}
        th {{ background: #090d16; color: var(--dim); text-transform: uppercase; font-size: 0.75rem; }}
        
        .badge {{ padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }}
        .badge-crit {{ background: rgba(244, 63, 94, 0.2); border: 1px solid var(--red); color: #fda4af; }}
        .badge-high {{ background: rgba(251, 191, 36, 0.2); border: 1px solid var(--yellow); color: #fde68a; }}
        
        .mitre-list {{ list-style: none; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; margin-bottom: 28px; }}
        .mitre-item {{ background: #0f172a; border: 1px solid #334155; padding: 12px 16px; border-radius: 8px; font-size: 0.88rem; }}
        .mitre-item strong {{ color: var(--blue); }}
        
        code {{ color: var(--blue); font-family: monospace; background: #090d16; padding: 2px 6px; border-radius: 4px; }}
        .btn-print {{ background: var(--blue); color: #0b0f19; font-weight: bold; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; }}
        @media print {{ .btn-print {{ display: none; }} body {{ background: #fff; color: #000; }} table, .card {{ border-color: #ccc; background: #fff; }} }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Kurukshetra 2.0 Threat Intelligence &amp; Forensics Report</h1>
            <div class="meta-text">Generated on: <strong>{report_data['generated_at']}</strong> &bull; Honeypot Telemetry Source</div>
        </div>
        <div>
            <button class="btn-print" onclick="window.print()">🖨️ Print / Save as PDF</button>
        </div>
    </div>

    <div class="grid-stats">
        <div class="card">
            <div class="card-title">Overall Risk Assessment</div>
            <div class="card-num" style="color: {'#f43f5e' if report_data['overall_severity'] == 'CRITICAL' else '#fbbf24'};">{report_data['overall_severity']} ({report_data['overall_risk_score']}/100)</div>
        </div>
        <div class="card">
            <div class="card-title">Total Ingested Events</div>
            <div class="card-num" style="color: var(--blue);">{report_data['total_events']}</div>
        </div>
        <div class="card">
            <div class="card-title">Identified Threat Actors</div>
            <div class="card-num" style="color: #c084fc;">{report_data['unique_attackers']}</div>
        </div>
        <div class="card">
            <div class="card-title">Decoys Tripped</div>
            <div class="card-num" style="color: var(--red);">{len(report_data['decoys_tripped'])}</div>
        </div>
    </div>

    <h2>🎯 MITRE ATT&amp;CK Framework Mappings (Observed Evidence)</h2>
    <ul class="mitre-list">
        {mitre_items if mitre_items else "<li class='mitre-item'>No MITRE techniques recorded yet.</li>"}
    </ul>

    <h2>🕵️ Identified Threat Actors &amp; Profiles</h2>
    <table>
        <thead>
            <tr>
                <th>Attacker IP</th>
                <th>Calculated Threat Score</th>
                <th>Correlated Sessions</th>
                <th>Total Activity</th>
                <th>Targeted Services</th>
                <th>Last Active Timestamp</th>
            </tr>
        </thead>
        <tbody>
            {attacker_rows if attacker_rows else "<tr><td colspan='6'>No active attackers detected.</td></tr>"}
        </tbody>
    </table>

    <h2>🚨 Decoy Resource Access &amp; Credential Theft Alarms</h2>
    <table>
        <thead>
            <tr>
                <th>Source IP</th>
                <th>Decoy Asset Name</th>
                <th>Probed Target / Action</th>
            </tr>
        </thead>
        <tbody>
            {decoy_rows if decoy_rows else "<tr><td colspan='3'>No decoy alarms tripped.</td></tr>"}
        </tbody>
    </table>

    <h2>✏️ Attacker File Creation &amp; Tampering Evidence</h2>
    <table>
        <thead>
            <tr>
                <th>Attacker IP</th>
                <th>Tampering Action</th>
                <th>Target File Path</th>
            </tr>
        </thead>
        <tbody>
            {file_rows if file_rows else "<tr><td colspan='3'>No file tampering recorded.</td></tr>"}
        </tbody>
    </table>

    <div class="card" style="margin-top: 20px;">
        <div class="card-title">🛡️ Automated AI Defensive Recommendations</div>
        <ol style="margin-left: 20px; font-size: 0.9rem; color: #cbd5e1;">
            <li><strong>Isolate Attacker Source IPs:</strong> Block identified malicious IPs (e.g. <code>{', '.join(report_data['attackers'].keys()) if report_data['attackers'] else 'None'}</code>) at edge firewall.</li>
            <li><strong>Rotate Compromised Deception Secrets:</strong> Audit and invalidate all credentials probed by threat actors (Root SSH keys, PostgreSQL passwords, AWS tokens).</li>
            <li><strong>Enforce Zero-Trust MFA:</strong> Restrict administrative access to SSH and internal SSO endpoints.</li>
        </ol>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Also save JSON report
    json_path = output_path.replace(".html", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(report_data, indent=2))

    return output_path


def main():
    console.print(Panel("[bold cyan]Kurukshetra 2.0 Threat Intelligence Report Generator[/bold cyan]"))
    data = analyze_telemetry()
    out = generate_html_report(data)
    console.print(f"[bold green][OK] Executive Threat Report Generated Successfully![/bold green]")
    console.print(f"  [cyan]HTML Report :[/cyan] file:///{os.path.abspath(out)}")
    console.print(f"  [cyan]JSON Report :[/cyan] file:///{os.path.abspath(out.replace('.html', '.json'))}")
    console.print(f"  [yellow]Overall Risk Score:[/yellow] [bold red]{data['overall_severity']} ({data['overall_risk_score']}/100)[/bold red]")
    console.print(f"  [yellow]Identified Attackers:[/yellow] [bold cyan]{data['unique_attackers']}[/bold cyan] ({list(data['attackers'].keys())})")


if __name__ == "__main__":
    main()
