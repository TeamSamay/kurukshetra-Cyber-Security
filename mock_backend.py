"""
Mock Backend Server (Simulating Member 3's Threat Intelligence Ingestion API).
Receives structured honeypot events at POST /api/events, validates contract compliance,
and presents a live real-time web view for Hackathon demo presentation.
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

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
from rich.console import Console
from rich.panel import Panel

console = Console(legacy_windows=False)

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from honeypot.common.event_schema import HoneypotEvent
from generate_report import analyze_telemetry, generate_html_report

app = FastAPI(title="Kurukshetra Mock Threat Intelligence Backend (Member 3 Simulator)")

received_events: List[Dict[str, Any]] = []
backend_log_file = Path("logs/backend_received_events.jsonl")
backend_log_file.parent.mkdir(parents=True, exist_ok=True)


@app.get("/report", response_class=HTMLResponse)
async def serve_threat_report():
    """Generates and serves real-time executive threat intelligence report."""
    data = analyze_telemetry()
    html_path = generate_html_report(data)
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/events", status_code=status.HTTP_201_CREATED)
async def receive_event(request: Request):
    """
    Ingests structured telemetry from the Honeypot Server.
    Strictly validates the 9 required fields.
    """
    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")

    # Validate against HoneypotEvent schema
    try:
        event = HoneypotEvent(**data)
    except Exception as e:
        console.print(f"[bold red][BACKEND-REJECTED][/bold red] Invalid Schema: {e}")
        raise HTTPException(status_code=422, detail=f"Schema validation error: {e}")

    event_dict = event.to_dict()
    received_events.append(event_dict)

    # Append to backend received log
    with open(backend_log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_dict) + "\n")

    # Console feedback for live demo
    type_color = "red" if "decoy" in event.event_type or "file" in event.event_type else "yellow"
    console.print(
        f"[bold green][BACKEND-INGEST][/bold green] [cyan]{event.service.upper()}[/cyan] "
        f"[{type_color}]{event.event_type}[/{type_color}] from [blue]{event.source_ip}[/blue] "
        f"(Session: {event.session_id}) -> {event.event}"
    )

    return {
        "status": "success",
        "message": "Telemetry event received and indexed",
        "event_id": event.event_id,
        "processed_at": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/events", response_class=JSONResponse)
async def list_events(limit: int = 100):
    """Returns recently ingested events."""
    return {
        "total_events": len(received_events),
        "events": received_events[-limit:]
    }


@app.get("/api/stats", response_class=JSONResponse)
async def get_stats():
    """Aggregates telemetry statistics."""
    services = {}
    event_types = {}
    ips = set()
    for evt in received_events:
        svc = evt.get("service", "unknown")
        etype = evt.get("event_type", "unknown")
        services[svc] = services.get(svc, 0) + 1
        event_types[etype] = event_types.get(etype, 0) + 1
        ips.add(evt.get("source_ip", ""))

    return {
        "total_events": len(received_events),
        "unique_attackers": len(ips),
        "service_distribution": services,
        "event_type_distribution": event_types,
    }


def format_local_timestamp(iso_str: str) -> str:
    """Converts UTC ISO timestamp to crisp local IST clock time (e.g. 17:34:09 IST)."""
    try:
        clean_ts = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        local_dt = dt.astimezone()  # Auto-converts to system local timezone (IST)
        local_time_str = local_dt.strftime("%H:%M:%S")
        date_str = local_dt.strftime("%Y-%m-%d")
        return f'<div style="font-weight:800; color:#38bdf8; font-size:1.0rem; font-family:monospace; white-space:nowrap;">{local_time_str} <span style="font-size:0.72rem; color:#10b981; background:rgba(16,185,129,0.15); padding:2px 5px; border-radius:4px; border:1px solid #10b981;">IST</span></div><small style="color:#64748b; font-size:0.75rem;">{date_str}</small>'
    except Exception:
        return f'<code>{iso_str}</code>'


@app.get("/", response_class=HTMLResponse)
async def live_dashboard():
    """Live Visual SOC Dashboard for Hackathon presentation."""
    rows = ""
    decoys_count = 0
    file_changes_count = 0
    attackers = set()

    for evt in reversed(received_events[-80:]):
        svc = evt.get("service", "other").lower()
        etype = evt.get("event_type", "").lower()
        source_ip = evt.get("source_ip", "")
        if source_ip:
            attackers.add(source_ip)

        # Count special highlights
        if "decoy" in etype:
            decoys_count += 1
        if "file" in etype:
            file_changes_count += 1

        badge_cls = "badge-ssh" if svc == "ssh" else ("badge-web" if svc == "web" else "badge-api")
        
        # Event type badge color
        if "decoy" in etype:
            type_badge = '<span class="badge-alert">🚨 DECOY ACCESS</span>'
        elif "file_created" in etype:
            type_badge = '<span class="badge-file">📝 FILE CREATED</span>'
        elif "file_modified" in etype:
            type_badge = '<span class="badge-mod">✏️ FILE MODIFIED</span>'
        elif "file_deleted" in etype:
            type_badge = '<span class="badge-del">🗑️ FILE DELETED</span>'
        elif "auth" in etype:
            type_badge = '<span class="badge-auth">🔑 AUTH ATTEMPT</span>'
        else:
            type_badge = f'<strong>{evt["event_type"]}</strong>'

        # Metadata preview
        meta_str = ""
        meta = evt.get("metadata", {})
        if meta:
            meta_items = [f"<b>{k}:</b> {v}" for k, v in meta.items() if k not in ("user_agent", "content_type")]
            meta_str = "<br><small style='color:#94a3b8;'>" + " | ".join(meta_items[:4]) + "</small>"

        formatted_time = format_local_timestamp(evt.get("timestamp", ""))

        rows += f"""
        <tr>
            <td style="white-space:nowrap;">{formatted_time}</td>
            <td><span class="badge {badge_cls}">{evt['service'].upper()}</span></td>
            <td>{type_badge}</td>
            <td><span class="ip-badge">{evt['source_ip']}</span></td>
            <td><small style="color:#38bdf8;">{evt['session_id']}</small></td>
            <td><strong>{evt['event']}</strong>{meta_str}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kurukshetra Threat Intelligence Telemetry Stream</title>
        <meta http-equiv="refresh" content="3">
        <style>
            :root {{
                --bg: #0b0f19;
                --card-bg: #151d30;
                --border: #23304b;
                --accent-blue: #38bdf8;
                --danger: #f43f5e;
                --warning: #fbbf24;
                --success: #10b981;
            }}
            * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
            body {{ background: var(--bg); color: #f3f4f6; padding: 24px 32px; margin: 0; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
            h1 {{ color: var(--accent-blue); margin: 0; font-size: 1.6rem; display: flex; align-items: center; gap: 10px; }}
            .stats-bar {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
            .stat-card {{ background: var(--card-bg); padding: 18px 20px; border-radius: 10px; border: 1px solid var(--border); }}
            .stat-label {{ color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; font-weight: 600; margin-bottom: 6px; }}
            .stat-val {{ font-size: 1.8rem; font-weight: 800; color: #f8fafc; }}
            
            table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }}
            th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); text-align: left; font-size: 0.88rem; }}
            th {{ background: #090d16; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
            
            .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }}
            .badge-ssh {{ background: #0284c7; color: white; }}
            .badge-web {{ background: #9333ea; color: white; }}
            .badge-api {{ background: #d97706; color: white; }}
            
            .badge-alert {{ background: rgba(244, 63, 94, 0.2); border: 1px solid #f43f5e; color: #fda4af; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-file {{ background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #6ee7b7; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-mod {{ background: rgba(251, 191, 36, 0.2); border: 1px solid #fbbf24; color: #fde68a; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-del {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-auth {{ background: rgba(59, 130, 246, 0.2); border: 1px solid #3b82f6; color: #93c5fd; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            
            .ip-badge {{ background: #1e293b; color: #38bdf8; padding: 4px 8px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; border: 1px solid #334155; }}
            code {{ color: #38bdf8; font-family: monospace; }}
            .status-pill {{ background: rgba(16, 185, 129, 0.2); color: #34d399; padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; border: 1px solid #10b981; }}
            .btn-report {{ background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 0.85rem; border: 1px solid #38bdf8; margin-right: 12px; display: inline-flex; align-items: center; gap: 6px; }}
            .btn-report:hover {{ opacity: 0.9; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🛡️ Kurukshetra Threat Intelligence Telemetry Stream</h1>
                <p style="color: #94a3b8; font-size: 0.85rem; margin-top: 4px;">
                    Live High-Interaction Cyber Deception Layer &bull; Auto-refreshes every 3 seconds
                </p>
            </div>
            <div style="display: flex; align-items: center;">
                <a href="/report" target="_blank" class="btn-report">📑 View Threat Intelligence Report</a>
                <span class="status-pill">● LIVE INGESTION ACTIVE</span>
            </div>
        </div>
        
        <div class="stats-bar">
            <div class="stat-card">
                <div class="stat-label">Total Events Ingested</div>
                <div class="stat-val" style="color: #38bdf8;">{len(received_events)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Attacker IPs</div>
                <div class="stat-val" style="color: #a855f7;">{len(attackers)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Decoy Traps Tripped</div>
                <div class="stat-val" style="color: #f43f5e;">{decoys_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Files Created / Modified</div>
                <div class="stat-val" style="color: #10b981;">{file_changes_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Service</th>
                    <th>Event Classification</th>
                    <th>Attacker IP</th>
                    <th>Session ID</th>
                    <th>Action, Command &amp; File Tampering Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else "<tr><td colspan='6' style='text-align:center; color:#64748b; padding:40px;'>Awaiting attacker connection... Launch attack from Parrot OS to populate live feed!</td></tr>"}
            </tbody>
        </table>
    </body>
    </html>
    """
    return html


def run_mock_backend(host: str = "0.0.0.0", port: int = 8000):
    console.print(Panel(
        f"[bold green]Mock Backend Telemetry Receiver Online[/bold green]\n"
        f"Ingestion Endpoint: [cyan]http://{host}:{port}/api/events[/cyan]\n"
        f"Live Web Monitor  : [yellow]http://localhost:{port}/[/yellow]",
        title="[bold blue]Member 3 Backend Simulator[/bold blue]"
    ))
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_mock_backend()
