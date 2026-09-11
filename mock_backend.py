"""
Kurukshetra 2.0 — Threat Intelligence Ingestion API & Live SOC Operations Dashboard.
Powered by Groq LLM AI for real-time threat monitoring, automated mitigation
recommendations, interactive SOC copilot, and high-fidelity cyber deception forensics.
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

from fastapi import FastAPI, Request, HTTPException, status, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from rich.console import Console
from rich.panel import Panel

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from honeypot.common.event_schema import HoneypotEvent
from honeypot.common.ai_advisor import ai_advisor
from honeypot.config.settings import settings
from generate_report import analyze_telemetry, generate_html_report

console = Console(legacy_windows=False)

app = FastAPI(
    title="Kurukshetra 2.0 Threat Intelligence & AI Defense Backend",
    description="Groq-Powered Cyber Threat Ingestion, Real-Time Monitoring & Adaptive Deception API",
    version="2.0.0"
)

# Enable CORS for cross-origin dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

received_events: List[Dict[str, Any]] = []
backend_log_file = Path("logs/backend_received_events.jsonl")
backend_log_file.parent.mkdir(parents=True, exist_ok=True)

# Load existing events if available for persistence across restarts
if backend_log_file.exists():
    try:
        with open(backend_log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        received_events.append(json.loads(line))
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"[yellow]Note: Could not preload past events: {e}[/yellow]")


@app.get("/api/health", response_class=JSONResponse)
async def health_check():
    """Health check endpoint for backend monitoring and cloud platforms (Render/Docker/K8s)."""
    return {
        "status": "HEALTHY",
        "service": "Kurukshetra Threat Intelligence Backend",
        "events_indexed": len(received_events),
        "ai_engine_online": ai_advisor.is_ai_online,
        "ai_model": ai_advisor.model if ai_advisor.is_ai_online else "Kurukshetra Heuristic Cyber Engine",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/events", status_code=status.HTTP_201_CREATED)
async def receive_event(request: Request):
    """
    Ingests structured telemetry from Honeypot sensors (SSH, Web, API, Decoys).
    Validates schema and updates backend threat intelligence index.
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

    # Append to backend log
    try:
        with open(backend_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict) + "\n")
    except Exception:
        pass

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
async def list_events(
    limit: int = Query(100, ge=1, le=1000),
    service: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None
):
    """Returns recently ingested events with optional filtering."""
    filtered = received_events
    if service:
        filtered = [e for e in filtered if e.get("service", "").lower() == service.lower()]
    if source_ip:
        filtered = [e for e in filtered if e.get("source_ip", "") == source_ip]
    if event_type:
        filtered = [e for e in filtered if event_type.lower() in e.get("event_type", "").lower()]

    return {
        "total_events": len(received_events),
        "filtered_count": len(filtered),
        "events": filtered[-limit:]
    }


@app.get("/api/stats", response_class=JSONResponse)
async def get_stats():
    """Aggregates telemetry statistics and deception health metrics."""
    services: Dict[str, int] = {}
    event_types: Dict[str, int] = {}
    ips: set = set()
    decoys_count = 0
    file_changes_count = 0

    for evt in received_events:
        svc = evt.get("service", "unknown")
        etype = evt.get("event_type", "unknown")
        services[svc] = services.get(svc, 0) + 1
        event_types[etype] = event_types.get(etype, 0) + 1
        if evt.get("source_ip"):
            ips.add(evt.get("source_ip"))
        if "decoy" in etype:
            decoys_count += 1
        if "file" in etype:
            file_changes_count += 1

    return {
        "total_events": len(received_events),
        "unique_attackers": len(ips),
        "decoys_tripped": decoys_count,
        "file_tampering_events": file_changes_count,
        "service_distribution": services,
        "event_type_distribution": event_types,
        "ai_engine_status": "ONLINE" if ai_advisor.is_ai_online else "HEURISTIC_STANDBY"
    }


@app.get("/api/ai/insights", response_class=JSONResponse)
async def get_ai_threat_insights():
    """
    Returns real-time Groq LLM Threat Intelligence Analysis, MITRE ATT&CK mappings,
    and automated defensive mitigation playbooks / firewall commands.
    """
    insights = ai_advisor.analyze_threat_landscape(received_events)
    return insights


@app.post("/api/ai/chat", response_class=JSONResponse)
async def ai_copilot_chat(request: Request):
    """
    Interactive SOC AI Copilot endpoint: Answers analyst queries with live telemetry awareness.
    Payload: {"query": "...", "history": [...]}
    """
    try:
        body = await request.json()
        query = body.get("query", "").strip()
        history = body.get("history", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    response = ai_advisor.chat_copilot(query=query, events=received_events, conversation_history=history)
    return response


@app.get("/api/ai/attacker/{ip}", response_class=JSONResponse)
async def get_attacker_ai_dossier(ip: str):
    """Generates an AI threat intelligence profile for a specific attacker IP."""
    attacker_events = [e for e in received_events if e.get("source_ip") == ip]
    if not attacker_events:
        raise HTTPException(status_code=404, detail=f"No telemetry found for IP {ip}")

    # Analyze specifically for this IP
    analysis = ai_advisor.analyze_threat_landscape(attacker_events)
    return {
        "ip": ip,
        "event_count": len(attacker_events),
        "first_seen": attacker_events[0].get("timestamp"),
        "last_seen": attacker_events[-1].get("timestamp"),
        "analysis": analysis
    }


@app.get("/report", response_class=HTMLResponse)
async def serve_threat_report():
    """Generates and serves real-time executive threat intelligence report."""
    data = analyze_telemetry()
    html_path = generate_html_report(data)
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


def format_local_timestamp(iso_str: str) -> str:
    """Converts UTC ISO timestamp to crisp local IST clock time."""
    try:
        clean_ts = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        local_dt = dt.astimezone()
        local_time_str = local_dt.strftime("%H:%M:%S")
        date_str = local_dt.strftime("%Y-%m-%d")
        return f'<div style="font-weight:800; color:#38bdf8; font-size:0.95rem; font-family:monospace; white-space:nowrap;">{local_time_str} <span style="font-size:0.7rem; color:#10b981; background:rgba(16,185,129,0.15); padding:1px 4px; border-radius:4px; border:1px solid #10b981;">IST</span></div><small style="color:#64748b; font-size:0.75rem;">{date_str}</small>'
    except Exception:
        return f'<code>{iso_str}</code>'


@app.get("/", response_class=HTMLResponse)
async def live_dashboard():
    """
    Next-Gen Real-Time Cyber Operations Center (SOC) Dashboard.
    Features live Groq AI threat reasoning, mitigation suggestions, interactive AI Copilot,
    MITRE matrix, and instant telemetry stream.
    """
    rows = ""
    decoys_count = 0
    file_changes_count = 0
    attackers = set()

    for evt in reversed(received_events[-100:]):
        svc = evt.get("service", "other").lower()
        etype = evt.get("event_type", "").lower()
        source_ip = evt.get("source_ip", "")
        if source_ip:
            attackers.add(source_ip)

        if "decoy" in etype:
            decoys_count += 1
        if "file" in etype:
            file_changes_count += 1

        badge_cls = "badge-ssh" if svc == "ssh" else ("badge-web" if svc == "web" else "badge-api")

        if "decoy" in etype:
            type_badge = '<span class="badge-alert">🚨 DECOY TRAP HIT</span>'
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

    # Fetch AI threat analysis for initial page load
    ai_data = ai_advisor.analyze_threat_landscape(received_events)
    ai_status_badge = "🤖 GROQ LLM (LLaMA 3.3 70B)" if ai_advisor.is_ai_online else "⚡ KURUKSHETRA HEURISTIC AI"

    recs_list = ""
    for r in ai_data.get("recommendations", []):
        color = "#f43f5e" if r.get("priority") == "CRITICAL" else ("#fbbf24" if r.get("priority") == "HIGH" else "#38bdf8")
        recs_list += f"""
        <div style="background:rgba(15,23,42,0.8); border:1px solid #334155; border-left:4px solid {color}; padding:10px 14px; border-radius:6px; margin-bottom:8px;">
            <div style="font-weight:700; color:{color}; font-size:0.85rem;">[{r.get('priority', 'INFO')}] {r.get('title', '')}</div>
            <div style="font-size:0.85rem; color:#cbd5e1; margin-top:2px;">{r.get('action', '')}</div>
        </div>
        """

    fw_list = ""
    for cmd in ai_data.get("firewall_rules", []):
        fw_list += f"""
        <div style="display:flex; justify-content:space-between; align-items:center; background:#090d16; border:1px solid #1e293b; padding:6px 12px; border-radius:6px; margin-bottom:6px;">
            <code style="color:#38bdf8; font-size:0.85rem;">{cmd}</code>
            <button onclick="copyToClipboard('{cmd}')" style="background:#1e293b; color:#94a3b8; border:1px solid #334155; border-radius:4px; padding:3px 8px; font-size:0.72rem; cursor:pointer;">Copy</button>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Kurukshetra 2.0 — AI Threat Operations &amp; Cyber Deception Center</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {{
                --bg: #070a13;
                --card-bg: #111827;
                --card-header: #1f293d;
                --border: #1e293b;
                --border-accent: #3b82f6;
                --accent-blue: #38bdf8;
                --accent-purple: #a855f7;
                --danger: #f43f5e;
                --warning: #fbbf24;
                --success: #10b981;
                --text-main: #f8fafc;
                --text-dim: #94a3b8;
            }}
            * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
            body {{ background: var(--bg); color: var(--text-main); padding: 24px 32px; margin: 0; }}
            
            /* Header */
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 22px; }}
            .header-title {{ display: flex; align-items: center; gap: 12px; }}
            h1 {{ color: var(--accent-blue); margin: 0; font-size: 1.6rem; letter-spacing: -0.02em; }}
            .badge-ai {{ background: linear-gradient(135deg, #9333ea, #6366f1); color: #fff; font-size: 0.72rem; font-weight: 800; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; }}
            
            /* Top Stats */
            .stats-bar {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 22px; }}
            .stat-card {{ background: var(--card-bg); padding: 16px 18px; border-radius: 10px; border: 1px solid var(--border); transition: transform 0.2s; }}
            .stat-card:hover {{ transform: translateY(-2px); border-color: #334155; }}
            .stat-label {{ color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; font-weight: 700; margin-bottom: 6px; }}
            .stat-val {{ font-size: 1.8rem; font-weight: 800; color: #fff; }}
            
            /* AI Advisory Grid */
            .ai-grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 24px; }}
            .ai-card {{ background: linear-gradient(135deg, rgba(17, 24, 39, 0.9), rgba(15, 23, 42, 0.95)); border: 1px solid #334155; border-radius: 12px; padding: 20px; }}
            .ai-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid #1e293b; padding-bottom: 10px; }}
            .ai-title {{ color: var(--accent-purple); font-size: 1.05rem; font-weight: 700; display: flex; align-items: center; gap: 8px; }}
            
            /* Chat Copilot Box */
            .chat-container {{ background: #0b0f19; border: 1px solid #1e293b; border-radius: 10px; height: 320px; display: flex; flex-direction: column; overflow: hidden; }}
            .chat-messages {{ flex: 1; padding: 12px; overflow-y: auto; font-size: 0.88rem; display: flex; flex-direction: column; gap: 10px; }}
            .chat-msg {{ padding: 8px 12px; border-radius: 8px; max-width: 90%; line-height: 1.4; }}
            .chat-msg-user {{ background: #1e293b; color: #38bdf8; align-self: flex-end; border: 1px solid #334155; }}
            .chat-msg-ai {{ background: rgba(147, 51, 234, 0.15); border: 1px solid #9333ea; color: #f3f4f6; align-self: flex-start; }}
            .chat-input-bar {{ display: flex; border-top: 1px solid #1e293b; background: #090d16; }}
            .chat-input {{ flex: 1; background: transparent; border: none; padding: 10px 14px; color: #fff; font-size: 0.85rem; outline: none; }}
            .chat-send-btn {{ background: #9333ea; color: white; border: none; padding: 0 16px; font-weight: bold; cursor: pointer; }}
            .chat-send-btn:hover {{ background: #a855f7; }}

            /* Table */
            .table-container {{ background: var(--card-bg); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); text-align: left; font-size: 0.86rem; }}
            th {{ background: #090d16; color: var(--text-dim); text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.05em; }}
            tr:hover {{ background: rgba(255,255,255,0.02); }}
            
            /* Badges */
            .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }}
            .badge-ssh {{ background: #0284c7; color: white; }}
            .badge-web {{ background: #9333ea; color: white; }}
            .badge-api {{ background: #d97706; color: white; }}
            
            .badge-alert {{ background: rgba(244, 63, 94, 0.2); border: 1px solid #f43f5e; color: #fda4af; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-file {{ background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #6ee7b7; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-mod {{ background: rgba(251, 191, 36, 0.2); border: 1px solid #fbbf24; color: #fde68a; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-del {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            .badge-auth {{ background: rgba(59, 130, 246, 0.2); border: 1px solid #3b82f6; color: #93c5fd; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
            
            .ip-badge {{ background: #1e293b; color: #38bdf8; padding: 3px 8px; border-radius: 6px; font-family: monospace; font-size: 0.82rem; border: 1px solid #334155; }}
            code {{ color: #38bdf8; font-family: monospace; }}
            .status-pill {{ background: rgba(16, 185, 129, 0.2); color: #34d399; padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; border: 1px solid #10b981; }}
            .btn-action {{ background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 0.85rem; border: 1px solid #38bdf8; display: inline-flex; align-items: center; gap: 6px; }}
            .btn-action:hover {{ opacity: 0.9; }}

            @media (max-width: 1024px) {{
                .ai-grid {{ grid-template-columns: 1fr; }}
                body {{ padding: 16px; }}
            }}
        </style>
        <script>
            function copyToClipboard(text) {{
                navigator.clipboard.writeText(text);
                alert("Copied command to clipboard:\\n" + text);
            }}

            async function sendAiCopilotMessage() {{
                const input = document.getElementById("copilotInput");
                const query = input.value.trim();
                if (!query) return;

                const msgBox = document.getElementById("copilotMessages");
                
                // Add user message
                const userDiv = document.createElement("div");
                userDiv.className = "chat-msg chat-msg-user";
                userDiv.innerText = query;
                msgBox.appendChild(userDiv);
                input.value = "";
                msgBox.scrollTop = msgBox.scrollHeight;

                // Add loading AI message
                const aiDiv = document.createElement("div");
                aiDiv.className = "chat-msg chat-msg-ai";
                aiDiv.innerHTML = "<em>Analyzing live telemetry with Groq...</em>";
                msgBox.appendChild(aiDiv);
                msgBox.scrollTop = msgBox.scrollHeight;

                try {{
                    const resp = await fetch("/api/ai/chat", {{
                        method: "POST",
                        headers: {{ "Content-Type": "application/json" }},
                        body: JSON.stringify({{ query: query }})
                    }});
                    const data = await resp.json();
                    aiDiv.innerHTML = data.answer.replace(/\\n/g, "<br>");
                }} catch (e) {{
                    aiDiv.innerHTML = "<span style='color:#f43f5e;'>Error consulting AI copilot: " + e + "</span>";
                }}
                msgBox.scrollTop = msgBox.scrollHeight;
            }}
        </script>
    </head>
    <body>
        <div class="header">
            <div>
                <div class="header-title">
                    <h1>🛡️ Kurukshetra 2.0 Threat Intelligence &amp; Cyber Deception Center</h1>
                    <span class="badge-ai">{ai_status_badge}</span>
                </div>
                <p style="color: #94a3b8; font-size: 0.85rem; margin-top: 4px;">
                    High-Interaction Deception Network &bull; Groq LLM Threat Intelligence &bull; Real-time Auto Refresh (3s)
                </p>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <a href="/report" target="_blank" class="btn-action">📑 Executive Threat Report</a>
                <span class="status-pill">● LIVE SENSORS ACTIVE</span>
            </div>
        </div>
        
        <!-- Top Metric KPI Bar -->
        <div class="stats-bar">
            <div class="stat-card">
                <div class="stat-label">Total Ingested Events</div>
                <div class="stat-val" style="color: #38bdf8;">{len(received_events)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Threat Actors</div>
                <div class="stat-val" style="color: #a855f7;">{len(attackers)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Decoy Honeytokens Tripped</div>
                <div class="stat-val" style="color: #f43f5e;">{decoys_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Filesystem Tampering</div>
                <div class="stat-val" style="color: #10b981;">{file_changes_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">AI Platform Threat Score</div>
                <div class="stat-val" style="color: {'#f43f5e' if ai_data.get('threat_score', 0) >= 70 else '#fbbf24'};">{ai_data.get('threat_level', 'LOW')} ({ai_data.get('threat_score', 0)}/100)</div>
            </div>
        </div>

        <!-- Groq AI Threat Advisory & Interactive Copilot Grid -->
        <div class="ai-grid">
            <div class="ai-card">
                <div class="ai-header">
                    <div class="ai-title">⚡ Real-Time Groq AI Threat Assessment &amp; Defense Playbook</div>
                    <span style="color:#38bdf8; font-size:0.75rem; font-weight:700;">Engine: {ai_data.get('model_used', 'Groq')}</span>
                </div>
                
                <p style="color:#f1f5f9; font-size:0.95rem; line-height:1.5; margin:0 0 16px 0;">
                    {ai_data.get('executive_summary', 'Awaiting live attacker telemetry to initialize AI threat modeling...')}
                </p>

                <div style="margin-bottom:14px;">
                    <div style="font-size:0.8rem; text-transform:uppercase; color:#94a3b8; font-weight:700; margin-bottom:8px;">🎯 Prioritized Tactical Defensive Suggestions:</div>
                    {recs_list if recs_list else '<div style="color:#64748b; font-size:0.85rem;">No critical remediation actions needed at this time.</div>'}
                </div>

                {f'''
                <div style="margin-top:14px;">
                    <div style="font-size:0.8rem; text-transform:uppercase; color:#fbbf24; font-weight:700; margin-bottom:8px;">🛡️ Instant Firewall Containment Commands:</div>
                    {fw_list}
                </div>
                ''' if fw_list else ''}
            </div>

            <!-- Interactive AI SOC Copilot Chat -->
            <div class="ai-card" style="display:flex; flex-direction:column;">
                <div class="ai-header">
                    <div class="ai-title">🤖 AI SOC Copilot (Ask Anything)</div>
                    <span style="color:#10b981; font-size:0.75rem; font-weight:700;">● Ready</span>
                </div>
                <div class="chat-container">
                    <div class="chat-messages" id="copilotMessages">
                        <div class="chat-msg chat-msg-ai">
                            👋 <strong>Kurukshetra SOC Copilot online.</strong> Ask me about active attackers, payload forensics, CVEs, or mitigation iptables rules!
                        </div>
                    </div>
                    <div class="chat-input-bar">
                        <input type="text" id="copilotInput" class="chat-input" placeholder="Ask AI: e.g. How to block attacker IP or explain decoy trip?" onkeydown="if(event.key==='Enter') sendAiCopilotMessage()" />
                        <button class="chat-send-btn" onclick="sendAiCopilotMessage()">Ask AI</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Live Honeypot Telemetry Stream -->
        <div class="table-container">
            <div style="padding:14px 18px; background:#0f172a; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center;">
                <div style="font-weight:700; font-size:0.95rem; color:#38bdf8;">📡 Live Honeypot Ingestion Feed &amp; Evidence Log</div>
                <div style="font-size:0.75rem; color:#94a3b8;">Showing latest 100 events &bull; Auto-indexed</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp (Local)</th>
                        <th>Service</th>
                        <th>Event Classification</th>
                        <th>Attacker Source IP</th>
                        <th>Session ID</th>
                        <th>Action, Shell Command &amp; Evidence Payload</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else "<tr><td colspan='6' style='text-align:center; color:#64748b; padding:40px;'>Awaiting attacker connection... Launch attack simulator or live probes to populate telemetry stream!</td></tr>"}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html


def run_mock_backend(host: str = "0.0.0.0", port: int = 8000):
    console.print(Panel(
        f"[bold green]Kurukshetra 2.0 Threat Intelligence Backend Online[/bold green]\n"
        f"Ingestion Endpoint : [cyan]http://{host}:{port}/api/events[/cyan]\n"
        f"Live AI SOC Monitor: [yellow]http://localhost:{port}/[/yellow]\n"
        f"Threat Intel Report: [magenta]http://localhost:{port}/report[/magenta]\n"
        f"AI Copilot Endpoint: [blue]http://{host}:{port}/api/ai/chat[/blue]",
        title="[bold blue]Kurukshetra AI Defense Backend[/bold blue]"
    ))
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_mock_backend()
