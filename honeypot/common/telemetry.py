"""
Unified Telemetry Dispatcher.
Single entry point for all honeypot services (SSH, Web, API, Decoys)
to generate, locally log, and backend-forward events.
"""

from typing import Optional, Dict, Any

from honeypot.common.event_schema import HoneypotEvent, create_event
from honeypot.common.event_logger import default_logger
from honeypot.common.backend_client import backend_client
from honeypot.common.threat_learning_engine import threat_engine
from honeypot.config.settings import settings

# Internal / probe traffic — log locally only, never forward to production backend
_INTERNAL_IPS = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0"})
_SILENT_EVENT_TYPES = frozenset({"honeypot_started", "health_check", "system"})
_SILENT_SESSION_PREFIXES = ("SYSTEM-", "HEALTH-")


def _should_forward_to_backend(source_ip: str, session_id: str, event_type: str, metadata: Dict[str, Any]) -> bool:
    if event_type in _SILENT_EVENT_TYPES:
        return False
    if any(session_id.startswith(p) for p in _SILENT_SESSION_PREFIXES):
        return False
    if metadata.get("internal_probe") or metadata.get("health_check"):
        return False
    ip = (source_ip or "").split("%")[0]
    if ip in _INTERNAL_IPS:
        return False
    return True


def emit_event(
    service: str,
    event_type: str,
    event: str,
    source_ip: str,
    session_id: str,
    target_ip: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> HoneypotEvent:
    """
    Analyzes attack interaction, enriches with MITRE TTPs & tool detection,
    creates validated event, locally logs, and asynchronously transmits to Render backend.
    """
    combined_meta = dict(metadata or {})
    
    # Analyze interaction through Threat Learning Engine ("Game Bajaye")
    try:
        intel = threat_engine.analyze_interaction(
            service=service,
            event_type=event_type,
            payload=event,
            source_ip=source_ip,
            session_id=session_id,
            raw_metadata=combined_meta,
        )
        combined_meta["threat_intel"] = intel
        combined_meta["mitre_tactics"] = intel.get("attack_phases", [])
        combined_meta["detected_tools"] = intel.get("detected_tools", [])
        combined_meta["attacker_skill"] = intel.get("attacker_skill_level", "NOVICE")
        combined_meta["attacker_intent"] = intel.get("attacker_intent", "RECON")
        combined_meta["risk_score"] = intel.get("threat_risk_score", 10)
    except Exception:
        pass

    evt = create_event(
        service=service,
        event_type=event_type,
        event=event,
        source_ip=source_ip,
        session_id=session_id,
        target_ip=target_ip or settings.HONEYPOT_TARGET_IP,
        metadata=combined_meta,
    )

    # 1. Thread-safe Local File & Console Logging
    default_logger.log(evt)

    # 2. Forward only real external attacker telemetry (not health checks / internal probes)
    if _should_forward_to_backend(source_ip, session_id, event_type, combined_meta):
        backend_client.send_event(evt)

    return evt

