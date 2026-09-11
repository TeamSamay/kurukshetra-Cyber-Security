"""
Unified Telemetry Dispatcher.
Single entry point for all honeypot services (SSH, Web, API, Decoys)
to generate, locally log, and backend-forward events.
"""

from typing import Optional, Dict, Any

from honeypot.common.event_schema import HoneypotEvent, create_event
from honeypot.common.event_logger import default_logger
from honeypot.common.backend_client import backend_client
from honeypot.config.settings import settings


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
    Creates, validates, locally persists, and asynchronously transmits
    a structured honeypot telemetry event.
    """
    evt = create_event(
        service=service,
        event_type=event_type,
        event=event,
        source_ip=source_ip,
        session_id=session_id,
        target_ip=target_ip or settings.HONEYPOT_TARGET_IP,
        metadata=metadata or {},
    )

    # 1. Thread-safe Local File & Console Logging
    default_logger.log(evt)

    # 2. Asynchronous Non-blocking Backend Dispatch
    backend_client.send_event(evt)

    return evt
