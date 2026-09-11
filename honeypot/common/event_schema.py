"""
Event Schema Module for the Honeypot / Cyber Deception Layer.
Defines the strict telemetry JSON contract required by Member 3 and the Backend API.
"""

import uuid
import itertools
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


# Counter for human-readable sequential event IDs if preferred
_event_counter = itertools.count(1)


class HoneypotEvent(BaseModel):
    """
    Standard Structured Telemetry Event Contract.
    
    Required Fields:
      - event_id: Unique identifier for the event (e.g. 'EVT-0001' or 'EVT-UUID')
      - session_id: Tracking ID for attacker session (e.g. 'ATK-001' or 'ATK-UUID')
      - source_ip: Remote attacker IP address
      - target_ip: Honeypot destination IP address
      - service: Service name ('ssh', 'web', 'api', 'port_scan', etc.)
      - timestamp: ISO 8601 UTC timestamp (e.g. '2026-09-11T10:30:00Z')
      - event_type: Classification ('command', 'auth_attempt', 'decoy_access', 'http_request', etc.)
      - event: Human/machine readable event summary / command / path
      - metadata: Arbitrary key-value dictionary for rich context
    """
    event_id: str = Field(..., description="Unique event identifier")
    session_id: str = Field(..., description="Correlated attacker session identifier")
    source_ip: str = Field(..., description="Source IPv4/IPv6 address of the attacker")
    target_ip: str = Field(..., description="Target honeypot IP address")
    service: str = Field(..., description="Service identifier (ssh, web, api)")
    timestamp: str = Field(..., description="ISO8601 UTC formatted timestamp")
    event_type: str = Field(..., description="Categorical event type")
    event: str = Field(..., description="Event payload / command / action")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual telemetry details")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        # Verify it parses as valid ISO format
        try:
            # Handle standard ISO formats (including trailing Z)
            clean_ts = v.replace("Z", "+00:00")
            datetime.fromisoformat(clean_ts)
        except Exception as e:
            raise ValueError(f"Invalid ISO 8601 timestamp '{v}': {e}")
        return v

    def to_dict(self) -> Dict[str, Any]:
        """Convert to standard serializable dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Convert to compact JSON string."""
        return self.model_dump_json()


def generate_event_id(prefix: str = "EVT") -> str:
    """Generates a unique event identifier."""
    unique_suffix = uuid.uuid4().hex[:8].upper()
    seq = next(_event_counter)
    return f"{prefix}-{seq:04d}-{unique_suffix}"


def generate_session_id(prefix: str = "ATK", ip: Optional[str] = None) -> str:
    """Generates a session identifier optionally derived from client IP."""
    short_uuid = uuid.uuid4().hex[:8].upper()
    return f"{prefix}-{short_uuid}"


def get_utc_timestamp() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_event(
    service: str,
    event_type: str,
    event: str,
    source_ip: str,
    session_id: str,
    target_ip: str = "127.0.0.1",
    metadata: Optional[Dict[str, Any]] = None,
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> HoneypotEvent:
    """
    Factory helper to instantiate a validated HoneypotEvent.
    """
    return HoneypotEvent(
        event_id=event_id or generate_event_id(),
        session_id=session_id,
        source_ip=source_ip,
        target_ip=target_ip,
        service=service,
        timestamp=timestamp or get_utc_timestamp(),
        event_type=event_type,
        event=event,
        metadata=metadata or {},
    )
