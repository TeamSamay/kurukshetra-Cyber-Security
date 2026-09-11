import os
import sys
import json
import threading
from pathlib import Path
from typing import Optional, Union, Dict, Any

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

from rich.console import Console
from rich.text import Text
from rich.table import Table

from honeypot.common.event_schema import HoneypotEvent


class EventLogger:
    """
    Thread-safe logger that appends events to a JSONL file
    and prints formatted telemetry to the terminal console.
    """
    def __init__(self, log_file_path: str = "logs/events.jsonl", console_output: bool = True):
        self.log_file_path = Path(log_file_path)
        self.console_output = console_output
        self.lock = threading.Lock()
        self.console = Console()
        
        # Ensure log directory exists
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
    def log(self, event: Union[HoneypotEvent, Dict[str, Any]]) -> HoneypotEvent:
        """
        Logs a structured event to local JSONL and outputs to console.
        Returns the validated HoneypotEvent.
        """
        if isinstance(event, dict):
            validated_event = HoneypotEvent(**event)
        else:
            validated_event = event

        event_json = validated_event.to_json()

        # Thread-safe file append
        with self.lock:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(event_json + "\n")

        # Console display
        if self.console_output:
            self._print_console(validated_event)

        return validated_event

    def _print_console(self, event: HoneypotEvent) -> None:
        """Formats and prints the event to standard output using Rich."""
        # Color palette by service & event type
        service_colors = {
            "ssh": "bold cyan",
            "web": "bold magenta",
            "api": "bold yellow",
            "decoy": "bold red",
        }
        svc_style = service_colors.get(event.service.lower(), "bold white")
        
        type_style = "bold red" if "decoy" in event.event_type or "attack" in event.event_type else "green"

        msg = Text()
        msg.append(f"[{event.timestamp}] ", style="dim")
        msg.append(f"[{event.service.upper()}] ", style=svc_style)
        msg.append(f"[{event.event_type}] ", style=type_style)
        msg.append(f"src={event.source_ip} ", style="bold blue")
        msg.append(f"session={event.session_id} ", style="cyan")
        msg.append(f"| {event.event}", style="white")

        self.console.print(msg)


# Global default logger instance
default_logger = EventLogger()
