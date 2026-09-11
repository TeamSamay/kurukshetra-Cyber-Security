"""
Base Scenario Class for Controlled Attack Simulation.
"""

import time
import sys
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from rich.console import Console

# UTF-8 stream handling
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False)


class BaseScenario(ABC):
    def __init__(self, target_host: str, ssh_port: int = 2222, web_port: int = 8080, delay: float = 0.5):
        self.target_host = target_host
        self.ssh_port = ssh_port
        self.web_port = web_port
        self.delay = delay
        self.stats = {
            "probes_sent": 0,
            "success_responses": 0,
            "error_responses": 0,
            "decoys_triggered": 0,
            "start_time": 0.0,
            "end_time": 0.0,
        }

    def sleep(self):
        if self.delay > 0:
            time.sleep(self.delay)

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """Executes the scenario and returns telemetry metrics."""
        pass
