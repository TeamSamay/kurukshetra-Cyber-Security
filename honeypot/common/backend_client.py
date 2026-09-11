"""
Backend Client Module for Honeypot Telemetry Forwarding.
Queues events and sends them asynchronously to Member 3's backend API (POST /api/events).
Includes exponential backoff retry, keepalive warming for Render backend, and visual status reporting.
"""

import time
import queue
import threading
import logging
from typing import Optional, Dict, Any
import httpx
from rich.console import Console

from honeypot.common.event_schema import HoneypotEvent
from honeypot.config.settings import settings

logger = logging.getLogger("honeypot.backend_client")
console = Console()


class BackendClient:
    """
    Asynchronous event dispatcher with internal FIFO queue, retry loop,
    and automatic keepalive pinger for Render cloud deployment.
    """
    def __init__(
        self,
        backend_url: Optional[str] = None,
        timeout: Optional[float] = None,
        max_queue_size: Optional[int] = None,
        retry_interval: Optional[float] = None,
    ):
        self._custom_backend_url = backend_url
        self.base_url = settings.BACKEND_URL.rstrip("/")
        self.timeout = timeout or settings.BACKEND_TIMEOUT_SEC
        self.retry_interval = retry_interval or settings.BACKEND_RETRY_INTERVAL_SEC
        self.max_queue_size = max_queue_size or settings.BACKEND_MAX_QUEUE_SIZE

        self._queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self._client: Optional[httpx.Client] = None
        
        # Stats
        self.total_sent = 0
        self.total_failed = 0
        self.total_queued = 0
        self.last_delivery_status = "INITIALIZING"

    @property
    def backend_url(self) -> str:
        if self._custom_backend_url:
            return self._custom_backend_url.rstrip("/")
        return settings.full_backend_events_url.rstrip("/")

    @backend_url.setter
    def backend_url(self, val: Optional[str]):
        self._custom_backend_url = val

    def start(self) -> None:
        """Starts the background worker thread and keepalive pinger."""
        if self._running:
            return
        self._running = True
        self._client = httpx.Client(timeout=self.timeout)
        
        # 1. Main Telemetry Forwarder Worker
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="BackendForwarder")
        self._worker_thread.start()

        # 2. Render Cloud Keepalive Worker (prevents spin-down)
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True, name="BackendKeepalive")
        self._keepalive_thread.start()

    def stop(self, wait_empty: bool = True, timeout: float = 3.0) -> None:
        """Stops background worker threads."""
        self._running = False
        if wait_empty:
            start_t = time.time()
            while not self._queue.empty() and (time.time() - start_t) < timeout:
                time.sleep(0.05)

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass

    def send_event(self, event: HoneypotEvent) -> bool:
        """
        Enqueues an event for background delivery to the backend.
        Returns True if queued successfully.
        """
        if not self._running:
            self.start()

        try:
            self._queue.put_nowait(event)
            self.total_queued += 1
            return True
        except queue.Full:
            logger.warning("Backend forwarder queue full! Dropping event from queue (local log intact).")
            self.total_failed += 1
            return False

    def send_sync(self, event: HoneypotEvent) -> bool:
        """
        Directly sends an event to the backend synchronously.
        Useful for startup verification and testing.
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self.backend_url,
                    json=event.to_dict(),
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code in (200, 201, 202):
                    self.total_sent += 1
                    self.last_delivery_status = "ONLINE"
                    return True
                else:
                    self.last_delivery_status = f"HTTP_{resp.status_code}"
                    return False
        except Exception as e:
            self.last_delivery_status = f"ERROR: {e}"
            return False

    def _worker_loop(self) -> None:
        """Background thread consuming events and posting to backend."""
        while self._running or not self._queue.empty():
            try:
                event: HoneypotEvent = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Attempt to send with retry
            delivered = False
            attempts = 0
            max_retries = 3

            while attempts < max_retries and self._running:
                attempts += 1
                try:
                    if not self._client:
                        self._client = httpx.Client(timeout=self.timeout)

                    resp = self._client.post(
                        self.backend_url,
                        json=event.to_dict(),
                        headers={"Content-Type": "application/json"}
                    )
                    if resp.status_code in (200, 201, 202):
                        delivered = True
                        self.total_sent += 1
                        self.last_delivery_status = "ONLINE"
                        
                        # Visual notification in console
                        console.print(
                            f"[dim green]  ↳ [FORWARDED -> {self.backend_url}][/dim green] "
                            f"[bold cyan]{event.event_id}[/bold cyan] ({event.service}:{event.event_type}) "
                            f"[green]HTTP {resp.status_code} OK[/green]"
                        )
                        break
                    else:
                        time.sleep(1.0)
                except Exception as ex:
                    time.sleep(1.0)

            if not delivered:
                self.total_failed += 1
                self.last_delivery_status = "DEGRADED"

            self._queue.task_done()

    def _keepalive_loop(self) -> None:
        """Periodically pings the Render backend to prevent free tier cold sleep."""
        while self._running:
            try:
                if not self._client:
                    self._client = httpx.Client(timeout=self.timeout)
                # Ping health or root
                health_url = f"{self.base_url}/health"
                r = self._client.get(health_url)
                if r.status_code == 200:
                    self.last_delivery_status = "ONLINE"
            except Exception:
                pass

            # Sleep for keepalive interval (e.g. 5 minutes)
            for _ in range(int(settings.BACKEND_KEEPALIVE_INTERVAL_SEC)):
                if not self._running:
                    break
                time.sleep(1.0)


# Global backend client instance
backend_client = BackendClient()
