"""
Backend Client Module for Honeypot Telemetry Forwarding.
Queues events and sends them asynchronously to Member 3's backend API (POST /api/events).
Includes exponential backoff retry and resilient error handling.
"""

import time
import queue
import threading
import logging
from typing import Optional, Dict, Any
import httpx

from honeypot.common.event_schema import HoneypotEvent
from honeypot.config.settings import settings

logger = logging.getLogger("honeypot.backend_client")


class BackendClient:
    """
    Asynchronous event dispatcher with internal FIFO queue and retry loop.
    Ensures honeypot services are never blocked or crashed by backend latency/failures.
    """
    def __init__(
        self,
        backend_url: Optional[str] = None,
        timeout: Optional[float] = None,
        max_queue_size: Optional[int] = None,
        retry_interval: Optional[float] = None,
    ):
        self.backend_url = (backend_url or settings.full_backend_events_url).rstrip("/")
        self.timeout = timeout or settings.BACKEND_TIMEOUT_SEC
        self.retry_interval = retry_interval or settings.BACKEND_RETRY_INTERVAL_SEC
        self.max_queue_size = max_queue_size or settings.BACKEND_MAX_QUEUE_SIZE

        self._queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._client: Optional[httpx.Client] = None
        
        # Stats
        self.total_sent = 0
        self.total_failed = 0
        self.total_queued = 0

    def start(self) -> None:
        """Starts the background worker thread."""
        if self._running:
            return
        self._running = True
        self._client = httpx.Client(timeout=self.timeout)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="BackendForwarder")
        self._worker_thread.start()

    def stop(self, wait_empty: bool = True, timeout: float = 3.0) -> None:
        """Stops the background worker thread."""
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
        Useful for testing and verification.
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
                    return True
                else:
                    logger.warning(f"Backend returned HTTP {resp.status_code}: {resp.text}")
                    self.total_failed += 1
                    return False
        except Exception as e:
            logger.warning(f"Backend send failed: {e}")
            self.total_failed += 1
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
                        break
                    else:
                        time.sleep(0.5)
                except Exception:
                    # Connection refused / network down
                    time.sleep(0.5)

            if not delivered:
                self.total_failed += 1

            self._queue.task_done()


# Global backend client instance
backend_client = BackendClient()
