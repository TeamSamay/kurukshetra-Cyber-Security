"""
Configuration module for the Cyber Deception Layer / Honeypot Server.
Loads environment variables from .env or config.env with robust defaults.
"""

import os
import socket
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_local_ip() -> str:
    """Best-effort discovery of local LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Does not actually establish connection, just routes socket
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class Settings(BaseSettings):
    # Network Bindings
    HONEYPOT_HOST: str = "0.0.0.0"
    HONEYPOT_TARGET_IP: str = get_local_ip()
    
    # Service Ports
    SSH_PORT: int = 2222
    WEB_PORT: int = 8080
    API_PORT: int = 8080
    
    # Backend Configuration (Member 3)
    BACKEND_URL: str = "http://localhost:8000"
    BACKEND_EVENT_ENDPOINT: str = "/api/events"
    BACKEND_RETRY_INTERVAL_SEC: float = 5.0
    BACKEND_MAX_QUEUE_SIZE: int = 5000
    BACKEND_TIMEOUT_SEC: float = 4.0
    
    # Local Storage
    LOG_DIR: str = "logs"
    EVENTS_JSONL_FILE: str = "logs/events.jsonl"
    
    # Honeypot Persona & Banners
    HONEYPOT_HOSTNAME: str = "corp-app-prod01"
    HONEYPOT_OS_VERSION: str = "Linux 5.15.0-88-generic #98-Ubuntu SMP x86_64"
    HONEYPOT_BANNER: str = "Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)"
    
    # SSH Configuration
    SSH_AUTH_MODE: str = "accept_all" # "accept_all" or "wordlist"
    SSH_BANNER: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    SSH_SESSION_TIMEOUT_SEC: int = 300
    
    # Web / API Deception
    WEB_TITLE: str = "Internal Corporate Enterprise Portal"
    FAKE_JWT_SECRET: str = "c3VwZXItc2VjcmV0LWtleS1kb25vdC1zaGFyZQ=="

    model_config = SettingsConfigDict(
        env_file=(".env", "config.env", "honeypot/config/config.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def full_backend_events_url(self) -> str:
        base = self.BACKEND_URL.rstrip("/")
        endpoint = self.BACKEND_EVENT_ENDPOINT.lstrip("/")
        return f"{base}/{endpoint}"


# Global settings instance
settings = Settings()
