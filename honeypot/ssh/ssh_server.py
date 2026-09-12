"""
SSH Honeypot Server Implementation using Paramiko.
Provides realistic SSH handshake, authentication trap, and interactive deception shell.
Tracks sessions, records all attempts, and generates high-fidelity telemetry events.
"""

import os
import sys
import time
import socket
import threading
import logging
from typing import Optional, Dict, Any
import paramiko

# Silence verbose paramiko debug logs
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from honeypot.common.event_schema import generate_session_id
from honeypot.common.telemetry import emit_event
from honeypot.ssh.fake_shell import FakeShell
from honeypot.config.settings import settings


def generate_or_get_host_key(key_file: str = "logs/host_rsa.key") -> paramiko.RSAKey:
    """Loads existing host key or generates a new 2048-bit RSA key."""
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    if os.path.exists(key_file):
        try:
            return paramiko.RSAKey(filename=key_file)
        except Exception:
            pass

    # Generate new RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_file, "wb") as f:
        f.write(pem)

    return paramiko.RSAKey(filename=key_file)


class HoneypotSSHInterface(paramiko.ServerInterface):
    """
    Paramiko ServerInterface for intercepting auth and session requests.
    """
    def __init__(self, client_ip: str, session_id: str):
        self.client_ip = client_ip
        self.session_id = session_id
        self.authenticated_user: Optional[str] = None
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Intercepts password authentication attempt.
        Logs attempt and decides admission based on configured strategy.
        """
        auth_mode = settings.SSH_AUTH_MODE
        
        # Determine success
        if auth_mode == "accept_all":
            allowed = True
        else:
            # Common brute-force wordlist credentials allowed
            common_logins = {
                ("root", "root"), ("root", "toor"), ("root", "password"), ("root", "123456"),
                ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
                ("devops", "devops"), ("user", "user"), ("guest", "guest")
            }
            allowed = (username, password) in common_logins

        event_type = "auth_success" if allowed else "auth_failure"

        # Emit auth attempt telemetry (automatically analyzed by Threat Learning Engine)
        emit_event(
            service="ssh",
            event_type=event_type,
            event=f"SSH login attempt: user='{username}', password='{password}' ({'SUCCESS' if allowed else 'FAILED'})",
            source_ip=self.client_ip,
            session_id=self.session_id,
            metadata={
                "username": username,
                "password": password,
                "auth_method": "password",
                "auth_success": allowed,
            }
        )

        # Adaptive Counter-Deception ("Game Bajaye"): Slow down brute-forcers
        from honeypot.common.threat_learning_engine import threat_engine
        threat_engine.apply_tarpit(self.client_ip, self.session_id)

        if allowed:
            self.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Logs public key authentication attempt."""
        key_fingerprint = key.get_base64()
        emit_event(
            service="ssh",
            event_type="auth_attempt",
            event=f"SSH pubkey attempt: user='{username}', key_type={key.get_name()}",
            source_ip=self.client_ip,
            session_id=self.session_id,
            metadata={
                "username": username,
                "key_type": key.get_name(),
                "key_fingerprint": key_fingerprint[:24] + "...",
                "auth_method": "publickey",
                "auth_success": True,
            }
        )
        self.authenticated_user = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True


_active_ip_sessions: Dict[str, tuple] = {}
_session_lock = threading.Lock()

def get_or_create_ip_session(client_ip: str, prefix: str = "ATK-SSH", max_idle_sec: float = 300.0) -> str:
    """Reuses active session ID for repeated attempts from the same IP within 5 minutes."""
    now = time.time()
    with _session_lock:
        if client_ip in _active_ip_sessions:
            sess_id, last_active = _active_ip_sessions[client_ip]
            if now - last_active < max_idle_sec:
                _active_ip_sessions[client_ip] = (sess_id, now)
                return sess_id
        clean_ip = client_ip.replace(".", "-").replace(":", "-")
        new_sess_id = f"{prefix}-{clean_ip}"
        _active_ip_sessions[client_ip] = (new_sess_id, now)
        return new_sess_id


def handle_ssh_client(client_sock: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey) -> None:
    """
    Handles a single connected SSH client in a dedicated thread.
    """
    client_ip, client_port = client_addr
    session_id = get_or_create_ip_session(client_ip, prefix="ATK-SSH")

    # 1. Telemetry: New incoming connection
    emit_event(
        service="ssh",
        event_type="connection_opened",
        event=f"SSH connection from {client_ip}:{client_port}",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"client_port": client_port}
    )

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = settings.SSH_BANNER
        transport.add_server_key(host_key)

        server_interface = HoneypotSSHInterface(client_ip=client_ip, session_id=session_id)
        
        try:
            transport.start_server(server=server_interface)
        except (paramiko.SSHException, EOFError, OSError):
            return

        # Wait for authentication and channel open
        chan = transport.accept(20)
        if chan is None:
            return

        server_interface.event.wait(10)
        username = server_interface.authenticated_user or "root"

        # 2. Telemetry: Interactive session start
        emit_event(
            service="ssh",
            event_type="session_start",
            event=f"SSH session opened for user '{username}'",
            source_ip=client_ip,
            session_id=session_id,
            metadata={"username": username}
        )

        fake_shell = FakeShell(username=username, source_ip=client_ip, session_id=session_id)

        # Send welcome message & banner
        banner_msg = f"{settings.HONEYPOT_BANNER}\r\nWelcome to Enterprise Production Gateway (Authorized Access Only)\r\nLast login: Thu Sep 11 08:34:10 2026 from 10.0.4.5\r\n\r\n"
        chan.send(banner_msg)

        # Interactive shell loop
        buf = ""
        prompt = fake_shell.get_prompt()
        chan.send(prompt)

        while transport.is_active():
            # Read single characters for authentic terminal feel
            char = chan.recv(1)
            if not char:
                break

            # Handle Enter (\r or \n)
            if char in (b"\r", b"\n"):
                chan.send(b"\r\n")
                command = buf.strip()
                buf = ""

                if command:
                    output, should_exit = fake_shell.execute_command(command)
                    if output:
                        # Normalize newlines for terminal
                        formatted_out = output.replace("\r\n", "\n").replace("\n", "\r\n")
                        chan.send(formatted_out + "\r\n")

                    if should_exit:
                        break

                prompt = fake_shell.get_prompt()
                chan.send(prompt)

            # Handle Backspace (\x7f or \x08)
            elif char in (b"\x7f", b"\x08"):
                if len(buf) > 0:
                    buf = buf[:-1]
                    chan.send(b"\b \b")

            # Handle Ctrl+C (\x03)
            elif char == b"\x03":
                chan.send(b"^C\r\n")
                buf = ""
                prompt = fake_shell.get_prompt()
                chan.send(prompt)

            # Handle Ctrl+D (\x04)
            elif char == b"\x04":
                if not buf:
                    break

            # Normal printable characters
            elif ord(char) >= 32 and ord(char) <= 126:
                try:
                    c_str = char.decode("utf-8", errors="ignore")
                    buf += c_str
                    chan.send(char)  # Echo back character
                except Exception:
                    pass

    except Exception as e:
        pass
    finally:
        # Telemetry: Session End
        emit_event(
            service="ssh",
            event_type="session_end",
            event=f"SSH session closed for session {session_id}",
            source_ip=client_ip,
            session_id=session_id,
            metadata={"client_port": client_port}
        )
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


class SSHHoneypotServer:
    """
    Multi-threaded SSH Honeypot Server daemon.
    """
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host or settings.HONEYPOT_HOST
        self.port = port or settings.SSH_PORT
        self.host_key = generate_or_get_host_key()
        self.server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = False) -> None:
        """Starts the SSH honeypot listener."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(50)
        self._running = True

        print(f"[+] [SSH-HONEYPOT] Listening on {self.host}:{self.port} (Deception Active)")

        if blocking:
            self._serve_loop()
        else:
            self._thread = threading.Thread(target=self._serve_loop, daemon=True, name="SSHHoneypot")
            self._thread.start()

    def _serve_loop(self) -> None:
        while self._running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(
                    target=handle_ssh_client,
                    args=(client_sock, client_addr, self.host_key),
                    daemon=True
                )
                t.start()
            except Exception:
                if not self._running:
                    break

    def stop(self) -> None:
        """Gracefully shuts down SSH listener."""
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass


# Global server instance
ssh_honeypot = SSHHoneypotServer()
