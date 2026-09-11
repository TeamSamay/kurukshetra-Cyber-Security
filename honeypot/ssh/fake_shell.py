"""
Interactive Fake Shell for the SSH Honeypot.
Completely emulated - NO attacker commands are ever executed on the host OS.
Logs every keystroke and command, generates structured telemetry events,
and trips alarms on decoy resource inspection.
"""

import os
import re
import shlex
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Any, Optional

from honeypot.ssh.fake_fs import FakeFS
from honeypot.decoys.decoy_manager import decoy_manager
from honeypot.common.telemetry import emit_event
from honeypot.config.settings import settings


class FakeShell:
    """
    Simulated Linux interactive shell session.
    """
    def __init__(self, username: str, source_ip: str, session_id: str, fs: Optional[FakeFS] = None):
        self.username = username
        self.source_ip = source_ip
        self.session_id = session_id
        self.fs = fs or FakeFS()
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        if not self.fs.is_dir(self.cwd):
            self.cwd = "/"
            
        self.history: List[str] = []
        self.env: Dict[str, str] = {
            "USER": self.username,
            "LOGNAME": self.username,
            "HOME": self.cwd,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "HOSTNAME": settings.HONEYPOT_HOSTNAME,
            "LANG": "en_US.UTF-8",
        }

    def get_prompt(self) -> str:
        """Generates realistic Linux bash prompt."""
        symbol = "#" if self.username == "root" else "$"
        display_path = "~" if self.cwd == self.env.get("HOME") else self.cwd
        return f"{self.username}@{settings.HONEYPOT_HOSTNAME}:{display_path}{symbol} "

    def execute_command(self, raw_cmd: str) -> Tuple[str, bool]:
        """
        Interprets a command line string.
        Returns (output_string, should_exit).
        """
        cmd_str = raw_cmd.strip()
        if not cmd_str:
            return "", False

        # 1. Record command in history
        self.history.append(cmd_str)

        # 2. Check for Decoy triggers in command string
        decoy_manager.check_and_trigger(
            target_str=cmd_str,
            service="ssh",
            source_ip=self.source_ip,
            session_id=self.session_id,
            extra_metadata={"raw_command": cmd_str, "cwd": self.cwd, "user": self.username}
        )

        # 3. Emit standard structured 'command' telemetry event
        emit_event(
            service="ssh",
            event_type="command",
            event=cmd_str,
            source_ip=self.source_ip,
            session_id=self.session_id,
            metadata={
                "username": self.username,
                "cwd": self.cwd,
                "command_length": len(cmd_str),
            }
        )

        # 4. Handle multiple chained commands (e.g. cmd1; cmd2 or cmd1 && cmd2)
        if ";" in cmd_str:
            parts = [p.strip() for p in cmd_str.split(";") if p.strip()]
            all_out = []
            for part in parts:
                out, exit_flag = self._handle_single_command(part)
                if out:
                    all_out.append(out)
                if exit_flag:
                    return "\r\n".join(all_out), True
            return "\r\n".join(all_out), False

        return self._handle_single_command(cmd_str)

    def _handle_single_command(self, cmd_line: str) -> Tuple[str, bool]:
        try:
            tokens = shlex.split(cmd_line)
        except Exception:
            tokens = cmd_line.split()

        if not tokens:
            return "", False

        cmd = tokens[0].lower()
        args = tokens[1:]

        # Exit command
        if cmd in ("exit", "logout", "quit"):
            return "logout", True

        # whoami
        if cmd == "whoami":
            return self.username, False

        # id
        if cmd == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)", False
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),27(sudo)", False

        # uname
        if cmd == "uname":
            if "-a" in args or "--all" in args:
                return f"{settings.HONEYPOT_OS_VERSION}", False
            elif "-r" in args:
                return "5.15.0-88-generic", False
            return "Linux", False

        # hostname
        if cmd == "hostname":
            if "-i" in args or "-I" in args:
                return settings.HONEYPOT_TARGET_IP, False
            return settings.HONEYPOT_HOSTNAME, False

        # pwd
        if cmd == "pwd":
            return self.cwd, False

        # cd
        if cmd == "cd":
            target = args[0] if args else self.env.get("HOME", "/")
            if target == "~":
                target = self.env.get("HOME", "/")
            resolved = self.fs.normalize_path(self.cwd, target)
            if self.fs.is_dir(resolved):
                self.cwd = resolved
                return "", False
            else:
                return f"bash: cd: {target}: No such file or directory", False

        # ls
        if cmd in ("ls", "ll", "la", "dir"):
            target = self.cwd
            show_all = "-a" in args or "-la" in args or "-al" in args or "la" in cmd
            show_long = "-l" in args or "-la" in args or "-al" in args or "ll" in cmd

            # Check if an argument is a specific directory or file
            for arg in args:
                if not arg.startswith("-"):
                    target = self.fs.normalize_path(self.cwd, arg)
                    break

            if self.fs.is_file(target):
                return os.path.basename(target), False

            items = self.fs.list_dir(target)
            if items is None:
                return f"ls: cannot access '{target}': No such file or directory", False

            if show_long or cmd in ("ll", "la"):
                lines = [f"total {len(items) * 4}"]
                if show_all:
                    lines.append(f"drwxr-xr-x  {len(items)+2} {self.username} {self.username}  4096 Sep 11 10:00 .")
                    lines.append(f"drwxr-xr-x  4 root root  4096 Sep 11 09:30 ..")
                for name, is_d, size in items:
                    if not show_all and name.startswith("."):
                        continue
                    perms = "drwxr-xr-x" if is_d else "-rw-r--r--"
                    lines.append(f"{perms}  1 {self.username} {self.username} {size:5d} Sep 11 10:15 {name}")
                return "\r\n".join(lines), False
            else:
                visible = [name for name, is_d, _ in items if show_all or not name.startswith(".")]
                return "  ".join(visible), False

        # cat
        if cmd in ("cat", "more", "less", "head", "tail"):
            if not args:
                return "", False
            target_file = self.fs.normalize_path(self.cwd, args[-1])
            content = self.fs.read_file(target_file)
            if content is not None:
                # Trigger decoy alarm if targeted file matches decoy
                decoy_manager.check_and_trigger(
                    target_str=target_file,
                    service="ssh",
                    source_ip=self.source_ip,
                    session_id=self.session_id,
                    extra_metadata={"action": "read_file", "path": target_file}
                )
                return content.strip(), False
            else:
                return f"{cmd}: {args[-1]}: No such file or directory", False

        # sudo
        if cmd == "sudo":
            if not args:
                return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]", False
            sub_cmd = " ".join(args)
            # Emulate running with elevated privileges
            old_user = self.username
            self.username = "root"
            out, exit_flag = self._handle_single_command(sub_cmd)
            self.username = old_user
            return out, exit_flag

        # su
        if cmd == "su":
            target_user = args[0] if args else "root"
            self.username = target_user
            self.cwd = "/root" if target_user == "root" else f"/home/{target_user}"
            return f"Switched to user {target_user}.", False

        # ps
        if cmd == "ps":
            return """  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  412 ?        00:00:00 systemd-journal
  890 ?        00:00:01 sshd
 1204 ?        00:00:05 postgres
 1342 ?        00:00:12 uvicorn
 2810 pts/0    00:00:00 bash
 2845 pts/0    00:00:00 ps""", False

        # netstat / ss
        if cmd in ("netstat", "ss"):
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN     """, False

        # ip / ifconfig
        if cmd in ("ip", "ifconfig"):
            return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet {settings.HONEYPOT_TARGET_IP}/24 brd 192.168.1.255 scope global eth0""", False

        # env / printenv
        if cmd in ("env", "printenv"):
            lines = [f"{k}={v}" for k, v in self.env.items()]
            return "\r\n".join(lines), False

        # Handle Redirection (> and >>)
        if ">>" in cmd_line:
            left, right = cmd_line.split(">>", 1)
            target_file = self.fs.normalize_path(self.cwd, right.strip())
            out, exit_flag = self._handle_single_command(left.strip())
            self.fs.append_file(target_file, out + "\n")
            emit_event(
                service="ssh",
                event_type="file_modified",
                event=f"File appended: {target_file}",
                source_ip=self.source_ip,
                session_id=self.session_id,
                metadata={"action": "append", "path": target_file}
            )
            return "", exit_flag

        if ">" in cmd_line:
            left, right = cmd_line.split(">", 1)
            target_file = self.fs.normalize_path(self.cwd, right.strip())
            out, exit_flag = self._handle_single_command(left.strip())
            self.fs.write_file(target_file, out + "\n")
            emit_event(
                service="ssh",
                event_type="file_created",
                event=f"File written/modified: {target_file}",
                source_ip=self.source_ip,
                session_id=self.session_id,
                metadata={"action": "write", "path": target_file}
            )
            return "", exit_flag

        # history
        if cmd == "history":
            lines = [f"{i+1:5d}  {entry}" for i, entry in enumerate(self.history)]
            return "\r\n".join(lines), False

        # echo
        if cmd == "echo":
            msg = " ".join(args)
            if (msg.startswith('"') and msg.endswith('"')) or (msg.startswith("'") and msg.endswith("'")):
                msg = msg[1:-1]
            return msg, False

        # touch
        if cmd == "touch":
            if args:
                target = self.fs.normalize_path(self.cwd, args[0])
                self.fs.write_file(target, "")
                emit_event(
                    service="ssh",
                    event_type="file_created",
                    event=f"File created: {target}",
                    source_ip=self.source_ip,
                    session_id=self.session_id,
                    metadata={"action": "touch", "path": target}
                )
            return "", False

        # cp
        if cmd == "cp":
            if len(args) >= 2:
                src = self.fs.normalize_path(self.cwd, args[0])
                dst = self.fs.normalize_path(self.cwd, args[1])
                if self.fs.copy_file(src, dst):
                    return "", False
                return f"cp: cannot stat '{args[0]}': No such file or directory", False
            return "cp: missing destination file operand", False

        # mv
        if cmd == "mv":
            if len(args) >= 2:
                src = self.fs.normalize_path(self.cwd, args[0])
                dst = self.fs.normalize_path(self.cwd, args[1])
                if self.fs.move_file(src, dst):
                    return "", False
                return f"mv: cannot stat '{args[0]}': No such file or directory", False
            return "mv: missing destination file operand", False

        # rm
        if cmd == "rm":
            if args:
                target_arg = args[-1]
                target = self.fs.normalize_path(self.cwd, target_arg)
                deleted = self.fs.delete_file(target)
                if deleted:
                    emit_event(
                        service="ssh",
                        event_type="file_deleted",
                        event=f"File deleted: {target}",
                        source_ip=self.source_ip,
                        session_id=self.session_id,
                        metadata={"action": "rm", "path": target}
                    )
                    return "", False
                return f"rm: cannot remove '{target_arg}': No such file or directory", False
            return "rm: missing operand", False

        # mkdir
        if cmd == "mkdir":
            if args:
                target = self.fs.normalize_path(self.cwd, args[0])
                self.fs.directories.add(target)
            return "", False

        # nano / vi / vim (Simulated editor)
        if cmd in ("nano", "vi", "vim"):
            if args:
                target = self.fs.normalize_path(self.cwd, args[0])
                if not self.fs.is_file(target):
                    self.fs.write_file(target, "# Modified via editor\n")
                return f"[{cmd}: file '{args[0]}' opened and saved in honeypot memory]", False
            return f"[{cmd}: usage {cmd} <filename>]", False

        # chmod / chown
        if cmd in ("chmod", "chown"):
            return "", False

        # curl / wget / download attempts
        if cmd in ("curl", "wget", "nc", "nmap"):
            return f"[+] {cmd}: operation completed (simulated).", False

        # help
        if cmd == "help":
            return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.", False

        # clear
        if cmd == "clear":
            return "\033[2J\033[H", False

        # Default fallback for unknown commands
        return f"bash: {cmd}: command not found", False
