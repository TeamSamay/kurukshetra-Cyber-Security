"""
Virtual In-Memory Linux File System for the SSH Honeypot.
Completely isolated from the host OS. Contains synthetic decoy files and realistic Linux directories.
"""

from typing import Dict, List, Optional, Tuple
import os

class FakeFS:
    """
    Simulated Linux filesystem.
    """
    def __init__(self):
        self.files: Dict[str, str] = {}
        self.directories: set = set()
        self._populate_filesystem()

    def _populate_filesystem(self) -> None:
        # Core directory hierarchy
        dirs = [
            "/", "/root", "/root/.ssh", "/root/.aws",
            "/home", "/home/admin", "/home/admin/.ssh", "/home/admin/.aws",
            "/etc", "/etc/ssh", "/etc/cron.d", "/etc/systemd",
            "/var", "/var/log", "/var/www", "/var/www/html",
            "/opt", "/opt/backups", "/opt/app",
            "/tmp", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/local/bin"
        ]
        for d in dirs:
            self.directories.add(d)

        # 1. Root directory files & Decoys
        self.files["/root/fake-credentials.txt"] = """# INFRASTRUCTURE ROOT CREDENTIALS - CONFIDENTIAL
DB_HOST=10.0.4.15
DB_USER=superadmin
DB_PASS=SuperSecretDBPass!2026#Prod
AWS_ACCESS_KEY_ID=AKIAFAKE99JHQEXAMPLE7
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
INTERNAL_VPN_KEY=vpn-auth-master-prod-2026
"""

        self.files["/root/.bash_history"] = """cd /opt/app
git pull origin main
systemctl restart corporate-portal
cat /root/fake-credentials.txt
pg_dump -U postgres enterprise_core > /opt/backups/fake-backup.sql
curl -s http://169.254.169.254/latest/meta-data/
"""

        self.files["/root/.ssh/authorized_keys"] = (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEkeyDevOpsLead2026 devops@corp.internal"
        )
        self.files["/root/.ssh/id_rsa"] = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACBA8U5b78FakeKeyDecoyDeceptionOnly789ABCDEF12345678==\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )

        # 2. System files (/etc)
        self.files["/etc/passwd"] = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
admin:x:1000:1000:Enterprise Admin,,,:/home/admin:/bin/bash
devops:x:1001:1001:DevOps Lead,,,:/home/devops:/bin/bash
svc_backup:x:1002:1002:Backup Service Account,,,:/opt/backups:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
"""

        self.files["/etc/shadow"] = """root:$6$rounds=4096$FkSalt$fakeHashRootPassword1234567890abcdefghijklmnopqrstuvwxyz:19600:0:99999:7:::
admin:$6$rounds=4096$AkSalt$fakeHashAdminPassword1234567890abcdefghijklmnopqrstuvwxyz:19600:0:99999:7:::
devops:$6$rounds=4096$DkSalt$fakeHashDevOpsPassword1234567890abcdefghijklmnopqrstuvwxyz:19600:0:99999:7:::
"""

        self.files["/etc/hostname"] = "corp-app-prod01\n"
        self.files["/etc/hosts"] = """127.0.0.1 localhost
127.0.1.1 corp-app-prod01
10.0.4.15 db-master.corp.internal db-master
10.0.4.16 redis-cache.corp.internal redis-cache
10.0.4.20 auth-gateway.corp.internal auth-gateway
"""

        self.files["/etc/os-release"] = """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
"""

        self.files["/etc/issue"] = "Ubuntu 22.04.3 LTS \\n \\l\n"

        # 3. Web & Config files (/var/www/html)
        self.files["/var/www/html/fake-config.php"] = """<?php
// Production Database Credentials Decoy
define('DB_SERVER', '10.0.4.15:5432');
define('DB_USERNAME', 'corp_admin');
define('DB_PASSWORD', 'P@ssw0rd2026!ProdDbSecure');
define('DB_DATABASE', 'enterprise_portal_prod');
define('API_SECRET_KEY', 'sec_tok_991823719284');
?>"""

        self.files["/var/www/html/.env"] = """APP_NAME=EnterprisePortal
APP_ENV=production
APP_KEY=base64:c3VwZXItc2VjcmV0LWtleS1kb25vdC1zaGFyZQ==
APP_DEBUG=false
APP_URL=http://internal-portal.corp

DB_CONNECTION=pgsql
DB_HOST=10.0.4.15
DB_PORT=5432
DB_DATABASE=enterprise_portal_prod
DB_USERNAME=corp_admin
DB_PASSWORD=P@ssw0rd2026!ProdDbSecure

AWS_ACCESS_KEY_ID=AKIAFAKE99JHQEXAMPLE7
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

        # 4. Decoy Backups (/opt/backups)
        self.files["/opt/backups/fake-backup.sql"] = """-- PostgreSQL Enterprise Backup Dump
-- Decoy Data Asset
CREATE TABLE internal_accounts (id SERIAL PRIMARY KEY, username VARCHAR(50), secret_token VARCHAR(255));
INSERT INTO internal_accounts VALUES (1, 'ciso_admin', 'sec_ciso_992182938');
INSERT INTO internal_accounts VALUES (2, 'finance_lead', 'sec_fin_882910293');
INSERT INTO internal_accounts VALUES (3, 'ceo_exec', 'sec_exec_772019283');
"""
        self.files["/opt/backups/fake-users.csv"] = """id,username,email,role,access_level
101,admin,admin@corp.internal,SuperAdmin,5
102,secops,secops@corp.internal,Security,4
103,devops,devops@corp.internal,DevOps,4
104,finance,finance@corp.internal,Finance,3
"""

        # 5. User home files (/home/admin)
        self.files["/home/admin/project_notes.txt"] = """TODO for next deployment:
- Rotate DB passwords on 10.0.4.15
- Clean up old backup files in /opt/backups
- Verify AWS IAM roles before migration
- Disable SSH password auth for root
"""
        self.files["/home/admin/.aws/credentials"] = """[default]
aws_access_key_id = AKIAFAKE99JHQEXAMPLE7
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

    def normalize_path(self, current_dir: str, target: str) -> str:
        """Resolves relative and absolute Linux paths safely."""
        if not target or target == ".":
            return current_dir
        if target.startswith("/"):
            resolved = os.path.normpath(target)
        else:
            resolved = os.path.normcase(os.path.normpath(os.path.join(current_dir, target)))
        
        # Ensure POSIX style forward slashes
        clean = resolved.replace("\\", "/")
        if not clean.startswith("/"):
            clean = "/" + clean
        return clean

    def is_dir(self, path: str) -> bool:
        return path in self.directories

    def is_file(self, path: str) -> bool:
        return path in self.files

    def list_dir(self, path: str) -> Optional[List[Tuple[str, bool, int]]]:
        """Returns list of (name, is_directory, size) inside the directory."""
        if not self.is_dir(path):
            return None
        
        items = []
        clean_path = path.rstrip("/")
        prefix = clean_path + "/" if clean_path else "/"

        # Subdirectories
        for d in self.directories:
            if d == path or d == "/":
                continue
            parent = os.path.dirname(d).replace("\\", "/")
            if parent == clean_path or (clean_path == "" and parent == "/"):
                items.append((os.path.basename(d), True, 4096))

        # Files
        for f, content in self.files.items():
            parent = os.path.dirname(f).replace("\\", "/")
            if parent == clean_path or (clean_path == "" and parent == "/"):
                items.append((os.path.basename(f), False, len(content)))

        return sorted(items, key=lambda x: (not x[1], x[0]))

    def read_file(self, path: str) -> Optional[str]:
        return self.files.get(path)

    def write_file(self, path: str, content: str) -> None:
        """Allows attacker to create or overwrite fake file in honeypot memory (not host)."""
        self.files[path] = content
        parent = os.path.dirname(path).replace("\\", "/")
        if parent:
            self.directories.add(parent)

    def append_file(self, path: str, content: str) -> None:
        """Allows attacker to append to a fake file."""
        existing = self.files.get(path, "")
        if existing and not existing.endswith("\n"):
            existing += "\n"
        self.files[path] = existing + content
        parent = os.path.dirname(path).replace("\\", "/")
        if parent:
            self.directories.add(parent)

    def delete_file(self, path: str) -> bool:
        """Deletes file from virtual filesystem."""
        if path in self.files:
            del self.files[path]
            return True
        return False

    def copy_file(self, src: str, dst: str) -> bool:
        if src in self.files:
            self.write_file(dst, self.files[src])
            return True
        return False

    def move_file(self, src: str, dst: str) -> bool:
        if src in self.files:
            content = self.files[src]
            del self.files[src]
            self.write_file(dst, content)
            return True
        return False
