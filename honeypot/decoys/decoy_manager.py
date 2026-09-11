"""
Decoy Manager & Fake Resource Registry.
Maintains synthetic decoys (fake-admin, fake-users, fake-config, fake-backup, fake-credentials)
and triggers high-fidelity 'decoy_access' telemetry alerts whenever probed.
"""

from typing import Dict, Any, Optional, Tuple
from honeypot.common.telemetry import emit_event


class DecoyResource:
    def __init__(self, key: str, name: str, description: str, synthetic_data: Any, match_patterns: list):
        self.key = key
        self.name = name
        self.description = description
        self.synthetic_data = synthetic_data
        self.match_patterns = match_patterns


class DecoyManager:
    """
    Central repository of deception assets and decoys.
    """
    def __init__(self):
        self.decoys: Dict[str, DecoyResource] = {}
        self._initialize_decoys()

    def _initialize_decoys(self) -> None:
        # 1. fake-credentials
        self.decoys["fake-credentials"] = DecoyResource(
            key="fake-credentials",
            name="Decoy Credentials Store",
            description="Fake SSH keys, root passwords, and cloud tokens",
            synthetic_data="""# ==========================================
# CONFIDENTIAL - INTERNAL INFRASTRUCTURE CREDENTIALS
# DO NOT DISTRIBUTE OUTSIDE DEVOPS TEAM
# ==========================================
[master-database]
host = db-cluster-primary.corp.internal
port = 5432
user = corp_superadmin
pass = SuperSecretDBPass!2026#Prod
database = enterprise_core

[aws-infrastructure]
aws_access_key_id = AKIAFAKE99JHQEXAMPLE7
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_default_region = us-east-1

[root-ssh-key]
private_key = -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBA8U5b78FakeKeyDecoyDeceptionOnly789ABCDEF12345678==
-----END OPENSSH PRIVATE KEY-----
""",
            match_patterns=[
                "fake-credentials",
                "credentials",
                "id_rsa",
                "id_ed25519",
                ".aws/credentials",
                "passwords.txt",
                "secret",
            ]
        )

        # 2. fake-config
        self.decoys["fake-config"] = DecoyResource(
            key="fake-config",
            name="Decoy Production Configuration",
            description="Synthetic environment secrets, DB strings, and API keys",
            synthetic_data={
                "environment": "production",
                "app_name": "Kurukshetra-Enterprise-Platform",
                "version": "4.12.0",
                "database_url": "postgresql://admin:P@ssw0rd2026!@10.0.4.15:5432/corp_prod",
                "redis_url": "redis://:AuthToken994827@10.0.4.16:6379/0",
                "jwt_secret": "c3VwZXItc2VjcmV0LWtleS1kb25vdC1zaGFyZQ==",
                "payment_gateway_api_key": "sk_live_51M0FakeStripeKey99482DeceptionOnly",
                "debug_mode": False,
                "allowed_hosts": ["*.corp.internal", "localhost", "192.168.1.*"]
            },
            match_patterns=[
                "fake-config",
                "config",
                ".env",
                "settings.py",
                "appsettings.json",
                "web.config",
                "wp-config.php",
            ]
        )

        # 3. fake-users
        self.decoys["fake-users"] = DecoyResource(
            key="fake-users",
            name="Decoy User Database Dump",
            description="Synthetic employee directory with fake hashes",
            synthetic_data=[
                {"id": 1, "username": "admin", "email": "admin@enterprise-corp.internal", "role": "SuperAdmin", "status": "active", "password_hash": "$2b$12$e8FfakeHashAdmin7890123456789012345678901234567890"},
                {"id": 2, "username": "ciso", "email": "secops-lead@enterprise-corp.internal", "role": "SecurityAdmin", "status": "active", "password_hash": "$2b$12$f9GfakeHashSecOps8901234567890123456789012345678901"},
                {"id": 3, "username": "devops_lead", "email": "devops@enterprise-corp.internal", "role": "DevOps", "status": "active", "password_hash": "$2b$12$h1HfakeHashDevOps9012345678901234567890123456789012"},
                {"id": 4, "username": "finance_mgr", "email": "finance@enterprise-corp.internal", "role": "Finance", "status": "active", "password_hash": "$2b$12$j2JfakHashFinance0123456789012345678901234567890123"},
                {"id": 5, "username": "service_backup", "email": "svc_backup@enterprise-corp.internal", "role": "ServiceAccount", "status": "active", "api_token": "tok_svc_9928347101823901"}
            ],
            match_patterns=[
                "fake-users",
                "users",
                "employees",
                "user_list",
                "accounts",
                "passwd",
            ]
        )

        # 4. fake-backup
        self.decoys["fake-backup"] = DecoyResource(
            key="fake-backup",
            name="Decoy Database Backup",
            description="Synthetic SQL dump & archive metadata",
            synthetic_data="""-- Enterprise Core Database Backup (Decoy Telemetry)
-- Version: PostgreSQL 15.3 (Ubuntu 15.3-1.pgdg22.04+1)
-- Dumped by pg_dump version 15.3
-- Date: 2026-09-10 03:00:00 UTC

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

CREATE TABLE public.customers (
    id integer NOT NULL,
    company_name character varying(255),
    revenue_arr numeric(15,2),
    credit_card_vault_id character varying(128)
);

INSERT INTO public.customers VALUES (101, 'Global Defense Systems', 8450000.00, 'vault_tok_9918231');
INSERT INTO public.customers VALUES (102, 'Apex Financial Group', 14200000.00, 'vault_tok_8829104');
INSERT INTO public.customers VALUES (103, 'AeroSpace Dynamics Ltd', 6300000.00, 'vault_tok_7739182');
-- End of Backup Dump
""",
            match_patterns=[
                "fake-backup",
                "backup",
                "dump.sql",
                "database.bak",
                "corp_backup.tar.gz",
                "backup.zip",
            ]
        )

        # 5. fake-admin
        self.decoys["fake-admin"] = DecoyResource(
            key="fake-admin",
            name="Decoy Administrator Portal",
            description="Administrative control interface with fake high-privilege operations",
            synthetic_data={
                "portal": "Enterprise Root Management Console",
                "system_status": "ONLINE",
                "cluster_nodes": 6,
                "firewall_bypass_rule": "ENABLED",
                "audit_mode": "ENFORCED",
                "admin_actions": [
                    "flush_firewall_rules",
                    "dump_active_sessions",
                    "override_mfa",
                    "download_master_keys"
                ]
            },
            match_patterns=[
                "fake-admin",
                "admin",
                "administrator",
                "cpanel",
                "root_panel",
                "wp-admin",
            ]
        )

    def check_and_trigger(
        self,
        target_str: str,
        service: str,
        source_ip: str,
        session_id: str,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Tuple[str, Any]]:
        """
        Checks if a queried resource / URI / command targets a known decoy.
        If matched, emits a high-priority 'decoy_access' event and returns (decoy_key, synthetic_data).
        """
        lower_target = target_str.lower()
        for key, decoy in self.decoys.items():
            for pattern in decoy.match_patterns:
                if pattern in lower_target:
                    meta = {
                        "resource": key,
                        "resource_name": decoy.name,
                        "probed_target": target_str,
                        "decoy_type": "high_interaction_synthetic",
                    }
                    if extra_metadata:
                        meta.update(extra_metadata)

                    # Trigger telemetry event
                    emit_event(
                        service=service,
                        event_type="decoy_access",
                        event=f"Decoy accessed: {key} (probed: '{target_str}')",
                        source_ip=source_ip,
                        session_id=session_id,
                        metadata=meta,
                    )
                    return key, decoy.synthetic_data

        return None


# Global decoy manager instance
decoy_manager = DecoyManager()
