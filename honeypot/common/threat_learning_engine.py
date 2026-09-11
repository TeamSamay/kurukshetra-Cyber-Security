"""
Attacker Technique Learning & Behavioral Threat Analysis Engine ("Game Bajaye").
Analyzes incoming attacks in real time to:
  1. Detect tools & exploit frameworks (Nmap, Hydra, Sqlmap, Metasploit, curl, bots).
  2. Map commands and payloads to MITRE ATT&CK Tactics & Techniques.
  3. Profile Attacker DNA (Skill Level, Intent, Attack Phases, Risk Score).
  4. Deploy Adaptive Counter-Deception (Tarpit latency, honeytokens, decoy traps).
"""

import re
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class AttackerProfile:
    """Maintains behavioral state and learned techniques for a unique attacker (IP/Session)."""
    def __init__(self, identifier: str, source_ip: str):
        self.identifier = identifier
        self.source_ip = source_ip
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_seen = datetime.now(timezone.utc).isoformat()
        self.total_interactions = 0
        self.detected_tools: set = set()
        self.mitre_techniques: Dict[str, Dict[str, str]] = {}  # {tech_id: {name, tactic}}
        self.attack_phases: set = set()
        self.failed_auth_count = 0
        self.command_history: List[str] = []
        self.probed_paths: List[str] = []
        self.accessed_decoys: List[str] = []
        self.risk_score = 10
        self.skill_level = "NOVICE"  # NOVICE, AUTOMATED_BOT, INTERMEDIATE, ADVANCED_APT
        self.intent = "RECONNAISSANCE"
        self.tarpit_delay_sec = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_interactions": self.total_interactions,
            "risk_score": min(100, self.risk_score),
            "skill_level": self.skill_level,
            "intent": self.intent,
            "detected_tools": list(self.detected_tools),
            "attack_phases": list(self.attack_phases),
            "mitre_techniques": [
                {"technique_id": k, "name": v["name"], "tactic": v["tactic"]}
                for k, v in self.mitre_techniques.items()
            ],
            "accessed_decoys_count": len(self.accessed_decoys),
            "tarpit_penalty_sec": round(self.tarpit_delay_sec, 2),
        }


class ThreatLearningEngine:
    """
    Core AI & Heuristic Intelligence Engine that learns attacker patterns,
    classifies MITRE techniques, and powers adaptive deception traps.
    """
    def __init__(self):
        self.profiles: Dict[str, AttackerProfile] = {}
        self._init_rules()

    def _init_rules(self):
        # 1. User-Agent / Tool Signatures
        self.tool_signatures = [
            (re.compile(r"sqlmap", re.I), "Sqlmap Automated SQL Injection Tool", "T1190"),
            (re.compile(r"nmap|nmap scripting engine", re.I), "Nmap Network Scanner", "T1046"),
            (re.compile(r"nikto", re.I), "Nikto Web Vulnerability Scanner", "T1595"),
            (re.compile(r"hydra", re.I), "THC-Hydra Brute Force Tool", "T1110"),
            (re.compile(r"gobuster|dirb|dirbuster|ffuf", re.I), "Directory & Web Fuzzer", "T1083"),
            (re.compile(r"metasploit|meterpreter", re.I), "Metasploit Exploitation Framework", "T1203"),
            (re.compile(r"burpcollaborator|burpsuite", re.I), "Burp Suite Professional Scanner", "T1595"),
            (re.compile(r"masscan", re.I), "Masscan High-Speed Port Scanner", "T1046"),
            (re.compile(r"python-requests|aiohttp|httpx|urllib|curl|wget", re.I), "Automated CLI Script / Bot", "T1059"),
        ]

        # 2. Command / Payload Patterns -> MITRE TTPs
        self.mitre_rules = [
            # Discovery & Recon
            (re.compile(r"whoami|id\b|w\b|who\b", re.I), "T1033", "System Owner/User Discovery", "Discovery", 15),
            (re.compile(r"uname|cat\s+/etc/\*release|hostname", re.I), "T1082", "System Information Discovery", "Discovery", 15),
            (re.compile(r"ip\s+a|ifconfig|route|netstat|ss\b", re.I), "T1016", "System Network Configuration Discovery", "Discovery", 20),
            (re.compile(r"cat\s+/etc/passwd|getent\s+passwd", re.I), "T1087.001", "Local Account Discovery", "Discovery", 25),
            (re.compile(r"ps\s+-ef|ps\s+aux|top\b", re.I), "T1057", "Process Discovery", "Discovery", 15),
            (re.compile(r"ls\s+-[a-zA-Z]*|find\s+/", re.I), "T1083", "File and Directory Discovery", "Discovery", 10),
            
            # Credential Access
            (re.compile(r"fake-credentials|id_rsa|id_ed25519|\.aws|credentials\.txt|passwords\.txt|shadow", re.I), "T1552.001", "Credentials in Files", "Credential Access", 30),
            (re.compile(r"cat\s+/etc/shadow|unshadow", re.I), "T1003.008", "OS Credential Dumping: /etc/shadow", "Credential Access", 35),
            
            # Privilege Escalation & Execution
            (re.compile(r"sudo\s+|su\s+|chmod\s+\+s", re.I), "T1548.001", "Abuse Elevation Control Mechanism: Sudo", "Privilege Escalation", 25),
            (re.compile(r"/bin/bash|/bin/sh|python\s+-c|perl\s+-e", re.I), "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", 20),
            (re.compile(r"curl\s+http|wget\s+http|nc\s+-e|bash\s+-i", re.I), "T1105", "Ingress Tool Transfer / Reverse Shell", "Command and Control", 30),
            
            # Web & Injection Attacks
            (re.compile(r"union\s+select|' OR '1'='1|--|; DROP TABLE", re.I), "T1190", "Exploit Public-Facing Application: SQL Injection", "Initial Access", 35),
            (re.compile(r"\.\./\.\./|/etc/passwd|/windows/win\.ini", re.I), "T1083", "Path Traversal & Local File Inclusion", "Initial Access", 25),
            (re.compile(r"<script>|javascript:|alert\(|onerror=", re.I), "T1189", "Drive-by Compromise: Cross-Site Scripting", "Initial Access", 20),
        ]

    def get_or_create_profile(self, source_ip: str, session_id: Optional[str] = None) -> AttackerProfile:
        key = session_id or source_ip
        if key not in self.profiles:
            self.profiles[key] = AttackerProfile(identifier=key, source_ip=source_ip)
        return self.profiles[key]

    def analyze_interaction(
        self,
        service: str,
        event_type: str,
        payload: str,
        source_ip: str,
        session_id: str,
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyzes a single attack event, learns the attacker's technique,
        updates the profile DNA, and generates enriched threat intelligence.
        """
        profile = self.get_or_create_profile(source_ip, session_id)
        profile.total_interactions += 1
        profile.last_seen = datetime.now(timezone.utc).isoformat()
        meta = raw_metadata or {}

        detected_mitre: List[Dict[str, str]] = []
        detected_tools_this_event: List[str] = []
        risk_increase = 0

        # 1. Inspect User-Agent & Headers for Tools
        user_agent = meta.get("user_agent", "")
        for sig_re, tool_name, tech_id in self.tool_signatures:
            if sig_re.search(user_agent) or sig_re.search(payload):
                profile.detected_tools.add(tool_name)
                detected_tools_this_event.append(tool_name)
                risk_increase += 20
                if tech_id not in profile.mitre_techniques:
                    profile.mitre_techniques[tech_id] = {
                        "name": tool_name,
                        "tactic": "Reconnaissance / Initial Access"
                    }

        # 2. Inspect Payload & Commands against MITRE Rules
        for pattern, tech_id, name, tactic, score_val in self.mitre_rules:
            if pattern.search(payload):
                tech_data = {"name": name, "tactic": tactic}
                profile.mitre_techniques[tech_id] = tech_data
                detected_mitre.append({"technique_id": tech_id, "name": name, "tactic": tactic})
                profile.attack_phases.add(tactic.upper())
                risk_increase += score_val

        # 3. Track Specific Event Types
        if event_type == "auth_attempt":
            if not meta.get("auth_success", False):
                profile.failed_auth_count += 1
                if profile.failed_auth_count >= 3:
                    profile.detected_tools.add("Credential Spraying / Brute Force Engine")
                    profile.mitre_techniques["T1110"] = {
                        "name": "Brute Force: Password Guessing",
                        "tactic": "Credential Access"
                    }
                    profile.attack_phases.add("CREDENTIAL_ACCESS")
                    risk_increase += 25
        elif event_type == "decoy_access":
            decoy_key = meta.get("resource", payload)
            profile.accessed_decoys.append(decoy_key)
            profile.attack_phases.add("COLLECTION")
            risk_increase += 35
            profile.mitre_techniques["T1552"] = {
                "name": "Unsecured Credentials: Decoy Honeytoken Accessed",
                "tactic": "Credential Access"
            }
        elif event_type == "command":
            profile.command_history.append(payload)

        # 4. Update Profile Risk & Skill Assessment
        profile.risk_score = min(100, profile.risk_score + risk_increase)

        # Determine Skill Level & Intent
        if len(profile.detected_tools) >= 2 or profile.risk_score >= 80:
            profile.skill_level = "ADVANCED_PENTESTER_OR_APT"
        elif len(profile.mitre_techniques) >= 3 or profile.risk_score >= 50:
            profile.skill_level = "INTERMEDIATE_ATTACKER"
        elif "Automated CLI Script / Bot" in profile.detected_tools or profile.failed_auth_count >= 5:
            profile.skill_level = "AUTOMATED_SCAN_BOT"
        else:
            profile.skill_level = "NOVICE_RECON"

        if "COLLECTION" in profile.attack_phases or "CREDENTIAL_ACCESS" in profile.attack_phases:
            profile.intent = "DATA_EXFILTRATION_AND_CREDENTIAL_THEFT"
        elif "PRIVILEGE_ESCALATION" in profile.attack_phases or "EXECUTION" in profile.attack_phases:
            profile.intent = "SYSTEM_TAKEOVER_AND_PERSISTENCE"
        else:
            profile.intent = "SURFACE_RECONNAISSANCE"

        # 5. Adaptive Counter-Deception ("Game Bajaye")
        # Increase tarpit penalty if attacker is aggressively spraying
        if profile.failed_auth_count > 2 or profile.total_interactions > 10:
            profile.tarpit_delay_sec = min(5.0, 0.5 * (profile.failed_auth_count + (profile.total_interactions // 5)))

        # Return rich analysis result to attach to telemetry event
        return {
            "threat_risk_score": profile.risk_score,
            "attacker_skill_level": profile.skill_level,
            "attacker_intent": profile.intent,
            "detected_tools": list(profile.detected_tools),
            "attack_phases": list(profile.attack_phases),
            "mitre_techniques": [
                {"technique_id": k, "name": v["name"], "tactic": v["tactic"]}
                for k, v in profile.mitre_techniques.items()
            ],
            "tarpit_delay_applied": round(profile.tarpit_delay_sec, 2),
            "forensic_summary": (
                f"Attacker from {source_ip} identified as '{profile.skill_level}'. "
                f"Objective: '{profile.intent}'. Tools: {', '.join(profile.detected_tools) or 'Manual'}. "
                f"TTPs mapped: {len(profile.mitre_techniques)} MITRE techniques."
            )
        }

    def apply_tarpit(self, source_ip: str, session_id: Optional[str] = None) -> float:
        """Applies adaptive deception tarpit delay to exhaust attacker automation."""
        profile = self.get_or_create_profile(source_ip, session_id)
        delay = profile.tarpit_delay_sec
        if delay > 0:
            time.sleep(delay)
        return delay

    def get_all_attacker_dossiers(self) -> List[Dict[str, Any]]:
        """Returns aggregated threat intelligence dossiers for all tracked attackers."""
        return [p.to_dict() for p in self.profiles.values()]


# Global threat learning engine instance
threat_engine = ThreatLearningEngine()
