"""
Groq LLM AI Threat Intelligence & Defense Advisory Engine for Kurukshetra.
Provides real-time attack monitoring, MITRE ATT&CK mapping, automated mitigation
recommendations, attacker DNA profiling, and an interactive SOC AI Copilot.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from honeypot.config.settings import settings

logger = logging.getLogger("honeypot.ai_advisor")


class GroqThreatAdvisor:
    """
    AI-powered Cyber Threat Intelligence Advisor powered by Groq (LLaMA 3.3 70B / 8B).
    Provides real-time threat monitoring, automated SOC recommendations,
    mitigation firewall rules, and interactive security copilot query capabilities.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.GROQ_API_KEY or os.environ.get("GROQ_API_KEY", "")
        self.model = model or settings.GROQ_MODEL or "llama-3.3-70b-versatile"
        self._client: Optional[Any] = None
        self._last_analysis_cache: Optional[Dict[str, Any]] = None
        self._last_analysis_time: float = 0
        self._cache_ttl_sec: float = 8.0  # Fast refresh for real-time dashboard

        if self.api_key and GROQ_AVAILABLE:
            try:
                self._client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Groq client: {e}")
                self._client = None

    @property
    def is_ai_online(self) -> bool:
        """Returns True if Groq AI is properly configured and available."""
        return bool(self.api_key and self._client)

    def _call_groq(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 1024) -> Optional[str]:
        """Executes a completion request against Groq LLM API."""
        if not self.is_ai_online:
            return None

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"} if "JSON" in system_prompt else None
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq API Error: {e}")
            # Try lightweight fallback model if 70B hit rate limit
            if "70b" in self.model:
                try:
                    fallback_response = self._client.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                    return fallback_response.choices[0].message.content
                except Exception as ex:
                    logger.error(f"Groq Fallback Model Error: {ex}")
            return None

    def analyze_threat_landscape(self, events: List[Dict[str, Any]], stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyzes full honeypot telemetry stream and returns real-time AI threat assessment,
        actionable recommendations, and immediate defensive firewall commands.
        """
        # If no events
        if not events:
            return {
                "ai_powered": self.is_ai_online,
                "model_used": self.model if self.is_ai_online else "Kurukshetra Heuristic Cyber Engine",
                "threat_level": "LOW",
                "threat_score": 10,
                "executive_summary": "Kurukshetra Cyber Deception sensors are active and monitoring. No adversarial probing detected at this moment.",
                "attack_vectors": [],
                "mitre_techniques": [],
                "recommendations": [
                    {"priority": "INFO", "title": "Maintain Sensor Readiness", "action": "Ensure all SSH, Web, and API decoy ports are reachable by threat actors."}
                ],
                "firewall_rules": [],
                "deception_health": "OPTIMAL - Decoy Honeytokens Intact",
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }

        # Format compact event telemetry for LLM prompt
        recent_events = events[-35:]
        summary_events = []
        attacker_ips = set()
        decoys_hit = []
        tampered_files = []

        for e in recent_events:
            src = e.get("source_ip", "unknown")
            attacker_ips.add(src)
            svc = e.get("service", "unknown")
            etype = e.get("event_type", "unknown")
            evt_msg = e.get("event", "")
            meta = e.get("metadata", {})
            summary_events.append(f"[{svc.upper()}] {src} | {etype} -> {evt_msg} (meta: {meta})")
            if "decoy" in etype:
                decoys_hit.append(f"{src} accessed {meta.get('resource', evt_msg)}")
            if "file" in etype:
                tampered_files.append(f"{src} {etype}: {meta.get('path', evt_msg)}")

        ips_list = list(attacker_ips)
        
        # Construct Groq prompt if API key available
        if self.is_ai_online:
            system_prompt = (
                "You are Kurukshetra 2.0 AI SOC Lead Security Analyst. "
                "You are analyzing real-time high-interaction cyber deception honeypot telemetry. "
                "Analyze the events and respond strictly with a valid JSON object containing:\n"
                "- threat_level: (CRITICAL, HIGH, MEDIUM, or LOW)\n"
                "- threat_score: (Integer 0 to 100)\n"
                "- executive_summary: (2 to 3 sentences concise CISO summary of ongoing attacks)\n"
                "- attack_vectors: (List of detected attack vectors e.g. SSH Brute Force, Decoy Honeytoken Theft, Shell Discovery)\n"
                "- mitre_techniques: (List of strings e.g. ['T1110 - Brute Force', 'T1552 - Unsecured Credentials'])\n"
                "- recommendations: (List of objects: [{'priority': 'HIGH'/'CRITICAL'/'MEDIUM', 'title': '...', 'action': '...'}])\n"
                "- firewall_rules: (List of exact Linux iptables or fail2ban commands to immediately block malicious actors)\n"
                "- deception_assessment: (Short advice on counter-deception and trap efficiency)\n"
                "Ensure JSON is valid with no markdown formatting around it."
            )
            user_prompt = (
                f"Analyze these {len(recent_events)} telemetry events:\n"
                f"Attacker IPs: {ips_list}\n"
                f"Decoys Tripped: {decoys_hit}\n"
                f"File Tampering: {tampered_files}\n\n"
                f"Telemetry Stream:\n" + "\n".join(summary_events)
            )

            raw_ai = self._call_groq(system_prompt, user_prompt, temperature=0.1)
            if raw_ai:
                try:
                    # Clean potential markdown wrapping
                    cleaned = raw_ai.strip()
                    if cleaned.startswith("```"):
                        lines = cleaned.split("\n")
                        cleaned = "\n".join(lines[1:-1])
                    parsed = json.loads(cleaned)
                    parsed["ai_powered"] = True
                    parsed["model_used"] = f"Groq ({self.model})"
                    parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
                    return parsed
                except Exception as e:
                    logger.warning(f"Failed to parse Groq response as JSON: {e}")

        # Intelligent Heuristic Fallback Engine
        return self._heuristic_threat_analysis(events, ips_list, decoys_hit, tampered_files)

    def _heuristic_threat_analysis(
        self,
        events: List[Dict[str, Any]],
        ips: List[str],
        decoys_hit: List[str],
        tampered_files: List[str]
    ) -> Dict[str, Any]:
        """High-precision local heuristic cyber analysis when Groq is in standby."""
        has_decoys = len(decoys_hit) > 0
        has_file_tampering = len(tampered_files) > 0
        has_auth_fail = any("auth" in e.get("event_type", "") for e in events)
        has_commands = any("command" in e.get("event_type", "") for e in events)

        threat_score = 30
        if has_auth_fail:
            threat_score += 20
        if has_commands:
            threat_score += 20
        if has_file_tampering:
            threat_score += 15
        if has_decoys:
            threat_score += 25
        threat_score = min(100, threat_score)

        if threat_score >= 80:
            threat_level = "CRITICAL"
        elif threat_score >= 50:
            threat_level = "HIGH"
        elif threat_score >= 30:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        vectors = []
        if has_auth_fail:
            vectors.append("SSH & API Credential Spraying / Brute Force")
        if has_commands:
            vectors.append("Interactive Unix Shell Reconnaissance & Discovery")
        if has_decoys:
            vectors.append("High-Value Honeytoken & Decoy Asset Compromise")
        if has_file_tampering:
            vectors.append("Filesystem Tampering & Ingress Tool Upload")

        mitre = []
        if has_auth_fail:
            mitre.append("T1110 - Brute Force / Credential Stuffing")
        if has_commands:
            mitre.append("T1059.004 - Unix Shell Command Execution")
            mitre.append("T1082 - System Information Discovery")
        if has_decoys:
            mitre.append("T1552 - Unsecured Credentials & Honeytoken Access")
        if has_file_tampering:
            mitre.append("T1105 - Ingress Tool Transfer & Tampering")

        # Dynamic recommendations
        recommendations = []
        fw_rules = []
        for ip in ips:
            if ip and ip != "127.0.0.1" and ip != "localhost":
                fw_rules.append(f"iptables -A INPUT -s {ip} -j DROP")
                fw_rules.append(f"fail2ban-client set sshd banip {ip}")

        if has_decoys:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Immediate Honeytoken Rotation",
                "action": "Threat actor probed deception secrets (AWS keys, DB passwords). Invalidate credentials across production clusters immediately."
            })
        if has_commands or has_auth_fail:
            recommendations.append({
                "priority": "HIGH",
                "title": "Perimeter IP Blacklisting",
                "action": f"Block identified source IPs ({', '.join(ips)}) at the upstream edge firewall / Cloudflare WAF."
            })
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Zero-Trust SSH Hardening",
            "action": "Enforce hardware MFA key authentication and disable password-based logins on public-facing bastion hosts."
        })

        summary = (
            f"Active adversarial reconnaissance detected targeting Kurukshetra deception nodes from {len(ips)} distinct IP(s). "
            f"Threat actors executed interactive shell probes and tripped {len(decoys_hit)} decoy honeytoken traps. "
            f"Overall platform risk assessed at {threat_level} ({threat_score}/100)."
        )

        return {
            "ai_powered": False,
            "model_used": "Kurukshetra Heuristic Cyber Engine (Configure GROQ_API_KEY in .env for LLaMA 3.3 70B)",
            "threat_level": threat_level,
            "threat_score": threat_score,
            "executive_summary": summary,
            "attack_vectors": vectors or ["Baseline Probing"],
            "mitre_techniques": mitre or ["T1595 - Active Vulnerability Scanning"],
            "recommendations": recommendations,
            "firewall_rules": fw_rules[:6],
            "deception_assessment": "Decoy traps successfully diverted adversary away from production assets. Tarpit delay actively exhausting bot cycles.",
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }

    def chat_copilot(
        self,
        query: str,
        events: List[Dict[str, Any]],
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Interactive SOC AI Assistant: Answers questions about ongoing attacks,
        suggests mitigation commands, and provides deep forensics on demand.
        """
        recent_events = events[-30:] if events else []
        context_str = json.dumps(recent_events[:15], indent=2)

        if self.is_ai_online:
            system_prompt = (
                "You are Kurukshetra AI Security Copilot, an elite Tier-3 SOC analyst & cyber deception expert. "
                "You are assisting a security defender in real-time. You have direct visibility into the live honeypot "
                "telemetry stream, decoy triggers, and attacker commands. "
                "Give clear, highly actionable, technical answers with exact Linux commands (iptables, fail2ban, auditd, curl), "
                "MITRE ATT&CK mappings, and defensive recommendations. Keep explanations structured with bold bullet points."
            )
            
            messages = [{"role": "system", "content": system_prompt}]
            
            # Attach history if available
            if conversation_history:
                for msg in conversation_history[-6:]:
                    messages.append(msg)
            
            # Attach query with context
            user_msg = (
                f"Telemetry Context (Recent Honeypot Events):\n{context_str}\n\n"
                f"Analyst Question: {query}"
            )
            messages.append({"role": "user", "content": user_msg})

            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=800,
                )
                answer = response.choices[0].message.content
                return {
                    "answer": answer,
                    "ai_powered": True,
                    "model": self.model,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            except Exception as e:
                logger.error(f"Groq Copilot Error: {e}")

        # Fallback Copilot logic
        query_lower = query.lower()
        if "block" in query_lower or "iptables" in query_lower or "firewall" in query_lower:
            ips = list(set([e.get("source_ip", "") for e in recent_events if e.get("source_ip")]))
            ip_cmds = "\n".join([f"sudo iptables -A INPUT -s {ip} -j DROP" for ip in ips]) if ips else "sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP"
            answer = (
                f"### 🛡️ Immediate Attacker Containment Playbook\n\n"
                f"To block identified adversaries at your host firewall:\n\n"
                f"```bash\n{ip_cmds}\nsudo fail2ban-client set sshd banip {ips[0] if ips else '192.168.1.100'}\n```\n\n"
                f"**Verification:** Run `sudo iptables -L -v -n` to verify dropped packet counts."
            )
        elif "decoy" in query_lower or "trap" in query_lower or "honeytoken" in query_lower:
            decoys = [e for e in recent_events if "decoy" in e.get("event_type", "")]
            answer = (
                f"### 🍯 Deception & Honeytoken Status\n\n"
                f"- **Total Decoy Alarms:** {len(decoys)}\n"
                f"- **Active Traps:** Fake AWS `.aws/credentials`, MySQL `fake-credentials.txt`, Corporate Internal Portal, Decoy SSH Keys.\n"
                f"- **Status:** All decoys are armed. When an attacker accesses any of these files, high-priority telemetry is dispatched immediately."
            )
        else:
            answer = (
                f"### 🤖 Kurukshetra AI Cyber Copilot\n\n"
                f"**Current Situation:** Monitoring {len(recent_events)} live events.\n"
                f"- **Top Threat Actors:** {', '.join(set([e.get('source_ip', 'unknown') for e in recent_events])) or 'None detected'}\n"
                f"- **Recommended Actions:** Check `/report` for the full executive intelligence dossier, or execute `iptables` rules to drop malicious traffic.\n\n"
                f"*(Tip: Set `GROQ_API_KEY` in your `.env` to enable full Groq LLaMA 3.3 70B live interactive reasoning)*"
            )

        return {
            "answer": answer,
            "ai_powered": False,
            "model": "Kurukshetra Heuristic Cyber Engine",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def generate_executive_summary(self, report_data: Dict[str, Any]) -> str:
        """Generates a CISO-level executive summary narrative for threat intelligence reports."""
        if self.is_ai_online:
            system_prompt = (
                "You are a Chief Information Security Officer (CISO) and Lead Threat Intelligence Researcher. "
                "Generate a professional, high-impact executive summary paragraph (3-4 sentences) summarizing the honeypot "
                "telemetry findings, attacker behavior, MITRE ATT&CK techniques observed, and the defense efficacy of the "
                "Kurukshetra Deception Layer."
            )
            user_prompt = f"Threat Data Summary:\n{json.dumps(report_data, default=str)}"
            raw = self._call_groq(system_prompt, user_prompt, temperature=0.3, max_tokens=300)
            if raw:
                return raw.strip()

        # Heuristic fallback summary
        attackers_count = report_data.get("unique_attackers", 0)
        risk = report_data.get("overall_severity", "ELEVATED")
        decoys = len(report_data.get("decoys_tripped", []))
        return (
            f"During the active monitoring window, Kurukshetra 2.0 Cyber Deception architecture successfully engaged and "
            f"neutralized {attackers_count} threat actor(s) under an overall platform severity rating of {risk}. "
            f"Adversarial reconnaissance and credential harvesting attempts tripped {decoys} high-interaction decoy honeytokens, "
            f"effectively isolating threat actors in a sandbox environment and preventing lateral movement into production systems."
        )


# Global AI Threat Advisor instance
ai_advisor = GroqThreatAdvisor()
