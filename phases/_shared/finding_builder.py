"""
phases/_shared/finding_builder.py
───────────────────────────────────
Shared utility for building normalized finding dicts from agent outputs.
Ensures all findings conform to the same schema (SARIF-compatible + extras).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Optional


CWE_MAP = {
    "sqli": ("CWE-89",  "A03:2021 – Injection"),
    "rce":  ("CWE-78",  "A03:2021 – Injection"),
    "xss":  ("CWE-79",  "A03:2021 – Injection"),
    "ssrf": ("CWE-918", "A10:2021 – Server-Side Request Forgery"),
    "path_traversal": ("CWE-22", "A01:2021 – Broken Access Control"),
    "redirect": ("CWE-601", "A01:2021 – Broken Access Control"),
    "deser": ("CWE-502", "A08:2021 – Software and Data Integrity Failures"),
    "xxe":  ("CWE-611", "A05:2021 – Security Misconfiguration"),
    "ssti": ("CWE-94",  "A03:2021 – Injection"),
    "header_inject": ("CWE-113", "A03:2021 – Injection"),
    "custom": ("CWE-20", "A03:2021 – Injection"),
    "idor": ("CWE-639", "A01:2021 – Broken Access Control"),
    "mass_assign": ("CWE-915", "A04:2021 – Insecure Design"),
    "auth_bypass": ("CWE-306", "A07:2021 – Identification and Authentication Failures"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def build_finding(
    path: dict,
    verify_result: dict,
    enriched: dict,
    agent_raw: str,
    phase: str,
) -> Optional[dict]:
    """
    Parse the agent's raw JSON output and merge with path/verify context
    into a normalised finding dict. Returns None if agent says not confirmed.
    """
    agent_data = _parse_agent_json(agent_raw)

    if not agent_data.get("confirmed", True):
        return None

    sink = path.get("sink", {})
    source = path.get("source", {})
    sink_type = sink.get("type", "custom")
    verify_vuln_type = verify_result.get("vuln_type", sink_type)

    cwe, owasp = CWE_MAP.get(sink_type, ("CWE-20", "A03:2021 – Injection"))

    severity = (
        agent_data.get("severity")
        or _confidence_to_severity(verify_result.get("confidence", "MED"), sink_type)
    ).upper()

    finding_id = hashlib.md5(
        f"{path.get('id', '')}:{phase}:{sink_type}".encode()
    ).hexdigest()[:12]

    return {
        "id": finding_id,
        "vuln_type": verify_vuln_type,
        "title": agent_data.get("title") or f"{sink_type.upper()} in {source.get('file', '')}",
        "severity": severity,
        "confidence": verify_result.get("confidence", "MED"),
        "path": path,
        "reasoning": verify_result.get("reasoning", "") + " | " + agent_data.get("exploit_scenario", ""),
        "attack_vector": verify_result.get("attack_vector") or agent_data.get("payload_example") or agent_data.get("attack_scenario", ""),
        "sanitizers_found": verify_result.get("sanitizers_found", []),
        "phase": phase,
        "file": sink.get("file", source.get("file", "")),
        "line_start": sink.get("line", 0),
        "line_end": sink.get("line", 0),
        "code_snippet": sink.get("snippet", "")[:500],
        "cwe": verify_result.get("cwe") or cwe,
        "owasp": verify_result.get("owasp") or owasp,
        "sarif_rule_id": f"pentest/{phase}/{sink_type}",
        "fix_example": agent_data.get("fix_example", agent_data.get("fix", "")),
        "agent_detail": agent_data,
    }


def _parse_agent_json(raw: str) -> dict:
    """Extract JSON object from agent response text."""
    m = re.search(r'\{[\s\S]*\}', raw)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    # Fallback: assume confirmed if we got any response
    return {"confirmed": True, "severity": "MEDIUM"}


def _confidence_to_severity(confidence: str, sink_type: str) -> str:
    critical_sinks = {"sqli", "rce", "deser", "xxe"}
    high_sinks = {"ssrf", "ssti", "path_traversal"}
    if confidence == "HIGH":
        return "CRITICAL" if sink_type in critical_sinks else "HIGH"
    if confidence == "MED":
        return "HIGH" if sink_type in critical_sinks else "MEDIUM"
    return "LOW"


def load_skill(skill_path: Path) -> str:
    """Load a skill markdown file, return content or empty string."""
    if skill_path.exists():
        return skill_path.read_text(encoding="utf-8")
    return ""
