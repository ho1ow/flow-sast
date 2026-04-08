"""
phases/4_analyze/server_agent.py
──────────────────────────────────
ANALYZE agent: server-side vulnerabilities

Covers:
  - SQL Injection (SQLi)
  - Remote Code Execution (RCE)
  - Server-Side Request Forgery (SSRF)
  - Path Traversal / LFI / RFI
  - XML External Entity (XXE)
  - Server-Side Template Injection (SSTI)
  - Deserialization

Input: state["current_path"] + state["current_verify_result"] + state["current_enriched"]
Output: findings[] entries with SARIF-compatible fields
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import List, Optional

import anthropic

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState
from phases._shared.finding_builder import build_finding, load_skill


SKILL_FILE = Path(__file__).parents[2] / "prompts" / "agent_skills" / "sqli_skill.md"

SERVER_VULN_TYPES = {"sqli", "rce", "ssrf", "path_traversal", "xxe", "ssti", "deser"}


@safe_node("server_agent")
def server_agent(state: PentestState) -> dict:
    """Analyze server-side vulns from current verified path."""
    path = state.get("current_path")
    verify_result = state.get("current_verify_result", {})
    enriched = state.get("current_enriched", {})

    if not path or not verify_result.get("is_vulnerable"):
        return {"findings": []}

    sink_type = path.get("sink", {}).get("type", "")
    if sink_type not in SERVER_VULN_TYPES:
        return {"findings": []}

    cfg = state["config"]
    anthropic_cfg = cfg.get("anthropic", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    audit_log(audit_dir, run_id, "server_agent:start", {
        "path_id": path.get("id"), "sink_type": sink_type
    })

    skill_content = load_skill(SKILL_FILE)
    prompt = _build_server_prompt(path, verify_result, enriched, skill_content)

    client = anthropic.Anthropic(api_key=anthropic_cfg.get("api_key", ""))
    _call = with_retry(
        lambda: client.messages.create(
            model=anthropic_cfg.get("model", "claude-sonnet-4-5"),
            max_tokens=anthropic_cfg.get("max_tokens", 4096),
            system=_server_system(sink_type),
            messages=[{"role": "user", "content": prompt}],
        )
    )
    response = _call()
    raw = response.content[0].text if response.content else ""

    finding = build_finding(
        path=path,
        verify_result=verify_result,
        enriched=enriched,
        agent_raw=raw,
        phase="server",
    )

    if finding:
        audit_log(audit_dir, run_id, "server_agent:finding", {
            "path_id": path.get("id"), "severity": finding.get("severity")
        })
        return {"findings": [finding]}

    return {"findings": []}


def _server_system(sink_type: str) -> str:
    vuln_guidance = {
        "sqli":  "Focus on: parameterized queries vs string concat, ORM safe usage, DBAPI2 compliance.",
        "rce":   "Focus on: shell=True, user input in args[], eval/exec with external data.",
        "ssrf":  "Focus on: URL validation, allowlist, internal IP/metadata endpoint access.",
        "path_traversal": "Focus on: '../' removal, os.path.abspath/realpath, send_file with user path.",
        "xxe":   "Focus on: external entity resolution, DTD disabled, defusedxml usage.",
        "ssti":  "Focus on: Jinja2 sandbox, render_template_string with user input, Mako/Twig.",
        "deser": "Focus on: pickle.loads with network data, yaml.load (not safe_load), objectInputStream.",
    }
    return f"""You are a senior application security engineer specializing in server-side vulnerabilities.
Perform deep technical analysis of the suspected {sink_type.upper()} vulnerability.

{vuln_guidance.get(sink_type, '')}

Provide:
1. Confirmed exploit scenario (or why it's a false positive)
2. Exact vulnerable code location and why it's exploitable
3. CVSS-style severity reasoning (Critical/High/Medium/Low)
4. Recommended fix with code example

Format your response as JSON matching the finding schema."""


def _build_server_prompt(path: dict, verify: dict, enriched: dict, skill: str) -> str:
    return f"""## Server-Side Vulnerability Deep Analysis

**Verified by**: {verify.get('reasoning', '')}
**Attack Vector**: {verify.get('attack_vector', '')}
**CWE**: {verify.get('cwe', '')}

## Source Code Context
Source ({path.get('source', {}).get('file', '')}:{path.get('source', {}).get('line', '')}):
```
{enriched.get('source', {}).get('snippet', '')}
```

Sink ({path.get('sink', {}).get('file', '')}:{path.get('sink', {}).get('line', '')}):
```
{enriched.get('sink', {}).get('snippet', '')}
```

## Security Skill Reference
{skill[:2000]}

---
Confirm this finding and provide the JSON finding object.
JSON schema: {{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": str, "confirmed": bool,
"exploit_scenario": str, "vulnerable_code": str, "fix_example": str, "cvss_score": float}}
"""
