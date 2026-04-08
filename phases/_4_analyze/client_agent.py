"""
phases/4_analyze/client_agent.py
──────────────────────────────────
ANALYZE agent: client-side vulnerabilities

Covers:
  - XSS (Reflected, Stored, DOM-based)
  - Open Redirect
  - Client-Side Template Injection (CSTI)
  - Header Injection / CRLF
  - Clickjacking indicators
"""

from __future__ import annotations

from pathlib import Path

import anthropic

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState
from phases._shared.finding_builder import build_finding, load_skill


SKILL_FILE = Path(__file__).parents[2] / "prompts" / "agent_skills" / "xss_skill.md"

CLIENT_VULN_TYPES = {"xss", "redirect", "header_inject", "ssti"}


@safe_node("client_agent")
def client_agent(state: PentestState) -> dict:
    """Analyze client-side vulns from current verified path."""
    path = state.get("current_path")
    verify_result = state.get("current_verify_result", {})
    enriched = state.get("current_enriched", {})

    if not path or not verify_result.get("is_vulnerable"):
        return {"findings": []}

    sink_type = path.get("sink", {}).get("type", "")
    if sink_type not in CLIENT_VULN_TYPES:
        return {"findings": []}

    cfg = state["config"]
    anthropic_cfg = cfg.get("anthropic", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    audit_log(audit_dir, run_id, "client_agent:start", {
        "path_id": path.get("id"), "sink_type": sink_type
    })

    skill_content = load_skill(SKILL_FILE)
    prompt = _build_client_prompt(path, verify_result, enriched, sink_type, skill_content)

    client = anthropic.Anthropic(api_key=anthropic_cfg.get("api_key", ""))
    _call = with_retry(
        lambda: client.messages.create(
            model=anthropic_cfg.get("model", "claude-sonnet-4-5"),
            max_tokens=anthropic_cfg.get("max_tokens", 4096),
            system=_client_system(sink_type),
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
        phase="client",
    )

    if finding:
        audit_log(audit_dir, run_id, "client_agent:finding", {
            "path_id": path.get("id"), "severity": finding.get("severity")
        })
        return {"findings": [finding]}

    return {"findings": []}


def _client_system(sink_type: str) -> str:
    guidance = {
        "xss":          "Focus on: output encoding, Content-Security-Policy, framework auto-escape, innerHTML vs textContent.",
        "redirect":      "Focus on: URL validation, allowlist domains, relative vs absolute URL, open redirect chain.",
        "header_inject": "Focus on: CRLF characters, Set-Cookie via user input, Location header injection.",
        "ssti":          "Focus on: client-side template injection in Angular/Vue expressions.",
    }
    return f"""You are an expert in client-side web security and browser attack surface.
Analyze the suspected {sink_type.upper()} vulnerability deeply.

{guidance.get(sink_type, '')}

Provide your JSON analysis of the finding."""


def _build_client_prompt(path: dict, verify: dict, enriched: dict, sink_type: str, skill: str) -> str:
    return f"""## Client-Side Vulnerability Analysis: {sink_type.upper()}

**Initial Assessment**: {verify.get('reasoning', '')}
**Potential Attack**: {verify.get('attack_vector', '')}

## Sink Code ({path.get('sink', {}).get('file', '')}:{path.get('sink', {}).get('line', '')}):
```
{enriched.get('sink', {}).get('snippet', '')}
```

## Source Code ({path.get('source', {}).get('file', '')}:{path.get('source', {}).get('line', '')}):
```
{enriched.get('source', {}).get('snippet', '')}
```

## Skill Reference (XSS/Client Attacks):
{skill[:1500]}

Confirm the finding with JSON: {{"severity": "HIGH|MEDIUM|LOW", "confirmed": bool, 
"xss_type": "reflected|stored|dom", "payload_example": str, "impact": str, "fix": str}}
"""
