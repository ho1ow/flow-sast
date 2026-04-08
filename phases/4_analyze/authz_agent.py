"""
phases/4_analyze/authz_agent.py
─────────────────────────────────
ANALYZE agent: Authorization & Access Control

Covers:
  - IDOR (Insecure Direct Object Reference)
  - Missing Authentication / Auth bypass
  - Mass Assignment
  - Privilege Escalation
  - Broken Function Level Authorization
  - JWT/Session vulnerabilities
"""

from __future__ import annotations

import re
from pathlib import Path

import anthropic

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState
from phases._shared.finding_builder import build_finding, load_skill


SKILL_FILE = Path(__file__).parents[2] / "prompts" / "agent_skills" / "authz_skill.md"

# Authz agent runs on ALL paths (authorization issues can appear anywhere)
# but prioritizes paths touching object lookup / resource access patterns
AUTHZ_INDICATORS = re.compile(
    r"(findById|getById|fetchById|get_by_id|\.find\(|\.get\(id|"
    r"\*\*request\.|\.populate\(|bind\(|mass.assign|"
    r"@login_required|@jwt_required|hasPermission|isAuthenticated|"
    r"request\.user|current_user|g\.user)",
    re.IGNORECASE,
)


@safe_node("authz_agent")
def authz_agent(state: PentestState) -> dict:
    """Analyze authorization / access control issues."""
    path = state.get("current_path")
    verify_result = state.get("current_verify_result", {})
    enriched = state.get("current_enriched", {})

    if not path:
        return {"findings": []}

    # Run authz checks even if verify says LOW — authz bugs often slip through taint analysis
    all_code = _gather_code(enriched)
    if not AUTHZ_INDICATORS.search(all_code) and not verify_result.get("is_vulnerable"):
        return {"findings": []}

    cfg = state["config"]
    anthropic_cfg = cfg.get("anthropic", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    audit_log(audit_dir, run_id, "authz_agent:start", {"path_id": path.get("id")})

    skill_content = load_skill(SKILL_FILE)
    prompt = _build_authz_prompt(path, verify_result, enriched, all_code, skill_content)

    client = anthropic.Anthropic(api_key=anthropic_cfg.get("api_key", ""))
    _call = with_retry(
        lambda: client.messages.create(
            model=anthropic_cfg.get("model", "claude-sonnet-4-5"),
            max_tokens=anthropic_cfg.get("max_tokens", 4096),
            system=_authz_system(),
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
        phase="authz",
    )

    if finding:
        audit_log(audit_dir, run_id, "authz_agent:finding", {
            "path_id": path.get("id"), "severity": finding.get("severity")
        })
        return {"findings": [finding]}

    return {"findings": []}


def _authz_system() -> str:
    return """You are an expert in authorization security and access control vulnerabilities.

Analyze the code for:
1. **IDOR**: Does the code fetch objects using user-supplied IDs without ownership verification?
2. **Mass Assignment**: Are request body fields blindly assigned to model attributes?
3. **Auth bypass**: Are authentication decorators/middleware missing on sensitive routes?
4. **Privilege escalation**: Can a lower-privileged user reach admin functionality?
5. **JWT issues**: Token not validated, role claims trusted from payload, weak secret?

Output JSON: {"severity": "CRITICAL|HIGH|MEDIUM|LOW", "confirmed": bool,
"issue_type": "IDOR|mass_assign|auth_bypass|priv_esc|jwt", 
"affected_resource": str, "exploit_scenario": str, "missing_check": str, "fix": str}"""


def _build_authz_prompt(path: dict, verify: dict, enriched: dict, all_code: str, skill: str) -> str:
    return f"""## Authorization Vulnerability Analysis

**Path**: {enriched.get('path_summary', '')}

## Endpoint Handler Code
```
{enriched.get('source', {}).get('snippet', '')}
```

## Resource Access Code  
```
{enriched.get('sink', {}).get('snippet', '')}
```

## Authz Skill Reference:
{skill[:2000]}

**Key questions**:
- Is there an ownership check before accessing the resource?
- Is the route protected by authentication middleware?
- Can body parameters overwrite protected model fields?
- Is the JWT/session token properly validated?

Provide your JSON analysis."""


def _gather_code(enriched: dict) -> str:
    parts = [
        enriched.get("source", {}).get("snippet", ""),
        enriched.get("sink", {}).get("snippet", ""),
    ]
    for fn in enriched.get("intermediate_fns", []):
        parts.append(fn.get("code", ""))
    return " ".join(parts)
