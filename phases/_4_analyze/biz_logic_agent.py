"""
phases/4_analyze/biz_logic_agent.py
─────────────────────────────────────
ANALYZE agent: Business Logic Vulnerabilities

Covers:
  - Race conditions (TOCTOU)
  - State machine bypass (order/payment flows)
  - Negative value / integer overflow attacks
  - Replay attacks
  - Workflow bypass (skip steps)
  - Time-based vulnerabilities
"""

from __future__ import annotations

import re
from pathlib import Path

import anthropic

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState
from phases._shared.finding_builder import build_finding, load_skill


BIZ_LOGIC_INDICATORS = re.compile(
    r"(status\s*==|state\s*==|\.update\(|\.save\(|balance|quantity|"
    r"price|amount|order|payment|transfer|withdraw|coupon|discount|"
    r"token.*expir|sleep\(|time\.time|datetime\.now|lock\(|mutex|"
    r"atomic|transaction|rollback|commit)",
    re.IGNORECASE,
)


@safe_node("biz_logic_agent")
def biz_logic_agent(state: PentestState) -> dict:
    """Analyze business logic vulnerabilities."""
    path = state.get("current_path")
    verify_result = state.get("current_verify_result", {})
    enriched = state.get("current_enriched", {})

    if not path:
        return {"findings": []}

    all_code = _gather_code(enriched)
    if not BIZ_LOGIC_INDICATORS.search(all_code):
        return {"findings": []}

    cfg = state["config"]
    anthropic_cfg = cfg.get("anthropic", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    audit_log(audit_dir, run_id, "biz_logic_agent:start", {"path_id": path.get("id")})

    prompt = _build_biz_prompt(path, verify_result, enriched, all_code)

    client = anthropic.Anthropic(api_key=anthropic_cfg.get("api_key", ""))
    _call = with_retry(
        lambda: client.messages.create(
            model=anthropic_cfg.get("model", "claude-sonnet-4-5"),
            max_tokens=anthropic_cfg.get("max_tokens", 4096),
            system=_biz_system(),
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
        phase="biz_logic",
    )

    if finding:
        return {"findings": [finding]}

    return {"findings": []}


def _biz_system() -> str:
    return """You are an expert in business logic security vulnerabilities.

Analyze for:
1. **Race Conditions**: Non-atomic read-modify-write on shared state (balance, stock, orders)
2. **State Machine Bypass**: Can steps be skipped? (e.g., skip payment → get order confirmed)
3. **Negative Values**: Price=−100, quantity=−1 exploits
4. **Replay Attacks**: Reusing tokens / signatures
5. **TOCTOU**: Check at time T, use at time T+Δ with changed state

Output JSON: {"severity": "HIGH|MEDIUM|LOW", "confirmed": bool,
"issue_type": "race|state_bypass|negative_val|replay|toctou",
"attack_scenario": str, "preconditions": str, "impact": str, "fix": str}"""


def _build_biz_prompt(path: dict, verify: dict, enriched: dict, all_code: str) -> str:
    return f"""## Business Logic Analysis

**Path**: {enriched.get('path_summary', '')}

## Handler / Transaction Code:
```
{enriched.get('source', {}).get('snippet', '')}
```

## State Update / DB Write Code:
```
{enriched.get('sink', {}).get('snippet', '')}
```

**Look for**:
- Is there a lock/transaction wrapping the read-modify-write?
- Are status/state transitions validated server-side?
- Can a negative or extreme value be passed?
- Is there a time window exploitable by concurrent requests?

Provide JSON analysis."""


def _gather_code(enriched: dict) -> str:
    parts = [
        enriched.get("source", {}).get("snippet", ""),
        enriched.get("sink", {}).get("snippet", ""),
    ]
    for fn in enriched.get("intermediate_fns", []):
        parts.append(fn.get("code", ""))
    return " ".join(parts)
