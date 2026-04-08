"""
phases/3_verify/claude_verifier.py
────────────────────────────────────
LangGraph node: verify_claude

3 prompt templates tùy theo PathDecision từ joern_pre_filter:
  - CLAUDE_SANITIZER_ONLY  → ~800 tokens: chỉ check sanitizer quality
  - CLAUDE_FULL_VERIFY     → ~2500 tokens: full call chain verify
  - CLAUDE_OBJECT_TRACE    → ~3000 tokens: full class source trace

CONFIRMED_HIGH paths skip node này hoàn toàn (đã handled bởi router).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import anthropic

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState


SKILLS_DIR = Path(__file__).parents[2] / "prompts" / "agent_skills"

SKILL_MAP = {
    "sqli":           "sqli_skill.md",
    "rce":            "sqli_skill.md",
    "xss":            "xss_skill.md",
    "ssrf":           "xss_skill.md",
    "path_traversal": "xss_skill.md",
    "redirect":       "xss_skill.md",
    "deser":          "sqli_skill.md",
    "xxe":            "sqli_skill.md",
    "ssti":           "sqli_skill.md",
    "header_inject":  "xss_skill.md",
    "custom":         "authz_skill.md",
}


@safe_node("verify_claude")
def verify_claude(state: PentestState) -> dict:
    """LangGraph node — call Claude with the appropriate prompt template."""
    cfg = state["config"]
    anthropic_cfg = cfg.get("anthropic", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    enriched = state.get("current_enriched")
    path = state.get("current_path", {})

    if not enriched:
        return {"current_verify_result": {"is_vulnerable": False, "confidence": "LOW"}}

    # CONFIRMED_HIGH → skip (router should not call us, but guard here)
    path_decision = path.get("path_decision", "full_verify")
    if path_decision == "confirmed":
        return {"current_verify_result": {
            "is_vulnerable": True, "confidence": "HIGH",
            "vuln_type": path.get("sink", {}).get("type", ""),
            "reasoning": "Confirmed by Joern CFG taint analysis (no sanitizer found)",
            "sanitizers_found": [],
            "attack_vector": "",
            "cwe": "", "owasp": "",
            "path_decision": "confirmed",
        }}

    sink_type = path.get("sink", {}).get("type", "custom")
    sanitizer_fn = path.get("joern_sanitizer", [])

    # Select prompt template
    prompt, system = _build_prompt_for_decision(
        decision=path_decision,
        enriched=enriched,
        path=path,
        sink_type=sink_type,
        sanitizer_fn=sanitizer_fn,
    )

    audit_log(audit_dir, run_id, "verify_claude:start", {
        "path_id": enriched.get("path_id"),
        "sink_type": sink_type,
        "template": path_decision,
        "retry": state.get("verify_retry_count", 0),
    })

    client = anthropic.Anthropic(api_key=anthropic_cfg.get("api_key", ""))
    model = anthropic_cfg.get("model", "claude-sonnet-4-5")
    max_tokens = anthropic_cfg.get("max_tokens", 4096)

    _call = with_retry(
        lambda: client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        ),
        max_attempts=3,
        rate_limit_max=5,
    )
    response = _call()
    raw_text = response.content[0].text if response.content else ""

    verify_result = _parse_response(raw_text, sink_type, path_decision)

    audit_log(audit_dir, run_id, "verify_claude:done", {
        "path_id": enriched.get("path_id"),
        "template": path_decision,
        "confidence": verify_result.get("confidence"),
        "is_vulnerable": verify_result.get("is_vulnerable"),
    })

    return {"current_verify_result": verify_result}


# ── 3 Prompt Templates ────────────────────────────────────────────────────────

def _build_prompt_for_decision(
    decision: str,
    enriched: dict,
    path: dict,
    sink_type: str,
    sanitizer_fn: list,
) -> tuple[str, str]:
    """Return (user_prompt, system_prompt) for the given PathDecision."""
    system = _build_system(sink_type)

    if decision == "sanitizer":
        return _prompt_sanitizer_check(path, enriched, sink_type, sanitizer_fn), system

    if decision == "object_trace":
        return _prompt_object_trace(path, enriched, sink_type), system

    # Default: full_verify
    return _prompt_full_verify(path, enriched, sink_type), system


def _build_system(sink_type: str) -> str:
    skill_file = SKILL_MAP.get(sink_type, "sqli_skill.md")
    skill_path = SKILLS_DIR / skill_file
    skill_content = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""

    return f"""You are an expert penetration tester and secure code reviewer.
Be precise: distinguish TRUE positives from FALSE positives.

## Specialty
{skill_content[:2000]}

## Output Format
Respond with a single JSON object only. No markdown. Schema varies by task (shown in prompt).
"""


def _prompt_sanitizer_check(
    path: dict,
    enriched: dict,
    sink_type: str,
    sanitizer_fn: list,
) -> str:
    """~800 tokens — Joern confirmed taint, check sanitizer quality."""
    source = enriched.get("source", {})
    sink = enriched.get("sink", {})
    sanitizer_names = ", ".join(sanitizer_fn) if sanitizer_fn else "(unknown)"
    call_chain = path.get("call_chain", [])

    return f"""## Sanitizer Quality Check

Joern confirmed data flow:
  Source: {source.get("type", "?")} in {source.get("file", "")}:{source.get("line", "")}
  Sink: {sink.get("name", "")} ({sink_type.upper()})

Sanitizer detected on path: `{sanitizer_names}`
Call chain: {" → ".join(str(n) for n in call_chain)}

## Sink Code
```
{sink.get("snippet", "(not available)")}
```

**Questions:**
1. Is `{sanitizer_names}` the correct sanitizer for a `{sink_type.upper()}` sink?
2. Is it bypassable? (encoding trick, second parameter, context-specific weakness)
3. Is it applied to the correct variable at the correct position?

JSON only:
{{"correct": bool, "bypassable": bool, "bypass_reason": str,
  "payload": str, "severity": "HIGH|MED|LOW", "confidence": "HIGH|MED|LOW",
  "is_vulnerable": bool, "vuln_type": "{sink_type}", "reasoning": str,
  "sanitizers_found": ["{sanitizer_names}"], "attack_vector": str,
  "cwe": str, "owasp": str}}
"""


def _prompt_full_verify(path: dict, enriched: dict, sink_type: str) -> str:
    """~2500 tokens — GitNexus structural path, no Joern confirm."""
    source = enriched.get("source", {})
    sink = enriched.get("sink", {})
    intermediates = enriched.get("intermediate_fns", [])
    call_chain = path.get("call_chain", [])
    source_param = source.get("code", source.get("type", "?"))
    sink_fn = sink.get("name", path.get("sink", {}).get("name", "?"))
    imports_str = "\n".join(enriched.get("imports", [])[:15]) or "(none)"

    intermediate_section = ""
    for fn in intermediates[:4]:
        intermediate_section += f"""
### {fn.get("method", "")} ({fn.get("file", "")}:{fn.get("line", "")})
```
{fn.get("code", "")}
```"""

    return f"""## Full Vulnerability Path Verification

Call chain: {" → ".join(str(n) for n in call_chain)}
Source param: `{source_param}` (user-controlled: {source.get("type", "?")})
Sink: `{sink_fn}` ({sink_type.upper()})
Hops: {path.get("hops", "?")} | Score: {path.get("score", "")}

## Source Code ({source.get("file", "")}:{source.get("line", "")})
```
{source.get("snippet", "(not available)")}
```

## Sink Code ({sink.get("file", "")}:{sink.get("line", "")})
```
{sink.get("snippet", "(not available)")}
```
{intermediate_section}

## Imports
```
{imports_str}
```

**Analyze:**
1. Does `{source_param}` reach `{sink_fn}`? (trace argument mapping)
2. Any sanitizer/validator? Correct type for `{sink_type.upper()}`?
3. Bypassable? Framework auto-protection?

JSON only:
{{"flows": bool, "sanitizer": "name|null", "correct_type": bool,
  "bypassable": bool, "bypass_reason": str, "payload": str,
  "confidence": "HIGH|MED|LOW", "is_vulnerable": bool, "vuln_type": "{sink_type}",
  "reasoning": str, "sanitizers_found": [], "attack_vector": str,
  "cwe": str, "owasp": str}}
"""


def _prompt_object_trace(path: dict, enriched: dict, sink_type: str) -> str:
    """~3000 tokens — Object taint via constructor, needs full class source."""
    class_name = path.get("class_name", "")
    constructor_fn = path.get("constructor_fn", "__construct")
    sink_method = path.get("sink_method", "")
    sink = enriched.get("sink", {})
    source = enriched.get("source", {})
    sink_fn = sink.get("name", path.get("sink", {}).get("name", "?"))

    # For object trace, we show the full class code
    intermediate_section = ""
    for fn in enriched.get("intermediate_fns", [])[:6]:
        intermediate_section += f"""
### {fn.get("method", "")}
```
{fn.get("code", "")}
```"""

    return f"""## Object Taint Trace

Class: `{class_name}`
Constructor receives tainted data via: `{constructor_fn}()`
Suspected taint path: `{constructor_fn}` → `$this->?` → `{sink_method}()` → `{sink_fn}`

## Entry Point
Called from: {path.get("called_from", "?")} in {source.get("file", "")}
```
{source.get("snippet", "(entry point code not available)")}
```

## Class Methods
```
{sink.get("snippet", "(sink code not available)")}
```
{intermediate_section}

**Trace:**
- What constructor parameter receives user data?
- What `$this->property` does it get stored in?
- Does `{sink_method}()` use that property when calling `{sink_fn}()`?
- Is it sanitized between assignment and use?

JSON only:
{{"property": str, "reaches_sink": bool, "sink_method": "{sink_method}",
  "sanitized": bool, "sanitizer_fn": "name|null", "payload": str,
  "confidence": "HIGH|MED|LOW", "is_vulnerable": bool, "vuln_type": "{sink_type}",
  "reasoning": str, "sanitizers_found": [], "attack_vector": str,
  "cwe": str, "owasp": str}}
"""


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_response(raw_text: str, sink_type: str, template: str) -> dict:
    """Normalise JSON from Claude response into standard verify_result."""
    m = re.search(r'\{[\s\S]*\}', raw_text)
    if m:
        try:
            data = json.loads(m.group(0))
            # Handle both template output schemas
            is_vul = bool(
                data.get("is_vulnerable")
                or data.get("flows")
                or data.get("reaches_sink")
                or (data.get("bypassable") and data.get("correct") is False)
            )
            return {
                "is_vulnerable": is_vul,
                "confidence": str(data.get("confidence", "LOW")).upper(),
                "vuln_type": str(data.get("vuln_type", sink_type)),
                "reasoning": str(data.get("reasoning", "")),
                "sanitizers_found": list(data.get("sanitizers_found", [])),
                "attack_vector": str(data.get("attack_vector", data.get("payload", ""))),
                "cwe": str(data.get("cwe", "")),
                "owasp": str(data.get("owasp", "")),
                "path_decision": template,
                # Template-specific extras
                "sanitizer_correct": data.get("correct_type", data.get("correct", True)),
                "bypassable": data.get("bypassable", False),
            }
        except json.JSONDecodeError:
            pass

    # Heuristic fallback
    confidence = "LOW"
    is_vul = False
    if re.search(r'"confidence"\s*:\s*"HIGH"', raw_text):
        confidence, is_vul = "HIGH", True
    elif re.search(r'"confidence"\s*:\s*"MED"', raw_text):
        confidence = "MED"
        is_vul = "vulnerable" in raw_text.lower()

    return {
        "is_vulnerable": is_vul,
        "confidence": confidence,
        "vuln_type": sink_type,
        "reasoning": raw_text[:500],
        "sanitizers_found": [],
        "attack_vector": "",
        "cwe": "", "owasp": "",
        "path_decision": template,
        "sanitizer_correct": True,
        "bypassable": False,
    }
