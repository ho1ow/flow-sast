"""
phases/_shared/prompt_loader.py
────────────────────────────────
Centralized loader cho tất cả prompts/*.yaml và prompts/agent_skills/*.md

Caching in-memory để tránh re-read file mỗi Claude call.
All agents import từ đây — không hardcode path hay yaml.load inline.

Usage:
    skill = load_skill("sqli")          # → str content of sqli_skill.md
    verify_tpl = load_verify_template("full_verify")
    analyze_tpl = load_analyze_template("server")
    ctx_section = format_business_context(state["business_context"])
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

# ── Directory layout ──────────────────────────────────────────────────────────
_ROOT = Path(__file__).parents[2]           # ai_pentest_agent/
_PROMPTS_DIR = _ROOT / "prompts"
_SKILLS_DIR  = _PROMPTS_DIR / "agent_skills"
_VERIFY_YAML = _PROMPTS_DIR / "verify_prompts.yaml"
_ANALYZE_YAML = _PROMPTS_DIR / "analyze_prompts.yaml"


# ── In-memory caches ──────────────────────────────────────────────────────────
_skill_cache: Dict[str, str] = {}
_verify_cache: Dict[str, Any] = {}
_analyze_cache: Dict[str, Any] = {}


# ── Skill loader ──────────────────────────────────────────────────────────────

SKILL_ALIASES: Dict[str, str] = {
    # injection / server-side
    "sqli":          "sqli_skill.md",
    "rce":           "sqli_skill.md",
    "deser":         "sqli_skill.md",
    "xxe":           "sqli_skill.md",
    "ssti":          "sqli_skill.md",
    "path_traversal":"sqli_skill.md",
    # client-side
    "xss":           "xss_skill.md",
    "ssrf":          "xss_skill.md",
    "redirect":      "xss_skill.md",
    "crlf":          "xss_skill.md",
    "csti":          "xss_skill.md",
    "header_inject": "xss_skill.md",
    # authz
    "authz":         "authz_skill.md",
    "idor":          "authz_skill.md",
    "bfla":          "authz_skill.md",
    "mass_assign":   "authz_skill.md",
    "auth_bypass":   "authz_skill.md",
    # business logic
    "biz_logic":     "business_logic_skill.md",
    "race":          "business_logic_skill.md",
    "state_bypass":  "business_logic_skill.md",
    # hardcoded secrets
    "hardcode":      "hardcode_skill.md",
    "secret":        "hardcode_skill.md",
    "crypto":        "hardcode_skill.md",
    # server/client agents
    "server":        "server_side_skill.md",
    "client":        "client_side_skill.md",
    # context
    "context":       "system_context_skill.md",
    "system":        "system_context_skill.md",
    "custom":        "authz_skill.md",
}


def load_skill(category: str, max_chars: int = 3000) -> str:
    """
    Load skill .md file for a given vulnerability category.
    Returns empty string if file not found (never raises).
    """
    key = category.lower()
    if key in _skill_cache:
        return _skill_cache[key]

    filename = SKILL_ALIASES.get(key, f"{key}_skill.md")
    skill_path = _SKILLS_DIR / filename
    if not skill_path.exists():
        # Try exact filename
        direct = _SKILLS_DIR / key
        if direct.exists():
            skill_path = direct
        else:
            _skill_cache[key] = ""
            return ""

    content = skill_path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    _skill_cache[key] = content
    return content


# ── Verify prompt loader (Phase 3) ────────────────────────────────────────────

def load_verify_template(template_name: str) -> Dict[str, Any]:
    """
    Load a Phase 3 verify prompt template from verify_prompts.yaml.

    template_name: "sanitizer_check" | "full_verify" | "object_trace"
    Returns dict with keys: system, user_template, output_schema
    """
    _ensure_verify_loaded()
    template = _verify_cache.get(template_name, {})
    if not template:
        # Fallback to full_verify
        template = _verify_cache.get("full_verify", {})
    return template


def _ensure_verify_loaded() -> None:
    if _verify_cache:
        return
    if not _VERIFY_YAML.exists():
        return
    try:
        data = yaml.safe_load(_VERIFY_YAML.read_text(encoding="utf-8"))
        templates = data.get("templates", data) if isinstance(data, dict) else {}
        _verify_cache.update(templates)
    except Exception:
        pass


# ── Analyze prompt loader (Phase 4) ──────────────────────────────────────────

def load_analyze_template(agent_name: str) -> Dict[str, Any]:
    """
    Load a Phase 4 analyze prompt template from analyze_prompts.yaml.

    agent_name: "server" | "client" | "authz" | "biz_logic" | "hardcode"
    Returns dict with keys: system_prefix, task_instruction, output_schema
    """
    _ensure_analyze_loaded()
    template = _analyze_cache.get(agent_name, {})
    if not template:
        template = _analyze_cache.get("server", {})
    return template


def _ensure_analyze_loaded() -> None:
    if _analyze_cache:
        return
    if not _ANALYZE_YAML.exists():
        return
    try:
        data = yaml.safe_load(_ANALYZE_YAML.read_text(encoding="utf-8"))
        templates = data.get("agents", data) if isinstance(data, dict) else {}
        _analyze_cache.update(templates)
    except Exception:
        pass


# ── Business context formatter ────────────────────────────────────────────────

def format_business_context(business_context: dict, max_chars: int = 1500) -> str:
    """
    Format business_context dict into a compact prompt section for Claude.
    Returns empty string if no context available.
    """
    if not business_context:
        return ""

    parts = []
    sys_type = business_context.get("system_type", "")
    description = business_context.get("description", "")
    assets = business_context.get("critical_assets", [])
    flows = business_context.get("business_flows", [])
    tech = business_context.get("tech_stack_hints", [])

    if sys_type and sys_type != "unknown":
        parts.append(f"System type: {sys_type.upper()}")
    if description:
        parts.append(f"Description: {description[:300]}")
    if assets:
        parts.append("Critical assets: " + ", ".join(assets[:5]))
    if flows:
        parts.append("Business flows: " + ", ".join(flows[:5]))
    if tech:
        parts.append("Tech stack: " + ", ".join(tech[:8]))

    if not parts:
        return ""

    section = "\n".join(parts)
    return f"\n## Business Context\n{section}\n"[:max_chars]


# ── Invalidation (for testing) ────────────────────────────────────────────────

def clear_caches() -> None:
    """Clear all in-memory caches. Used in tests."""
    _skill_cache.clear()
    _verify_cache.clear()
    _analyze_cache.clear()
