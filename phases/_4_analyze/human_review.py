"""
phases/4_analyze/human_review.py
──────────────────────────────────
LangGraph node: human_review_gate

Human-in-the-loop checkpoint sau khi 5 agents analyze xong.
Sử dụng LangGraph interrupt() để pause pipeline và chờ user input.

Nếu --no-review flag được set → auto-accept tất cả, không pause.

Interactive CLI session:
  [a]ccept <id>  — accept finding (default: accept all)
  [r]eject <id>  — reject finding (remove from pipeline)
  [n]ote <id>    — thêm manual note vào finding
  [s]how         — show tất cả pending findings
  [done]         — accept tất cả remaining và continue
  [q]uit         — stop pipeline, save current findings

Sau review: chỉ accepted findings tiếp tục sang Phase 5 (confirm/feedback).
"""

from __future__ import annotations

import json
from typing import List, Optional

from langgraph.types import interrupt

from core.state import PentestState
from core.reliability import audit_log, safe_node


# ── ANSI colors cho CLI display ───────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_DIM    = "\033[2m"
_ORANGE = "\033[33m"

SEV_COLORS = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MED":      _YELLOW,
    "MEDIUM":   _YELLOW,
    "LOW":      _GREEN,
    "INFO":     _DIM,
}


@safe_node("human_review_gate")
def human_review_gate(state: PentestState) -> dict:
    """
    LangGraph node — pause và hiện findings cho user review.
    Sử dụng interrupt() để preserve state khi pause.
    """
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    # Skip nếu disable human review
    if pipeline_cfg.get("no_review", False):
        audit_log(audit_dir, run_id, "human_review:skip", {"reason": "no_review_flag"})
        return {}

    findings: List[dict] = state.get("findings", [])
    if not findings:
        print(f"\n{_DIM}[human_review] No findings to review.{_RESET}")
        return {}

    # ── Interrupt pipeline → gửi findings cho CLI handler ────────────────────
    # LangGraph sẽ serialize findings và chờ resume input
    review_payload = {
        "findings_count": len(findings),
        "findings":       [_summarize(f, i) for i, f in enumerate(findings)],
        "message":        "Review analyze findings before proceeding to confirm phase.",
    }

    # interrupt() là blocking call — pipeline pause ở đây
    # CLI handler (trong main.py) sẽ read này và handle user input
    user_decisions: dict = interrupt(review_payload)

    # ── Apply decisions ───────────────────────────────────────────────────────
    accepted  = []
    rejected  = []
    noted     = {}

    if user_decisions.get("action") == "accept_all":
        accepted = findings
    elif user_decisions.get("action") == "reject_all":
        rejected = findings
    else:
        decisions = user_decisions.get("decisions", {})
        notes     = user_decisions.get("notes", {})

        for i, finding in enumerate(findings):
            fid = finding.get("id", str(i))
            decision = decisions.get(fid, decisions.get(str(i), "accept"))
            if decision == "accept":
                if fid in notes:
                    finding = {**finding, "reviewer_note": notes[fid]}
                accepted.append(finding)
            else:
                rejected.append(finding)

    audit_log(audit_dir, run_id, "human_review:done", {
        "total":    len(findings),
        "accepted": len(accepted),
        "rejected": len(rejected),
    })

    return {"findings": accepted}


# ── CLI review session (called from main.py after interrupt) ──────────────────

def run_review_session(findings: List[dict]) -> dict:
    """
    Interactive CLI review session — gọi từ main.py khi nhận interrupt.

    Returns:
        dict: user_decisions để resume pipeline
            {
                "action": "custom",
                "decisions": {"<finding_id>": "accept"|"reject"},
                "notes":     {"<finding_id>": "<note text>"}
            }
    """
    pending = {f.get("id", str(i)): f for i, f in enumerate(findings)}
    decisions: dict[str, str] = {}
    notes:     dict[str, str] = {}

    _print_header(len(pending))
    _print_findings_table(list(pending.values()))

    print(f"\n{_BOLD}Commands:{_RESET}")
    print(f"  {_CYAN}a <id>{_RESET}   — accept finding  {_DIM}(default: accept all){_RESET}")
    print(f"  {_CYAN}r <id>{_RESET}   — reject finding")
    print(f"  {_CYAN}n <id>{_RESET}   — add note to finding")
    print(f"  {_CYAN}show{_RESET}     — show all findings again")
    print(f"  {_CYAN}done{_RESET}     — accept all remaining and continue")
    print(f"  {_CYAN}reject_all{_RESET} — reject all and continue")
    print(f"  {_CYAN}q{_RESET}        — quit pipeline\n")

    while True:
        try:
            raw = input(f"{_BOLD}review>{_RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{_YELLOW}Interrupted — accepting all findings{_RESET}")
            return {"action": "accept_all"}

        if not raw:
            continue

        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("done", "continue", "c"):
            # Accept remaining undecided
            for fid in pending:
                if fid not in decisions:
                    decisions[fid] = "accept"
            break

        elif cmd in ("reject_all",):
            return {"action": "reject_all"}

        elif cmd in ("q", "quit", "exit"):
            print(f"{_YELLOW}Stopping after review. Current findings saved.{_RESET}")
            return {"action": "accept_all"}  # save what we have

        elif cmd in ("a", "accept"):
            fids = _resolve_ids(arg, pending)
            for fid in fids:
                decisions[fid] = "accept"
                print(f"  {_GREEN}✓ accepted:{_RESET} {fid}")

        elif cmd in ("r", "reject"):
            fids = _resolve_ids(arg, pending)
            for fid in fids:
                decisions[fid] = "reject"
                print(f"  {_RED}✗ rejected:{_RESET} {fid}")

        elif cmd in ("n", "note"):
            if not arg:
                print(f"  {_YELLOW}Usage: n <id>{_RESET}")
                continue
            parts2 = arg.split(None, 1)
            fid = parts2[0]
            if fid not in pending:
                print(f"  {_YELLOW}Unknown ID: {fid}{_RESET}")
                continue
            if len(parts2) > 1:
                notes[fid] = parts2[1]
                print(f"  {_GREEN}✓ note added:{_RESET} {fid}")
            else:
                note = input(f"  Note for {fid}: ").strip()
                if note:
                    notes[fid] = note

        elif cmd in ("show", "ls"):
            _print_findings_table(list(pending.values()), decisions)

        elif cmd in ("help", "h", "?"):
            print(f"  Commands: a <id> | r <id> | n <id> | show | done | reject_all | q")

        else:
            print(f"  {_YELLOW}Unknown command. Type 'help' for usage.{_RESET}")

    # Summary
    accepted_count = sum(1 for v in decisions.values() if v == "accept")
    rejected_count = sum(1 for v in decisions.values() if v == "reject")
    print(f"\n{_GREEN}✓ Review complete:{_RESET} {accepted_count} accepted, {rejected_count} rejected")

    return {
        "action":    "custom",
        "decisions": decisions,
        "notes":     notes,
    }


# ── Display helpers ───────────────────────────────────────────────────────────

def _print_header(count: int) -> None:
    print(f"\n{'─' * 60}")
    print(f"{_BOLD}  🔍 flow-sast — Human Review Gate{_RESET}")
    print(f"  {count} finding(s) from analyze phase")
    print(f"{'─' * 60}\n")


def _print_findings_table(
    findings: List[dict],
    decisions: Optional[dict] = None
) -> None:
    for i, f in enumerate(findings):
        fid     = f.get("id", str(i))
        sev     = f.get("severity", "?")
        vuln    = f.get("vuln_type", "?")
        title   = f.get("title", "—")[:60]
        ffile   = f.get("file", "?")
        line    = f.get("line", "?")
        conf    = f.get("confidence", "?")
        phase   = f.get("phase", "analyze")

        sev_color = SEV_COLORS.get(sev.upper(), "")
        status = ""
        if decisions:
            d = decisions.get(fid, "pending")
            status = (f" {_GREEN}[✓]{_RESET}" if d == "accept"
                      else f" {_RED}[✗]{_RESET}" if d == "reject"
                      else f" {_DIM}[?]{_RESET}")

        print(f"  {_BOLD}[{fid}]{_RESET}{status} "
              f"{sev_color}{sev}{_RESET} · {_CYAN}{vuln}{_RESET}")
        print(f"    {title}")
        print(f"    {_DIM}{ffile}:{line} · confidence:{conf} · phase:{phase}{_RESET}")
        if f.get("payload"):
            print(f"    Payload: {_YELLOW}{f['payload'][:80]}{_RESET}")
        if f.get("reviewer_note"):
            print(f"    Note: {_DIM}{f['reviewer_note']}{_RESET}")
        print()


def _summarize(finding: dict, idx: int) -> dict:
    """Compact summary for interrupt payload."""
    return {
        "id":         finding.get("id", str(idx)),
        "severity":   finding.get("severity", "?"),
        "vuln_type":  finding.get("vuln_type", "?"),
        "title":      finding.get("title", ""),
        "file":       finding.get("file", ""),
        "line":       finding.get("line", 0),
        "confidence": finding.get("confidence", "?"),
    }


def _resolve_ids(arg: str, pending: dict) -> List[str]:
    """Resolve 'all' or space-separated IDs to valid finding IDs."""
    if not arg or arg.lower() == "all":
        return list(pending.keys())
    ids = arg.split()
    valid = [fid for fid in ids if fid in pending]
    invalid = [fid for fid in ids if fid not in pending]
    if invalid:
        print(f"  {_YELLOW}Unknown IDs: {', '.join(invalid)}{_RESET}")
    return valid
