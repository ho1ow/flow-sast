# Security Audit Skill — flow-sast

## Trigger
When asked to verify, analyze, or audit findings from a `findings.md` or `findings.json` file.

## Context: source_type và sink_type
Mỗi finding có metadata:
- `source_type: semgrep` → source từ known ruleset, pattern rõ ràng
- `source_type: gitnexus` → source do Claude discover qua Cypher, có thể là
  non-HTTP (queue, DB read, WebSocket) — cần trace kỹ hơn
- `sink_type: known` → sink framework standard
- `sink_type: custom` → sink custom wrapper — cần đọc implementation của wrapper đó

---

## Phase 3: Verify

### Goal
Eliminate false positives before deep analysis.
Read the actual source code for each finding. Do NOT rely solely on findings.md snippets.

### For each finding, verify:

**1. Sanitizer check**
- Trace the call chain in full source code
- Look for: htmlspecialchars, prepared statements, parameterized queries,
  intval/floatval casts, strip_tags, addslashes, custom validation functions
- If sanitizer found AND applied before sink → mark as FALSE_POSITIVE, skip

**2. Full data flow verify**
- Follow the source variable through all intermediate functions
- Check if source is ever reassigned to a safe value before reaching sink
- Check if sink is behind an auth middleware or permission gate
  (for authz findings: IDOR, BFLA)

**3. Object taint trace** (for object/property-based findings)
- If source is an object property (e.g. `$user->name`), trace where the object
  was populated from
- Check if population point applied validation

**4. Custom sink/source extra check** (khi sink_type hoặc source_type = "gitnexus")
- Đọc implementation của custom sink/source wrapper
- Xác nhận wrapper không có internal sanitization
- Với non-HTTP sources: xác nhận data origin (queue message, DB row, env var)
  có thể bị attacker control không

### Confidence gate routing:
- HIGH confidence (clear taint path, no sanitizer) → proceed to Analyze
- MEDIUM confidence (sanitizer present but bypassable, or indirect path) →
  note the bypass vector, proceed to Analyze with caveat
- LOW confidence (sanitizer correctly applied, or no real taint) →
  mark FALSE_POSITIVE, skip Analyze

### Output per finding:
```
Finding #<id>: <CONFIRMED|FALSE_POSITIVE|UNCERTAIN>
Confidence: HIGH|MED|LOW
Reason: <1-2 sentences>
Bypass vector (if MED): <specific bypass>
```

---

## Phase 4: Analyze

### Goal
For each CONFIRMED or UNCERTAIN finding, perform deep vulnerability analysis
using the appropriate skill below.

### Before analyzing any finding
If business_ctx.json or --context file exists in the project:
1. Read system_context_skill.md first
2. Load business_ctx.json (auto-generated from --context file during scan)
3. Keep this context active for ALL findings in this session — do not reload per finding

Business context affects:
- Severity rating (e.g. unauthenticated endpoint → escalate to CRITICAL)
- Impact description (e.g. "attacker can charge arbitrary amounts via PaymentGateway")
- Pre-conditions (e.g. "exploitable without auth via /webhook/payment")

### Routing by vuln_type:

| vuln_type | Skill to apply |
|---|---|
| sqli, ssti, xxe, lfi, rce, deserialize | → server_side_skill |
| xss, ssrf, redirect, crlf, csti | → client_side_skill |
| idor, bfla, jwt, mass_assign, priv_esc | → authz_skill |
| race, state_bypass, neg_value, trust_abuse | → business_logic_skill |
| secrets, weak_crypto, disabled_tls | → hardcode_skill |

### Apply skill = read the corresponding skill file, then:
1. Perform the analysis steps defined in that skill
2. Construct a concrete PoC payload or test case
3. Identify exact parameters, headers, or body fields to manipulate
4. Estimate CVSS score (rough: CRITICAL/HIGH/MED/LOW)

### Output per finding:
```
Finding #<id> — <vuln_type> ANALYSIS
Severity: CRITICAL|HIGH|MED|LOW
Attack vector: <specific HTTP request or code path>
PoC payload: <exact payload or pseudocode>
Pre-conditions: <auth required? specific role? specific state?>
Impact: <what an attacker can achieve>
Remediation: <specific fix, not generic advice>
```

---

## Phase 5: Confirm (if Burp MCP available)

For each analyzed finding with a concrete PoC:

1. Use Burp MCP to send the PoC request to the target
2. Check response for: error messages, unexpected data, timing differences
3. If confirmed → mark `poc_confirmed: true`, attach HTTP evidence
4. If not confirmed → note why (WAF? different env? pre-condition not met?)

If Burp MCP is not connected, skip Phase 5 and note findings as
"static analysis only — dynamic confirmation pending".

---

## Workflow command

When user says: "verify and analyze findings.md"

1. Read findings.md (or findings.json)
2. For each finding, run Phase 3 (Verify)
3. Print verify results, ask user: "Proceed to analyze X confirmed findings?"
4. On confirmation, run Phase 4 (Analyze) for confirmed findings
5. Ask: "Run Burp confirmation?" → Phase 5 if yes
6. Output final report

Do NOT run all phases silently without user confirmation between phases.
Human review between Verify and Analyze is intentional.
