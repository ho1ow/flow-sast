# flow-sast

**Automated whitebox penetration testing pipeline powered by GitNexus, Semgrep, and Claude AI.**

> GitHub: [ho1ow/flow-sast](https://github.com/ho1ow/flow-sast)

Phân tích source code để phát hiện lỗ hổng bảo mật theo quy trình:
**Catalog → Connect → Classification → Claude Agent Verify & Analyze**.

---

## Kiến trúc

```
scan.py --repo <path> --stack <stack> [options]
        ↓
   ┌─────────────────────────────────────────────┐
   │ PRE-PHASE: CONTEXT PARSING                  │
   │                                             │
   │  [Claude - context_parser()]                │
   │  --context FILE                             │
   │  → đọc raw text, gỡ rối, trích xuất:        │
   │  → business_ctx.json                        │
   │      ├─ custom_sinks[]                      │
   │      ├─ custom_sources[]                    │
   │      ├─ sensitive_flows[]                   │
   │      ├─ non_http_sources[]                  │
   │      └─ business_notes                      │
   └──────────────────────────┬──────────────────┘
                              ↓
   ┌─────────────────────────────────────────────┐
   │ PHASE 1: CATALOG                            │
   │                                             │
   │  [No LLM]              [Claude-guided]      │
   │  semgrep_runner()      gitnexus_context()   │
   │  + non_http_sources    + custom_sinks       │
   │  → sources.json        + sensitive_flows    │
   │  → sinks.json          → read entry points, │
   │                          service layers,    │
   │  api_parser()            custom helpers     │
   │  → endpoints.json      → Claude generates   │
   │                          Cypher queries     │
   │  secrets_runner()      gitnexus_runner()    │
   │  → secrets.json        → custom_sinks.json  │
   │                        → custom_sources.json│
   └──────────────────────────┬──────────────────┘
                              ↓
   ┌─────────────────────────────────────────────┐
   │ PHASE 2: CONNECT                            │
   │                                             │
   │  [Claude-guided]                            │
   │  gitnexus_connect()                         │
   │  → Claude nhìn catalog output               │
   │  → generate Cypher path queries             │
   │    (bao gồm custom sinks/sources)           │
   │  → GitNexus trace paths                     │
   │  → candidate_paths.json                     │
   │                                             │
   │  [No LLM]                                   │
   │  gitnexus_fp_filter()  → filtered_paths     │
   │  joern_filter()        → cpg_confirmed      │
   │  triage_score()        → scored_paths       │
   │  checkmarx_seed()      (nếu --checkmarx-sarif)│
   └──────────────────────────┬──────────────────┘
                              ↓
   ┌─────────────────────────────────────────────┐
   │ CLASSIFICATION                              │
   │                                             │
   │  [No LLM]                                   │
   │  known sinks → lookup table                 │
   │  → vuln_type: sqli/rce/lfi/xxe/...          │
   │                                             │
   │  [Claude]                                   │
   │  custom sinks (gitnexus-discovered)         │
   │  → đọc sink name + implementation           │
   │  → gán vuln_type + analyze routing          │
   └──────────────────────────┬──────────────────┘
                              ↓
                    findings.md + findings.json
                      → reports/<run_id>/
```

---

## Yêu cầu hệ thống

### Bắt buộc

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| Python | ≥ 3.11 | |
| Semgrep | ≥ 1.50 | `pip install semgrep` |
| GitNexus | latest | binary `gitnexus` phải có trong PATH |
| Anthropic API Key | — | Yêu cầu `anthropic` package cho Claude AI context extraction |

### Tùy chọn (tăng độ chính xác)

| Thành phần | Ghi chú |
|---|---|
| Joern | Cần cấu hình Docker nếu muốn filter CPG (`joern_filter.py`) |
| Gitleaks | `brew install gitleaks` hoặc download binary cho hardcoded secrets |
| Checkmarx | SARIF output file để boost scoring |

---

## CLI Interface

```bash
# Cơ bản
python scan.py --repo /path/to/target --stack laravel

# Có Checkmarx seed
python scan.py --repo /path --stack php --checkmarx-sarif ./cx.sarif

# Không có Joern
python scan.py --repo /path --stack django --no-joern

# Tự load context nghiệp vụ từ file
python scan.py --repo /path --stack java --context business.md
```

**Flags:**

| Flag | Mặc định | Mô tả |
|---|---|---|
| `--repo PATH` | bắt buộc | Source code path |
| `--stack STACK` | `auto` | Tech stack (VD: php, python, node, java, go) |
| `--context FILE` | None | Business context file (.md/.txt) để feed cho Claude |
| `--no-joern` | False | Bỏ qua Joern filter |
| `--checkmarx-sarif FILE` | None | Checkmarx seed (SARIF file format) |

---

## Cấu trúc output

Tool xuất findings ra thư mục `reports/<run_id>/`:
- `findings.json`: Metadata chi tiết (source, sink, call chains, path_decision, vuln_type).
- `findings.md`: Dạng human-readable và AI-readable tóm tắt các phát hiện bảo mật.
- `catalog.json`: Tổng hợp endpoints, custom sinks/sources từ Phase 1.
- `business_ctx.json`: (Nếu có `--context`) Chứa nội dung Business context để Agent dùng ở phase phân tích sâu.

---

## Claude Code Agent Integration

`flow-sast` hoạt động hoàn hảo cùng với **Claude Code**. 
Trong thư mục gốc của project, file `CLAUDE.md` đã được cài đặt sẵn. File này hướng dẫn cho Agent cách đọc `reports/`, cách phân tích sâu, và các bước trace luồng data (Verify -> Analyze -> Confirm).

Trong thư mục `skills/` có sẵn các quy tắc Security phân rã thành từng mảnh:
- `authz_skill.md`
- `business_logic_skill.md`
- `hardcode_skill.md`
- `server_side_skill.md`
- `client_side_skill.md`
- `system_context_skill.md`

Sau khi bạn chạy `scan.py`, chỉ cần gọi Claude Code: "verify and analyze findings.md"

## Toàn trình flow-sast + Claude Code

```text
               YOU
                │  "verify and analyze findings.md"
                ▼
        ┌───────────────┐  ← reports/ findings.md, business_ctx.json
        │  Claude Code  │
        └───────┬───────┘
                │ (Đọc CLAUDE.md + skills/)
        ┌───────┴───────────────┬──────────────────────┐
        ▼                       ▼                      ▼
 ┌─────────────┐         ┌────────────┐        ┌──────────────┐
 │   PHASE 3   │         │  PHASE 4   │        │   PHASE 5    │
 │   VERIFY    │  ────►  │  ANALYZE   │  ────► │   CONFIRM    │
 └─────────────┘ (HIGH/  └────────────┘ (Tạo   └──────────────┘
  Đọc full code    MED)  - XSS/SSRF      PoC)  - Burp MCP
  Check taint            - SQLi/RCE            (Dynamic test)
  Check bypass           - Business Logic      - Attach evidence
```

Claude đóng vai trò là não bộ điều phối (orchestrator), tự động đọc code, reasoning, sinh payload và exploit.


---

## License

MIT License — [ho1ow/flow-sast](https://github.com/ho1ow/flow-sast)
