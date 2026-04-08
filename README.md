# flow-sast

**Automated whitebox penetration testing pipeline powered by LangGraph + Claude AI.**

> GitHub: [ho1ow/flow-sast](https://github.com/ho1ow/flow-sast)

Phân tích source code để tự động phát hiện lỗ hổng bảo mật theo quy trình:
Catalog → Connect → Verify → **Analyze** → **Human Review ⏸** → Confirm → Report.

---

## Mục lục

- [Kiến trúc](#kiến-trúc)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt](#cài-đặt)
- [Cấu hình](#cấu-hình)
- [Chạy pipeline](#chạy-pipeline)
- [Human Review Gate](#human-review-gate)
- [Output](#output)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [Troubleshooting](#troubleshooting)

---

## Kiến trúc

```
Source code
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 1: CATALOG (song song)                        │
│  ┌─────────────┐ ┌───────────────┐ ┌─────────────┐  │
│  │   Semgrep   │ │    GitNexus   │ │  API Parser │  │
│  │ (taint rule)│ │ (query+ctx)   │ │ (endpoints) │  │
│  └─────────────┘ └───────────────┘ └─────────────┘  │
│  ┌─────────────┐ ┌───────────────┐                  │
│  │  Gitleaks   │ │GitNexus Ctx   │                  │
│  │  (secrets)  │ │(business ctx) │ ◄── --context    │
│  └─────────────┘ └───────────────┘                  │
│  → sources.json + sinks.json + endpoints.json        │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│  PHASE 2: CONNECT                                    │
│  path_structural + path_object (GitNexus Cypher)     │
│         ↓                                            │
│  triage_score (threshold ≥ 6)                        │
│         ↓                                            │
│  gitnexus_fp_filter  ← pattern-based FP filter       │
│         ↓                                            │
│  joern_pre_filter    ← CPG/CFG taint confirm         │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│  PHASE 3: VERIFY (loop per path)                     │
│  enricher → claude_verifier                          │
│  confidence_gate:                                    │
│    HIGH  → analyze   MED → retry   LOW → skip        │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│  PHASE 4: ANALYZE (parallel fan-out)                 │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │server_agent│ │client_agent│ │  authz_agent     │ │
│  │SQLi/RCE/   │ │XSS/SSRF/  │ │ IDOR/BFLA/JWT/   │ │
│  │LFI/XXE/    │ │Redirect/  │ │ MassAssign       │ │
│  │SSTI/Deser  │ │CRLF/CSTI  │ └──────────────────┘ │
│  └────────────┘ └────────────┘                      │
│  ┌────────────────────┐ ┌──────────────────────────┐│
│  │  biz_logic_agent   │ │    hardcode_agent        ││
│  │Race/StateMachine/  │ │Secrets/WeakCrypto/       ││
│  │NegValue/TrustAbuse │ │DisabledTLS               ││
│  └────────────────────┘ └──────────────────────────┘│
└────────────────────────┬────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │  ⏸ HUMAN REVIEW    │  ← pause, hiện findings
              │  human_review_gate  │  ← accept / reject / note
              │  (skip: --no-review)│
              └──────────┬──────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│  PHASE 5: CONFIRM + FEEDBACK                         │
│  confirm_burp  ← dynamic PoC via Burp Suite MCP     │
│  feedback_expand ← GitNexus sibling vuln search      │
└────────────────────────┬────────────────────────────┘
                         │
                   reports/<run_id>/
              findings.json + output.sarif
```

---

## Yêu cầu hệ thống

### Bắt buộc

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| Python | ≥ 3.11 | |
| Semgrep | ≥ 1.50 | `pip install semgrep` |
| GitNexus | latest | binary `gitnexus` phải có trong PATH |
| Anthropic API Key | — | Claude claude-sonnet-4-5+ |

### Tùy chọn (tăng độ chính xác)

| Thành phần | Ghi chú |
|---|---|
| Docker + Docker Compose | Chạy Joern REST server (CFG analysis) |
| Burp Suite Pro + MCP | Dynamic PoC verification (Phase 5) |
| Gitleaks | `brew install gitleaks` hoặc download binary |

---

## Cài đặt

### 1. Clone repo

```bash
git clone https://github.com/ho1ow/flow-sast.git
cd flow-sast
```

### 2. Tạo virtual environment

```bash
python -m venv .venv

# Linux / macOS / WSL
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### 3. Cài dependencies

```bash
pip install -r requirements.txt
```

### 4. Cài Semgrep

```bash
pip install semgrep
# Hoặc xem: https://semgrep.dev/docs/getting-started/
```

### 5. Cài GitNexus

```bash
# Theo hướng dẫn chính thức của GitNexus
# Kiểm tra binary:
gitnexus --version
```

### 6. (Tùy chọn) Khởi động Joern

```bash
cd docker/
docker-compose up -d joern

# Kiểm tra health
curl http://localhost:8080/api/v1/version
```

---

## Cấu hình

### Bước 1 — Tạo file secrets (`.env`)

```bash
cp .env.example .env
```

Mở `.env` và điền giá trị thật:

```ini
ANTHROPIC_API_KEY=sk-ant-api03-...
BURP_MCP_API_KEY=your-burp-key          # Bỏ qua nếu không dùng Burp
BURP_MCP_BASE_URL=http://localhost:1337
JOERN_BASE_URL=http://localhost:8080     # Bỏ qua nếu không dùng Joern
```

> ⚠️ **Không bao giờ commit `.env`** — đã được gitignore.

### Bước 2 — Điều chỉnh `tools_config.json` (tùy chọn)

```json
{
  "anthropic": {
    "model": "claude-sonnet-4-5",
    "max_concurrency": 3
  },
  "pipeline": {
    "triage_threshold": 6,
    "max_paths_per_run": 200,
    "no_review": false
  }
}
```

> `tools_config.json` đã gitignore. Dùng `tools_config.json.env` làm template.

---

## Chạy pipeline

### Cú pháp cơ bản

```bash
python main.py --repo /path/to/target-repo --stack <stack>
```

### Các stack hỗ trợ

```
php        laravel    symfony    codeigniter
python     django     flask      fastapi
node       express    nestjs
java       spring
go         gin
ruby       rails
auto       # Tự detect dựa trên file extensions
```

### Ví dụ

```bash
# Laravel project
python main.py --repo /projects/shopify-clone --stack laravel

# Django, không cần Joern
python main.py --repo /projects/django-app --stack django --no-joern

# Cung cấp mô tả nghiệp vụ thủ công (overrides auto-detect từ README)
python main.py --repo /projects/ecom --stack laravel --context context.md

# CI/CD mode — bỏ qua human review, chạy fully unattended
python main.py --repo /projects/app --stack php --no-review

# Dry run — chỉ chạy CATALOG, không gọi Claude
python main.py --repo /projects/app --stack php --dry-run

# Resume từ checkpoint (khi pipeline bị interrupt)
python main.py --repo /projects/app --stack php --resume
```

### Tất cả flags

| Flag | Mặc định | Mô tả |
|---|---|---|
| `--repo PATH` | bắt buộc | Đường dẫn đến source code |
| `--stack STACK` | `auto` | Tech stack |
| `--context FILE` | None | File .md/.txt mô tả nghiệp vụ hệ thống (optional) |
| `--config FILE` | `tools_config.json` | File config JSON |
| `--no-joern` | False | Bỏ qua Joern CFG filter |
| `--no-burp` | False | Bỏ qua Burp MCP confirm |
| `--no-review` | False | Bỏ qua Human Review Gate (CI/CD mode) |
| `--checkmarx-sarif FILE` | None | Checkmarx SARIF output làm seed (optional) |
| `--dry-run` | False | Chỉ chạy catalog, không gọi AI |
| `--resume` | False | Resume từ checkpoint |
| `--run-id ID` | auto | Custom run ID |
| `--output DIR` | `reports/<run_id>` | Output directory |

---

## Checkmarx Integration (optional)

Nếu client đã có Checkmarx, dùng output làm **seed** cho flow-sast để tìm những gì CX miss.

```bash
# Checkmarx SARIF làm seed
python main.py --repo /path --stack php \
               --checkmarx-sarif ./cx_results.sarif
```

### Checkmarx seed được dùng như thế nào

| Phase | Cách dùng | Token cost |
|---|---|---|
| **CATALOG** | Seed known sources/sinks từ CX findings; custom sinks CX đã phát hiện | Zero |
| **CONNECT** | Boost triage score cho paths match với CX locations (`+2` per match) | Zero |
| **VERIFY/ANALYZE** | **Không dùng** — Claude chỉ thấy code, không thấy CX labels | Zero |

### Tại sao không inject CX vào Claude?

> **Claude cần đưa ra independent judgment.** Nếu inject CX findings vào prompt, Claude sẽ anchoring vào CX’s label thay vì tự phân tích code.
>
> flow-sast tập trung vào những gì CX miss — **business logic, object taint, custom wrapper sinks**.
> CX chỉ giúp uu tiên hóa paths đã biết, không giới hạn phân tích.

### Output khi dùng `--checkmarx-sarif`

```
  ▶ Checkmarx seed loaded:
    Total findings : 142
    Locations      : 287
    Custom sinks   : 18
    By severity    : CRITICAL:23 | HIGH:61 | MED:58
    Top types      : sqli:45 | xss:38 | rce:21 | path_traversal:15 | idor:12
  ℹ Note: CX seed used for prioritization only — NOT in Claude context
```

### Boost scoring

- Source location match CX finding: **+2 points**
- Sink location match CX finding: **+2 points**  
- Source + Sink cùng vuln type trong CX: **+1 point**
- Nhõing paths không có trong CX vẫn được phân tích đầy đủ để catch what CX missed

---

## Human Review Gate

Sau khi 5 agents phân tích xong, pipeline **tự động pause** và hiện tất cả findings để user review trước khi chuyển sang Phase 5 (Burp Suite confirm).

```
────────────────────────────────────────────────────────────
  🔍 flow-sast — Human Review Gate
  8 finding(s) from analyze phase
────────────────────────────────────────────────────────────

  [f1a2] CRITICAL · sqli
    SQL Injection in UserController::search()
    app/Http/Controllers/UserController.php:42 · confidence:HIGH
    Payload: ' OR 1=1--

  [b3c4] HIGH · idor
    Missing ownership check: Order::find($id) without user filter
    app/Http/Controllers/OrderController.php:87 · confidence:MED

  ...

Commands:
  a <id>      — accept finding (default)
  r <id>      — reject finding (remove from pipeline)
  n <id>      — thêm manual note vào finding
  show        — hiện lại tất cả findings
  done        — accept all remaining và continue
  reject_all  — reject tất cả
  q           — quit

review> r b3c4
  ✗ rejected: b3c4
review> n f1a2
  Note for f1a2: Confirmed, param goes directly to PDO::query()
review> done
  ✓ Review complete: 7 accepted, 1 rejected
```

### Disable review (CI/CD)

```bash
# CLI flag
python main.py --repo /app --stack laravel --no-review

# Hoặc trong tools_config.json
"pipeline": { "no_review": true }
```

---

## Output

### Thư mục output

```
reports/
└── <run_id>/
    ├── findings.json     ← Tất cả findings, đầy đủ metadata
    └── output.sarif      ← SARIF 2.1.0 (import vào VS Code, GitHub)

pentest_logs/
├── checkpoints/          ← Shelve checkpoints (dùng cho --resume)
└── audit_trail/
    └── <run_id>.jsonl    ← Mỗi quyết định của pipeline
```

### Ví dụ finding

```json
{
  "id": "f1a2c3d4",
  "vuln_type": "sqli",
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "title": "SQL Injection in UserController::search()",
  "file": "app/Http/Controllers/UserController.php",
  "line": 42,
  "source": "$_GET['q']",
  "sink": "DB::statement()",
  "call_chain": ["search", "buildQuery", "DB::statement"],
  "payload": "' OR 1=1--",
  "cwe": "CWE-89",
  "owasp": "A03:2021",
  "poc_confirmed": true,
  "reviewer_note": "Confirmed via manual trace",
  "burp_evidence": "HTTP 200 — 150 rows returned"
}
```

### Import SARIF vào VS Code

```bash
code --install-extension ms-sarif.sarif-viewer
code reports/<run_id>/output.sarif
```

---

## Cấu trúc thư mục

```
flow-sast/
├── core/
│   ├── state.py             # PentestState TypedDict (+ business_context)
│   ├── reliability.py       # Checkpoint, retry, audit trail
│   └── workflow.py          # LangGraph graph definition
│
├── phases/
│   ├── _shared/
│   │   ├── sink_catalog.py      # KNOWN_SINKS (single source of truth)
│   │   ├── source_catalog.py    # TAINT_SOURCES per stack
│   │   ├── prompt_loader.py     # Load prompts/*.yaml + skills/*.md (cached)
│   │   ├── finding_builder.py   # Chuẩn hóa finding schema
│   │   └── cpg_registry.py      # Singleton CPG registry cho Joern
│   │
│   ├── 1_catalog/
│   │   ├── semgrep_runner.py    # Semgrep taint analysis
│   │   ├── gitnexus_runner.py   # GitNexus Cypher queries
│   │   ├── gitnexus_context.py  # gitnexus context + doc reading → business_context
│   │   ├── api_parser.py        # Parse endpoints từ framework routes
│   │   └── secrets_runner.py    # Gitleaks secret detection
│   │
│   ├── 2_connect/
│   │   ├── run_structural.py     # GitNexus Cypher structural paths (2a)
│   │   ├── run_object_taint.py   # GitNexus Cypher object taint (2a')
│   │   ├── triage.py             # Scoring (threshold ≥ 6)
│   │   ├── gitnexus_fp_filter.py # Pattern-based FP filter (8 rules)
│   │   ├── joern_filter.py       # CPG/CFG taint confirmation
│   │   ├── joern_client.py       # Joern REST client
│   │   └── queries/              # Cypher query templates
│   │
│   ├── 3_verify/
│   │   ├── enricher.py          # Code context enrichment (50 lines window)
│   │   ├── claude_verifier.py   # 3 templates: sanitizer_check/full_verify/object_trace
│   │   └── router.py            # Confidence gate routing
│   │
│   ├── 4_analyze/
│   │   ├── server_agent.py      # SQLi/RCE/LFI/XXE/SSTI/Deser
│   │   ├── client_agent.py      # XSS/SSRF/Redirect/CRLF/CSTI
│   │   ├── authz_agent.py       # IDOR/BFLA/MassAssign/JWT/PrivEsc
│   │   ├── biz_logic_agent.py   # Race/StateBypass/NegValue/TrustAbuse
│   │   ├── hardcode_agent.py    # Secrets/WeakCrypto/DisabledTLS
│   │   └── human_review.py      # ⏸ Human-in-the-loop (interrupt + CLI session)
│   │
│   └── 5_confirm/
│       ├── burp_mcp_client.py   # Burp Suite MCP dynamic PoC
│       └── feedback_loop.py     # GitNexus sibling vulnerability search
│
├── prompts/
│   ├── agent_skills/            # Skill context files cho mỗi vuln type
│   │   ├── sqli_skill.md
│   │   ├── xss_skill.md
│   │   ├── authz_skill.md
│   │   ├── business_logic_skill.md
│   │   ├── hardcode_skill.md
│   │   ├── server_side_skill.md
│   │   ├── client_side_skill.md
│   │   └── system_context_skill.md
│   ├── verify_prompts.yaml      # Phase 3 templates
│   └── analyze_prompts.yaml     # Phase 4 agent templates (5 agents)
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml       # Joern REST server
│
├── main.py                      # CLI entry point
├── requirements.txt
├── tools_config.json            # Tool config (gitignored)
├── tools_config.json.env        # Config template (committed)
├── .env                         # Secrets (gitignored)
├── .env.example                 # Secrets template (committed)
├── .gitignore
└── README.md
```

---

## Troubleshooting

### Pipeline không tìm thấy gitnexus

```bash
which gitnexus
gitnexus --version

# Nếu không có trong PATH, set trong tools_config.json:
# "gitnexus": { "binary": "/full/path/to/gitnexus" }
```

### Joern không khởi động

```bash
docker-compose -f docker/docker-compose.yml logs joern
docker-compose -f docker/docker-compose.yml restart joern

# Chạy không cần Joern:
python main.py --repo /path --stack php --no-joern
```

### Claude rate limit

```bash
# Giảm concurrency trong tools_config.json:
# "anthropic": { "max_concurrency": 1 }
# Hoặc giảm số paths:
# "pipeline": { "max_paths_per_run": 50 }
```

### Resume sau interrupt

```bash
# Run ID được hiện lúc chạy hoặc tìm trong pentest_logs/checkpoints/
ls pentest_logs/checkpoints/
python main.py --repo /path --stack php --resume --run-id <run_id>
```

### Human review bị skip không mong muốn

```bash
# Kiểm tra tools_config.json có "no_review": true không
# Hoặc đảm bảo không dùng --no-review flag
```

### Import error: Cannot find module

```bash
# Cài dependencies trước
pip install -r requirements.txt

# Pyrefly/Pylance "Cannot find module phases._X..." là static analysis warning
# Modules được resolve runtime qua phases/__init__.py dynamic aliases
# Không phải runtime error
```

### Xem audit trail

```bash
cat pentest_logs/audit_trail/<run_id>.jsonl | python -m json.tool | head -100
```

---

## Biến môi trường

| Biến | Bắt buộc | Mô tả |
|---|---|---|
| `ANTHROPIC_API_KEY` | ✅ | Claude API key |
| `BURP_MCP_API_KEY` | ❌ | Burp Suite MCP key |
| `BURP_MCP_BASE_URL` | ❌ | Burp MCP server URL (default: `http://localhost:1337`) |
| `JOERN_BASE_URL` | ❌ | Joern REST URL (default: `http://localhost:8080`) |

---

## License

MIT License — [ho1ow/flow-sast](https://github.com/ho1ow/flow-sast)
