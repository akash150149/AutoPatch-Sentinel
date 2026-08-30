# AutoPatch Sentinel 🛡️⚡

> **Automated Vulnerability Find → Patch → Prove Pipeline**
>
> An end-to-end security automation pipeline that discovers memory safety vulnerabilities
> in C/C++ services, generates minimal AI-driven patches, and **proves the fix holds**
> through a rigorous 3-stage verification harness.
> 
> Now with **Stage 0 Static Analysis (SAST)** and a **Tactical Web Command Center** for live visual demos.

---

## 🏆 Key Differentiator

Most automated patching tools stop at *generating* a diff. **AutoPatch Sentinel proves the fix works** before reporting it as complete — and now independently confirms it with static analysis *before* fuzzing even begins:

| Tool | Static Analysis | Find Bug | Generate Patch | Verify Fix |
|------|----------------|----------|---------------|-----------|
| Typical LLM patcher | ❌ | ✅ | ✅ | ❌ |
| **AutoPatch Sentinel** | ✅ | ✅ | ✅ | ✅ ✅ ✅ |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 0: Static Analysis (SAST Pre-screening)                              │
│  cppcheck + clang-tidy — independently flags bugs before any fuzzing       │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │ Static Findings (CWE IDs, line numbers)
                             ▼
Compile ASan ──► Fuzz (Dynamic) ──► Crash Found ──► Triage Engine
                                                          │
                                              ┌───────────▼────────────┐
                                              │  Static + Dynamic       │
                                              │  Correlation            │
                                              │  "Flagged at line X    │
                                              │   by SAST, confirmed   │
                                              │   exploitable at        │
                                              │   runtime via ASan"    │
                                              └───────────┬────────────┘
                                                          │
                                                    LLM Patching
                                                          │
                                            ┌─────────────▼──────────────────────────────┐
                                            │  Prove the Fix Holds (Verification Gate)   │
                                            │  Stage 1: Crash Invalidation               │
                                            │  Stage 2: Regression Suite                 │
                                            │  Stage 3: Re-Fuzzing Burst                 │
                                            └─────────────┬──────────────────────────────┘
                                                          │
                                              Fail? → Feed error back to LLM (retry ≤ 3)
                                              Pass? → Generate structured audit report ✅
```

---

## 🎯 Target: Telemetry Packet Parser

The demo target models a **military/avionics UAV telemetry protocol** — a TLV (Type-Length-Value) sensor packet parser with two intentional vulnerabilities:

### Bug 1 — CWE-122: Heap Buffer Overflow *(Primary Demo Bug)*

**File:** [`targets/telemetry_parser/telemetry_parser.c`](targets/telemetry_parser/telemetry_parser.c) — Line 111

```c
// field_len comes directly from the attacker's network packet
field->data = (uint8_t *)malloc(MAX_PAYLOAD_SIZE);  // allocates 256 bytes
memcpy(field->data, ptr, field_len);                 // ← VULNERABLE: field_len can be 512+
```

An attacker sends a packet with `field_len = 512`. The `memcpy` writes 512 bytes into a 256-byte heap allocation → **heap-buffer-overflow** → crash / potential code execution.

**ASan detection:** `WRITE of size 512` past a `256-byte region`.  
**SAST detection:** `cppcheck` flags `bufferAccessOutOfBounds [CWE-122]` at line 111 **before fuzzing**.

---

### Bug 2 — CWE-190: Integer Overflow

**File:** [`targets/telemetry_parser/telemetry_parser.c`](targets/telemetry_parser/telemetry_parser.c) — `calc_alloc_size()`

```c
// uint16_t arithmetic: 512 × 256 = 131072 → wraps to 0
uint16_t result = count * element_size;  // ← integer overflow
return (size_t)result;                   // returns 0 → malloc(0) → tiny allocation
```

---

## 📁 Project Structure

```
Cybersec/
├── targets/
│   ├── telemetry_parser/
│   │   ├── telemetry_parser.c       ← Vulnerable C parser (BUG-1, BUG-2)
│   │   ├── telemetry_parser.h       ← Packet structs & public API
│   │   ├── fuzzer_harness.cc        ← libFuzzer / AFL++ entrypoint
│   │   ├── Makefile                 ← Build recipes (asan/libfuzzer/afl/standalone)
│   │   ├── generate_seeds.py        ← Creates binary test packets
│   │   └── tests/
│   │       ├── valid_gps_pkt.bin    ← Valid GPS frame (Stage 2 regression test)
│   │       ├── valid_temp_pkt.bin   ← Valid temperature frame
│   │       └── valid_multi_pkt.bin  ← Multi-field TLV frame
│   └── seeds/
│       ├── crash_overflow.bin       ← Crashing input (512-byte oversized field)
│       ├── valid_gps.bin            ← Fuzzer corpus seed
│       └── minimal_header.bin       ← Minimal valid header
│
├── crashes/                         ← Captured crash inputs & ASan logs
├── patches/                         ← LLM-generated unified diffs (all attempts)
├── reports/                         ← Markdown + JSON audit reports
│
├── src/
│   ├── orchestrator.py              ← Main pipeline loop (7 stages) + pipeline_state event bus
│   ├── compiler.py                  ← Clang + ASan/UBSan build automation
│   ├── fuzzer.py                    ← libFuzzer / AFL++ / seed-replay controller
│   ├── sast.py                      ← [NEW] Stage 0: cppcheck + clang-tidy wrapper
│   ├── triage.py                    ← ASan/UBSan log parser → structured CrashReport (+ SAST correlation)
│   ├── llm_patcher.py               ← LLM integration (Gemini/Claude/OpenAI/Ollama)
│   ├── verifier.py                  ← 3-stage verification harness
│   └── reporter.py                  ← Markdown + JSON audit report generator (+ SAST section)
│
├── web/                             ← [NEW] Tactical Web Command Center
│   ├── app.py                       ← FastAPI backend (status/run/reset/reports endpoints)
│   ├── __init__.py
│   └── static/
│       ├── index.html               ← Single-page mission control dashboard
│       ├── app.css                  ← Cyberpunk dark-mode CSS
│       └── app.js                   ← 1s polling, DOM updates, diff renderer
│
├── tests/
│   ├── test_triage.py               ← 21 unit tests for ASan log parser
│   ├── test_patch_applicator.py     ← 11 unit tests for diff applicator
│   └── test_sast.py                 ← [NEW] 20 unit tests for SAST module
│
├── config.yaml                      ← Pipeline configuration (incl. sast: and web: blocks)
├── requirements.txt                 ← Python dependencies (incl. fastapi, uvicorn)
└── README.md
```

---

## ⚙️ Prerequisites

| Tool | Purpose | Install |
|------|---------|---------| 
| **clang** (≥ 12) | Compile with ASan/UBSan | `sudo apt install clang` (WSL) |
| **cppcheck** | Stage 0 SAST static analysis | `sudo apt install cppcheck` (WSL) |
| **clang-tidy** | Stage 0 SAST supplementary checks | `sudo apt install clang-tools` (WSL) |
| **Python 3.10+** | Pipeline orchestration | Pre-installed on Ubuntu/WSL |
| **Gemini API key** | LLM patch generation (recommended) | [aistudio.google.com](https://aistudio.google.com) |
| **Ollama** (optional, local) | LLM patch generation offline | [ollama.com](https://ollama.com) |
| **WSL (Ubuntu)** | Linux environment on Windows | Windows Store |

---

## 🚀 Quick Start

### 1. Install System Dependencies (WSL)

```bash
sudo apt update && sudo apt install -y clang clang-tools cppcheck build-essential python3-pip
```

### 2. Install Python Dependencies (WSL)

```bash
cd /mnt/d/Cybersec
pip install -r requirements.txt
```

### 3. Set LLM API Key

```bash
# Gemini (recommended — free tier available)
export GEMINI_API_KEY="your-gemini-api-key"

# Or Claude
export ANTHROPIC_API_KEY="your-key"

# Or OpenAI
export OPENAI_API_KEY="your-key"

# Permanent: add to ~/.bashrc
echo 'export GEMINI_API_KEY="your-key"' >> ~/.bashrc && source ~/.bashrc
```

### 4. Launch the Tactical Web Command Center

```bash
cd /mnt/d/Cybersec
python3 -m web.app
```

Open your browser to **`http://localhost:8000`**, configure the pipeline, and click **⚡ Engage Pipeline**.

### 5. Or Run via CLI

```bash
python3 -m src.orchestrator \
  --target telemetry_parser \
  --provider gemini \
  --model gemini-2.0-flash \
  --mode seed_replay
```

---

## 🔁 Pipeline Stages

| Step | Module | What Happens |
|------|--------|-------------|
| **0. Static Analysis (SAST)** | `sast.py` | Runs `cppcheck` + `clang-tidy` on source; flags CWE-122, CWE-190 **before** fuzzing |
| **1. Build** | `compiler.py` | Compiles target with `-fsanitize=address,undefined` |
| **2. Fuzz** | `fuzzer.py` | Replays seeds / runs libFuzzer; captures crash + ASan log |
| **3. Triage** | `triage.py` | Parses ASan output → error type, CWE, crash line; correlates with SAST findings |
| **4. Patch** | `llm_patcher.py` | Sends static+dynamic context to LLM; receives unified diff; applies it |
| **5. Rebuild** | `compiler.py` | Recompiles patched source with ASan |
| **6. Verify** | `verifier.py` | Runs 3 verification stages; feeds failures back to LLM |
| **7. Report** | `reporter.py` | Generates Markdown + JSON audit report with SAST correlation section |

> **Stage 0 skip:** Use `--no-sast` flag to skip static analysis if tools are not installed.

---

## ✅ Verification Stages (The Key Innovation)

| Stage | Input | Pass Condition |
|-------|-------|---------------|
| **Stage 1: Crash Invalidation** | Original crashing packet | Exit 0, zero ASan errors |
| **Stage 2: Regression Suite** | All `valid_*.bin` test packets | All exit 0, parse correctly |
| **Stage 3: Re-Fuzzing Burst** | All seeds against patched binary | Zero new crashes |

All three must pass. If any fails → the error is fed back to the LLM for a corrected patch (up to `--max-retries` attempts).

---

## 🌐 Tactical Web Command Center

The Web Command Center provides a **real-time visual pipeline dashboard** for live demonstrations.

### Launch

```bash
# From project root (inside WSL)
python3 -m web.app

# Then open in Windows browser
http://localhost:8000
```

### Dashboard Features

| Panel | What it shows |
|-------|--------------|
| **Stage Progress Bar** | Animated 8-stage pipeline progress (SAST → Build → Fuzz → Triage → Patch → Rebuild → Verify → Report) |
| **SAST Pre-screening Card** | cppcheck findings with CWE tags and line numbers |
| **Dynamic Crash Card** | ASan error type, severity badge, crash location, raw trace |
| **LLM Patch Diff Viewer** | Syntax-highlighted unified diff (green additions, red deletions) |
| **3 Verification Gate Cards** | Gates light up sequentially: ⚪ waiting → 🟡 running → 🟢 pass / 🔴 fail |
| **Audit Reports List** | Links to generated Markdown and JSON reports |
| **Terminal Log Streamer** | Live pipeline events |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/api/status` | GET | Current pipeline state (polled every 1s) |
| `/api/run` | POST | Start pipeline with target/provider/mode options |
| `/api/reset` | POST | Reset state for a fresh demo run |
| `/api/reports` | GET | List all generated audit reports |
| `/api/reports/{name}` | GET | Read a specific report (MD or JSON) |

---

## 🤖 LLM Support

| Provider | Recommended Model | Set Up |
|----------|------------------|--------|
| **Google Gemini** *(recommended)* | `gemini-2.0-flash` | `export GEMINI_API_KEY=...` |
| **Anthropic Claude** | `claude-3-5-haiku-20241022` | `export ANTHROPIC_API_KEY=...` |
| **OpenAI** | `gpt-4o-mini` | `export OPENAI_API_KEY=...` |
| **Ollama** *(local, free)* | `llama3.2`, `codellama` | `ollama serve` + `ollama pull llama3.2` |

> **WSL + Ollama Note:** When running the pipeline inside WSL with Ollama on Windows, Ollama must be configured to listen on all interfaces: `$env:OLLAMA_HOST="0.0.0.0"; ollama serve` in Windows PowerShell.

```bash
# CLI examples
python3 -m src.orchestrator --provider gemini --model gemini-2.0-flash
python3 -m src.orchestrator --provider claude --model claude-3-5-haiku-20241022
python3 -m src.orchestrator --provider ollama --model llama3.2 --no-sast
```

---

## 🧪 Running Tests

```bash
# Run full test suite (works in WSL or Windows PowerShell)
cd /mnt/d/Cybersec
pytest tests/ -v

# Expected: 52+ tests passed
#   test_triage.py         — 21 tests: ASan log parser
#   test_patch_applicator.py — 11 tests: diff applicator
#   test_sast.py           — 20 tests: SAST XML parser, correlation, graceful fallback
```

---

## 📊 Sample Audit Report Output

```markdown
## 1. Executive Summary

| Field          | Value                                         |
|----------------|-----------------------------------------------|
| Target         | telemetry_parser                              |
| Vulnerability  | heap-buffer-overflow                          |
| CWE            | CWE-122 (Heap-based Buffer Overflow)          |
| Severity       | 🔴 CRITICAL                                   |
| Crash Location | parse_tlv_payload() @ telemetry_parser.c:111  |
| Fix Status     | ✅ Verified                                   |
| LLM Attempts   | 1                                             |

## 2b. Static Analysis Pre-Screening (SAST)

> ⚠️ 1 static finding correlated with the crash site — root cause flagged by
> static analysis AND confirmed exploitable at runtime.

| Tool      | Severity | CWE     | Message                         | Line |
|-----------|----------|---------|---------------------------------|------|
| cppcheck  | error    | CWE-122 | Buffer access out-of-bounds ... | 111  |

> Static → Dynamic confirmation: warning at line 111 matches ASan crash at telemetry_parser.c:111.

## 5. Verification Evidence

| Stage                         | Result  |
|-------------------------------|---------|
| Stage 1: Crash Invalidation   | ✅ PASS |
| Stage 2: Regression Suite     | ✅ PASS |
| Stage 3: Re-Fuzzing Burst     | ✅ PASS |
```

---

## 🐛 Troubleshooting

| Error | Fix |
|-------|-----|
| `clang: not found` | `sudo apt install clang` in WSL |
| `cppcheck not found in PATH` | `sudo apt install cppcheck` — or use `--no-sast` to skip |
| `ModuleNotFoundError: fastapi` | `pip install -r requirements.txt` |
| `Neither clang nor gcc found` | Pipeline must run in WSL, not Windows PowerShell |
| `Ollama connection refused` | Set `OLLAMA_HOST=0.0.0.0` in Windows before `ollama serve` |
| `404 models/llama3.2 not found` | Wrong model name for the provider — check the Model field in the dashboard matches your provider |
| `No such file: telemetry_parser_asan` | Run pipeline via the web server or `make asan` first |
| `No crashes found` | Run `python3 targets/telemetry_parser/generate_seeds.py` first |
| `externally-managed-environment` | Use venv: `python3 -m venv .venv && source .venv/bin/activate` |

---

## 🔒 Security Notice

The vulnerable target (`telemetry_parser.c`) contains **intentional memory safety bugs** for demonstration purposes. It is designed to be run in an isolated environment only. Do not deploy it in any production or network-accessible context.

---

*AutoPatch Sentinel — Automated Vulnerability Remediation Pipeline*  
*Static Analysis · Dynamic Fuzzing · AI-Driven Patching · 3-Stage Verification*
