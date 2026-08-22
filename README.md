# AutoPatch Sentinel 🛡️⚡

> **Automated Vulnerability Find → Patch → Prove Pipeline**
>
> An end-to-end security automation pipeline that discovers memory safety vulnerabilities
> in C/C++ services, generates minimal AI-driven patches, and **proves the fix holds**
> through a rigorous 3-stage verification harness.

---

## 🏆 Key Differentiator

Most automated patching tools stop at *generating* a diff. **AutoPatch Sentinel proves the fix works** before reporting it as complete:

| Tool | Find Bug | Generate Patch | Verify Fix |
|------|----------|---------------|-----------|
| Typical LLM patcher | ✅ | ✅ | ❌ |
| **AutoPatch Sentinel** | ✅ | ✅ | ✅ ✅ ✅ |

---

## 🎯 Live Demo: Confirmed Working

The following crash was captured live during development (see [`crashes/`](crashes/)):

```
==14642==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511000000140
WRITE of size 512 at 0x511000000140 thread T0
    #0 __asan_memcpy
    #1 parse_tlv_payload  telemetry_parser.c:111
    #2 parse_telemetry_frame  telemetry_parser.c:155
    #3 main  telemetry_parser.c:234

0x511000000140 is located 0 bytes after 256-byte region [0x511000000040, 0x511000000140)
SUMMARY: AddressSanitizer: heap-buffer-overflow in __asan_memcpy
```

**Cause:** A 512-byte attacker-controlled field was copied into a 256-byte heap buffer with no bounds check. The pipeline found, patched, and verified the fix autonomously.

---

## 🏗️ Architecture

```
Fuzz → CRASH FOUND ──► Triage ──► LLM Patch ──► Rebuild
                                                    │
                    ┌───────────────────────────────▼────────────────────────────┐
                    │              Prove the Fix Holds (Verification Gate)        │
                    │                                                             │
                    │  Stage 1: Crash Invalidation                               │
                    │    Replay exact crashing input → must execute cleanly      │
                    │                                                             │
                    │  Stage 2: Regression Suite                                 │
                    │    Run all valid test payloads → all must parse correctly  │
                    │                                                             │
                    │  Stage 3: Re-Fuzzing Burst                                 │
                    │    Short re-fuzz burst → no new crashes                   │
                    └───────────────────────────────┬────────────────────────────┘
                                                    │
                    ┌───────────────────────────────▼────────────────────────────┐
                    │  Fail? → Feed error back to LLM (retry ≤ 3 attempts)      │
                    │  Pass? → Generate structured audit report ✅               │
                    └────────────────────────────────────────────────────────────┘
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
│   ├── orchestrator.py              ← Main CLI & end-to-end pipeline loop
│   ├── compiler.py                  ← Clang + ASan/UBSan build automation
│   ├── fuzzer.py                    ← libFuzzer / AFL++ / seed-replay controller
│   ├── triage.py                    ← ASan/UBSan log parser → structured CrashReport
│   ├── llm_patcher.py               ← LLM integration (Gemini/Claude/OpenAI/Ollama)
│   ├── verifier.py                  ← 3-stage verification harness
│   └── reporter.py                  ← Markdown + JSON audit report generator
│
├── tests/
│   ├── test_triage.py               ← 21 unit tests for ASan log parser
│   └── test_patch_applicator.py     ← 11 unit tests for diff applicator
│
├── config.yaml                      ← Pipeline configuration
├── requirements.txt                 ← Python dependencies
└── README.md
```

---

## ⚙️ Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| **clang** (≥ 12) | Compile with ASan/UBSan | `sudo apt install clang` |
| **Python 3.10+** | Pipeline orchestration | Pre-installed on Ubuntu |
| **Ollama** (or cloud API) | LLM patch generation | [ollama.ai](https://ollama.ai) |
| **WSL (Ubuntu)** | Linux environment on Windows | Windows Store |

---

## 🚀 Quick Start

### 1. Install System Dependencies (WSL)

```bash
sudo apt update && sudo apt install -y clang build-essential python3-venv
```

### 2. Set Up Python Environment (WSL)

```bash
cd /mnt/d/Cybersec
python3 -m venv .venv
source .venv/bin/activate
pip install rich pyyaml openai
```

### 3. Generate Seed Files (WSL)

```bash
cd /mnt/d/Cybersec/targets/telemetry_parser
python3 generate_seeds.py
```

### 4. Build the Vulnerable Target (WSL)

```bash
make clean && make asan
```

### 5. Manually Verify the Bug (WSL)

```bash
# Valid packet — should parse cleanly
./telemetry_parser_asan tests/valid_gps_pkt.bin

# Malicious packet — should trigger ASan heap-buffer-overflow
ASAN_OPTIONS=detect_leaks=0 ./telemetry_parser_asan ../seeds/crash_overflow.bin
```

### 6. Run the Full Pipeline (WSL)

```bash
cd /mnt/d/Cybersec
source .venv/bin/activate

python3 src/orchestrator.py \
  --target telemetry_parser \
  --provider ollama \
  --model llama3.2:3b \
  --mode seed_replay \
  --verbose
```

### 7. View Results

```bash
ls reports/      # Markdown + JSON audit reports
ls patches/      # LLM-generated patch diffs
ls crashes/      # Captured crash inputs + ASan logs
```

---

## 🔁 Pipeline Stages

| Step | Module | What Happens |
|------|--------|-------------|
| **1. Build** | `compiler.py` | Compiles target with `-fsanitize=address,undefined` |
| **2. Fuzz** | `fuzzer.py` | Replays seeds / runs libFuzzer; captures crash + ASan log |
| **3. Triage** | `triage.py` | Parses ASan output → error type, CWE, crash line, stack trace |
| **4. Patch** | `llm_patcher.py` | Sends crash context to LLM; receives unified diff; applies it |
| **5. Rebuild** | `compiler.py` | Recompiles patched source with ASan |
| **6. Verify** | `verifier.py` | Runs 3 verification stages; feeds failures back to LLM |
| **7. Report** | `reporter.py` | Generates Markdown + JSON audit report |

---

## ✅ Verification Stages (The Key Innovation)

| Stage | Input | Pass Condition |
|-------|-------|---------------|
| **Stage 1: Crash Invalidation** | Original crashing packet | Exit 0, zero ASan errors |
| **Stage 2: Regression Suite** | All `valid_*.bin` test packets | All exit 0, parse correctly |
| **Stage 3: Re-Fuzzing Burst** | All seeds against patched binary | Zero new crashes |

All three must pass. If any fails → the error is fed back to the LLM for a corrected patch (up to 3 retries).

---

## 🤖 LLM Support

| Provider | Model | Set Up |
|----------|-------|--------|
| **Ollama** (local, free) | `llama3.2:3b`, `codellama` | `ollama serve` |
| Google Gemini | `gemini-2.5-pro` | `export GEMINI_API_KEY=...` |
| Anthropic Claude | `claude-sonnet-4-5` | `export ANTHROPIC_API_KEY=...` |
| OpenAI | `gpt-4o` | `export OPENAI_API_KEY=...` |

```bash
# Examples
python3 src/orchestrator.py --provider ollama --model llama3.2:3b
python3 src/orchestrator.py --provider gemini
python3 src/orchestrator.py --provider claude --max-retries 3
```

---

## 🧪 Running Tests

```bash
# In Windows PowerShell
cd d:\Cybersec
python -m pytest tests/ -v
# Result: 32 passed
```

---

## 📊 Sample Audit Report Output

```
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

## 5. Verification Evidence

┌─────────────────────────────────────┬────────┐
│ Stage 1: Crash Invalidation         │ ✅ PASS │
│ Stage 2: Regression Suite           │ ✅ PASS │
│ Stage 3: Re-Fuzzing Burst           │ ✅ PASS │
└─────────────────────────────────────┴────────┘
```

---

## 🐛 Troubleshooting

| Error | Fix |
|-------|-----|
| `clang: not found` | `sudo apt install clang` in WSL |
| `externally-managed-environment` | Use venv: `python3 -m venv .venv && source .venv/bin/activate` |
| `No such file: telemetry_parser_asan` | Run `make asan` in WSL first |
| `No crashes found` | Run `python3 generate_seeds.py` first |
| Ollama connection refused | Run `ollama serve` (or it's already running — check with `curl localhost:11434`) |
| `ModuleNotFoundError` | Activate venv: `source .venv/bin/activate` |

---

## 🔒 Security Notice

The vulnerable target (`telemetry_parser.c`) contains **intentional memory safety bugs** for demonstration purposes. It is designed to be run in an isolated environment only. Do not deploy it in any production or network-accessible context.

---

*AutoPatch Sentinel — Automated Vulnerability Remediation Pipeline*
