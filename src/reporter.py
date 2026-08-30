"""
src/reporter.py
AutoPatch Sentinel - Audit Report Generator

Generates structured vulnerability mitigation reports in:
  - Markdown (human-readable, for judges / stakeholders)
  - JSON (machine-readable, for CI integration)

Report sections:
  1. Executive Summary
  2. Vulnerability Details (CWE, severity, location)
  3. Root Cause Analysis (from LLM explanation)
  4. Patch Diff (unified diff with syntax highlighting)
  5. Verification Evidence (3-stage results table)
  6. Timeline & Metadata
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from triage import CrashReport
from llm_patcher import PatchAttempt
from verifier import VerificationResult

log = logging.getLogger("sentinel.reporter")

# ─────────────────────────────────────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:
    """
    Generates Markdown and JSON reports from a completed AutoPatch Sentinel run.

    Usage:
        reporter = Reporter(reports_dir=Path("reports"))
        reporter.generate(
            target_name="telemetry_parser",
            crash_report=triage_report,
            patch_attempt=patch.attempt,
            verification=verify_result,
            crash_input_path=crash_path,
        )
    """

    def __init__(self, reports_dir: Path = Path("reports")):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        target_name: str,
        crash_report: CrashReport,
        patch_attempt: Optional[PatchAttempt],
        verification: VerificationResult,
        crash_input_path: Optional[Path] = None,
        total_duration_s: float = 0.0,
        retry_count: int = 0,
    ) -> tuple[Path, Path]:
        """
        Generate both Markdown and JSON reports.
        Returns (markdown_path, json_path).
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        status = "VERIFIED" if (verification and verification.all_passed) else "FAILED"
        base_name = f"{target_name}_{timestamp}_{status}"

        md_path   = self.reports_dir / f"{base_name}.md"
        json_path = self.reports_dir / f"{base_name}.json"

        md_content   = self._generate_markdown(
            target_name, crash_report, patch_attempt, verification,
            crash_input_path, total_duration_s, retry_count, timestamp
        )
        json_content = self._generate_json(
            target_name, crash_report, patch_attempt, verification,
            crash_input_path, total_duration_s, retry_count, timestamp
        )

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        log.info(f"[+] Report written: {md_path.name}")
        log.info(f"[+] Report written: {json_path.name}")
        return md_path, json_path

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown generation
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_markdown(
        self,
        target_name: str,
        crash: CrashReport,
        patch: Optional[PatchAttempt],
        verification: Optional[VerificationResult],
        crash_input_path: Optional[Path],
        total_duration_s: float,
        retry_count: int,
        timestamp: str,
    ) -> str:
        status_badge = "✅ **FIX VERIFIED**" if (verification and verification.all_passed) else "❌ **FIX FAILED**"
        severity_emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
        }.get(crash.severity, "⚪")

        sections = [
            f"# AutoPatch Sentinel — Vulnerability Report",
            f"",
            f"> {status_badge} | Target: `{target_name}` | Generated: {timestamp}",
            f"",
            f"---",
            f"",
            # ── 1. Executive Summary ─────────────────────────────────────────
            f"## 1. Executive Summary",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Target | `{target_name}` |",
            f"| Vulnerability Class | `{crash.error_type}` |",
            f"| CWE | [{crash.cwe_id}](https://cwe.mitre.org/data/definitions/{crash.cwe_id.replace('CWE-','')}.html) |" if crash.cwe_id else "| CWE | Unknown |",
            f"| Severity | {severity_emoji} {crash.severity} |",
            f"| Crash Location | `{crash.crash_function}()` in `{crash.crash_file}:{crash.crash_line}` |",
            f"| Fix Status | {'✅ Verified' if (verification and verification.all_passed) else '❌ Not Verified'} |",
            f"| LLM Attempts | {retry_count + 1} |",
            f"| Total Pipeline Duration | {total_duration_s:.1f}s |",
            f"",
            f"---",
            f"",
            # ── 2. Vulnerability Details ─────────────────────────────────────
            f"## 2. Vulnerability Details",
            f"",
            f"**Error Type:** `{crash.error_type}`",
            f"",
            f"**Access Pattern:** {crash.access_type} of {crash.access_size} bytes" if crash.access_type else "",
            f"",
            f"**CWE Classification:** {crash.cwe_id} — {self._cwe_description(crash.cwe_id)}",
            f"",
            f"### Stack Trace",
            f"",
            f"```",
        ]
        for frame in crash.stack_frames[:8]:
            loc = f" [{frame.source_file}:{frame.line_no}]" if frame.source_file else ""
            sections.append(f"  #{frame.frame_no} {frame.function}{loc}")
        sections += [
            f"```",
            f"",
            f"---",
            f"",
            # ── 2b. Static Analysis Pre-Screening (SAST) ──────────────────────
            f"## 2b. Static Analysis Pre-Screening (SAST)",
            f"",
        ]

        sast_findings = getattr(crash, "sast_findings", [])
        if sast_findings:
            sections += [
                f"> ⚠️ **{len(sast_findings)} static finding(s) correlated with the crash site** — "
                f"root cause flagged by static analysis AND confirmed exploitable at runtime.",
                f"",
                f"| Tool | Severity | CWE | Message | Line |",
                f"|------|----------|-----|---------|------|",
            ]
            for sf in sast_findings:
                cwe = sf.cwe or "—"
                sections.append(
                    f"| `{sf.tool}` | `{sf.severity}` | `{cwe}` | {sf.message[:80]} | {sf.line} |"
                )
            sections += [f"",
                f"> **Static → Dynamic confirmation:** The static analysis warning at line {sast_findings[0].line} "
                f"matches the runtime AddressSanitizer crash at `{crash.crash_file}:{crash.crash_line}`.",
                f"",
            ]
        else:
            sections += [
                f"_No SAST findings correlated near the crash site. "
                f"(Install `cppcheck`/`clang-tidy` and re-run for full coverage.)_",
                f"",
            ]

        sections += [
            f"---",
            f"",
            # ── 3. Root Cause Analysis ───────────────────────────────────────
            f"## 3. Root Cause Analysis",
            f"",
            f"*Automated analysis by LLM ({patch.attempt_no if patch else 0} attempt(s)):*",
            f"",
            f"{patch.explanation if patch else '_No patch generated_'}",
            f"",
            f"---",
            f"",
            # ── 4. Patch Diff ────────────────────────────────────────────────
            f"## 4. Applied Patch",
            f"",
            f"```diff",
            patch.diff_text if patch else "# No patch generated",
            f"```",
            f"",
            f"---",
            f"",
            # ── 5. Verification Evidence ─────────────────────────────────────
            f"## 5. Verification Evidence",
            f"",
            verification.summary_table() if verification else "_No verification performed (patch generation failed)_",
            f"",
        ]

        if verification:
            for s in verification.stage_results:
                icon = "✅" if s.passed else "❌"
                sections += [
                    f"### {icon} {s.stage.value}",
                    f"",
                    f"**Result:** {'PASS' if s.passed else 'FAIL'}  ",
                    f"**Duration:** {s.duration_s:.1f}s  ",
                    f"**Details:** {s.details}",
                    f"",
                ]
                if not s.passed and s.error_output:
                    sections += [
                        f"<details><summary>Error Output</summary>",
                        f"",
                        f"```",
                        s.error_output[:2000],
                        f"```",
                        f"</details>",
                        f"",
                    ]

        sections += [
            f"---",
            f"",
            # ── 6. Metadata ──────────────────────────────────────────────────
            f"## 6. Pipeline Metadata",
            f"",
            f"| Property | Value |",
            f"|----------|-------|",
            f"| Crash Input | `{crash_input_path.name if crash_input_path else 'N/A'}` |",
            f"| LLM Provider | `{'Gemini / Claude / OpenAI / Ollama'}` |",
            f"| LLM Tokens Used | `{patch.tokens_used if patch else 0}` |",
            f"| Pipeline Version | AutoPatch Sentinel v1.0.0 |",
            f"",
            f"---",
            f"",
            f"*Report generated by AutoPatch Sentinel — Automated Vulnerability Remediation Pipeline*",
        ]

        return "\n".join(line for line in sections if line is not None)

    # ─────────────────────────────────────────────────────────────────────────
    # JSON generation
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_json(
        self,
        target_name: str,
        crash: CrashReport,
        patch: Optional[PatchAttempt],
        verification: Optional[VerificationResult],
        crash_input_path: Optional[Path],
        total_duration_s: float,
        retry_count: int,
        timestamp: str,
    ) -> str:
        data = {
            "autopatch_sentinel": {
                "version": "1.0.0",
                "timestamp": timestamp,
                "target": target_name,
            },
            "vulnerability": {
                "error_type": crash.error_type,
                "cwe_id": crash.cwe_id,
                "severity": crash.severity,
                "access_type": crash.access_type,
                "access_size_bytes": crash.access_size,
                "crash_function": crash.crash_function,
                "crash_file": crash.crash_file,
                "crash_line": crash.crash_line,
                "stack_frames": [
                    {
                        "no": f.frame_no,
                        "function": f.function,
                        "file": f.source_file,
                        "line": f.line_no,
                    }
                    for f in crash.stack_frames[:8]
                ],
            },
            "patch": {
                "attempt_count": retry_count + 1,
                "successful": patch is not None,
                "explanation": patch.explanation if patch else None,
                "diff": patch.diff_text if patch else None,
                "tokens_used": patch.tokens_used if patch else 0,
            },
            "verification": {
                "overall": "PASS" if (verification and verification.all_passed) else "FAIL",
                "stages": [
                    {
                        "stage": s.stage.value,
                        "passed": s.passed,
                        "details": s.details,
                        "duration_s": round(s.duration_s, 2),
                    }
                    for s in verification.stage_results
                ] if verification else [],
            },
            "pipeline": {
                "total_duration_s": round(total_duration_s, 2),
                "crash_input": str(crash_input_path) if crash_input_path else None,
            },
            "sast": {
                "findings_count": len(getattr(crash, "sast_findings", [])),
                "correlated_findings": [
                    {
                        "tool": sf.tool,
                        "severity": sf.severity,
                        "cwe": sf.cwe,
                        "message": sf.message,
                        "file": sf.source_file,
                        "line": sf.line,
                        "check_id": sf.check_id,
                    }
                    for sf in getattr(crash, "sast_findings", [])
                ],
                "static_dynamic_confirmed": len(getattr(crash, "sast_findings", [])) > 0,
            },
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def _cwe_description(cwe_id: Optional[str]) -> str:
        descriptions = {
            "CWE-122": "Heap-based Buffer Overflow",
            "CWE-121": "Stack-based Buffer Overflow",
            "CWE-416": "Use After Free",
            "CWE-415": "Double Free",
            "CWE-190": "Integer Overflow or Wraparound",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        }
        return descriptions.get(cwe_id or "", "Memory Safety Violation")
