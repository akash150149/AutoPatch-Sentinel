"""
src/sast.py
AutoPatch Sentinel - Static Analysis (SAST) Pre-screening Module

Runs source-level static analysis tools BEFORE fuzzing as Stage 0.
Provides a second, independent signal that agrees with (or predicts) what
ASan finds at runtime — enabling the report to say:
  "Flagged by static analysis at line X, confirmed exploitable at runtime."

Tools supported:
  - cppcheck  : Detects buffer overruns, integer overflows, unclamped memcpy, etc.
  - clang-tidy: Detects bugprone-* and cert-* class issues (supplementary).

Both tools are detected via PATH; if absent, the module logs a clear install
hint and returns an empty findings list — the pipeline continues normally.

Install on Linux/WSL:
    sudo apt install cppcheck clang-tools
Install on Windows:
    choco install cppcheck  (or download from https://cppcheck.sourceforge.io/)
    winget install LLVM.LLVM
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.sast")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SastFinding:
    """A single static analysis finding from cppcheck or clang-tidy."""
    tool: str               # "cppcheck" | "clang-tidy"
    severity: str           # "error" | "warning" | "style" | "performance" | "portability"
    message: str            # Human-readable description
    source_file: str        # Relative or absolute path to the source file
    line: Optional[int]     # Line number (None if unknown)
    column: Optional[int]   # Column number (None if unknown)
    check_id: str           # Tool-specific rule/check ID (e.g. "bufferAccessOutOfBounds")
    cwe: Optional[str]      # CWE ID if the tool provides it (e.g. "CWE-122")

    def summary(self) -> str:
        loc = f"{self.source_file}:{self.line}" if self.line else self.source_file
        cwe_tag = f" [{self.cwe}]" if self.cwe else ""
        return f"[{self.tool.upper()}] {self.severity.upper()}{cwe_tag}: {self.message} @ {loc}"


@dataclass
class SastReport:
    """Aggregated findings from all static analysis tools."""
    findings: list[SastFinding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    errors_count: int = 0
    warnings_count: int = 0
    duration_s: float = 0.0
    raw_outputs: dict[str, str] = field(default_factory=dict)

    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def findings_for_line(self, source_file: str, line: int, window: int = 5) -> list[SastFinding]:
        """Return findings within ±window lines of the given location."""
        fname = Path(source_file).name
        return [
            f for f in self.findings
            if Path(f.source_file).name == fname
            and f.line is not None
            and abs(f.line - line) <= window
        ]

    def findings_summary_text(self) -> str:
        """Multi-line human-readable summary, suitable for LLM context."""
        if not self.findings:
            return "No static analysis findings."
        lines = [f"Static Analysis Pre-Screening ({len(self.findings)} finding(s)):"]
        for f in self.findings:
            lines.append(f"  • {f.summary()}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serializable representation for JSON reports."""
        return {
            "tools_run": self.tools_run,
            "tools_missing": self.tools_missing,
            "errors": self.errors_count,
            "warnings": self.warnings_count,
            "duration_s": round(self.duration_s, 2),
            "findings": [
                {
                    "tool": f.tool,
                    "severity": f.severity,
                    "message": f.message,
                    "file": f.source_file,
                    "line": f.line,
                    "column": f.column,
                    "check_id": f.check_id,
                    "cwe": f.cwe,
                }
                for f in self.findings
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Static Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class StaticAnalyzer:
    """
    Runs cppcheck and optionally clang-tidy on C/C++ source files.

    Usage:
        analyzer = StaticAnalyzer(target_dir=Path("targets/telemetry_parser"))
        report = analyzer.run_all(["telemetry_parser.c"])
        print(report.findings_summary_text())
    """

    _CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

    def __init__(
        self,
        target_dir: Path,
        timeout_s: int = 30,
        run_clang_tidy: bool = True,
    ):
        self.target_dir = Path(target_dir)
        self.timeout_s = timeout_s
        self.run_clang_tidy_flag = run_clang_tidy

    # ── Public API ────────────────────────────────────────────────────────────

    def run_all(self, source_files: list[str]) -> SastReport:
        """
        Run all available static analysis tools and return a merged SastReport.
        Gracefully skips tools that are not installed.
        """
        import time
        start = time.time()

        report = SastReport()

        # --- cppcheck ---
        cppcheck_bin = shutil.which("cppcheck")
        if cppcheck_bin:
            findings, raw = self._run_cppcheck(source_files, cppcheck_bin)
            report.findings.extend(findings)
            report.tools_run.append("cppcheck")
            report.raw_outputs["cppcheck"] = raw
            log.info(f"[SAST] cppcheck: {len(findings)} finding(s)")
        else:
            report.tools_missing.append("cppcheck")
            log.warning(
                "[SAST] cppcheck not found in PATH. Install with:\n"
                "  Linux/WSL: sudo apt install cppcheck\n"
                "  Windows:   choco install cppcheck  (or https://cppcheck.sourceforge.io/)"
            )

        # --- clang-tidy ---
        if self.run_clang_tidy_flag:
            tidy_bin = shutil.which("clang-tidy")
            if tidy_bin:
                findings, raw = self._run_clang_tidy(source_files, tidy_bin)
                report.findings.extend(findings)
                report.tools_run.append("clang-tidy")
                report.raw_outputs["clang-tidy"] = raw
                log.info(f"[SAST] clang-tidy: {len(findings)} finding(s)")
            else:
                report.tools_missing.append("clang-tidy")
                log.warning(
                    "[SAST] clang-tidy not found in PATH. Install with:\n"
                    "  Linux/WSL: sudo apt install clang-tools\n"
                    "  Windows:   winget install LLVM.LLVM"
                )

        # Compute summary counts
        report.errors_count   = sum(1 for f in report.findings if f.severity == "error")
        report.warnings_count = sum(1 for f in report.findings if f.severity in ("warning", "style"))
        report.duration_s = time.time() - start

        return report

    # ── cppcheck ─────────────────────────────────────────────────────────────

    def _run_cppcheck(
        self, source_files: list[str], cppcheck_bin: str
    ) -> tuple[list[SastFinding], str]:
        """Run cppcheck with XML output and parse results."""

        src_paths = [str(self.target_dir / s) for s in source_files]
        include_flag = f"-I{self.target_dir}"

        cmd = [
            cppcheck_bin,
            "--enable=all",
            "--inconclusive",
            "--xml",
            "--xml-version=2",
            "--suppress=missingIncludeSystem",
            include_flag,
        ] + src_paths

        log.debug(f"[SAST] cppcheck command: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                cwd=str(self.target_dir),
            )
            # cppcheck writes XML to stderr
            raw_xml = proc.stderr
        except subprocess.TimeoutExpired:
            log.warning("[SAST] cppcheck timed out")
            return [], "TIMEOUT"
        except FileNotFoundError:
            return [], "NOT FOUND"

        findings = self._parse_cppcheck_xml(raw_xml)
        return findings, raw_xml

    def _parse_cppcheck_xml(self, xml_text: str) -> list[SastFinding]:
        """Parse cppcheck --xml-version=2 output into SastFinding list."""
        findings = []
        if not xml_text.strip():
            return findings

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            log.warning(f"[SAST] Failed to parse cppcheck XML: {e}")
            return findings

        for error in root.iter("error"):
            error_id  = error.get("id", "unknown")
            severity  = error.get("severity", "warning")
            message   = error.get("msg", "")
            cwe_attr  = error.get("cwe", "")
            cwe       = f"CWE-{cwe_attr}" if cwe_attr else self._extract_cwe(message)

            # Skip known noise
            if error_id in ("unmatchedSuppression", "missingInclude", "missingIncludeSystem"):
                continue

            # Location info is on child <location> elements
            location = error.find("location")
            source_file = ""
            line_no     = None
            col_no      = None
            if location is not None:
                source_file = location.get("file", "")
                line_str    = location.get("line", "")
                col_str     = location.get("column", "")
                line_no = int(line_str) if line_str.isdigit() else None
                col_no  = int(col_str)  if col_str.isdigit()  else None

            findings.append(SastFinding(
                tool="cppcheck",
                severity=severity,
                message=message,
                source_file=source_file,
                line=line_no,
                column=col_no,
                check_id=error_id,
                cwe=cwe or None,
            ))

        log.debug(f"[SAST] Parsed {len(findings)} cppcheck finding(s)")
        return findings

    # ── clang-tidy ────────────────────────────────────────────────────────────

    def _run_clang_tidy(
        self, source_files: list[str], tidy_bin: str
    ) -> tuple[list[SastFinding], str]:
        """Run clang-tidy with bugprone-* and cert-* checks."""

        src_paths = [str(self.target_dir / s) for s in source_files if s.endswith(".c")]
        if not src_paths:
            return [], ""

        checks = ",".join([
            "bugprone-*",
            "cert-*",
            "clang-analyzer-*",
            "-bugprone-easily-swappable-parameters",
        ])

        all_findings = []
        all_raw = ""

        for src in src_paths:
            cmd = [
                tidy_bin,
                src,
                f"--checks={checks}",
                "--",
                f"-I{self.target_dir}",
                "-g", "-O1",
            ]
            log.debug(f"[SAST] clang-tidy command: {' '.join(cmd)}")

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    cwd=str(self.target_dir),
                )
                raw = proc.stdout + proc.stderr
                all_raw += raw
                all_findings.extend(self._parse_clang_tidy_output(raw))
            except subprocess.TimeoutExpired:
                log.warning(f"[SAST] clang-tidy timed out on {src}")
            except FileNotFoundError:
                break

        return all_findings, all_raw

    # clang-tidy warning format:
    # /path/to/file.c:42:10: warning: message [check-name]
    _TIDY_LINE_RE = re.compile(
        r"^([^\s:][^:]*\.(?:c|cc|cpp|h)):\s*(\d+):\s*(\d+):\s*(warning|error|note):\s*(.+?)\s*\[([^\]]+)\]",
        re.MULTILINE,
    )

    def _parse_clang_tidy_output(self, text: str) -> list[SastFinding]:
        findings = []
        for m in self._TIDY_LINE_RE.finditer(text):
            source_file = m.group(1)
            line_no     = int(m.group(2))
            col_no      = int(m.group(3))
            severity    = m.group(4)
            message     = m.group(5)
            check_id    = m.group(6)
            cwe         = self._extract_cwe(message)

            findings.append(SastFinding(
                tool="clang-tidy",
                severity=severity,
                message=message,
                source_file=source_file,
                line=line_no,
                column=col_no,
                check_id=check_id,
                cwe=cwe or None,
            ))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_cwe(self, text: str) -> str:
        """Extract first CWE-NNN reference from a message string."""
        m = self._CWE_PATTERN.search(text)
        return f"CWE-{m.group(1)}" if m else ""
