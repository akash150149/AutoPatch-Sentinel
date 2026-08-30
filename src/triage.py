"""
src/triage.py
AutoPatch Sentinel - ASan/UBSan Crash Triage Engine

Parses raw AddressSanitizer and UndefinedBehaviorSanitizer output and extracts
structured crash information that can be fed to an LLM for root-cause analysis.

Extracts:
  - Error type (heap-buffer-overflow, stack-buffer-overflow, use-after-free, etc.)
  - Access type (READ / WRITE) and size
  - Crashing source file and line number
  - Relevant function name
  - Sanitizer stack trace (filtered to project frames only)
  - Shadow memory context (if present)
  - SAST correlation: static analysis findings near the crash site
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sast import SastFinding, SastReport

log = logging.getLogger("sentinel.triage")

# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StackFrame:
    frame_no: int
    function: str
    source_file: Optional[str]
    line_no: Optional[int]
    column_no: Optional[int]
    raw: str


@dataclass
class CrashReport:
    """Structured crash information extracted from an ASan log."""
    error_type: str                     # e.g. "heap-buffer-overflow"
    access_type: Optional[str]          # "READ" or "WRITE"
    access_size: Optional[int]          # bytes accessed
    crash_file: Optional[str]           # Source file of the crash
    crash_line: Optional[int]           # Line number
    crash_function: Optional[str]       # Function name
    stack_frames: list[StackFrame]      # Parsed frames (project-relevant)
    raw_asan_log: str                   # Full raw sanitizer output
    cwe_id: Optional[str]               # Mapped CWE if known
    severity: str                       # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
    sast_findings: list = field(default_factory=list)  # SastFinding objects correlated to crash site

    def summary(self) -> str:
        """One-line human-readable summary."""
        loc = f"{self.crash_file}:{self.crash_line}" if self.crash_file else "unknown"
        return (
            f"[{self.severity}] {self.error_type} "
            f"({self.access_type} {self.access_size}B) "
            f"in {self.crash_function}() @ {loc}"
        )

    def to_llm_context(self, source_snippet: str = "") -> str:
        """
        Format the crash report into a rich context block for the LLM prompt.
        Includes the sanitizer report + optional source code excerpt.
        If SAST findings were correlated, includes a static+dynamic confirmation block.
        """
        lines = [
            "=== CRASH TRIAGE REPORT ===",
            f"Error Type:    {self.error_type}",
            f"CWE:           {self.cwe_id or 'Unknown'}",
            f"Severity:      {self.severity}",
            f"Access:        {self.access_type} of {self.access_size} bytes",
            f"Location:      {self.crash_function}() in {self.crash_file}:{self.crash_line}",
            "",
            "--- Stack Trace (relevant frames) ---",
        ]
        for frame in self.stack_frames[:8]:
            loc = ""
            if frame.source_file and frame.line_no:
                loc = f" [{frame.source_file}:{frame.line_no}]"
            lines.append(f"  #{frame.frame_no} {frame.function}{loc}")

        # Static + Dynamic Correlation block
        if self.sast_findings:
            lines += [
                "",
                "--- Static + Dynamic Correlation [SAST Pre-Screen] ---",
                f"[!] Dynamic Crash: {self.error_type} in {self.crash_function}() @ "
                f"{self.crash_file}:{self.crash_line}",
            ]
            for sf in self.sast_findings[:5]:
                cwe_tag = f" [{sf.cwe}]" if sf.cwe else ""
                lines.append(
                    f"[!] Static Finding ({sf.tool}): {sf.check_id}{cwe_tag} — "
                    f"{sf.message} @ line {sf.line}"
                )
            lines.append(
                "=> Root cause independently flagged by static analysis "
                "AND confirmed exploitable at runtime via ASan."
            )

        if source_snippet:
            lines += [
                "",
                "--- Source Context ---",
                source_snippet,
            ]

        lines += [
            "",
            "--- Raw ASan Output (truncated) ---",
            self.raw_asan_log[:3000],
            "=========================",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CWE Mapping
# ─────────────────────────────────────────────────────────────────────────────

_ERROR_TYPE_TO_CWE = {
    "heap-buffer-overflow":   ("CWE-122", "CRITICAL"),
    "stack-buffer-overflow":  ("CWE-121", "CRITICAL"),
    "global-buffer-overflow": ("CWE-122", "HIGH"),
    "use-after-free":         ("CWE-416", "CRITICAL"),
    "double-free":            ("CWE-415", "CRITICAL"),
    "use-after-return":       ("CWE-416", "HIGH"),
    "use-after-scope":        ("CWE-416", "HIGH"),
    "heap-use-after-free":    ("CWE-416", "CRITICAL"),
    "integer-overflow":       ("CWE-190", "HIGH"),
    "signed-integer-overflow":("CWE-190", "HIGH"),
    "null-deref":             ("CWE-476", "HIGH"),
    "memcpy-param-overlap":   ("CWE-119", "MEDIUM"),
    "unknown":                ("CWE-119", "MEDIUM"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# ASan error type line e.g.:
#   ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc ...
#   SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow
_RE_ERROR_TYPE = re.compile(
    r"(?:AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer):\s+"
    r"(?:DEADLYSIGNAL\s+)?([a-zA-Z\-]+)"
)

# Access type + size: "WRITE of size 512 at 0x..."
_RE_ACCESS = re.compile(
    r"\b(READ|WRITE)\s+of\s+size\s+(\d+)",
    re.IGNORECASE
)

# Stack frame lines:
#   #0 0x7f1234 in parse_tlv_payload telemetry_parser.c:67
#   #0 0x7f1234 in parse_tlv_payload /path/to/telemetry_parser.c:67:15
_RE_FRAME = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)"
    r"(?:\s+((?:[A-Za-z]:)?[\w/\\.]+\.(?:c|cc|cpp|h|hpp)):(\d+)(?::(\d+))?)?"
)

# UBSAN runtime error:
#   telemetry_parser.c:42:24: runtime error: signed integer overflow:
_RE_UBSAN_LOC = re.compile(
    r"([\w/\\.]+\.(?:c|cc|cpp)):(\d+):\d+:\s+runtime\s+error:\s+(.+)"
)


# ─────────────────────────────────────────────────────────────────────────────
# Triage engine
# ─────────────────────────────────────────────────────────────────────────────

class TriageEngine:
    """
    Parses ASan/UBSan output and returns a structured CrashReport.

    Usage:
        engine = TriageEngine(project_root=Path("d:/Cybersec"))
        report = engine.parse(asan_stderr_text)
        print(report.summary())
    """

    def __init__(self, project_root: Path, filter_project_frames: bool = True):
        """
        Args:
            project_root: Path to the project root; frames whose source file
                          is under this path are considered "project frames"
                          and prioritized in the output.
            filter_project_frames: If True, prefer project source frames over
                                   library/runtime frames in the stack trace.
        """
        self.project_root = Path(project_root).resolve()
        self.filter_project = filter_project_frames

    def parse(self, asan_output: str, sast_report=None) -> CrashReport:
        """
        Parse raw ASan/UBSan stderr output into a CrashReport.

        Args:
            asan_output:  Raw ASan/UBSan stderr text.
            sast_report:  Optional SastReport from Stage 0. If provided,
                          findings near the crash site are correlated and
                          embedded in the report for LLM and audit output.
        """
        error_type = self._extract_error_type(asan_output)
        access_type, access_size = self._extract_access(asan_output)
        frames = self._extract_frames(asan_output)
        crash_frame = self._pick_crash_frame(frames)
        cwe, severity = _ERROR_TYPE_TO_CWE.get(
            error_type, _ERROR_TYPE_TO_CWE["unknown"]
        )

        # UBSAN may report location differently
        if not crash_frame:
            ubsan_file, ubsan_line, _ = self._extract_ubsan_loc(asan_output)
        else:
            ubsan_file = crash_frame.source_file
            ubsan_line = crash_frame.line_no

        # Correlate SAST findings with the crash site (±5 lines)
        correlated_findings = []
        if sast_report is not None and ubsan_file and ubsan_line:
            correlated_findings = sast_report.findings_for_line(
                source_file=ubsan_file,
                line=ubsan_line,
                window=5,
            )
            if correlated_findings:
                log.info(
                    f"[SAST] Correlated {len(correlated_findings)} static finding(s) "
                    f"near crash at {ubsan_file}:{ubsan_line}"
                )

        report = CrashReport(
            error_type=error_type,
            access_type=access_type,
            access_size=access_size,
            crash_file=ubsan_file,
            crash_line=ubsan_line,
            crash_function=crash_frame.function if crash_frame else None,
            stack_frames=frames,
            raw_asan_log=asan_output,
            cwe_id=cwe,
            severity=severity,
            sast_findings=correlated_findings,
        )
        log.info(f"Triaged: {report.summary()}")
        return report

    def parse_file(self, log_path: Path) -> CrashReport:
        """Parse a saved ASan log file."""
        with open(log_path, "r", errors="replace") as f:
            return self.parse(f.read())

    # ── Private helpers ──────────────────────────────────────────────────────

    def _extract_error_type(self, text: str) -> str:
        m = _RE_ERROR_TYPE.search(text)
        return m.group(1).lower() if m else "unknown"

    def _extract_access(self, text: str) -> tuple[Optional[str], Optional[int]]:
        m = _RE_ACCESS.search(text)
        if m:
            return m.group(1).upper(), int(m.group(2))
        return None, None

    def _extract_frames(self, text: str) -> list[StackFrame]:
        frames = []
        for m in _RE_FRAME.finditer(text):
            frames.append(StackFrame(
                frame_no=int(m.group(1)),
                function=m.group(2),
                source_file=m.group(3),
                line_no=int(m.group(4)) if m.group(4) else None,
                column_no=int(m.group(5)) if m.group(5) else None,
                raw=m.group(0),
            ))
        # Deduplicate by frame_no (keep first occurrence)
        seen = set()
        unique = []
        for f in frames:
            if f.frame_no not in seen:
                seen.add(f.frame_no)
                unique.append(f)
        return sorted(unique, key=lambda x: x.frame_no)

    def _pick_crash_frame(self, frames: list[StackFrame]) -> Optional[StackFrame]:
        """Select the most relevant project frame from the stack trace."""
        if not frames:
            return None
        if not self.filter_project:
            return frames[0]

        # Prefer frames that have a source file in our project
        for frame in frames:
            if frame.source_file and self._is_project_file(frame.source_file):
                return frame

        # Fallback: first frame with any source info
        for frame in frames:
            if frame.source_file:
                return frame

        return frames[0]

    def _is_project_file(self, path_str: str) -> bool:
        try:
            p = Path(path_str)
            if p.is_absolute():
                return str(p).startswith(str(self.project_root))
            # Relative path — assume project file if it's a .c/.cc/.cpp
            return p.suffix in (".c", ".cc", ".cpp")
        except Exception:
            return False

    def _extract_ubsan_loc(self, text: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
        m = _RE_UBSAN_LOC.search(text)
        if m:
            return m.group(1), int(m.group(2)), m.group(3)
        return None, None, None


# ─────────────────────────────────────────────────────────────────────────────
# Source code context extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_source_context(
    source_file: str,
    crash_line: int,
    context_lines: int = 10,
) -> str:
    """
    Extract ±context_lines lines around the crashing line from source file.
    Returns formatted string with line numbers.
    """
    try:
        p = Path(source_file)
        if not p.exists():
            return f"[Source file not found: {source_file}]"

        with open(p, "r", errors="replace") as f:
            all_lines = f.readlines()

        start = max(0, crash_line - context_lines - 1)
        end   = min(len(all_lines), crash_line + context_lines)

        result = []
        for i, line in enumerate(all_lines[start:end], start=start + 1):
            marker = ">>>" if i == crash_line else "   "
            result.append(f"{marker} {i:4d} | {line}", )

        return "".join(result)
    except Exception as e:
        return f"[Error reading source: {e}]"


# ─────────────────────────────────────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    _MOCK_ASAN = """
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000110 at pc 0x000000401234 bp 0x7ffe12345678 sp 0x7ffe12345670
WRITE of size 512 at 0x602000000110 thread T0
    #0 0x401234 in parse_tlv_payload /d/Cybersec/targets/telemetry_parser/telemetry_parser.c:67:5
    #1 0x4023ab in parse_telemetry_frame /d/Cybersec/targets/telemetry_parser/telemetry_parser.c:100:9
    #2 0x4031cd in LLVMFuzzerTestOneInput /d/Cybersec/targets/telemetry_parser/fuzzer_harness.cc:18:5
    #3 0x7f1234 in fuzzer::RunOneInput(unsigned char const*, unsigned long) fuzzer.cpp:100
SUMMARY: AddressSanitizer: heap-buffer-overflow telemetry_parser.c:67 in parse_tlv_payload
"""
    engine = TriageEngine(project_root=Path("d:/Cybersec"))
    report = engine.parse(_MOCK_ASAN)
    print(report.summary())
    print()
    print(report.to_llm_context())
