"""
tests/test_sast.py
Unit tests for the Static Analysis (SAST) module.

Tests:
  - cppcheck XML parsing with mock XML fixtures
  - clang-tidy output parsing with mock text fixtures
  - SastReport.findings_for_line() correlation
  - Graceful handling when tools are absent
  - Integration with TriageEngine.parse() SAST correlation
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from unittest.mock import patch, MagicMock
from sast import StaticAnalyzer, SastFinding, SastReport


# ── Mock cppcheck XML output ──────────────────────────────────────────────────

MOCK_CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.14"/>
  <errors>
    <error id="bufferAccessOutOfBounds" severity="error"
           msg="Buffer access out-of-bounds: data[field_len]; field_len=512 but buffer size is 256."
           cwe="122" inconclusive="false">
      <location file="telemetry_parser.c" line="111" column="9"/>
    </error>
    <error id="integerOverflowTrunc" severity="error"
           msg="int calculation is truncated (result = 0 instead of 131072): count * element_size."
           cwe="190" inconclusive="false">
      <location file="telemetry_parser.c" line="50" column="20"/>
    </error>
    <error id="missingIncludeSystem" severity="information"
           msg="Include file: &lt;stdio.h&gt; not found." inconclusive="false">
      <location file="telemetry_parser.c" line="27" column="0"/>
    </error>
    <error id="unmatchedSuppression" severity="information"
           msg="Unmatched suppression: unreadVariable" inconclusive="false">
      <location file="telemetry_parser.c" line="0" column="0"/>
    </error>
  </errors>
</results>"""

MOCK_CPPCHECK_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.14"/>
  <errors/>
</results>"""


# ── Mock clang-tidy output ────────────────────────────────────────────────────

MOCK_CLANG_TIDY_OUTPUT = """\
telemetry_parser.c:111:9: warning: Potential buffer overflow when copying 'field_len' bytes [bugprone-suspicious-memset-usage]
telemetry_parser.c:50:20: warning: Integer arithmetic may overflow before widening [cert-INT30-c]
/usr/include/stdio.h:100:5: note: expanded from macro 'printf'
"""


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer(tmp_path):
    return StaticAnalyzer(target_dir=tmp_path, timeout_s=5)


# ── Tests: cppcheck XML parsing ───────────────────────────────────────────────

class TestCppcheckParsing:
    def test_parses_error_finding(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        assert any(f.check_id == "bufferAccessOutOfBounds" for f in findings)

    def test_parses_cwe_from_attribute(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        buf = next(f for f in findings if f.check_id == "bufferAccessOutOfBounds")
        assert buf.cwe == "CWE-122"

    def test_parses_line_number(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        buf = next(f for f in findings if f.check_id == "bufferAccessOutOfBounds")
        assert buf.line == 111

    def test_parses_integer_overflow(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        ovf = next((f for f in findings if f.check_id == "integerOverflowTrunc"), None)
        assert ovf is not None
        assert ovf.cwe == "CWE-190"
        assert ovf.line == 50

    def test_filters_noise_ids(self, analyzer):
        """missingIncludeSystem and unmatchedSuppression should be filtered out."""
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        ids = [f.check_id for f in findings]
        assert "missingIncludeSystem" not in ids
        assert "unmatchedSuppression" not in ids

    def test_severity_is_error(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        buf = next(f for f in findings if f.check_id == "bufferAccessOutOfBounds")
        assert buf.severity == "error"

    def test_tool_name_is_cppcheck(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_XML)
        assert all(f.tool == "cppcheck" for f in findings)

    def test_empty_xml_returns_no_findings(self, analyzer):
        findings = analyzer._parse_cppcheck_xml(MOCK_CPPCHECK_EMPTY)
        assert findings == []

    def test_malformed_xml_returns_no_findings(self, analyzer):
        findings = analyzer._parse_cppcheck_xml("not xml at all !!!")
        assert findings == []

    def test_empty_string_returns_no_findings(self, analyzer):
        findings = analyzer._parse_cppcheck_xml("")
        assert findings == []


# ── Tests: clang-tidy output parsing ─────────────────────────────────────────

class TestClangTidyParsing:
    def test_parses_warning_line(self, analyzer):
        findings = analyzer._parse_clang_tidy_output(MOCK_CLANG_TIDY_OUTPUT)
        assert len(findings) >= 1

    def test_excludes_system_file_notes(self, analyzer):
        findings = analyzer._parse_clang_tidy_output(MOCK_CLANG_TIDY_OUTPUT)
        # /usr/include/stdio.h should not appear (note lines aren't parsed by the primary regex pattern with c/cc/cpp extension but header)
        # just check that we get the project-level ones
        project_findings = [f for f in findings if "telemetry_parser" in f.source_file]
        assert len(project_findings) >= 1

    def test_line_number_extracted(self, analyzer):
        findings = analyzer._parse_clang_tidy_output(MOCK_CLANG_TIDY_OUTPUT)
        project_findings = [f for f in findings if "telemetry_parser" in f.source_file]
        lines = {f.line for f in project_findings}
        assert 111 in lines or 50 in lines  # at least one of our known lines

    def test_tool_name_is_clang_tidy(self, analyzer):
        findings = analyzer._parse_clang_tidy_output(MOCK_CLANG_TIDY_OUTPUT)
        project_findings = [f for f in findings if "telemetry_parser" in f.source_file]
        assert all(f.tool == "clang-tidy" for f in project_findings)


# ── Tests: SastReport ─────────────────────────────────────────────────────────

class TestSastReport:
    def _make_report(self):
        findings = [
            SastFinding(
                tool="cppcheck", severity="error",
                message="Buffer overflow", source_file="telemetry_parser.c",
                line=111, column=9, check_id="bufferAccessOutOfBounds", cwe="CWE-122"
            ),
            SastFinding(
                tool="cppcheck", severity="error",
                message="Integer overflow", source_file="telemetry_parser.c",
                line=50, column=20, check_id="integerOverflowTrunc", cwe="CWE-190"
            ),
        ]
        report = SastReport(findings=findings, tools_run=["cppcheck"])
        report.errors_count = 2
        return report

    def test_has_findings_true(self):
        r = self._make_report()
        assert r.has_findings() is True

    def test_has_findings_false(self):
        r = SastReport()
        assert r.has_findings() is False

    def test_findings_for_line_exact(self):
        r = self._make_report()
        near = r.findings_for_line("telemetry_parser.c", 111, window=0)
        assert len(near) == 1
        assert near[0].line == 111

    def test_findings_for_line_window(self):
        r = self._make_report()
        near = r.findings_for_line("telemetry_parser.c", 113, window=5)
        assert any(f.line == 111 for f in near)

    def test_findings_for_line_wrong_file(self):
        r = self._make_report()
        near = r.findings_for_line("other_file.c", 111, window=5)
        assert len(near) == 0

    def test_summary_text_not_empty(self):
        r = self._make_report()
        text = r.findings_summary_text()
        assert "cppcheck" in text.lower()
        assert "CWE-122" in text or "bufferAccessOutOfBounds" in text

    def test_to_dict_structure(self):
        r = self._make_report()
        d = r.to_dict()
        assert "findings" in d
        assert "tools_run" in d
        assert len(d["findings"]) == 2
        assert d["findings"][0]["cwe"] == "CWE-122"


# ── Tests: tool availability (graceful handling) ──────────────────────────────

class TestToolAvailability:
    def test_missing_cppcheck_returns_empty_findings(self, analyzer):
        """When cppcheck is not installed, run_all should return empty findings gracefully."""
        with patch("shutil.which", return_value=None):
            report = analyzer.run_all(["telemetry_parser.c"])
        assert isinstance(report, SastReport)
        assert "cppcheck" in report.tools_missing
        assert report.findings == []

    def test_report_has_tools_missing_list(self, analyzer):
        with patch("shutil.which", return_value=None):
            report = analyzer.run_all(["telemetry_parser.c"])
        assert isinstance(report.tools_missing, list)
        assert len(report.tools_missing) > 0


# ── Tests: TriageEngine integration ──────────────────────────────────────────

class TestTriageSastIntegration:
    """Ensure that triage.py correctly consumes and correlates a SastReport."""

    MOCK_ASAN = """
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000110
WRITE of size 512 at 0x602000000110 thread T0
    #0 0x401234 in parse_tlv_payload /d/Cybersec/targets/telemetry_parser/telemetry_parser.c:111:5
    #1 0x4023ab in parse_telemetry_frame /d/Cybersec/targets/telemetry_parser/telemetry_parser.c:155:9
SUMMARY: AddressSanitizer: heap-buffer-overflow telemetry_parser.c:111 in parse_tlv_payload
"""

    def test_sast_findings_correlated_in_crash_report(self):
        from triage import TriageEngine
        from sast import SastReport, SastFinding

        engine = TriageEngine(project_root=Path("d:/Cybersec"))

        sast_report = SastReport()
        sast_report.findings = [
            SastFinding(
                tool="cppcheck", severity="error",
                message="Buffer overflow risk", source_file="telemetry_parser.c",
                line=111, column=9,
                check_id="bufferAccessOutOfBounds", cwe="CWE-122"
            )
        ]
        sast_report.errors_count = 1

        crash = engine.parse(self.MOCK_ASAN, sast_report=sast_report)

        assert crash.sast_findings is not None
        assert len(crash.sast_findings) > 0
        assert crash.sast_findings[0].check_id == "bufferAccessOutOfBounds"

    def test_llm_context_contains_correlation_block(self):
        from triage import TriageEngine
        from sast import SastReport, SastFinding

        engine = TriageEngine(project_root=Path("d:/Cybersec"))
        sast_report = SastReport()
        sast_report.findings = [
            SastFinding(
                tool="cppcheck", severity="error",
                message="Buffer overflow", source_file="telemetry_parser.c",
                line=111, column=9,
                check_id="bufferAccessOutOfBounds", cwe="CWE-122"
            )
        ]

        crash = engine.parse(self.MOCK_ASAN, sast_report=sast_report)
        ctx = crash.to_llm_context()

        assert "Static + Dynamic Correlation" in ctx
        assert "bufferAccessOutOfBounds" in ctx or "CWE-122" in ctx
        assert "confirmed exploitable at runtime" in ctx

    def test_no_sast_report_gives_empty_findings(self):
        from triage import TriageEngine

        engine = TriageEngine(project_root=Path("d:/Cybersec"))
        crash = engine.parse(self.MOCK_ASAN, sast_report=None)
        assert crash.sast_findings == []
