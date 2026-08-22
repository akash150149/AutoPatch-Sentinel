"""
tests/test_patch_applicator.py
Unit tests for the Python-based unified diff applicator in llm_patcher.py.
"""

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from llm_patcher import _apply_unified_diff, _extract_diff_and_explanation, apply_diff


# ─────────────────────────────────────────────────────────────────────────────
# Sample diffs and sources
# ─────────────────────────────────────────────────────────────────────────────

ORIGINAL_SOURCE = """\
int parse_tlv_payload(const uint8_t *payload, uint16_t payload_len,
                      TelemetryFrame *frame) {
    if (!payload || !frame) return TELEM_ERR_BADFIELD;

    const uint8_t *ptr = payload;
    const uint8_t *end = payload + payload_len;
    int field_count = 0;

    while (ptr < end && field_count < MAX_TLV_FIELDS) {
        if (ptr + 3 > end) break;

        uint8_t  field_type = ptr[0];
        uint16_t field_len  = read_u16_be(ptr + 1);
        ptr += 3;

        if (ptr + field_len > end) break;

        TLVField *field = &frame->fields[field_count];
        field->type   = field_type;
        field->length = field_len;
        memcpy(field->data, ptr, field_len);   /* VULNERABLE LINE */

        ptr += field_len;
        field_count++;
    }

    frame->field_count = field_count;
    return field_count;
}
"""

# A valid minimal patch: add bounds check before memcpy
VALID_DIFF = """\
--- a/telemetry_parser.c
+++ b/telemetry_parser.c
@@ -18,6 +18,8 @@ int parse_tlv_payload(const uint8_t *payload, uint16_t payload_len,
         TLVField *field = &frame->fields[field_count];
         field->type   = field_type;
-        field->length = field_len;
-        memcpy(field->data, ptr, field_len);   /* VULNERABLE LINE */
+        /* Clamp field_len to MAX_PAYLOAD_SIZE to prevent heap-buffer-overflow (CWE-122) */
+        uint16_t safe_len = field_len < MAX_PAYLOAD_SIZE ? field_len : MAX_PAYLOAD_SIZE;
+        field->length = safe_len;
+        memcpy(field->data, ptr, safe_len);   /* Fixed: bounded copy */
 
         ptr += field_len;
         field_count++;
"""

# LLM response wrapping the diff in markdown
LLM_RESPONSE_WITH_FENCES = f"""
I've analyzed the crash report. The issue is in `parse_tlv_payload` where `field_len` is not
clamped before memcpy.

```diff
{VALID_DIFF}
```

EXPLANATION:
The heap-buffer-overflow occurs because `field_len` from the packet is copied directly into
`field->data[MAX_PAYLOAD_SIZE]` without clamping. The fix adds a bounds check to ensure the
copy size never exceeds `MAX_PAYLOAD_SIZE` (256 bytes).
"""

LLM_RESPONSE_NO_DIFF = """
I think the fix involves checking the length but here is my reasoning... (no diff provided)
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tests: _extract_diff_and_explanation
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffExtraction:
    def test_extracts_diff_from_fences(self):
        diff, explanation = _extract_diff_and_explanation(LLM_RESPONSE_WITH_FENCES)
        assert diff.strip().startswith("---")
        assert "+++ b/telemetry_parser.c" in diff

    def test_extracts_explanation(self):
        diff, explanation = _extract_diff_and_explanation(LLM_RESPONSE_WITH_FENCES)
        assert "heap-buffer-overflow" in explanation or len(explanation) > 5

    def test_no_diff_returns_empty(self):
        diff, explanation = _extract_diff_and_explanation(LLM_RESPONSE_NO_DIFF)
        assert diff == "" or not diff.strip().startswith("---")

    def test_raw_diff_without_fences(self):
        diff, explanation = _extract_diff_and_explanation(VALID_DIFF)
        assert "---" in diff or diff == VALID_DIFF.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Tests: _apply_unified_diff
# ─────────────────────────────────────────────────────────────────────────────

class TestPythonPatchApplicator:
    def test_apply_simple_substitution(self):
        """Test applying a diff that replaces lines."""
        original = [
            "line 1\n",
            "old line 2\n",
            "line 3\n",
        ]
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -1,3 +1,3 @@\n"
            " line 1\n"
            "-old line 2\n"
            "+new line 2\n"
            " line 3\n"
        )
        result = _apply_unified_diff(original, diff)
        assert result[1] == "new line 2\n"
        assert len(result) == 3

    def test_apply_addition(self):
        """Test applying a diff that adds a line."""
        original = [
            "line 1\n",
            "line 2\n",
        ]
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -1,2 +1,3 @@\n"
            " line 1\n"
            "+inserted line\n"
            " line 2\n"
        )
        result = _apply_unified_diff(original, diff)
        assert len(result) == 3
        assert result[1] == "inserted line\n"

    def test_apply_deletion(self):
        """Test applying a diff that removes a line."""
        original = [
            "line 1\n",
            "remove me\n",
            "line 3\n",
        ]
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -1,3 +1,2 @@\n"
            " line 1\n"
            "-remove me\n"
            " line 3\n"
        )
        result = _apply_unified_diff(original, diff)
        assert len(result) == 2
        assert result[1] == "line 3\n"

    def test_preserves_unchanged_lines(self):
        """Context lines should be preserved exactly."""
        original = ["a\n", "b\n", "c\n", "d\n"]
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -2,2 +2,2 @@\n"
            " b\n"
            "-c\n"
            "+C\n"
        )
        result = _apply_unified_diff(original, diff)
        assert result[0] == "a\n"
        assert result[1] == "b\n"
        assert result[2] == "C\n"
        assert result[3] == "d\n"


# ─────────────────────────────────────────────────────────────────────────────
# Tests: apply_diff (file-level)
# ─────────────────────────────────────────────────────────────────────────────

class TestApplyDiffToFile:
    def test_applies_to_file_successfully(self, tmp_path):
        """Apply a simple patch to a temp file and verify contents."""
        source = tmp_path / "test.c"
        source.write_text("int x = 1;\nint y = 2;\n")

        diff = (
            "--- a/test.c\n"
            "+++ b/test.c\n"
            "@@ -1,2 +1,2 @@\n"
            " int x = 1;\n"
            "-int y = 2;\n"
            "+int y = 42; /* fixed */\n"
        )

        success, error = apply_diff(diff, source)
        assert success, f"Patch failed: {error}"
        content = source.read_text()
        assert "42" in content

    def test_empty_diff_fails(self, tmp_path):
        source = tmp_path / "test.c"
        source.write_text("int x = 1;\n")
        success, error = apply_diff("", source)
        assert not success
        assert "Empty diff" in error

    def test_dry_run_does_not_modify_file(self, tmp_path):
        source = tmp_path / "test.c"
        original_content = "int x = 1;\nint y = 2;\n"
        source.write_text(original_content)

        diff = (
            "--- a/test.c\n"
            "+++ b/test.c\n"
            "@@ -1,2 +1,2 @@\n"
            " int x = 1;\n"
            "-int y = 2;\n"
            "+int y = 999;\n"
        )

        success, _ = apply_diff(diff, source, dry_run=True)
        # Content should be unchanged
        assert source.read_text() == original_content
