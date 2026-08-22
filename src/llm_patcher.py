"""
src/llm_patcher.py
AutoPatch Sentinel - LLM-Driven Patch Generator

Interfaces with LLM APIs (Google Gemini, Anthropic Claude, OpenAI)
to generate minimal, surgical C/C++ patches in unified diff format.

Key design decisions:
  - Output is strictly constrained to unified diff format (git diff --no-index)
  - Prompt includes crash context, source snippet, and explicit constraints
  - Patch is validated (parseable, applies cleanly) before returning
  - Supports multi-turn retry: feed back compiler/test failures for correction
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.llm_patcher")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

class LLMProvider(Enum):
    GEMINI  = "gemini"
    CLAUDE  = "claude"
    OPENAI  = "openai"
    OLLAMA  = "ollama"


@dataclass
class PatchAttempt:
    attempt_no: int
    diff_text: str            # Raw unified diff
    explanation: str          # LLM's root cause explanation
    raw_response: str         # Full LLM response (for debugging)
    tokens_used: int


@dataclass
class PatchResult:
    success: bool             # Did patch apply cleanly?
    attempt: Optional[PatchAttempt]
    applied_path: Optional[Path]  # Path to patched source file
    error: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# System prompt (core prompt engineering)
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a world-class C/C++ security engineer specializing in memory safety vulnerabilities.
Your job is to analyze a crash report from AddressSanitizer or UndefinedBehaviorSanitizer and
produce a MINIMAL, SURGICAL patch to fix the root cause.

CRITICAL RULES:
1. Output ONLY a single valid unified diff in the format below. Do NOT output prose before or after the diff block.
2. The patch must be MINIMAL — only add the necessary bounds check, type promotion, or null check. Do not refactor unrelated code.
3. Do NOT change function signatures, add new functions, or alter packet parsing logic.
4. Do NOT remove or comment out existing code unless it is the direct cause of the bug.
5. The fix must be complete — the crashing input must no longer trigger the sanitizer error.
6. After the diff, add a brief explanation as a C comment inside the diff (in the changed lines).

OUTPUT FORMAT (strictly):
```diff
--- a/targets/telemetry_parser/telemetry_parser.c
+++ b/targets/telemetry_parser/telemetry_parser.c
@@ -LINE,COUNT +LINE,COUNT @@
 context line
-old line
+new fixed line
 context line
```

EXPLANATION:
<One to three sentences explaining the root cause and why your fix works>
"""

_USER_PROMPT_TEMPLATE = """\
## Crash Report

{crash_context}

## Source File: {source_file}

```c
{source_snippet}
```

## Task

The vulnerability is in the C source file above. Identify the exact root cause from the crash report
and produce a minimal unified diff to fix it.

Remember:
- Only fix the specific unsafe operation identified in the crash report.
- Do NOT change any struct definitions, function signatures, or unrelated logic.
- Preserve all existing comments and code formatting style.
- The patch MUST fix the crash without breaking valid packet parsing.
"""

_RETRY_PROMPT_TEMPLATE = """\
Your previous patch (attempt #{attempt_no}) failed verification with the following error:

## Verification Failure

Stage: {failed_stage}
Error:
```
{error_output}
```

## Your Previous Diff

```diff
{previous_diff}
```

## Original Crash Context

{crash_context}

## Source File (current state after failed patch)

```c
{source_snippet}
```

Please analyze the verification failure and produce a corrected minimal unified diff.
Do NOT repeat the same fix — address the specific reason the patch failed.
"""


# ─────────────────────────────────────────────────────────────────────────────
# LLM client wrappers
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(prompt: str, model: str = "gemini-2.5-pro") -> tuple[str, int]:
    """Call Google Gemini API. Requires GEMINI_API_KEY env var."""
    try:
        import google.generativeai as genai
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError("GEMINI_API_KEY not set")
        genai.configure(api_key=api_key)
        client = genai.GenerativeModel(model)
        response = client.generate_content(
            [_SYSTEM_PROMPT, prompt],
            generation_config={"temperature": 0.1, "max_output_tokens": 2048},
        )
        text = response.text
        tokens = getattr(response.usage_metadata, "total_token_count", 0)
        return text, tokens
    except ImportError:
        raise ImportError("google-generativeai not installed. Run: pip install google-generativeai")


def _call_claude(prompt: str, model: str = "claude-sonnet-4-5") -> tuple[str, int]:
    """Call Anthropic Claude API. Requires ANTHROPIC_API_KEY env var."""
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError("ANTHROPIC_API_KEY not set")
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text
        tokens = message.usage.input_tokens + message.usage.output_tokens
        return text, tokens
    except ImportError:
        raise ImportError("anthropic not installed. Run: pip install anthropic")


def _call_openai(prompt: str, model: str = "gpt-4o") -> tuple[str, int]:
    """Call OpenAI API. Requires OPENAI_API_KEY env var."""
    try:
        from openai import OpenAI
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY not set")
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        text = response.choices[0].message.content
        tokens = response.usage.total_tokens
        return text, tokens
    except ImportError:
        raise ImportError("openai not installed. Run: pip install openai")


def _call_ollama(prompt: str, model: str = "codellama") -> tuple[str, int]:
    """
    Call local Ollama API using OpenAI-compatible endpoint.
    No API key required. Ollama must be running: `ollama serve`
    Default base URL: http://localhost:11434/v1
    """
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama",   # Ollama ignores this but the library requires a non-empty value
        )
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        text   = response.choices[0].message.content
        tokens = response.usage.total_tokens if response.usage else 0
        return text, tokens
    except ImportError:
        raise ImportError("openai not installed. Run: pip install openai")
    except Exception as e:
        raise RuntimeError(
            f"Ollama call failed: {e}\n"
            "Make sure Ollama is running: `ollama serve`\n"
            f"And the model is pulled: `ollama pull {model}`"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Diff extraction from LLM response
# ─────────────────────────────────────────────────────────────────────────────

_RE_DIFF_BLOCK = re.compile(
    r"```diff\s*\n(.*?)```",
    re.DOTALL
)

_RE_EXPLANATION = re.compile(
    r"EXPLANATION:\s*\n(.+?)(?:\n\n|\Z)",
    re.DOTALL
)


def _extract_diff_and_explanation(response: str) -> tuple[str, str]:
    """
    Extract the unified diff and explanation from an LLM response.
    Handles markdown code blocks and plain diff output.
    """
    # Try ```diff ... ``` code block
    m = _RE_DIFF_BLOCK.search(response)
    if m:
        diff = m.group(1).strip()
    elif response.strip().startswith("---"):
        # Raw diff without code fences
        diff = response.strip()
    else:
        # Search for any line starting with ---
        lines = response.split("\n")
        diff_lines = []
        in_diff = False
        for line in lines:
            if line.startswith("--- "):
                in_diff = True
            if in_diff:
                diff_lines.append(line)
                if line.startswith("```") and diff_lines:
                    break
        diff = "\n".join(diff_lines).strip()

    # Extract explanation
    m2 = _RE_EXPLANATION.search(response)
    explanation = m2.group(1).strip() if m2 else "(no explanation provided)"

    return diff, explanation


# ─────────────────────────────────────────────────────────────────────────────
# Patch applicator (applies unified diff to source file)
# ─────────────────────────────────────────────────────────────────────────────

def apply_diff(diff_text: str, source_file: Path, dry_run: bool = False) -> tuple[bool, str]:
    """
    Apply a unified diff to a source file using the `patch` command.
    Falls back to Python-based patching if `patch` is unavailable.

    Returns (success, error_message).
    """
    if not diff_text.strip():
        return False, "Empty diff"

    # Write diff to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(diff_text)
        patch_file = tmp.name

    try:
        if shutil.which("patch"):
            flags = ["--dry-run"] if dry_run else []
            result = subprocess.run(
                ["patch", "-p1"] + flags + [str(source_file)],
                input=diff_text,
                capture_output=True,
                text=True,
                cwd=str(source_file.parent),
                timeout=30,
            )
            return result.returncode == 0, result.stderr
        else:
            return _python_patch(diff_text, source_file, dry_run)
    finally:
        os.unlink(patch_file)


def _python_patch(diff_text: str, source_file: Path, dry_run: bool) -> tuple[bool, str]:
    """
    Pure-Python unified diff applicator (no external `patch` binary required).
    Parses the diff and applies hunk by hunk to the source file.
    """
    import difflib

    try:
        with open(source_file, "r", encoding="utf-8") as f:
            original_lines = f.readlines()

        patched_lines = _apply_unified_diff(original_lines, diff_text)

        if not dry_run:
            with open(source_file, "w", encoding="utf-8") as f:
                f.writelines(patched_lines)

        return True, ""
    except Exception as e:
        return False, f"Python patch failed: {e}"


def _apply_unified_diff(original_lines: list[str], diff_text: str) -> list[str]:
    """
    Apply a unified diff (--- / +++ / @@ ... @@) to original_lines.
    Returns patched lines.
    """
    result = list(original_lines)
    offset = 0  # Line number offset as hunks are applied

    # Parse hunks
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
    diff_lines = diff_text.split("\n")

    i = 0
    while i < len(diff_lines):
        line = diff_lines[i]
        m = hunk_re.match(line)
        if m:
            old_start = int(m.group(1)) - 1  # 0-indexed
            old_count = int(m.group(2)) if m.group(2) else 1
            i += 1
            # Collect hunk lines
            hunk_old = []
            hunk_new = []
            while i < len(diff_lines) and not diff_lines[i].startswith("@@") \
                    and not diff_lines[i].startswith("---") \
                    and not diff_lines[i].startswith("+++"):
                hl = diff_lines[i]
                if hl.startswith("-"):
                    hunk_old.append(hl[1:] + "\n")
                elif hl.startswith("+"):
                    hunk_new.append(hl[1:] + "\n")
                elif hl.startswith(" "):
                    hunk_old.append(hl[1:] + "\n")
                    hunk_new.append(hl[1:] + "\n")
                i += 1
            # Apply hunk
            real_start = old_start + offset
            result[real_start:real_start + len(hunk_old)] = hunk_new
            offset += len(hunk_new) - len(hunk_old)
        else:
            i += 1

    return result




# ─────────────────────────────────────────────────────────────────────────────
# LLMPatcher main class
# ─────────────────────────────────────────────────────────────────────────────

class LLMPatcher:
    """
    Uses an LLM to generate and apply a minimal patch for a given crash report.

    Usage:
        patcher = LLMPatcher(provider=LLMProvider.GEMINI, model="gemini-2.5-pro")
        attempt = patcher.generate_patch(
            crash_context=report.to_llm_context(source_snippet),
            source_snippet=source_snippet,
            source_file=source_file_path,
        )
    """

    def __init__(
        self,
        provider: LLMProvider = LLMProvider.GEMINI,
        model: Optional[str] = None,
        patches_dir: Path = Path("patches"),
    ):
        self.provider    = provider
        self.model       = model or self._default_model(provider)
        self.patches_dir = Path(patches_dir)
        self.patches_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _default_model(provider: LLMProvider) -> str:
        return {
            LLMProvider.GEMINI:  "gemini-2.5-pro",
            LLMProvider.CLAUDE:  "claude-sonnet-4-5",
            LLMProvider.OPENAI:  "gpt-4o",
            LLMProvider.OLLAMA:  "codellama",
        }[provider]

    def generate_patch(
        self,
        crash_context: str,
        source_snippet: str,
        source_file: Path,
        attempt_no: int = 1,
        previous_attempt: Optional[PatchAttempt] = None,
        failed_stage: str = "",
        verification_error: str = "",
    ) -> PatchResult:
        """
        Generate a patch via the LLM and apply it to source_file.
        On first attempt, uses the initial prompt.
        On retries, includes the previous diff and failure context.
        """
        if attempt_no > 1 and previous_attempt:
            prompt = _RETRY_PROMPT_TEMPLATE.format(
                attempt_no=attempt_no,
                failed_stage=failed_stage,
                error_output=verification_error[:2000],
                previous_diff=previous_attempt.diff_text,
                crash_context=crash_context,
                source_snippet=source_snippet,
            )
        else:
            prompt = _USER_PROMPT_TEMPLATE.format(
                crash_context=crash_context,
                source_file=str(source_file),
                source_snippet=source_snippet,
            )

        log.info(f"Requesting patch from {self.provider.value}/{self.model} (attempt {attempt_no})")
        t0 = time.time()

        try:
            raw_response, tokens = self._call_llm(prompt)
        except Exception as e:
            log.error(f"LLM API call failed: {e}")
            return PatchResult(success=False, attempt=None, applied_path=None, error=str(e))

        elapsed = time.time() - t0
        log.info(f"LLM responded in {elapsed:.1f}s, ~{tokens} tokens")

        diff_text, explanation = _extract_diff_and_explanation(raw_response)

        if not diff_text:
            log.error("LLM response contained no parseable diff")
            return PatchResult(
                success=False,
                attempt=PatchAttempt(attempt_no, "", explanation, raw_response, tokens),
                applied_path=None,
                error="No diff found in LLM response",
            )

        # Save the patch
        patch_path = self.patches_dir / f"attempt_{attempt_no}_{int(time.time())}.patch"
        with open(patch_path, "w") as f:
            f.write(f"# Attempt {attempt_no}\n# Explanation: {explanation}\n\n")
            f.write(diff_text)
        log.info(f"Patch saved: {patch_path.name}")

        attempt = PatchAttempt(
            attempt_no=attempt_no,
            diff_text=diff_text,
            explanation=explanation,
            raw_response=raw_response,
            tokens_used=tokens,
        )

        # Create backup of original source
        backup_path = source_file.with_suffix(".c.bak")
        import shutil
        shutil.copy(source_file, backup_path)

        # Apply the diff
        success, error = apply_diff(diff_text, source_file)
        if not success:
            # Restore backup on failure
            shutil.copy(backup_path, source_file)
            log.error(f"Diff application failed: {error}")
            return PatchResult(
                success=False,
                attempt=attempt,
                applied_path=None,
                error=f"Patch application failed: {error}",
            )

        log.info(f"[+] Patch applied successfully to {source_file.name}")
        return PatchResult(success=True, attempt=attempt, applied_path=source_file)

    def restore_backup(self, source_file: Path) -> bool:
        """Restore original source from backup (rollback a failed patch)."""
        import shutil
        backup = source_file.with_suffix(".c.bak")
        if backup.exists():
            shutil.copy(backup, source_file)
            log.info(f"Restored backup: {source_file.name}")
            return True
        return False

    def _call_llm(self, prompt: str) -> tuple[str, int]:
        if self.provider == LLMProvider.GEMINI:
            return _call_gemini(prompt, self.model)
        elif self.provider == LLMProvider.CLAUDE:
            return _call_claude(prompt, self.model)
        elif self.provider == LLMProvider.OPENAI:
            return _call_openai(prompt, self.model)
        elif self.provider == LLMProvider.OLLAMA:
            return _call_ollama(prompt, self.model)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")
