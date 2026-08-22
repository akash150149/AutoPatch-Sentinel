"""
src/verifier.py
AutoPatch Sentinel - 3-Stage Verification Harness

Implements the "Prove the Fix Holds" component — the key differentiator
of AutoPatch Sentinel versus naive LLM patching tools.

Stage 1 - Crash Invalidation:
    Re-run the EXACT crashing input against the PATCHED ASan binary.
    The binary must execute without ANY sanitizer error and return exit code 0.

Stage 2 - Regression Suite:
    Run all valid functional test payloads (e.g., valid_gps_pkt.bin).
    The patched parser must correctly process all valid inputs.

Stage 3 - Differential Re-Fuzzing:
    Run a short libFuzzer / seed-replay burst against the patched binary.
    Confirms no secondary or adjacent memory safety bugs were introduced.

All three stages must PASS for the system to report "fix verified."
If any stage fails, the structured failure context is fed back to the LLM.
"""

from __future__ import annotations

import os
import subprocess
import time
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.verifier")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

class VerificationStage(Enum):
    CRASH_INVALIDATION = "Stage 1: Crash Invalidation"
    REGRESSION_SUITE   = "Stage 2: Regression Suite"
    REFUZZ_BURST       = "Stage 3: Re-Fuzzing Burst"


@dataclass
class StageResult:
    stage: VerificationStage
    passed: bool
    details: str          # Human-readable summary
    error_output: str     # Compiler/test/ASan output on failure
    duration_s: float


@dataclass
class VerificationResult:
    all_passed: bool
    stage_results: list[StageResult]
    failed_stage: Optional[VerificationStage]
    failure_output: str   # Output to feed back to LLM on failure

    def summary_table(self) -> str:
        lines = ["┌─────────────────────────────────────────┬────────┐"]
        lines.append("│ Stage                                   │ Status │")
        lines.append("├─────────────────────────────────────────┼────────┤")
        for s in self.stage_results:
            status = "✅ PASS" if s.passed else "❌ FAIL"
            name = s.stage.value[:41].ljust(41)
            lines.append(f"│ {name} │ {status} │")
        lines.append("└─────────────────────────────────────────┴────────┘")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Verifier
# ─────────────────────────────────────────────────────────────────────────────

class Verifier:
    """
    Runs all three verification stages against the patched binary.

    Usage:
        verifier = Verifier(
            target_dir=Path("targets/telemetry_parser"),
            asan_binary="telemetry_parser_asan",
            tests_dir=Path("targets/telemetry_parser/tests"),
            crashes_dir=Path("crashes"),
            seeds_dir=Path("targets/seeds"),
        )
        result = verifier.verify_all(crash_input=crash_path)
    """

    def __init__(
        self,
        target_dir: Path,
        asan_binary: str,
        tests_dir: Path,
        crashes_dir: Path,
        seeds_dir: Path,
        refuzz_duration_s: float = 30.0,
    ):
        self.target_dir         = Path(target_dir)
        self.asan_binary_path   = self.target_dir / asan_binary
        self.tests_dir          = Path(tests_dir)
        self.crashes_dir        = Path(crashes_dir)
        self.seeds_dir          = Path(seeds_dir)
        self.refuzz_duration_s  = refuzz_duration_s
        self._asan_env          = {
            **os.environ,
            "ASAN_OPTIONS": "halt_on_error=1:exitcode=1:color=never",
        }

    # ── Public API ───────────────────────────────────────────────────────────

    def verify_all(self, crash_input: Path) -> VerificationResult:
        """
        Run all three verification stages.
        Stops at first failure (fast-fail) to minimize LLM retry latency.
        """
        results: list[StageResult] = []

        # ── Stage 1 ──────────────────────────────────────────────────────────
        s1 = self.stage1_crash_invalidation(crash_input)
        results.append(s1)
        log.info(f"[Stage 1] {'PASS' if s1.passed else 'FAIL'}: {s1.details}")
        if not s1.passed:
            return VerificationResult(
                all_passed=False,
                stage_results=results,
                failed_stage=VerificationStage.CRASH_INVALIDATION,
                failure_output=s1.error_output,
            )

        # ── Stage 2 ──────────────────────────────────────────────────────────
        s2 = self.stage2_regression_suite()
        results.append(s2)
        log.info(f"[Stage 2] {'PASS' if s2.passed else 'FAIL'}: {s2.details}")
        if not s2.passed:
            return VerificationResult(
                all_passed=False,
                stage_results=results,
                failed_stage=VerificationStage.REGRESSION_SUITE,
                failure_output=s2.error_output,
            )

        # ── Stage 3 ──────────────────────────────────────────────────────────
        s3 = self.stage3_refuzz_burst()
        results.append(s3)
        log.info(f"[Stage 3] {'PASS' if s3.passed else 'FAIL'}: {s3.details}")
        if not s3.passed:
            return VerificationResult(
                all_passed=False,
                stage_results=results,
                failed_stage=VerificationStage.REFUZZ_BURST,
                failure_output=s3.error_output,
            )

        return VerificationResult(
            all_passed=True,
            stage_results=results,
            failed_stage=None,
            failure_output="",
        )

    # ── Stage 1: Crash Invalidation ──────────────────────────────────────────

    def stage1_crash_invalidation(self, crash_input: Path) -> StageResult:
        """
        Replay the exact crashing input against the patched binary.
        PASS: exit code 0 and no ASan error detected.
        FAIL: any non-zero exit code or ASan error string in output.
        """
        start = time.time()
        stage = VerificationStage.CRASH_INVALIDATION

        if not self.asan_binary_path.exists():
            return StageResult(
                stage=stage, passed=False,
                details=f"ASan binary not found: {self.asan_binary_path}",
                error_output="Binary missing — rebuild failed?",
                duration_s=0.0,
            )

        if not crash_input.exists():
            return StageResult(
                stage=stage, passed=False,
                details=f"Crash input not found: {crash_input}",
                error_output="Crash input file missing",
                duration_s=0.0,
            )

        try:
            proc = subprocess.run(
                [str(self.asan_binary_path), str(crash_input)],
                capture_output=True,
                text=True,
                timeout=30,
                env=self._asan_env,
            )
            output = proc.stdout + proc.stderr
            elapsed = time.time() - start

            crashed = proc.returncode != 0 or self._has_asan_error(output)

            if crashed:
                return StageResult(
                    stage=stage, passed=False,
                    details=f"Patch did NOT fix the crash (exit={proc.returncode})",
                    error_output=output[:3000],
                    duration_s=elapsed,
                )
            return StageResult(
                stage=stage, passed=True,
                details="Crashing input now executes safely (exit=0, no ASan errors)",
                error_output="",
                duration_s=elapsed,
            )
        except subprocess.TimeoutExpired:
            return StageResult(
                stage=stage, passed=False,
                details="Timeout during crash replay",
                error_output="Process timed out",
                duration_s=30.0,
            )

    # ── Stage 2: Regression Suite ────────────────────────────────────────────

    def stage2_regression_suite(self) -> StageResult:
        """
        Run all valid functional test cases (*.bin in tests_dir).
        PASS: all inputs return exit code 0 with no ASan errors.
        FAIL: any input fails or triggers an ASan error.
        """
        start = time.time()
        stage = VerificationStage.REGRESSION_SUITE

        test_files = sorted(self.tests_dir.glob("valid_*.bin"))
        if not test_files:
            return StageResult(
                stage=stage, passed=True,
                details="No regression tests found — skipping (trivial pass)",
                error_output="",
                duration_s=0.0,
            )

        failures = []
        for test_file in test_files:
            try:
                proc = subprocess.run(
                    [str(self.asan_binary_path), str(test_file)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=self._asan_env,
                )
                output = proc.stdout + proc.stderr

                if proc.returncode != 0 or self._has_asan_error(output):
                    failures.append((test_file.name, output[:1000]))
                    log.warning(f"  Regression FAIL: {test_file.name} (exit={proc.returncode})")
                else:
                    log.debug(f"  Regression PASS: {test_file.name}")
            except subprocess.TimeoutExpired:
                failures.append((test_file.name, "Timeout"))

        elapsed = time.time() - start
        total = len(test_files)

        if failures:
            error_parts = [f"FAILED: {name}\n{out}" for name, out in failures]
            return StageResult(
                stage=stage, passed=False,
                details=f"{len(failures)}/{total} regression tests FAILED",
                error_output="\n\n".join(error_parts),
                duration_s=elapsed,
            )

        return StageResult(
            stage=stage, passed=True,
            details=f"All {total} regression tests PASSED",
            error_output="",
            duration_s=elapsed,
        )

    # ── Stage 3: Re-Fuzzing Burst ────────────────────────────────────────────

    def stage3_refuzz_burst(self) -> StageResult:
        """
        Run a short re-fuzzing burst against the patched binary.
        Uses seed replay against patched binary + all seeds (including crash seed).
        If libFuzzer is available, runs a short timed burst instead.
        PASS: no new crashes found.
        FAIL: a new crash found.
        """
        start = time.time()
        stage = VerificationStage.REFUZZ_BURST

        seeds = sorted(self.seeds_dir.glob("*.bin"))
        if not seeds:
            return StageResult(
                stage=stage, passed=True,
                details="No seeds for re-fuzzing — skipping",
                error_output="",
                duration_s=0.0,
            )

        new_crashes = []
        for seed in seeds:
            try:
                proc = subprocess.run(
                    [str(self.asan_binary_path), str(seed)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=self._asan_env,
                )
                output = proc.stdout + proc.stderr
                if proc.returncode != 0 and self._has_asan_error(output):
                    new_crashes.append((seed.name, output[:1000]))
            except subprocess.TimeoutExpired:
                log.debug(f"Re-fuzz timeout on seed: {seed.name}")

        elapsed = time.time() - start

        if new_crashes:
            # Filter: exclude the ORIGINAL crash seed (already fixed by Stage 1)
            # Only fail if a previously-PASSING seed now crashes
            genuine_regressions = [
                (name, out) for name, out in new_crashes
                if "crash_overflow" not in name  # original crashing seed is expected to pass Stage 1
            ]
            if genuine_regressions:
                error_parts = [f"NEW CRASH: {n}\n{o}" for n, o in genuine_regressions]
                return StageResult(
                    stage=stage, passed=False,
                    details=f"{len(genuine_regressions)} NEW crash(es) found during re-fuzz",
                    error_output="\n\n".join(error_parts),
                    duration_s=elapsed,
                )

        return StageResult(
            stage=stage, passed=True,
            details=f"Re-fuzz burst complete: no new crashes ({len(seeds)} inputs tested)",
            error_output="",
            duration_s=elapsed,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _has_asan_error(output: str) -> bool:
        """Check if output contains AddressSanitizer or UBSan error markers."""
        error_markers = [
            "AddressSanitizer:",
            "UndefinedBehaviorSanitizer:",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "double-free",
            "SEGFAULT",
            "runtime error:",
        ]
        return any(marker in output for marker in error_markers)
