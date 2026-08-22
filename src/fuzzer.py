"""
src/fuzzer.py
AutoPatch Sentinel - Fuzzer Controller

Manages fuzzing execution using libFuzzer (primary) or AFL++ (optional),
captures crashes, and produces structured output for the triage engine.

Supports two modes:
  1. REAL_FUZZ: Runs libFuzzer/AFL++ as a subprocess for a configured duration.
  2. SEED_REPLAY: For demo/Windows environments where libFuzzer isn't available,
     replays pre-seeded crashing inputs against the ASan-instrumented binary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.fuzzer")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

class FuzzMode(Enum):
    LIBFUZZER    = auto()   # clang libFuzzer (-fsanitize=fuzzer)
    AFL          = auto()   # AFL++ (afl-fuzz)
    SEED_REPLAY  = auto()   # Replay known seeds against ASan binary


@dataclass
class FuzzResult:
    mode: FuzzMode
    crashed: bool
    crash_input_path: Optional[Path]   # Binary input that caused the crash
    asan_log: str                       # ASan stderr output
    duration_s: float
    num_executions: int
    extra_info: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzer controller
# ─────────────────────────────────────────────────────────────────────────────

class FuzzerController:
    """
    Runs the fuzzer, collects crashes, and returns structured FuzzResult.

    Usage:
        ctrl = FuzzerController(
            target_dir=Path("targets/telemetry_parser"),
            asan_binary="telemetry_parser_asan",
            crashes_dir=Path("crashes"),
        )
        result = ctrl.run(mode=FuzzMode.SEED_REPLAY, duration_s=30)
    """

    def __init__(
        self,
        target_dir: Path,
        asan_binary: str,
        crashes_dir: Path,
        seeds_dir: Optional[Path] = None,
        libfuzzer_binary: Optional[str] = None,
    ):
        self.target_dir         = Path(target_dir)
        self.asan_binary        = self.target_dir / asan_binary
        self.crashes_dir        = Path(crashes_dir)
        self.seeds_dir          = Path(seeds_dir) if seeds_dir else self.target_dir / ".." / "seeds"
        self.libfuzzer_binary   = self.target_dir / libfuzzer_binary if libfuzzer_binary else None
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ───────────────────────────────────────────────────────────

    def run(
        self,
        mode: FuzzMode = FuzzMode.SEED_REPLAY,
        duration_s: float = 60.0,
        max_input_len: int = 4096,
    ) -> FuzzResult:
        """
        Execute fuzzing in the specified mode.
        Returns the first crash found (or a no-crash result if none found).
        """
        log.info(f"Starting fuzzer: mode={mode.name} duration={duration_s}s")
        if mode == FuzzMode.SEED_REPLAY:
            return self._seed_replay()
        elif mode == FuzzMode.LIBFUZZER:
            return self._run_libfuzzer(duration_s, max_input_len)
        elif mode == FuzzMode.AFL:
            return self._run_afl(duration_s)
        else:
            raise ValueError(f"Unknown fuzz mode: {mode}")

    def replay_crash(self, crash_input: Path) -> tuple[bool, str]:
        """
        Replay a specific input against the ASan binary.
        Returns (crashed, asan_output).
        """
        if not self.asan_binary.exists():
            return False, f"ASan binary not found: {self.asan_binary}"

        env = {**os.environ, "ASAN_OPTIONS": "halt_on_error=1:exitcode=1"}

        try:
            with open(crash_input, "rb") as f:
                crash_data = f.read()

            proc = subprocess.run(
                [str(self.asan_binary), str(crash_input)],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
            crashed = proc.returncode != 0
            asan_out = proc.stdout + proc.stderr
            log.info(f"Replay {'CRASHED' if crashed else 'CLEAN'}: {crash_input.name}")
            return crashed, asan_out
        except subprocess.TimeoutExpired:
            return False, "Timeout during crash replay"
        except Exception as e:
            return False, str(e)

    # ── Seed replay mode ─────────────────────────────────────────────────────

    def _seed_replay(self) -> FuzzResult:
        """
        Replay all .bin files in seeds_dir against the ASan binary.
        Returns on first crash.
        """
        start = time.time()
        seeds = sorted(self.seeds_dir.glob("*.bin"))

        if not seeds:
            log.warning(f"No .bin seeds found in {self.seeds_dir}")
            return FuzzResult(
                mode=FuzzMode.SEED_REPLAY,
                crashed=False,
                crash_input_path=None,
                asan_log="No seeds found",
                duration_s=0.0,
                num_executions=0,
            )

        if not self.asan_binary.exists():
            log.error(f"ASan binary not found: {self.asan_binary}")
            return FuzzResult(
                mode=FuzzMode.SEED_REPLAY,
                crashed=False,
                crash_input_path=None,
                asan_log=f"ASan binary not found: {self.asan_binary}",
                duration_s=0.0,
                num_executions=0,
            )

        executions = 0
        env = {**os.environ, "ASAN_OPTIONS": "halt_on_error=1:exitcode=1:color=never"}

        for seed in seeds:
            executions += 1
            log.debug(f"Replaying seed: {seed.name}")
            try:
                proc = subprocess.run(
                    [str(self.asan_binary), str(seed)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=env,
                )
                asan_output = proc.stdout + proc.stderr
                if proc.returncode != 0 and (
                    "AddressSanitizer" in asan_output
                    or "UndefinedBehaviorSanitizer" in asan_output
                    or proc.returncode in (1, 134, -11)  # SIGABRT, SIGSEGV
                ):
                    # Copy crash input to crashes dir
                    crash_dest = self.crashes_dir / f"crash_{seed.stem}_{int(time.time())}.bin"
                    shutil.copy(seed, crash_dest)

                    # Save ASan log
                    log_path = crash_dest.with_suffix(".asan.log")
                    with open(log_path, "w") as f:
                        f.write(asan_output)

                    log.info(f"[!] CRASH found: {seed.name} → {crash_dest.name}")
                    return FuzzResult(
                        mode=FuzzMode.SEED_REPLAY,
                        crashed=True,
                        crash_input_path=crash_dest,
                        asan_log=asan_output,
                        duration_s=time.time() - start,
                        num_executions=executions,
                        extra_info={"seed": str(seed), "asan_log_path": str(log_path)},
                    )
            except subprocess.TimeoutExpired:
                log.warning(f"Timeout on seed: {seed.name}")
                continue

        log.info(f"No crashes found in {executions} seed replays")
        return FuzzResult(
            mode=FuzzMode.SEED_REPLAY,
            crashed=False,
            crash_input_path=None,
            asan_log="",
            duration_s=time.time() - start,
            num_executions=executions,
        )

    # ── libFuzzer mode ───────────────────────────────────────────────────────

    def _run_libfuzzer(self, duration_s: float, max_input_len: int) -> FuzzResult:
        if not self.libfuzzer_binary or not self.libfuzzer_binary.exists():
            log.warning("libFuzzer binary not found, falling back to seed replay")
            return self._seed_replay()

        corpus_dir = self.target_dir / "corpus"
        corpus_dir.mkdir(exist_ok=True)

        # Seed corpus with existing seeds
        if self.seeds_dir.exists():
            for seed in self.seeds_dir.glob("*.bin"):
                dest = corpus_dir / seed.name
                if not dest.exists():
                    shutil.copy(seed, dest)

        artifact_prefix = str(self.crashes_dir / "crash_libfuzzer_")
        cmd = [
            str(self.libfuzzer_binary),
            f"-max_total_time={int(duration_s)}",
            f"-max_len={max_input_len}",
            f"-artifact_prefix={artifact_prefix}",
            "-print_final_stats=1",
            str(corpus_dir),
        ]
        log.info(f"libFuzzer command: {' '.join(cmd)}")

        start = time.time()
        env = {**os.environ, "ASAN_OPTIONS": "halt_on_error=1:exitcode=1:color=never"}

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration_s + 30,
                env=env,
            )
            asan_output = proc.stdout + proc.stderr
            elapsed = time.time() - start

            # Check if a crash artifact was written
            crash_artifacts = sorted(self.crashes_dir.glob("crash_libfuzzer_*"))
            if crash_artifacts:
                latest_crash = crash_artifacts[-1]
                log_path = latest_crash.with_suffix(".asan.log")
                with open(log_path, "w") as f:
                    f.write(asan_output)
                return FuzzResult(
                    mode=FuzzMode.LIBFUZZER,
                    crashed=True,
                    crash_input_path=latest_crash,
                    asan_log=asan_output,
                    duration_s=elapsed,
                    num_executions=self._extract_exec_count(asan_output),
                )

            return FuzzResult(
                mode=FuzzMode.LIBFUZZER,
                crashed=False,
                crash_input_path=None,
                asan_log=asan_output,
                duration_s=elapsed,
                num_executions=self._extract_exec_count(asan_output),
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(
                mode=FuzzMode.LIBFUZZER,
                crashed=False,
                crash_input_path=None,
                asan_log="libFuzzer timed out",
                duration_s=duration_s,
                num_executions=0,
            )

    # ── AFL++ mode ───────────────────────────────────────────────────────────

    def _run_afl(self, duration_s: float) -> FuzzResult:
        if not shutil.which("afl-fuzz"):
            log.warning("afl-fuzz not found, falling back to seed replay")
            return self._seed_replay()

        findings_dir = self.target_dir / "afl_findings"
        findings_dir.mkdir(exist_ok=True)

        cmd = [
            "afl-fuzz",
            "-i", str(self.seeds_dir),
            "-o", str(findings_dir),
            "-V", str(int(duration_s)),   # -V = run for N seconds
            "--",
            str(self.asan_binary), "@@",
        ]
        log.info(f"AFL++ command: {' '.join(cmd)}")

        start = time.time()
        env = {**os.environ, "AFL_NO_UI": "1", "AFL_AUTORESUME": "1"}

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration_s + 30,
                env=env,
            )
            elapsed = time.time() - start
            crashes_dir = findings_dir / "default" / "crashes"

            if crashes_dir.exists():
                crashes = [p for p in crashes_dir.iterdir()
                           if p.name != "README.txt" and p.is_file()]
                if crashes:
                    crash = sorted(crashes)[0]
                    shutil.copy(crash, self.crashes_dir / crash.name)
                    asan_log = self._run_crash_to_get_asan(crash)
                    return FuzzResult(
                        mode=FuzzMode.AFL,
                        crashed=True,
                        crash_input_path=self.crashes_dir / crash.name,
                        asan_log=asan_log,
                        duration_s=elapsed,
                        num_executions=0,
                    )

            return FuzzResult(
                mode=FuzzMode.AFL,
                crashed=False,
                crash_input_path=None,
                asan_log=proc.stdout + proc.stderr,
                duration_s=elapsed,
                num_executions=0,
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(
                mode=FuzzMode.AFL, crashed=False, crash_input_path=None,
                asan_log="AFL++ timed out", duration_s=duration_s, num_executions=0,
            )

    def _run_crash_to_get_asan(self, crash_file: Path) -> str:
        """Re-run crash input to get ASan output (AFL itself doesn't always capture it)."""
        _, asan_log = self.replay_crash(crash_file)
        return asan_log

    @staticmethod
    def _extract_exec_count(output: str) -> int:
        """Extract number of executions from libFuzzer stats output."""
        import re
        m = re.search(r"stat::number_of_executed_units:\s*(\d+)", output)
        return int(m.group(1)) if m else 0


# ─────────────────────────────────────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    ctrl = FuzzerController(
        target_dir=Path("targets/telemetry_parser"),
        asan_binary="telemetry_parser_asan",
        crashes_dir=Path("crashes"),
        seeds_dir=Path("targets/seeds"),
    )
    result = ctrl.run(mode=FuzzMode.SEED_REPLAY)
    print(f"Crashed: {result.crashed}")
    if result.crash_input_path:
        print(f"Crash input: {result.crash_input_path}")
        print(f"ASan log excerpt:\n{result.asan_log[:500]}")
