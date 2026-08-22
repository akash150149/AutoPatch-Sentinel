"""
src/orchestrator.py
AutoPatch Sentinel - Main Pipeline Orchestrator

The entry point for the full Find → Patch → Prove loop.

Usage:
    python -m src.orchestrator --target telemetry_parser [OPTIONS]

Options:
    --target        Target name (subdirectory under targets/)
    --mode          Fuzz mode: seed_replay | libfuzzer | afl  [default: seed_replay]
    --provider      LLM provider: gemini | claude | openai    [default: gemini]
    --model         LLM model name                             [default: provider default]
    --max-retries   Max LLM patch retry attempts               [default: 3]
    --fuzz-duration Duration in seconds for fuzzing/re-fuzz    [default: 30]
    --no-color      Disable Rich colored terminal output

Pipeline execution order:
    1. Build target with ASan/UBSan (compiler.py)
    2. Run fuzzer to find crash (fuzzer.py)  [or use pre-seeded crashes]
    3. Triage ASan crash output (triage.py)
    4. Generate patch via LLM (llm_patcher.py)
    5. Rebuild with patch applied (compiler.py)
    6. Run 3-stage verification (verifier.py)
    7. If verification fails → retry loop (up to max_retries)
    8. Generate audit report (reporter.py)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

# Add parent dir to path for module imports
sys.path.insert(0, str(Path(__file__).parent))

from compiler    import Compiler
from fuzzer      import FuzzerController, FuzzMode
from triage      import TriageEngine, extract_source_context
from llm_patcher import LLMPatcher, LLMProvider
from verifier    import Verifier
from reporter    import Reporter

# Rich for beautiful terminal output
try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich.text    import Text
    from rich         import print as rprint
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )

log = logging.getLogger("sentinel.orchestrator")


# ─────────────────────────────────────────────────────────────────────────────
# Terminal UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def _banner():
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]⚡ AutoPatch Sentinel[/bold cyan]\n"
            "[dim]Automated Vulnerability Find → Patch → Prove Pipeline[/dim]",
            border_style="cyan",
        ))
    else:
        print("=" * 60)
        print("  AutoPatch Sentinel — Find → Patch → Prove")
        print("=" * 60)


def _step(n: int, total: int, msg: str):
    if RICH_AVAILABLE:
        console.print(f"\n[bold yellow]Step {n}/{total}[/bold yellow] [white]{msg}[/white]")
    else:
        print(f"\n[{n}/{total}] {msg}")


def _ok(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [bold green]✓[/bold green] {msg}")
    else:
        print(f"  [OK] {msg}")


def _fail(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [bold red]✗[/bold red] {msg}")
    else:
        print(f"  [FAIL] {msg}")


def _info(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [dim]{msg}[/dim]")
    else:
        print(f"  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(args: argparse.Namespace) -> int:
    """
    Main pipeline execution.
    Returns exit code: 0 = fix verified, 1 = fix failed / pipeline error.
    """
    project_root = Path(__file__).parent.parent.resolve()
    target_dir   = project_root / "targets" / args.target
    crashes_dir  = project_root / "crashes"
    patches_dir  = project_root / "patches"
    reports_dir  = project_root / "reports"
    seeds_dir    = project_root / "targets" / "seeds"
    tests_dir    = target_dir / "tests"

    if not target_dir.exists():
        _fail(f"Target directory not found: {target_dir}")
        return 1

    # Resolve source files for this target
    source_files = [f.name for f in target_dir.glob("*.c")]
    if not source_files:
        _fail(f"No .c source files found in {target_dir}")
        return 1

    main_source  = args.target + ".c"
    if main_source not in source_files:
        main_source = source_files[0]

    asan_binary_name = args.target + "_asan"
    pipeline_start   = time.time()

    _banner()
    _info(f"Target:    {args.target}")
    _info(f"Source:    {main_source}")
    _info(f"LLM:       {args.provider} / {args.model or 'default'}")
    _info(f"Mode:      {args.mode}")
    _info(f"Retries:   {args.max_retries}")

    # ── Step 1: Build ────────────────────────────────────────────────────────
    _step(1, 6, "Building target with ASan + UBSan")
    compiler = Compiler(target_dir)
    build    = compiler.build_asan(source_files, asan_binary_name)

    if not build.success:
        _fail(f"Build failed:\n{build.stderr}")
        return 1
    _ok(f"Built: {asan_binary_name}")

    # Generate seeds if not already present
    seed_files = list(seeds_dir.glob("*.bin")) if seeds_dir.exists() else []
    if not seed_files:
        _info("No seeds found — generating from generate_seeds.py")
        _run_seed_generator(target_dir)
        seed_files = list(seeds_dir.glob("*.bin"))

    # ── Step 2: Fuzz ─────────────────────────────────────────────────────────
    _step(2, 6, f"Fuzzing target [{args.mode}]")
    fuzz_mode = {
        "seed_replay": FuzzMode.SEED_REPLAY,
        "libfuzzer":   FuzzMode.LIBFUZZER,
        "afl":         FuzzMode.AFL,
    }.get(args.mode, FuzzMode.SEED_REPLAY)

    fuzzer_ctrl = FuzzerController(
        target_dir=target_dir,
        asan_binary=asan_binary_name,
        crashes_dir=crashes_dir,
        seeds_dir=seeds_dir,
    )
    fuzz_result = fuzzer_ctrl.run(mode=fuzz_mode, duration_s=args.fuzz_duration)

    if not fuzz_result.crashed:
        _fail("No crashes found. Target may already be patched, or seeds are insufficient.")
        _info("Hint: Add known crashing seeds to targets/seeds/ or run with --mode libfuzzer")
        return 1
    _ok(f"Crash found: {fuzz_result.crash_input_path.name if fuzz_result.crash_input_path else 'unknown'}")
    _info(f"ASan output excerpt: {fuzz_result.asan_log[:200].strip()}")

    # ── Step 3: Triage ───────────────────────────────────────────────────────
    _step(3, 6, "Triaging crash with ASan log parser")
    triage_engine = TriageEngine(project_root=project_root)
    crash_report  = triage_engine.parse(fuzz_result.asan_log)
    _ok(f"Triaged: {crash_report.summary()}")

    # Extract source context around the crash line
    source_file_path = target_dir / main_source
    source_snippet   = ""
    if crash_report.crash_line and crash_report.crash_file:
        # Try absolute path first, then relative inside target_dir
        crash_src = Path(crash_report.crash_file)
        if not crash_src.exists():
            crash_src = source_file_path
        source_snippet = extract_source_context(str(crash_src), crash_report.crash_line)

    crash_context = crash_report.to_llm_context(source_snippet)

    # ── Steps 4-5-6: LLM Patch + Rebuild + Verify (retry loop) ──────────────
    _step(4, 6, "Generating patch via LLM")

    provider_enum = {
        "gemini": LLMProvider.GEMINI,
        "claude": LLMProvider.CLAUDE,
        "openai": LLMProvider.OPENAI,
        "ollama": LLMProvider.OLLAMA,
    }.get(args.provider, LLMProvider.OLLAMA)

    patcher  = LLMPatcher(provider=provider_enum, model=args.model, patches_dir=patches_dir)
    verifier = Verifier(
        target_dir=target_dir,
        asan_binary=asan_binary_name,
        tests_dir=tests_dir,
        crashes_dir=crashes_dir,
        seeds_dir=seeds_dir,
        refuzz_duration_s=args.fuzz_duration,
    )

    final_patch  = None
    final_verify = None
    previous_attempt = None
    failed_stage_name = ""
    verification_error = ""

    for attempt_no in range(1, args.max_retries + 2):
        _info(f"\n  — Attempt {attempt_no} of {args.max_retries + 1} —")

        # 4. Generate patch
        patch_result = patcher.generate_patch(
            crash_context=crash_context,
            source_snippet=source_snippet,
            source_file=source_file_path,
            attempt_no=attempt_no,
            previous_attempt=previous_attempt,
            failed_stage=failed_stage_name,
            verification_error=verification_error,
        )

        if not patch_result.success:
            _fail(f"Patch generation/application failed: {patch_result.error}")
            if attempt_no > args.max_retries:
                break
            continue

        _ok(f"Patch applied (attempt {attempt_no})")
        _info(f"Explanation: {patch_result.attempt.explanation[:200]}")

        # 5. Rebuild
        _step(5, 6, f"Rebuilding with patch (attempt {attempt_no})")
        rebuild = compiler.rebuild_after_patch(source_files, asan_binary_name)
        if not rebuild.success:
            _fail(f"Rebuild failed:\n{rebuild.stderr[:500]}")
            verification_error = f"Compilation failed:\n{rebuild.stderr}"
            failed_stage_name  = "Compilation"
            previous_attempt   = patch_result.attempt
            # Restore backup before next attempt
            patcher.restore_backup(source_file_path)
            continue
        _ok("Rebuild successful")

        # 6. Verify
        _step(6, 6, f"Running 3-stage verification (attempt {attempt_no})")
        verify = verifier.verify_all(crash_input=fuzz_result.crash_input_path)
        final_patch  = patch_result.attempt
        final_verify = verify

        if RICH_AVAILABLE:
            console.print(verify.summary_table())
        else:
            print(verify.summary_table())

        if verify.all_passed:
            _ok("🎉 ALL VERIFICATION STAGES PASSED — Fix confirmed!")
            break
        else:
            _fail(f"Verification failed at: {verify.failed_stage.value}")
            verification_error = verify.failure_output
            failed_stage_name  = verify.failed_stage.value if verify.failed_stage else ""
            previous_attempt   = patch_result.attempt
            # Restore backup for next attempt
            patcher.restore_backup(source_file_path)

    # ── Step 7: Generate report ──────────────────────────────────────────────
    total_duration = time.time() - pipeline_start
    _step(6, 6, "Generating audit report")
    reporter = Reporter(reports_dir=reports_dir)
    md_path, json_path = reporter.generate(
        target_name=args.target,
        crash_report=crash_report,
        patch_attempt=final_patch,
        verification=final_verify,
        crash_input_path=fuzz_result.crash_input_path,
        total_duration_s=total_duration,
        retry_count=(args.max_retries - 1) if final_verify and final_verify.all_passed else args.max_retries,
    )
    _ok(f"Report (MD):   {md_path}")
    _ok(f"Report (JSON): {json_path}")

    if final_verify and final_verify.all_passed:
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                f"[bold green]✅ AutoPatch Sentinel: FIX VERIFIED[/bold green]\n"
                f"[white]Total time: {total_duration:.1f}s | LLM calls: {args.max_retries + 1 - (args.max_retries)}[/white]",
                border_style="green",
            ))
        return 0
    else:
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                f"[bold red]❌ AutoPatch Sentinel: FIX NOT VERIFIED[/bold red]\n"
                f"[white]Exhausted {args.max_retries + 1} attempt(s). Manual review required.[/white]",
                border_style="red",
            ))
        return 1


def _run_seed_generator(target_dir: Path):
    """Run the seed generator script if seeds are missing."""
    import subprocess
    gen_script = target_dir / "generate_seeds.py"
    if gen_script.exists():
        try:
            subprocess.run([sys.executable, str(gen_script)], cwd=str(target_dir), timeout=15)
        except Exception as e:
            log.warning(f"Seed generation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AutoPatch Sentinel — Automated Vulnerability Remediation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline with Gemini LLM, seed-replay fuzzing:
  python -m src.orchestrator --target telemetry_parser --provider gemini

  # Use Claude with 3 retry attempts:
  python -m src.orchestrator --target telemetry_parser --provider claude --max-retries 3

  # Use libFuzzer for real fuzzing (requires clang + libFuzzer):
  python -m src.orchestrator --target telemetry_parser --mode libfuzzer --fuzz-duration 60
        """,
    )
    parser.add_argument("--target",        default="telemetry_parser",
                        help="Target subdirectory under targets/")
    parser.add_argument("--mode",          choices=["seed_replay", "libfuzzer", "afl"],
                        default="seed_replay", help="Fuzzing mode")
    parser.add_argument("--provider",      choices=["gemini", "claude", "openai", "ollama"],
                        default="ollama", help="LLM provider")
    parser.add_argument("--model",         default=None,
                        help="Override LLM model name")
    parser.add_argument("--max-retries",   type=int, default=3,
                        help="Maximum LLM patch retry attempts (default: 3)")
    parser.add_argument("--fuzz-duration", type=float, default=30.0,
                        help="Fuzzing / re-fuzz burst duration in seconds (default: 30)")
    parser.add_argument("--verbose",       action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = parse_args()
    setup_logging(args.verbose)
    sys.exit(run_pipeline(args))
