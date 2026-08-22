"""
src/compiler.py
AutoPatch Sentinel - C/C++ Build Automation Module

Wraps clang/clang++ to compile target sources with:
  - AddressSanitizer (ASan)
  - UndefinedBehaviorSanitizer (UBSan)
  - Debug symbols (-g)
  - libFuzzer instrumentation (optional)

On Windows, automatically falls back to WSL `clang` if a native clang is
not available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("sentinel.compiler")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BuildResult:
    success: bool
    binary_path: Optional[Path]
    stdout: str
    stderr: str
    returncode: int
    command: str


# ─────────────────────────────────────────────────────────────────────────────
# Compiler detection
# ─────────────────────────────────────────────────────────────────────────────

def _find_clang() -> tuple[str, str]:
    """
    Locate clang and clang++ on PATH.
    On Windows tries WSL as a fallback ('wsl clang').
    Returns (clang_cc, clang_cxx).
    """
    for cc in ("clang", "clang-18", "clang-17", "clang-16", "clang-15"):
        if shutil.which(cc):
            cxx = cc.replace("clang", "clang++")
            if shutil.which(cxx):
                return cc, cxx
            return cc, "clang++"

    # Windows-specific: try GCC as a last resort (no ASan on MSVC)
    if sys.platform == "win32":
        if shutil.which("gcc"):
            log.warning(
                "clang not found — falling back to gcc. "
                "Note: AddressSanitizer is only partially supported under GCC on Windows. "
                "Consider installing LLVM or using WSL."
            )
            return "gcc", "g++"

    raise EnvironmentError(
        "Neither clang nor gcc was found on PATH. "
        "Install LLVM (https://github.com/llvm/llvm-project/releases) "
        "or use WSL with 'sudo apt install clang'."
    )


def _is_asan_supported(cc: str) -> bool:
    """Quick probe: does this compiler support -fsanitize=address?"""
    try:
        res = subprocess.run(
            [cc, "-fsanitize=address", "-x", "c", "-", "-o", os.devnull],
            input=b"int main(){return 0;}",
            capture_output=True,
            timeout=10,
        )
        return res.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Compiler class
# ─────────────────────────────────────────────────────────────────────────────

class Compiler:
    """
    Builds C/C++ targets for the AutoPatch Sentinel pipeline.

    Usage:
        compiler = Compiler(target_dir=Path("targets/telemetry_parser"))
        result = compiler.build_asan(
            sources=["telemetry_parser.c"],
            output="telemetry_parser_asan"
        )
    """

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir)
        self.cc, self.cxx = _find_clang()
        self.asan_supported = _is_asan_supported(self.cc)
        log.info(f"Compiler detected: {self.cc} / {self.cxx} | ASan: {self.asan_supported}")

    # ── Public build methods ─────────────────────────────────────────────────

    def build_asan(
        self,
        sources: list[str],
        output: str,
        extra_flags: list[str] | None = None,
        defines: list[str] | None = None,
    ) -> BuildResult:
        """
        Build with ASan + UBSan + debug symbols.
        Used for: crash replay (Stage 1), regression test (Stage 2).
        """
        flags = ["-g", "-O1", "-Wall", "-Wextra", "-Wno-unused-parameter"]

        if self.asan_supported:
            flags += [
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
            ]
        else:
            log.warning("ASan not supported — building without sanitizers (results won't be meaningful)")

        if defines:
            flags += [f"-D{d}" for d in defines]
        if extra_flags:
            flags += extra_flags

        return self._compile(self.cc, sources, output, flags)

    def build_libfuzzer(
        self,
        sources: list[str],
        output: str,
        harness: str | None = None,
    ) -> BuildResult:
        """
        Build a libFuzzer-instrumented binary.
        Requires clang with -fsanitize=fuzzer support.
        """
        all_sources = ([harness] if harness else []) + sources
        flags = [
            "-g", "-O1",
            "-fsanitize=address,fuzzer",
            "-fno-omit-frame-pointer",
            "-DFUZZER_BUILD",
        ]
        return self._compile(self.cxx, all_sources, output, flags)

    def build_standalone(
        self,
        sources: list[str],
        output: str,
    ) -> BuildResult:
        """Build a plain debug binary (no sanitizers)."""
        flags = ["-g", "-O0", "-Wall"]
        return self._compile(self.cc, sources, output, flags)

    def rebuild_after_patch(
        self,
        sources: list[str],
        output: str,
    ) -> BuildResult:
        """Rebuild with ASan after a patch is applied — used in the verify loop."""
        return self.build_asan(sources, output)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _compile(
        self,
        compiler: str,
        sources: list[str],
        output: str,
        flags: list[str],
    ) -> BuildResult:
        src_paths = [str(self.target_dir / s) for s in sources]
        out_path  = self.target_dir / output

        cmd = [compiler] + flags + src_paths + ["-o", str(out_path)]
        cmd_str = " ".join(cmd)
        log.debug(f"Compile command: {cmd_str}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.target_dir),
                timeout=120,
            )
            success = proc.returncode == 0
            if success:
                log.info(f"[BUILD OK] → {out_path.name}")
            else:
                log.error(f"[BUILD FAIL] exit={proc.returncode}\n{proc.stderr}")

            return BuildResult(
                success=success,
                binary_path=out_path if success else None,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                command=cmd_str,
            )
        except subprocess.TimeoutExpired:
            return BuildResult(
                success=False,
                binary_path=None,
                stdout="",
                stderr="Compilation timed out after 120 seconds",
                returncode=-1,
                command=cmd_str,
            )
        except FileNotFoundError:
            return BuildResult(
                success=False,
                binary_path=None,
                stdout="",
                stderr=f"Compiler not found: {compiler}",
                returncode=-1,
                command=cmd_str,
            )


# ─────────────────────────────────────────────────────────────────────────────
# CLI helper (quick smoke test)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    compiler = Compiler(Path("targets/telemetry_parser"))
    result = compiler.build_asan(["telemetry_parser.c"], "telemetry_parser_asan")
    print("Success:", result.success)
    if not result.success:
        print("STDERR:", result.stderr)
