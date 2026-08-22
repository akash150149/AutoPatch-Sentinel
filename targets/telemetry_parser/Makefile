# AutoPatch Sentinel - Makefile
# Target: telemetry_parser (deliberately vulnerable C service)
#
# Targets:
#   make asan        - Build with AddressSanitizer + UBSan (primary for fuzzing)
#   make libfuzzer   - Build libFuzzer instrumented binary
#   make afl         - Build AFL++ instrumented binary (requires afl-clang-fast)
#   make standalone  - Build a regular debug binary for manual testing
#   make clean       - Remove all build artifacts

CC      = clang
CXX     = clang++
CFLAGS_BASE  = -g -O1 -Wall -Wextra -Wno-unused-parameter
ASAN_FLAGS   = -fsanitize=address,undefined -fno-omit-frame-pointer
UBSAN_FLAGS  = -fsanitize=undefined
FUZZER_FLAGS = -fsanitize=address,fuzzer

TARGET_SRC  = telemetry_parser.c
HARNESS_SRC = fuzzer_harness.cc
TARGET_BIN  = telemetry_parser_asan
FUZZER_BIN  = fuzzer_target
AFL_BIN     = afl_target
STANDALONE  = telemetry_parser

.PHONY: all asan libfuzzer afl standalone clean

all: asan standalone

# ── ASan + UBSan binary (for crash replay and regression) ─────────────────────
asan: $(TARGET_SRC)
	$(CC) $(CFLAGS_BASE) $(ASAN_FLAGS) \
	    -o $(TARGET_BIN) $(TARGET_SRC)
	@echo "[+] Built: $(TARGET_BIN) (ASan + UBSan)"

# ── libFuzzer binary ───────────────────────────────────────────────────────────
libfuzzer: $(TARGET_SRC) $(HARNESS_SRC)
	$(CXX) $(CFLAGS_BASE) $(FUZZER_FLAGS) -DFUZZER_BUILD \
	    -o $(FUZZER_BIN) $(HARNESS_SRC) $(TARGET_SRC)
	@echo "[+] Built: $(FUZZER_BIN) (libFuzzer)"

# ── AFL++ binary ──────────────────────────────────────────────────────────────
afl: $(TARGET_SRC) $(HARNESS_SRC)
	AFL_USE_ASAN=1 afl-clang-fast $(CFLAGS_BASE) $(ASAN_FLAGS) -DFUZZER_BUILD \
	    -o $(AFL_BIN) $(HARNESS_SRC) $(TARGET_SRC)
	@echo "[+] Built: $(AFL_BIN) (AFL++)"

# ── Standalone debug binary ────────────────────────────────────────────────────
standalone: $(TARGET_SRC)
	$(CC) $(CFLAGS_BASE) -o $(STANDALONE) $(TARGET_SRC)
	@echo "[+] Built: $(STANDALONE) (standalone debug)"

clean:
	rm -f $(TARGET_BIN) $(FUZZER_BIN) $(AFL_BIN) $(STANDALONE)
	@echo "[+] Cleaned"
