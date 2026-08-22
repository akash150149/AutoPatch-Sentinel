/**
 * fuzzer_harness.cc
 * AutoPatch Sentinel - libFuzzer / AFL++ Harness
 *
 * Compilation:
 *   libFuzzer (clang, Linux/macOS):
 *     clang -DFUZZER_BUILD -fsanitize=address,fuzzer -g -O1 \
 *           fuzzer_harness.cc telemetry_parser.c -o fuzzer_target
 *
 *   AFL++ (Linux/WSL):
 *     AFL_USE_ASAN=1 afl-clang-fast -DFUZZER_BUILD -fsanitize=address,undefined \
 *           -g -O1 fuzzer_harness.cc telemetry_parser.c -o afl_target
 *
 * Usage:
 *   libFuzzer:  ./fuzzer_target -max_total_time=60 corpus/ -artifact_prefix=crashes/
 *   AFL++:      afl-fuzz -i seeds/ -o findings/ -- ./afl_target @@
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" {
#include "telemetry_parser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    TelemetryFrame frame;
    memset(&frame, 0, sizeof(frame));

    /* Feed arbitrary bytes into the parser — ASAN will catch OOB accesses */
    parse_telemetry_frame(data, size, &frame);

    /* Exercise the TLV decoder directly on the raw buffer as well,
     * to maximize coverage of parse_tlv_payload() */
    if (size >= 3) {
        TelemetryFrame frame2;
        memset(&frame2, 0, sizeof(frame2));
        uint16_t payload_len = (uint16_t)(size < 65535 ? size : 65535);
        parse_tlv_payload(data, payload_len, &frame2);
    }

    return 0;  /* Non-crash return; 0 = input accepted */
}
