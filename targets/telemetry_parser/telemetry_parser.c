/**
 * telemetry_parser.c
 * AutoPatch Sentinel - Deliberately Vulnerable Target
 *
 * Implements a TLV (Type-Length-Value) telemetry frame parser
 * modeled on avionics/UAV sensor protocol framing.
 *
 * ┌────────────────────────────────────────────┐
 * │  INTENTIONAL VULNERABILITY CATALOGUE       │
 * │                                            │
 * │  BUG-1 [CWE-122] Heap Buffer Overflow:     │
 * │    parse_tlv_payload() copies field->data  │
 * │    using field->length without clamping to │
 * │    MAX_PAYLOAD_SIZE, enabling heap OOB     │
 * │    write when attacker sends length > 256. │
 * │                                            │
 * │  BUG-2 [CWE-190] Integer Overflow:         │
 * │    calc_alloc_size() multiplies two        │
 * │    uint16_t values; result wraps at 65535  │
 * │    causing undersized malloc for large     │
 * │    field counts.                           │
 * └────────────────────────────────────────────┘
 */

#include "telemetry_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/**
 * calc_alloc_size [BUG-2 / CWE-190]
 *
 * VULNERABLE: multiplying two uint16_t values without promoting to a wider
 * integer first.  When count=512, element_size=256: 512*256 = 131072, but
 * uint16_t max is 65535, so the product wraps to 131072 % 65536 = 0.
 * malloc(0) returns a tiny valid pointer, and subsequent writes overflow.
 */
size_t calc_alloc_size(uint16_t count, uint16_t element_size) {
    /* BUG: arithmetic done in uint16_t width, wraps silently */
    uint16_t result = count * element_size;   /* <── integer overflow */
    return (size_t)result;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Checksum
 * ───────────────────────────────────────────────────────────────────────────── */

int verify_checksum(const uint8_t *buf, size_t buf_len, uint16_t expected) {
    if (buf_len < TELEM_HEADER_SIZE) return TELEM_ERR_SHORT;

    uint16_t acc = 0;
    /* XOR all bytes except the last two (checksum field itself) */
    for (size_t i = 0; i < buf_len - 2; i++) {
        acc ^= (uint16_t)buf[i];
    }
    return (acc == expected) ? TELEM_OK : TELEM_ERR_CHECKSUM;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * TLV payload parser  [BUG-1 / CWE-122]
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * parse_tlv_payload [BUG-1 / CWE-122]
 *
 * VULNERABLE: The loop reads field_len from the packet (attacker-controlled)
 * and passes it directly to memcpy into field->data[MAX_PAYLOAD_SIZE].
 * When field_len > MAX_PAYLOAD_SIZE (256) the memcpy overflows the heap
 * allocation backing the TelemetryFrame.
 *
 * ASAN will report:
 *   ERROR: AddressSanitizer: heap-buffer-overflow on address ...
 *   WRITE of size <N> at ... telemetry_parser.c:<line>
 */
int parse_tlv_payload(const uint8_t *payload, uint16_t payload_len,
                      TelemetryFrame *frame) {
    if (!payload || !frame) return TELEM_ERR_BADFIELD;

    const uint8_t *ptr = payload;
    const uint8_t *end = payload + payload_len;
    int field_count = 0;

    while (ptr < end && field_count < MAX_TLV_FIELDS) {
        /* Need at least 3 bytes: type(1) + length(2) */
        if (ptr + 3 > end) break;

        uint8_t  field_type = ptr[0];
        uint16_t field_len  = read_u16_be(ptr + 1);
        ptr += 3;

        /* BUG-1: field_len is NOT clamped to MAX_PAYLOAD_SIZE (256).
         * An attacker can send field_len = 0x1000 (4096) and this memcpy
         * will write 4096 bytes into a 256-byte data[] buffer → heap OOB. */
        if (ptr + field_len > end) break;

        TLVField *field = &frame->fields[field_count];
        field->type   = field_type;
        field->length = field_len;
        field->data   = (uint8_t *)malloc(MAX_PAYLOAD_SIZE);  /* exactly 256 bytes */
        if (!field->data) return TELEM_ERR_NOMEM;
        memcpy(field->data, ptr, field_len);   /* VULNERABLE: field_len > 256 → heap OOB */

        ptr += field_len;
        field_count++;
    }

    frame->field_count = field_count;
    return field_count;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Main frame parser
 * ───────────────────────────────────────────────────────────────────────────── */

int parse_telemetry_frame(const uint8_t *buf, size_t buf_len,
                          TelemetryFrame *frame) {
    if (!buf || !frame) return TELEM_ERR_SHORT;
    if (buf_len < TELEM_HEADER_SIZE) return TELEM_ERR_SHORT;

    /* Parse header */
    frame->magic       = read_u16_be(buf + 0);
    frame->version     = buf[2];
    frame->pkt_type    = buf[3];
    frame->payload_len = read_u16_be(buf + 4);
    frame->checksum    = read_u16_be(buf + 6);
    frame->field_count = 0;

    /* Validate magic */
    if (frame->magic != TELEM_MAGIC) return TELEM_ERR_MAGIC;

    /* Validate version */
    if (frame->version != TELEM_VERSION) return TELEM_ERR_VERSION;

    /* Ensure payload doesn't exceed available buffer */
    if ((size_t)(TELEM_HEADER_SIZE + frame->payload_len) > buf_len)
        return TELEM_ERR_SHORT;

    /* Verify checksum (soft check — log but continue in permissive mode) */
    if (verify_checksum(buf, buf_len, frame->checksum) != TELEM_OK) {
        fprintf(stderr, "[WARN] checksum mismatch, continuing in permissive mode\n");
    }

    /* Parse TLV payload */
    const uint8_t *payload = buf + TELEM_HEADER_SIZE;
    int result = parse_tlv_payload(payload, frame->payload_len, frame);
    return result < 0 ? result : TELEM_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Payload decoders
 * ───────────────────────────────────────────────────────────────────────────── */

int decode_gps_payload(const TLVField *field, GPSPayload *out) {
    if (!field || !out) return TELEM_ERR_BADFIELD;
    /* GPS payload must be at least sizeof(GPSPayload) = 22 bytes */
    if (field->length < sizeof(GPSPayload)) return TELEM_ERR_SHORT;

    memcpy(out, field->data, sizeof(GPSPayload));
    return TELEM_OK;
}

int decode_temp_payload(const TLVField *field, TempPayload *out) {
    if (!field || !out) return TELEM_ERR_BADFIELD;
    if (field->length < sizeof(TempPayload)) return TELEM_ERR_SHORT;

    memcpy(out, field->data, sizeof(TempPayload));
    return TELEM_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Debug print
 * ───────────────────────────────────────────────────────────────────────────── */

void print_frame(const TelemetryFrame *frame) {
    if (!frame) return;
    printf("─── Telemetry Frame ───────────────────────────────\n");
    printf("  Magic:       0x%04X\n", frame->magic);
    printf("  Version:     0x%02X\n", frame->version);
    printf("  Packet Type: 0x%02X\n", frame->pkt_type);
    printf("  Payload Len: %u bytes\n", frame->payload_len);
    printf("  Checksum:    0x%04X\n", frame->checksum);
    printf("  TLV Fields:  %d\n", frame->field_count);
    for (int i = 0; i < frame->field_count; i++) {
        const TLVField *f = &frame->fields[i];
        printf("    [%d] type=0x%02X len=%u data_preview=", i, f->type, f->length);
        uint16_t show = f->length < 8 ? f->length : 8;
        for (uint16_t j = 0; j < show; j++) printf("%02X ", f->data[j]);
        if (f->length > 8) printf("...");
        printf("\n");
    }
    printf("───────────────────────────────────────────────────\n");
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Standalone entry point (used when compiled as a standalone CLI binary)
 * ───────────────────────────────────────────────────────────────────────────── */

#ifndef FUZZER_BUILD
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <packet_file>\n", argv[0]);
        fprintf(stderr, "  Parses a binary telemetry packet file.\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    uint8_t buf[4096];
    size_t  nread = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (nread == 0) {
        fprintf(stderr, "Empty file.\n");
        return 1;
    }

    TelemetryFrame frame;
    memset(&frame, 0, sizeof(frame));

    int rc = parse_telemetry_frame(buf, nread, &frame);
    if (rc != TELEM_OK) {
        fprintf(stderr, "Parse error: %d\n", rc);
        return rc;
    }

    print_frame(&frame);
    return 0;
}
#endif /* FUZZER_BUILD */
