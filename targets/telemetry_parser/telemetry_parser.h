/**
 * telemetry_parser.h
 * AutoPatch Sentinel - Deliberately Vulnerable Target
 *
 * Models a military/avionics sensor telemetry frame parser.
 * TLV (Type-Length-Value) packet format used in UAV/sensor networks.
 *
 * INTENTIONAL BUGS (for AutoPatch Sentinel demonstration):
 *   1. heap-buffer-overflow: parse_tlv_payload() does not validate payload
 *      length against buffer bounds before memcpy.
 *   2. integer-overflow: calc_alloc_size() can wrap on large length fields
 *      leading to undersized malloc.
 */

#ifndef TELEMETRY_PARSER_H
#define TELEMETRY_PARSER_H

#include <stdint.h>
#include <stddef.h>

/* ─── Packet constants ─────────────────────────────────────────────────────── */
#define TELEM_MAGIC         0xDEAD
#define TELEM_VERSION       0x01
#define MAX_PAYLOAD_SIZE    256
#define MAX_TLV_FIELDS      16
#define TELEM_HEADER_SIZE   8   /* magic(2) + version(1) + type(1) + length(2) + checksum(2) */

/* ─── Packet Types ─────────────────────────────────────────────────────────── */
typedef enum {
    PKT_GPS          = 0x01,   /* GPS coordinates payload */
    PKT_TEMPERATURE  = 0x02,   /* Sensor temperature data */
    PKT_ALTITUDE     = 0x03,   /* Barometric altitude */
    PKT_STATUS       = 0x04,   /* System status flags */
    PKT_COMMAND      = 0x05,   /* Control command */
} PacketType;

/* ─── TLV Field ────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  type;
    uint16_t length;
    uint8_t  *data;                     /* heap-allocated, exactly MAX_PAYLOAD_SIZE bytes */
} TLVField;

/* ─── Parsed Telemetry Frame ───────────────────────────────────────────────── */
typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   pkt_type;
    uint16_t  payload_len;
    uint16_t  checksum;
    TLVField  fields[MAX_TLV_FIELDS];
    int       field_count;
} TelemetryFrame;

/* ─── GPS Payload ──────────────────────────────────────────────────────────── */
typedef struct {
    double latitude;
    double longitude;
    float  altitude_m;
    uint8_t fix_quality;
    uint8_t num_satellites;
} GPSPayload;

/* ─── Temperature Payload ──────────────────────────────────────────────────── */
typedef struct {
    int16_t temp_celsius_x10;   /* temperature * 10 for fixed-point */
    uint8_t sensor_id;
    uint8_t flags;
} TempPayload;

/* ─── Error Codes ──────────────────────────────────────────────────────────── */
typedef enum {
    TELEM_OK              =  0,
    TELEM_ERR_SHORT       = -1,   /* Input too short for header */
    TELEM_ERR_MAGIC       = -2,   /* Magic bytes mismatch */
    TELEM_ERR_VERSION     = -3,   /* Unsupported version */
    TELEM_ERR_CHECKSUM    = -4,   /* Checksum verification failed */
    TELEM_ERR_OVERFLOW    = -5,   /* Buffer overflow detected */
    TELEM_ERR_BADFIELD    = -6,   /* Malformed TLV field */
    TELEM_ERR_NOMEM       = -7,   /* Memory allocation failed */
} TelemError;

/* ─── Public API ───────────────────────────────────────────────────────────── */

/**
 * parse_telemetry_frame()
 * Parse a raw byte buffer into a TelemetryFrame struct.
 *
 * @param buf       Raw input bytes
 * @param buf_len   Length of buf
 * @param frame     Output frame (caller-allocated)
 * @return          TELEM_OK on success, negative error code on failure
 */
int parse_telemetry_frame(const uint8_t *buf, size_t buf_len, TelemetryFrame *frame);

/**
 * parse_tlv_payload()
 * Parse TLV fields from the payload region of a telemetry frame.
 * [VULNERABLE] Does not adequately validate field length vs. remaining buffer space.
 *
 * @param payload     Pointer to start of payload region
 * @param payload_len Declared length of payload
 * @param frame       Frame to populate with TLV fields
 * @return            Number of fields parsed, or negative error code
 */
int parse_tlv_payload(const uint8_t *payload, uint16_t payload_len, TelemetryFrame *frame);

/**
 * decode_gps_payload()
 * Decode GPS payload from a TLVField.
 */
int decode_gps_payload(const TLVField *field, GPSPayload *out);

/**
 * decode_temp_payload()
 * Decode temperature payload from a TLVField.
 */
int decode_temp_payload(const TLVField *field, TempPayload *out);

/**
 * verify_checksum()
 * Verify XOR checksum of the packet (excludes checksum bytes themselves).
 */
int verify_checksum(const uint8_t *buf, size_t buf_len, uint16_t expected);

/**
 * calc_alloc_size()
 * [VULNERABLE] Computes allocation size for a copy buffer.
 * Multiplying two uint16_t values without promotion can overflow.
 */
size_t calc_alloc_size(uint16_t count, uint16_t element_size);

/**
 * print_frame()
 * Debug-print a parsed telemetry frame to stdout.
 */
void print_frame(const TelemetryFrame *frame);

#endif /* TELEMETRY_PARSER_H */
