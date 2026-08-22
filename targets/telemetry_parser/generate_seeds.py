"""
generate_seeds.py
Generates binary seed files for the telemetry_parser target:
  - Valid GPS packet (won't crash)
  - Valid Temperature packet (won't crash)
  - Crashing payload (heap OOB via oversized TLV field)

Run:  python generate_seeds.py
"""
import struct
import os

# ── Packet format ────────────────────────────────────────────────────────────
# Header: magic(2) + version(1) + pkt_type(1) + payload_len(2) + checksum(2)
# Payload: TLV fields: type(1) + length(2) + data(length)
#
# TELEM_MAGIC   = 0xDEAD
# TELEM_VERSION = 0x01
# PKT_GPS       = 0x01
# PKT_TEMPERATURE = 0x02

MAGIC   = 0xDEAD
VERSION = 0x01

def xor_checksum(data: bytes) -> int:
    acc = 0
    for b in data:
        acc ^= b
    return acc & 0xFFFF

def build_packet(pkt_type: int, tlv_fields: list[tuple[int, bytes]]) -> bytes:
    """Build a telemetry frame from a list of (type, data) TLV tuples."""
    payload = b""
    for ftype, fdata in tlv_fields:
        payload += struct.pack(">BH", ftype, len(fdata)) + fdata

    payload_len = len(payload)
    # Build header without checksum first
    header_no_cksum = struct.pack(">HBBH", MAGIC, VERSION, pkt_type, payload_len)
    # Compute checksum over header (sans checksum bytes) + payload
    raw_no_cksum = header_no_cksum + payload
    cksum = xor_checksum(raw_no_cksum)
    header = header_no_cksum + struct.pack(">H", cksum)
    return header + payload

# ── GPS payload: lat(8) + lon(8) + alt(4) + fix_quality(1) + num_sats(1) = 22 bytes
def gps_payload(lat=37.7749, lon=-122.4194, alt=15.5, fix=3, sats=8) -> bytes:
    return struct.pack(">ddffBB", lat, lon, alt, alt, fix, sats)

# ── Temperature payload: temp_x10(2) + sensor_id(1) + flags(1) = 4 bytes
def temp_payload(temp_c_x10=215, sensor_id=1, flags=0x00) -> bytes:
    return struct.pack(">hBB", temp_c_x10, sensor_id, flags)

def main():
    out_dir_tests = os.path.join(os.path.dirname(__file__), "tests")
    out_dir_seeds = os.path.join(os.path.dirname(__file__), "..", "seeds")
    os.makedirs(out_dir_tests, exist_ok=True)
    os.makedirs(out_dir_seeds, exist_ok=True)

    # ── Valid GPS packet ─────────────────────────────────────────────────────
    gps_pkt = build_packet(0x01, [(0x01, gps_payload())])
    path = os.path.join(out_dir_tests, "valid_gps_pkt.bin")
    with open(path, "wb") as f:
        f.write(gps_pkt)
    print(f"[+] Written {len(gps_pkt)} bytes -> {path}")

    # Also seed the fuzzer corpus with this valid packet
    seed_path = os.path.join(out_dir_seeds, "valid_gps.bin")
    with open(seed_path, "wb") as f:
        f.write(gps_pkt)
    print(f"[+] Written seed -> {seed_path}")

    # ── Valid Temperature packet ─────────────────────────────────────────────
    temp_pkt = build_packet(0x02, [(0x02, temp_payload())])
    path = os.path.join(out_dir_tests, "valid_temp_pkt.bin")
    with open(path, "wb") as f:
        f.write(temp_pkt)
    print(f"[+] Written {len(temp_pkt)} bytes -> {path}")

    # ── Multi-field packet (GPS + Temperature together) ──────────────────────
    multi_pkt = build_packet(0x01, [
        (0x01, gps_payload(lat=51.5, lon=-0.12, alt=50.0)),
        (0x02, temp_payload(temp_c_x10=220, sensor_id=2)),
    ])
    path = os.path.join(out_dir_tests, "valid_multi_pkt.bin")
    with open(path, "wb") as f:
        f.write(multi_pkt)
    print(f"[+] Written {len(multi_pkt)} bytes -> {path}")

    # ── CRASHING seed: TLV field with length > MAX_PAYLOAD_SIZE (256) ────────
    # This exploits BUG-1: parse_tlv_payload copies field_len bytes into
    # a 256-byte data[] buffer without clamping. Length = 0x1000 (4096)
    # will cause a heap-buffer-overflow detected by ASan.
    OVERFLOW_LEN = 0x0200  # 512 > MAX_PAYLOAD_SIZE(256)
    overflow_data = b"\xCC" * OVERFLOW_LEN
    crash_pkt = build_packet(0x01, [(0x01, overflow_data)])
    path = os.path.join(out_dir_seeds, "crash_overflow.bin")
    with open(path, "wb") as f:
        f.write(crash_pkt)
    print(f"[+] Written crashing seed ({OVERFLOW_LEN} byte payload) -> {path}")

    # ── Minimal seed for fuzzer corpus (just the header, short) ─────────────
    seed_min = struct.pack(">HBBHH", MAGIC, VERSION, 0x01, 0, 0)
    path = os.path.join(out_dir_seeds, "minimal_header.bin")
    with open(path, "wb") as f:
        f.write(seed_min)
    print(f"[+] Written minimal seed -> {path}")

if __name__ == "__main__":
    main()
