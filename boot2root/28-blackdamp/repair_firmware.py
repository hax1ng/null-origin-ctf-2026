#!/usr/bin/env python3
"""
28-blackdamp -- repair the deliberately-corrupted lamp firmware container.

The OTA server hands out firmware.bin unauthenticated. Its BDFW header:
    0   4   "BDFW" magic
    4   4   version (LE)
    8   4   payload offset
    12  4   payload length
    16  4   CRC-32 as shipped
    20  4   CRC-32 as built
    24  32  ASCII MD5 of the good payload
    56  8   payload type
    64 ...  maker's note

The maker's note admits 12 bytes of the SquashFS payload were zeroed:
    payload+0x00: restore b"hsqs"
    payload+0x28: restore payload length as LE u64
The recovered MD5 confirms the repair.

Usage: ./repair_firmware.py firmware.bin   # writes lamp-repaired.sqfs
"""
import hashlib, struct, sys
from pathlib import Path

src = sys.argv[1] if len(sys.argv) > 1 else "firmware.bin"
image = Path(src).read_bytes()

assert image[:4] == b"BDFW"
version, payload_off, payload_len = struct.unpack("<III", image[4:16])
expected_md5 = image[24:56].decode()

payload = bytearray(image[payload_off:payload_off + payload_len])
payload[0:4] = b"hsqs"
payload[0x28:0x30] = struct.pack("<Q", payload_len)

actual_md5 = hashlib.md5(payload).hexdigest()
print(f"version={version} offset={payload_off} length={payload_len}")
print(f"expected MD5: {expected_md5}")
print(f"actual MD5:   {actual_md5}")
assert actual_md5 == expected_md5, "repair failed -- MD5 mismatch"

Path("lamp-repaired.sqfs").write_bytes(payload)
print("wrote lamp-repaired.sqfs  (unsquashfs -d lamp-root lamp-repaired.sqfs)")
