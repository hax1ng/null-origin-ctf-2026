#!/usr/bin/env python3
"""Solve Null Origin CTF 2026 - Driftwood (stego chain, stage 31).

The real record lives in the alpha-channel LSB plane, read column-major
(zsteg's `b1,a,lsb,yx` order). Unlike the planted decoys, it begins with the
"PL8" works stamp and carries a CRC32 that matches its payload.
"""
from PIL import Image
import re
import struct
import zlib

image = Image.open("driftwood.png").convert("RGBA")

# Read the alpha-channel LSB column by column, each column top to bottom.
bits = [
    image.getpixel((x, y))[3] & 1
    for x in range(image.width)
    for y in range(image.height)
]

# Pack groups of eight bits, most-significant bit first.
data = bytes(
    sum(bits[i + j] << (7 - j) for j in range(8))
    for i in range(0, len(bits) - 7, 8)
)

stamp, issue, length, stored_crc = struct.unpack("<3sBHI", data[:10])
payload = data[10:10 + length]
actual_crc = zlib.crc32(payload) & 0xFFFFFFFF

print("Stamp:        ", stamp)
print("Issue:        ", issue)
print("Length:       ", length)
print(f"Stored CRC32:   {stored_crc:08x}")
print(f"Computed CRC32: {actual_crc:08x}")
print("Payload:      ", repr(payload))

assert stamp == b"PL8"
assert stored_crc == actual_crc

flag = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload).group().decode()
print("Flag:         ", flag)
