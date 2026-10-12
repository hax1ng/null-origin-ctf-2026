#!/usr/bin/env python3
"""Solve Null Origin CTF 2026 - Winnow (stego chain, stage 36).

The sheet is a 64x32 grid of 32x32 frames handled in pairs; the two frames in
a pair carry opposite bits. Each frame's first LSB is its data bit and the next
16 LSBs are a 2-byte SHA-256 seal over (key, frame number, bit). Only the
genuine frame of each pair reproduces its seal under the real key, so we keep
that bit and discard its partner, then decrypt the result as a PL8 record.
"""
from hashlib import sha256
from pathlib import Path
import re
import struct
import zlib

from PIL import Image
import numpy as np

SHEET = Path("sheet.png")
PREVIOUS_FLAG = b"Null0rigin{keep_the_grain_and_burn_the_chaff}"


def pack_msb(bits):
    if len(bits) % 8:
        raise ValueError("selected bit count is not byte-aligned")
    return bytes(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits), 8)
    )


def counter_stream(key, length):
    return b"".join(
        sha256(key + counter.to_bytes(4, "big")).digest()
        for counter in range((length + 31) // 32)
    )[:length]


image = np.asarray(Image.open(SHEET).convert("L"))
assert image.shape == (1024, 2048)

# 32 tile rows, 64 tile columns, and a 32x32 image inside each tile.
frames = image.reshape(32, 32, 64, 32).transpose(0, 2, 1, 3)
frames = frames.reshape(2048, 1024)

key = sha256(PREVIOUS_FLAG).digest()
selected_bits = []

for pair_start in range(0, 2048, 2):
    matches = []

    for frame_number in (pair_start, pair_start + 1):
        lsb = frames[frame_number] & 1
        bit = int(lsb[0])
        seal = np.packbits(lsb[1:17], bitorder="big").tobytes()

        expected = sha256(
            key + frame_number.to_bytes(2, "big") + bytes([bit])
        ).digest()[:2]

        if seal == expected:
            matches.append(bit)

    # The authenticated record is followed by unsealed filler.
    if not matches:
        break
    if len(matches) != 1:
        raise ValueError(f"pair {pair_start // 2} has {len(matches)} valid frames")

    selected_bits.append(matches[0])

encrypted = pack_msb(selected_bits)
stream = counter_stream(key, len(encrypted))
decoded = bytes(a ^ b for a, b in zip(encrypted, stream))

stamp, issue, length, stored_crc = struct.unpack("<3sBHI", decoded[:10])
payload = decoded[10:10 + length]
actual_crc = zlib.crc32(payload) & 0xFFFFFFFF

print("Selected bits:  ", len(selected_bits))
print("Encrypted bytes:", len(encrypted))
print("Stamp:          ", stamp)
print("Issue:          ", issue)
print("Payload length: ", length)
print(f"Stored CRC32:     {stored_crc:08x}")
print(f"Actual CRC32:     {actual_crc:08x}")
print("Payload:        ", repr(payload))

assert stamp == b"PL8"
assert len(payload) == length
assert stored_crc == actual_crc

flag = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload).group()
print("Flag:           ", flag.decode())
