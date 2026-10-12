#!/usr/bin/env python3
"""Solve Null Origin CTF 2026 - SafeLight (stego chain, stage 32).

A perfect negative/print pair satisfies N + P = 255. The real channel is the
set of pixels whose difference is exactly +/-1 (560 of them); the much louder
+3 pixels draw a decoy. The extracted bits are decrypted with the chain's
SHA-256 counter stream keyed on the previous stage's flag, then verified as a
PL8 record.
"""
from hashlib import sha256
import re
import struct
import zlib

import numpy as np
from PIL import Image

PREVIOUS_SEAL = b"Null0rigin{what_the_negative_kept_from_the_print}"

# A signed type is important because the differences can be negative.
negative = np.array(Image.open("negative.png"), dtype=np.int16)
printed = np.array(Image.open("print.png"), dtype=np.int16)

# A perfect negative/print pair adds up to 255.
difference = negative + printed - 255

# Read row by row and keep only the subtle +/-1 channel.
bits = []
for value in difference.ravel():
    if value == -1:
        bits.append(0)
    elif value == 1:
        bits.append(1)

print("Extracted bits:", len(bits))
assert len(bits) == 560

# Pack groups of eight bits, most-significant bit first.
encoded = bytes(
    sum(bits[i + j] << (7 - j) for j in range(8))
    for i in range(0, len(bits), 8)
)

# Derive the stage key and build the SHA256(k || counter) stream.
k = sha256(PREVIOUS_SEAL).digest()
print("SHA-256 key:", k.hex())

stream = bytearray()
counter = 0
while len(stream) < len(encoded):
    stream.extend(sha256(k + counter.to_bytes(4, "big")).digest())
    counter += 1

decoded = bytes(a ^ b for a, b in zip(encoded, stream))

# PL8 header: 3-byte stamp, 1-byte issue, 2-byte length, 4-byte CRC32 (LE).
stamp, issue, length, stored_crc = struct.unpack("<3sBHI", decoded[:10])
payload = decoded[10:10 + length]
calculated_crc = zlib.crc32(payload) & 0xFFFFFFFF

print("Stamp:        ", stamp)
print("Issue:        ", issue)
print("Length:       ", length)
print(f"Stored CRC:     {stored_crc:08x}")
print(f"Calculated CRC: {calculated_crc:08x}")
print("Payload:      ", repr(payload))

assert stamp == b"PL8"
assert stored_crc == calculated_crc

flag = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload).group().decode()
print("Flag:", flag)
