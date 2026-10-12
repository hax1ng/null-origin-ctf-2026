#!/usr/bin/env python3
from pathlib import Path
from hashlib import sha256
import re
import struct
import zlib

PNG = Path("mordant.png")
PREVIOUS_SEAL = b"Null0rigin{nothing_takes_until_it_is_fixed}"
SHARES = [
    bytes.fromhex("9e4c1af0d3b27651"),
    bytes.fromhex("2a77be05c4198d3f"),
    bytes.fromhex("f10983dd6b5ec4a2"),
    bytes.fromhex("55c2e79140ab3d08"),
    bytes.fromhex("bd3f60a8e2749c15"),
    bytes.fromhex("07e5cb3219d6f48b"),
]


def png_idat(path: Path):
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos = 8
    width = height = bit_depth = color_type = None
    idat = bytearray()
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        kind = data[pos+4:pos+8]
        chunk = data[pos+8:pos+8+length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk[:10])
        elif kind == b"IDAT":
            idat.extend(chunk)
        elif kind == b"IEND":
            break
    if (bit_depth, color_type) != (8, 0):
        raise ValueError(f"unexpected PNG format: depth={bit_depth}, type={color_type}")
    return width, height, zlib.decompress(idat)


def chain_stream(key_material: bytes, length: int) -> bytes:
    key = sha256(key_material).digest()
    return b"".join(
        sha256(key + counter.to_bytes(4, "big")).digest()
        for counter in range((length + 31) // 32)
    )[:length]


width, height, scanlines = png_idat(PNG)
stride = width + 1  # one filter byte + 8-bit grayscale pixels
if len(scanlines) != height * stride:
    raise ValueError("unexpected decompressed image size")

filters = [scanlines[y * stride] for y in range(height)]
if any(x > 4 for x in filters) or len(filters) % 4:
    raise ValueError("invalid filter stream")

# The fifth PNG filter (4, Paeth) duplicates symbol zero. Four base-4
# symbols, most-significant first, make one byte.
encoded = bytearray()
for pos in range(0, len(filters), 4):
    value = 0
    for filter_type in filters[pos:pos+4]:
        value = (value << 2) | (filter_type % 4)
    encoded.append(value)

page = bytes(a ^ b for a, b in zip(encoded, chain_stream(PREVIOUS_SEAL, len(encoded))))
mordant = b"".join(SHARES)
decoded = bytes(a ^ b for a, b in zip(page, chain_stream(mordant, len(page))))

if decoded[:3] != b"PL8":
    raise ValueError("bad PL8 stamp")
issue = decoded[3]
length = struct.unpack("<H", decoded[4:6])[0]
stored_crc = struct.unpack("<I", decoded[6:10])[0]
payload = decoded[10:10+length]
actual_crc = zlib.crc32(payload) & 0xffffffff
flag_match = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload)

print("dimensions:    ", width, "x", height)
print("filter counts: ", {x: filters.count(x) for x in range(5)})
print("encoded bytes: ", len(encoded))
print("issue:         ", issue)
print("payload length:", length)
print("stored CRC32:  ", f"{stored_crc:08x}")
print("actual CRC32:  ", f"{actual_crc:08x}")
print("payload:       ", repr(payload))
if stored_crc != actual_crc or not flag_match:
    raise ValueError("record failed validation")
print("flag:          ", flag_match.group().decode())
