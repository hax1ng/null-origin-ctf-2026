#!/usr/bin/env python3
"""Solve Null Origin CTF 2026 - Quietus (stego chain, stage 38, final).

The secret is in the PNG's DEFLATE token stream, not its pixels. A custom
fixed-Huffman parser keeps the original literal/back-reference choices. At each
point where a length-3 back-reference to the nearest legal distance was
possible, a literal encodes 0 and a match encodes 1. The choice bits are
decrypted with the chain's SHA-256 counter stream keyed on the previous flag
and verified as a PL8 record.
"""
from hashlib import sha256
from pathlib import Path
import re
import struct
import zlib

PNG = Path("quietus.png")
PREVIOUS_FLAG = b"Null0rigin{he_set_two_sorts_where_one_would_do}"


def png_idat(path):
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, chunks = 8, []
    while pos < len(data):
        size = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + size]
        pos += size + 12
        if kind == b"IDAT":
            chunks.append(payload)
        elif kind == b"IEND":
            break
    return b"".join(chunks)


class BitReader:
    def __init__(self, data):
        self.data = data
        self.bit = 0

    def read(self, count):
        value = 0
        for shift in range(count):
            value |= ((self.data[self.bit // 8] >> (self.bit % 8)) & 1) << shift
            self.bit += 1
        return value


def reverse_bits(value, width):
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


class Huffman:
    def __init__(self, lengths):
        counts = [0] * (max(lengths) + 1)
        for length in lengths:
            if length:
                counts[length] += 1

        code = 0
        next_code = [0] * len(counts)
        for width in range(1, len(counts)):
            code = (code + counts[width - 1]) << 1
            next_code[width] = code

        self.table = {}
        self.max_width = len(counts) - 1
        for symbol, width in enumerate(lengths):
            if width:
                canonical = next_code[width]
                next_code[width] += 1
                self.table[width, reverse_bits(canonical, width)] = symbol

    def decode(self, source):
        code = 0
        for width in range(1, self.max_width + 1):
            code |= source.read(1) << (width - 1)
            if (width, code) in self.table:
                return self.table[width, code]
        raise ValueError("invalid Huffman code")


FIXED_LITERAL = Huffman([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
FIXED_DISTANCE = Huffman([5] * 32)

LENGTH_BASE = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
]
LENGTH_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
]
DISTANCE_BASE = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
    6145, 8193, 12289, 16385, 24577,
]
DISTANCE_EXTRA = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
]


def deflate_tokens(raw):
    """Decode this carrier's fixed-Huffman block and retain its tokens."""
    source = BitReader(raw)
    final = source.read(1)
    block_type = source.read(2)
    if final != 1 or block_type != 1:
        raise ValueError("expected one final fixed-Huffman block")

    output = bytearray()
    tokens = []  # (output position, produced length, distance or None)
    while True:
        symbol = FIXED_LITERAL.decode(source)
        if symbol < 256:
            tokens.append((len(output), 1, None))
            output.append(symbol)
        elif symbol == 256:
            break
        elif 257 <= symbol <= 285:
            index = symbol - 257
            length = LENGTH_BASE[index] + source.read(LENGTH_EXTRA[index])
            distance_symbol = FIXED_DISTANCE.decode(source)
            if distance_symbol >= 30:
                raise ValueError("reserved distance symbol")
            distance = (
                DISTANCE_BASE[distance_symbol]
                + source.read(DISTANCE_EXTRA[distance_symbol])
            )
            tokens.append((len(output), length, distance))
            for _ in range(length):
                output.append(output[-distance])
        else:
            raise ValueError("reserved length symbol")
    return bytes(output), tokens


def extract_choice_bits(output, tokens):
    # Latest fully previous occurrence of each three-byte string. As the token
    # positions increase, `add_at` catches this table up to the current point.
    latest = {}
    add_at = 0
    bits = []

    for position, length, distance in tokens:
        while add_at <= position - 3:
            latest[output[add_at:add_at + 3]] = add_at
            add_at += 1

        triple = output[position:position + 3]
        if len(triple) < 3:
            nearest = None
        else:
            nearest = None

            # Distances 1 and 2 are legal overlapping copies in DEFLATE.
            for candidate in range(1, min(2, position) + 1):
                if output[position - candidate:position - candidate + 3] == triple:
                    nearest = candidate
                    break

            if nearest is None:
                previous = latest.get(triple)
                if previous is not None and position - previous <= 32768:
                    nearest = position - previous

        if nearest is None:
            if distance is not None:
                raise ValueError("back-reference existed without a legal choice")
            continue

        if distance is None:
            bits.append(0)  # went to the case and emitted a literal
        else:
            if length != 3 or distance != nearest:
                raise ValueError("back-reference was not length 3 and nearest")
            bits.append(1)  # reached backward

    return bits


def chain_stream(previous_flag, length):
    key = sha256(previous_flag).digest()
    return b"".join(
        sha256(key + counter.to_bytes(4, "big")).digest()
        for counter in range((length + 31) // 32)
    )[:length]


zlib_stream = png_idat(PNG)
if zlib_stream[1] & 0x20:
    raise ValueError("unexpected preset zlib dictionary")
output, tokens = deflate_tokens(zlib_stream[2:-4])
if output != zlib.decompress(zlib_stream):
    raise ValueError("custom DEFLATE parse disagrees with zlib")

bits = extract_choice_bits(output, tokens)
encrypted = bytes(
    sum(bits[i + j] << (7 - j) for j in range(8))
    for i in range(0, len(bits) - 7, 8)
)
decoded = bytes(
    byte ^ mask
    for byte, mask in zip(encrypted, chain_stream(PREVIOUS_FLAG, len(encrypted)))
)

stamp, issue, size, stored_crc = struct.unpack("<3sBHI", decoded[:10])
payload = decoded[10:10 + size]
actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
match = re.fullmatch(rb"Null0rigin\{[a-z0-9_]+\}", payload)

print("Decompressed bytes:", len(output))
print("DEFLATE tokens:    ", len(tokens))
print("Choice bits:       ", len(bits))
print("Record stamp:      ", stamp)
print("Issue:             ", issue)
print("Payload length:    ", size)
print("Stored CRC32:      ", f"{stored_crc:08x}")
print("Actual CRC32:      ", f"{actual_crc:08x}")
if stamp != b"PL8" or len(payload) != size or actual_crc != stored_crc or not match:
    raise ValueError("invalid final record")
print("Flag:              ", payload.decode())
