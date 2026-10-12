#!/usr/bin/env python3
"""Solve Null Origin CTF 2026's Pentimento challenge."""

from hashlib import sha256
from pathlib import Path
import re
import struct
import zlib


GIF = Path("pentimento.gif")
PREVIOUS_SEAL = b"Null0rigin{the_order_of_the_colours_is_the_message}"


def read_subblocks(data: bytes, pos: int) -> tuple[bytes, int]:
    chunks = []
    while data[pos]:
        size = data[pos]
        pos += 1
        chunks.append(data[pos : pos + size])
        pos += size
    return b"".join(chunks), pos + 1


def local_colour_tables(data: bytes) -> tuple[list[bytes], list[int], list[bytes]]:
    """Parse the GIF without letting an image library normalize its palettes."""
    if data[:3] != b"GIF":
        raise ValueError("not a GIF")

    packed = data[10]
    pos = 13
    if packed & 0x80:  # Skip the global colour table.
        pos += 3 * (1 << ((packed & 7) + 1))

    tables, delays, comments = [], [], []
    while pos < len(data):
        marker = data[pos]
        pos += 1

        if marker == 0x3B:  # GIF trailer
            break
        if marker == 0x21:  # Extension
            label = data[pos]
            payload, pos = read_subblocks(data, pos + 1)
            if label == 0xF9:  # Graphic control extension
                delays.append(int.from_bytes(payload[1:3], "little"))
            elif label == 0xFE:
                comments.append(payload)
            continue
        if marker != 0x2C:
            raise ValueError(f"unexpected GIF marker {marker:#x}")

        image_packed = data[pos + 8]
        pos += 9  # Image descriptor
        if not image_packed & 0x80:
            raise ValueError("frame has no local colour table")
        count = 1 << ((image_packed & 7) + 1)
        tables.append(data[pos : pos + 3 * count])
        pos += 3 * count

        pos += 1  # LZW minimum code size
        _, pos = read_subblocks(data, pos)

    return tables, delays, comments


def extract_frame_bits(table: bytes) -> list[int]:
    colours = [tuple(table[i : i + 3]) for i in range(0, len(table), 3)]
    if len(colours) != 256 or len(set(colours)) != 256:
        raise ValueError("expected 256 distinct colours")

    # The intended order is darkest to lightest, with RGB as the tie-breaker.
    ordered = sorted(colours, key=lambda rgb: (sum(rgb), *rgb))
    rank = {colour: i for i, colour in enumerate(ordered)}
    current_ranks = [rank[colour] for colour in colours]

    bits = []
    for i in range(0, 256, 2):
        pair = current_ranks[i : i + 2]
        if set(pair) != {i, i + 1}:
            raise ValueError(f"palette pair {i // 2} is not an adjacent swap")
        bits.append(int(pair[0] == i + 1))  # Normal=0, swapped=1.
    return bits


def pack_msb(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit count is not byte aligned")
    return bytes(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits), 8)
    )


def counter_stream(secret: bytes, length: int) -> bytes:
    key = sha256(secret).digest()
    return b"".join(
        sha256(key + counter.to_bytes(4, "big")).digest()
        for counter in range((length + 31) // 32)
    )[:length]


def main() -> None:
    tables, delays, comments = local_colour_tables(GIF.read_bytes())
    print("Frames:       ", len(tables))
    print("Delay card:   ", bytes(delays).decode("ascii"))
    for comment in comments:
        print("Decoy comment:", comment.decode("ascii"))

    encrypted = pack_msb([
        bit
        for table in tables
        for bit in extract_frame_bits(table)
    ])
    stream = counter_stream(PREVIOUS_SEAL, len(encrypted))
    decoded = bytes(a ^ b for a, b in zip(encrypted, stream))

    stamp, issue, length, stored_crc = struct.unpack("<3sBHI", decoded[:10])
    payload = decoded[10 : 10 + length]
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF

    print("Stamp:        ", stamp)
    print("Issue:        ", issue)
    print("Payload length:", length)
    print(f"Stored CRC32:   {stored_crc:08x}")
    print(f"Actual CRC32:   {actual_crc:08x}")
    print("Payload:       ", repr(payload))

    if stamp != b"PL8" or len(payload) != length or actual_crc != stored_crc:
        raise SystemExit("record validation failed")
    match = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload)
    if not match:
        raise SystemExit("flag not found")
    print("Flag:          ", match.group().decode())


if __name__ == "__main__":
    main()
