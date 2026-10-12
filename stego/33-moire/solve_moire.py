from collections import defaultdict
from hashlib import sha256
from PIL import Image
import re
import struct
import zlib

PREVIOUS_SEAL = b"Null0rigin{two_cells_of_equal_weight_are_not_equal}"

image = Image.open("moire.png").convert("1")
cell_width, cell_height = image.width // 4, image.height // 4

# Catalogue the 4x4 patterns. Only weights 5 through 11 have two forms.
cells = {}
patterns = defaultdict(set)
for cell_y in range(cell_height):
    for cell_x in range(cell_width):
        pattern = tuple(
            image.getpixel((4 * cell_x + x, 4 * cell_y + y)) == 0
            for y in range(4)
            for x in range(4)
        )
        weight = sum(pattern)
        cells[cell_x, cell_y] = weight, pattern
        patterns[weight].add(pattern)

patterns = {weight: sorted(forms) for weight, forms in patterns.items()}

# "As the ox ploughs": alternate left-to-right and right-to-left rows.
order = [
    (x, y)
    for y in range(cell_height)
    for x in (range(cell_width) if y % 2 == 0 else range(cell_width - 1, -1, -1))
]

raw_bits = []
weights = []
for position in order:
    weight, pattern = cells[position]
    if len(patterns[weight]) == 2:
        raw_bits.append(patterns[weight].index(pattern))
        weights.append(weight)

# The chain's key schedule: SHA256(previous seal), followed by the
# SHA256(key || big-endian counter) XOR stream.
key = sha256(PREVIOUS_SEAL).digest()
stream = b"".join(
    sha256(key + counter.to_bytes(4, "big")).digest()
    for counter in range(32)
)

# There are only seven two-form weights. Try their possible polarities;
# the PL8 stamp and CRC32 identify the valid interpretation unambiguously.
seen = set()
for polarity in range(1 << 7):
    bits = [
        bit ^ ((polarity >> (weight - 5)) & 1)
        for bit, weight in zip(raw_bits[:8192], weights[:8192])
    ]
    encoded = bytes(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits) - 7, 8)
    )
    decoded = bytes(a ^ b for a, b in zip(encoded, stream))

    if decoded[:3] != b"PL8":
        continue
    issue, length, stored_crc = struct.unpack("<BHI", decoded[3:10])
    payload = decoded[10 : 10 + length]
    if len(payload) != length or zlib.crc32(payload) & 0xFFFFFFFF != stored_crc:
        continue

    match = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload)
    if match and match.group() not in seen:
        seen.add(match.group())
        print("Issue:", issue)
        print("CRC32:", f"{stored_crc:08x}")
        print("Payload:", repr(payload))
        print("Flag:", match.group().decode())
