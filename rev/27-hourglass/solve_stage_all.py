#!/usr/bin/env python3
"""Solve one Dovetail GF(2) layer, retaining any free-variable branches."""
import hashlib
import struct
import sys

MASK = (1 << 64) - 1
binpath, stage, thex, outbase = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
b = open(binpath, "rb").read()
rec = 0x900E8 + (stage - 1) * 0xD0
nbits, nseed = struct.unpack_from("<II", b, rec - 8)
rhs = b[rec + 0x20:rec + 0x20 + (nbits + 7) // 8]
T = bytes.fromhex(thex)

rows = []
for i in range(nbits):
    h = hashlib.sha256(T + struct.pack("<Q", nseed) + struct.pack("<Q", i)).digest()
    state = 0
    for j in range(4):
        state ^= struct.unpack_from("<Q", h, j * 8)[0]
    eq = 0
    for w in range((nbits + 63) // 64):
        state = (state + 0x9E3779B97F4A7C15) & MASK
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        z ^= z >> 31
        eq |= z << (64 * w)
    eq &= (1 << nbits) - 1
    rows.append(eq | (((rhs[i // 8] >> (i & 7)) & 1) << nbits))

rank = 0
pivots = []
for col in range(nbits):
    p = next((j for j in range(rank, nbits) if (rows[j] >> col) & 1), None)
    if p is None:
        continue
    rows[rank], rows[p] = rows[p], rows[rank]
    pr = rows[rank]
    for j in range(nbits):
        if j != rank and ((rows[j] >> col) & 1):
            rows[j] ^= pr
    pivots.append(col)
    rank += 1

mask = (1 << nbits) - 1
for row in rows:
    assert (row & mask) or not ((row >> nbits) & 1), "inconsistent"
free = [c for c in range(nbits) if c not in set(pivots)]
assert len(free) <= 12, (rank, nbits, free)

for choice in range(1 << len(free)):
    x = sum(((choice >> j) & 1) << c for j, c in enumerate(free))
    # RREF pivot equation: x_p + sum(A[p,free]*x_free) = rhs.
    for r, col in enumerate(pivots):
        bit = (rows[r] >> nbits) & 1
        bit ^= ((rows[r] & x).bit_count() & 1)
        x |= bit << col
    assert all(((row & mask & x).bit_count() & 1) == ((row >> nbits) & 1) for row in rows)
    v = x.to_bytes((nbits + 7) // 8, "little")
    path = f"{outbase}.{choice}"
    open(path, "wb").write(v)
    print(path, "rank", rank, "free", free, "hex", v.hex(), "ascii", repr(v))
