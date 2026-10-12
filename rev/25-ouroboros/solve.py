#!/usr/bin/env python3
# Solve the ouroboros keygen: recover the candidate (flag) from the GF(2) linear
# systems of the password-INDEPENDENT layers (2..5).
#
# NOTE: this approach is a documented DEAD END. The ouroboros cascade re-seeds
# each layer from the candidate's own hash expansion, so the matrices are
# candidate-dependent and cannot be inverted externally. The real flag is a
# preimage recovered from the binary's usage string (see README). This script
# is kept to show the GF(2) machinery and why it fails here.
#
# Each dumped line: r12_1 i rax15 targ_ptr tbit rowhex
#   equation i of a layer:  parity( M_i AND x ) == tbit
#   x = candidate bits, bit j = flag_byte[j//8] bit (j%8), little-endian words.
import hashlib

lines = open("ouro_matrix.txt").read().split("\n")
layers = []          # list of (dim, [(rowmask_int, tbit), ...])
cur = None
for ln in lines:
    if not ln.strip():
        continue
    parts = ln.split()
    dim = int(parts[0]); i = int(parts[1]); rax15 = int(parts[2])
    tbit = int(parts[4]); rowhex = parts[5]
    rb = bytes.fromhex(rowhex)
    # row as bitmask: little-endian 64-bit words -> bit j = 64*w + b
    rowmask = int.from_bytes(rb, "little")   # since LE words concatenated == LE integer, bit j is column j
    if i == 0:
        cur = (dim, [])
        layers.append(cur)
    cur[1].append((rowmask, tbit))

print("layers (dim, #eqs):", [(d, len(e)) for d, e in layers])

# Layer 1 (first block) is password-dependent -> skip it. Use layers[1:] (layers 2..5).
use = layers[1:]
Nmax = max(d for d, _ in use)
print("using layers 2..5, Nmax bits =", Nmax, "= %d bytes" % (Nmax // 8))

# Build combined system: rows (bitmask over Nmax cols) and rhs bits.
rows = []
rhs = []
for d, eqs in use:
    for rowmask, tbit in eqs:
        rows.append(rowmask)
        rhs.append(tbit)
print("total equations:", len(rows))

# Gaussian elimination over GF(2). Represent each equation as (mask over cols) with rhs bit as an extra top bit.
# augmented = rowmask | (rhs << Nmax)
RHS = 1 << Nmax
aug = [rows[k] | (RHS if rhs[k] else 0) for k in range(len(rows))]

pivot_for_col = {}   # col -> aug row index in basis
basis = []
for a in aug:
    x = a
    # reduce by current basis
    for (col, brow) in basis:
        if (x >> col) & 1:
            x ^= brow
    coeff = x & ((1 << Nmax) - 1)   # column part
    if coeff == 0:
        # either 0=0 (fine) or 0=1 (inconsistent)
        if (x >> Nmax) & 1:
            print("INCONSISTENT equation encountered!")
        continue
    # pick lowest set column as pivot
    col = (coeff & -coeff).bit_length() - 1
    basis.append((col, x))

# Back-substitute: solve for each pivot col. Free cols default 0.
sol = 0
# Need to fully reduce basis to RREF for a direct read; do iterative solve.
# Sort basis by pivot col descending and substitute.
basis_by_col = {col: row for col, row in basis}
pivots = sorted(basis_by_col.keys())
xbits = [0] * Nmax
# process from highest pivot down
for col in sorted(pivots, reverse=True):
    row = basis_by_col[col]
    val = (row >> Nmax) & 1
    # xor contributions of already-set higher columns
    m = row & ((1 << Nmax) - 1)
    m &= ~(1 << col)
    acc = val
    mm = m
    while mm:
        c = (mm & -mm).bit_length() - 1
        acc ^= xbits[c]
        mm &= mm - 1
    xbits[col] = acc

# Assemble bytes (bit j = byte j//8 bit j%8)
nbytes = Nmax // 8
out = bytearray(nbytes)
for j in range(Nmax):
    if xbits[j]:
        out[j >> 3] |= (1 << (j & 7))

# free columns (no pivot) -> assumed 0; report them
free = [c for c in range(Nmax) if c not in basis_by_col]
print("num pivots:", len(pivots), "num free cols:", len(free))
print("raw bytes:", out)
# strip trailing zeros
s = bytes(out).rstrip(b"\x00")
print("candidate string:", s)
try:
    print("as text:", s.decode())
except Exception as e:
    print("decode err", e)

print("SHA256:", hashlib.sha256(s).hexdigest())
print("TARGET: 771ecbf65d76ff25534a8230d479a3a42f201c3884af3a3c771cabd6bfe3fe51")
print("MATCH:", hashlib.sha256(s).hexdigest() == "771ecbf65d76ff25534a8230d479a3a42f201c3884af3a3c771cabd6bfe3fe51")
