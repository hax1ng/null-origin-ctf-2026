#!/usr/bin/env python3
# Solve each ouroboros layer's square GF(2) system independently and inspect the
# unique solution. Companion to solve.py -- also a documented dead end, since the
# layer matrices are candidate-dependent (see README). Reads ouro_matrix.txt.
import hashlib

TARGET = "771ecbf65d76ff25534a8230d479a3a42f201c3884af3a3c771cabd6bfe3fe51"

lines = open("ouro_matrix.txt").read().split("\n")
layers = []
cur = None
for ln in lines:
    if not ln.strip():
        continue
    p = ln.split()
    dim = int(p[0]); i = int(p[1]); tbit = int(p[4]); rowhex = p[5]
    rowmask = int.from_bytes(bytes.fromhex(rowhex), "little")
    if i == 0:
        cur = (dim, []); layers.append(cur)
    cur[1].append((rowmask, tbit))

def solve_layer(dim, eqs):
    # augmented rows: rowmask (dim cols) with rhs at bit `dim`
    RHS = 1 << dim
    aug = [rm | (RHS if tb else 0) for rm, tb in eqs]
    basis = {}   # pivot col -> reduced row
    for a in aug:
        x = a
        for col in list(basis):
            if (x >> col) & 1:
                x ^= basis[col]
        coeff = x & ((1 << dim) - 1)
        if coeff == 0:
            if (x >> dim) & 1:
                return None, "inconsistent"
            continue
        col = (coeff & -coeff).bit_length() - 1
        # reduce existing basis by this new row
        basis[col] = x
    # full reduce to RREF
    cols = sorted(basis)
    xbits = [0]*dim
    for col in sorted(cols, reverse=True):
        row = basis[col]
        acc = (row >> dim) & 1
        m = (row & ((1<<dim)-1)) & ~(1<<col)
        mm = m
        while mm:
            c = (mm & -mm).bit_length()-1
            acc ^= xbits[c]
            mm &= mm-1
        xbits[col] = acc
    nb = dim // 8
    out = bytearray(nb)
    for j in range(dim):
        if xbits[j]:
            out[j>>3] |= 1<<(j&7)
    return bytes(out), ("pivots=%d/%d" % (len(cols), dim))

for idx, (dim, eqs) in enumerate(layers, start=1):
    sol, info = solve_layer(dim, eqs)
    tag = "layer%d dim=%d %s" % (idx, dim, info)
    if sol is None:
        print(tag, "-> NO SOLUTION")
        continue
    s = sol.rstrip(b"\x00")
    printable = all(32 <= c < 127 for c in s)
    h = hashlib.sha256(s).hexdigest()
    print(tag)
    print("   sol raw:", sol)
    print("   stripped:", s, "printable=", printable)
    if printable:
        try: print("   text:", s.decode())
        except: pass
    print("   sha256:", h, "MATCH" if h == TARGET else "")
