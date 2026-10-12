#!/usr/bin/env python3
# Palimpsest GF(2) solver.
#
# Reads a stage's scraped linear system (produced by extract.py / extract_s1.py
# as a JSON of matrix rows + answer vector), runs Gauss-Jordan elimination over
# GF(2), prints the unique solution V and self-checks A*V == b. For stage 1 the
# recovered V reads as the decoy ASCII "you_trusted_the_first_draft" -- a trap,
# because V is really inner_V(candidate) = a SHA-256 expansion, not raw bytes.
import json, sys

def bit(buf, j):
    return (buf[j//8] >> (j % 8)) & 1

def main(path):
    d = json.load(open(path))
    N = d["N"]; M = d["M"]
    exp = bytes.fromhex(d["exp"])
    rows = d["rows"]
    # Build augmented matrix over GF(2): each equation i -> row vector (N bits) | rhs
    # rep each row as Python int (bit j at position j), plus rhs bit.
    A = []
    b = []
    for i in range(N):
        mask = bytes.fromhex(rows[str(i)])
        r = 0
        for j in range(N):
            if bit(mask, j):
                r |= (1 << j)
        A.append(r)
        b.append(bit(exp, i))
    # Gaussian elimination over GF(2)
    # pivot per column
    nrow = N
    where = [-1]*N
    row = 0
    Acp = A[:]; bcp = b[:]
    for col in range(N):
        # find pivot
        piv = -1
        for r in range(row, nrow):
            if (Acp[r] >> col) & 1:
                piv = r; break
        if piv == -1:
            continue
        Acp[row], Acp[piv] = Acp[piv], Acp[row]
        bcp[row], bcp[piv] = bcp[piv], bcp[row]
        for r in range(nrow):
            if r != row and ((Acp[r] >> col) & 1):
                Acp[r] ^= Acp[row]
                bcp[r] ^= bcp[row]
        where[col] = row
        row += 1
    rank = row
    # check consistency
    for r in range(rank, nrow):
        if Acp[r] == 0 and bcp[r] == 1:
            print("INCONSISTENT system");
    # extract solution (set free vars = 0)
    x = 0
    for col in range(N):
        if where[col] != -1:
            if bcp[where[col]]:
                x |= (1 << col)
    print("rank =", rank, "of", N)
    # reconstruct bytes: bit j -> byte j//8 bit j%8
    nbytes = (N + 7)//8
    out = bytearray(nbytes)
    for j in range(N):
        if (x >> j) & 1:
            out[j//8] |= (1 << (j % 8))
    print("candidate bytes (hex):", out.hex())
    try:
        print("candidate ASCII     :", out.decode("latin1"))
    except Exception as e:
        print("decode err", e)
    # verify Ax=b
    ok = True
    for i in range(N):
        acc = 0
        rr = A[i] & x
        acc = bin(rr).count("1") & 1
        if acc != b[i]:
            ok = False; break
    print("self-check Ax==b:", ok)
    return bytes(out)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "system.json")
