#!/usr/bin/env python3
"""Offline solver for 27-hourglass once flags 21--26 are known."""
import argparse
import hashlib
import itertools
import json
import struct

D = b"NULL0RIGIN/REV/CASCADE/v1"
MASK = (1 << 64) - 1


def h(*xs):
    z = hashlib.sha256()
    for x in xs:
        z.update(x)
    return z.digest()


def lp(label, data):
    return label + struct.pack("<Q", len(data)) + data


def splitmix(z):
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
    return z ^ (z >> 31)


def solve_layer(T, nbits, seed, rhs):
    """Return every solution of M(T,seed) v = rhs (normally exactly one)."""
    rows = []
    for i in range(nbits):
        d = h(T, struct.pack("<Q", seed), struct.pack("<Q", i))
        state = 0
        for j in range(0, 32, 8):
            state ^= struct.unpack_from("<Q", d, j)[0]
        eq = 0
        for w in range((nbits + 63) // 64):
            state = (state + 0x9E3779B97F4A7C15) & MASK
            eq |= splitmix(state) << (64 * w)
        eq &= (1 << nbits) - 1
        rows.append(eq | (((rhs[i // 8] >> (i & 7)) & 1) << nbits))

    rank, pivots = 0, []
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

    vmask = (1 << nbits) - 1
    if any(not (r & vmask) and ((r >> nbits) & 1) for r in rows):
        return []
    pset = set(pivots)
    free = [c for c in range(nbits) if c not in pset]
    if len(free) > 12:
        raise RuntimeError(f"layer has unexpectedly many free variables: {len(free)}")
    out = []
    for choice in range(1 << len(free)):
        x = sum(((choice >> j) & 1) << c for j, c in enumerate(free))
        for r, col in enumerate(pivots):
            bit = ((rows[r] >> nbits) & 1) ^ ((rows[r] & x).bit_count() & 1)
            x |= bit << col
        assert all(((r & vmask & x).bit_count() & 1) == ((r >> nbits) & 1) for r in rows)
        out.append(x.to_bytes((nbits + 7) // 8, "little"))
    return out


def load_desc(path="hourglass"):
    b = open(path, "rb").read()
    base = 0xB3BA8
    ds = []
    for i in range(5):
        rec = base + i * 0xD0
        nbits, seed = struct.unpack_from("<II", b, rec - 8)
        ds.append({
            "nbits": nbits,
            "seed": seed,
            "checkpoint": b[rec:rec + 32],
            "rhs": b[rec + 32:rec + 32 + (nbits + 7) // 8],
        })
    return ds


def sources(row, timing_bit):
    return [
        h(b"hourglass/L1|", struct.pack("<I", row["prefix"])),
        h(b"hourglass/L2|", struct.pack("<I", row["final"])),
        h(b"hourglass/L3|", bytes([row["nest"]])),
        h(b"hourglass/L4|", bytes([timing_bit])),
        h(b"hourglass/L5|", bytes([row["completion"]])),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flags", help="comma-separated flags 21,22,23,24,25,26")
    ap.add_argument("--outputs", default="hg_outputs.json")
    ap.add_argument("--binary", default="hourglass")
    a = ap.parse_args()
    flags = a.flags.split(",")
    if len(flags) != 6:
        raise SystemExit("need exactly six comma-separated flags")

    joined = "|".join(flags).encode()
    meta = b"27-hourglass|meta|" + hashlib.sha256(joined).hexdigest().encode()
    assert len(meta) == 82
    S0 = h(D, b"|transcript|", meta)
    desc = load_desc(a.binary)
    outs = json.load(open(a.outputs))

    finals = []
    for row in outs:
        if "error" in row:
            continue
        for timing in (0, 1):
            srcs = sources(row, timing)
            states = [(S0, [])]
            for k in range(1, 6):
                nd = []
                for S, vs in states:
                    T = h(D, b"|stage=", meta, b"|layer=", str(k).encode(),
                          b"|t=", S, lp(b"|src=", srcs[k - 1]))
                    d = desc[k - 1]
                    if h(T) != d["checkpoint"]:
                        continue
                    for V in solve_layer(T, d["nbits"], d["seed"], d["rhs"]):
                        if k == 5:
                            finals.append((row["ov"], timing, V, vs + [V]))
                        else:
                            Sn = h(S, b"|k=", str(k).encode(),
                                   lp(b"|x=", V), lp(b"|src=", srcs[k - 1]))
                            nd.append((Sn, vs + [V]))
                states = nd
                if k < 5 and not states:
                    break

    if not finals:
        raise SystemExit("no consistent source/transcript path; check the six input flags")
    for ov, timing, raw, vs in finals:
        candidate = raw.rstrip(b"\0")
        print("overrides:", ov, "timing_bit:", timing)
        print("raw:", raw.hex())
        print("candidate:", repr(candidate))
        try:
            print("flag:", candidate.decode())
        except UnicodeDecodeError:
            pass


if __name__ == "__main__":
    main()
