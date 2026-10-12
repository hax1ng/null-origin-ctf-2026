#!/usr/bin/env python3
# Full 5-stage offline verification of the flag, faithfully reproducing the
# binary's check (SHA-256 transcript chain + splitmix64 GF(2) parity).
# Brute-forces each reduction-table index via the baked SHA256(T_k) checkpoint
# (bypasses the password), then verifies every stage's parity system.
import sys, struct
from qlib import sha, DOM, TAG, S0, src_of_idx, header, Dk, answer_bits
from solve import Tk, row_mask, inner_V

def le8(x): return struct.pack("<Q", x)

def state_update(k, S_prev, SRC, r14, index, flag):
    c = bytes([0x30 + k]); bc = (r14 + 7) // 8
    V = inner_V(k, flag, r14).to_bytes(bc, "little")   # hashed candidate expansion (candidate-dependent!)
    return sha(S_prev + b"|k=" + c + b"|x=" + le8(bc) + V + b"|src=" + le8(0x20) + SRC)

def find_idx(k, S_prev):
    tgt = Dk(k)
    for idx in range(2048):
        SRC = src_of_idx(idx)
        if sha(Tk(k, S_prev, SRC)) == tgt:
            return idx, SRC
    return None, None

def stage5_candidate_vec(flag, r14):
    bc = (r14 + 7) // 8
    raw = flag[:bc].ljust(bc, b"\x00")
    return int.from_bytes(raw, "little") & ((1 << r14) - 1)

def main():
    flag = sys.argv[1].encode()
    S = S0
    all_ok = True
    for k in range(1, 6):
        r14, index = header(k)
        idx, SRC = find_idx(k, S)
        if idx is None:
            print(f"stage {k}: CHECKPOINT MISMATCH"); all_ok = False; break
        T = Tk(k, S, SRC)
        V = stage5_candidate_vec(flag, r14) if k == 5 else inner_V(k, flag, r14)
        ab = answer_bits(k, (r14 + 7) // 8)
        good = all(bin(row_mask(T, index, i, r14) & V).count("1") & 1 == ((ab[i//8] >> (i%8)) & 1)
                   for i in range(r14))
        print(f"stage {k}: checkpoint OK (idx={idx:4d})  parity {'PASS' if good else 'FAIL'}  ({r14} rows, V={'raw candidate' if k==5 else 'hash(cand)'})")
        all_ok = all_ok and good
        if k < 5:
            S = state_update(k, S, SRC, r14, index, flag)
    print("\n==>", "ACCEPTED — flag verified across all 5 stages" if all_ok else "REJECTED")

if __name__ == "__main__":
    main()
