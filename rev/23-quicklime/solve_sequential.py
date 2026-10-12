#!/usr/bin/env python3
# Quicklime sequential cascade solver.
#
# Walks the full five-stage cascade. For each stage it brute-forces which of
# the 2048 reduction_tables.bin blocks reproduces the baked SHA256(T_k)
# checkpoint (this recovers even stage 3's password-derived index without the
# password), then solves that stage's GF(2) system. Stage 5's vector is the
# raw candidate -> the flag. Relies on qlib.py and solve.py helpers.
import hashlib,struct
from qlib import sha,DOM,TAG,S0,header,Dk,answer_bits,src_of_idx
from solve import Tk,row_mask,gf2_solve,bits_to_bytes

def le8(n): return struct.pack('<Q',n)
def solve_layer(k,T):
    nbits,seed=header(k); ab=answer_bits(k,(nbits+7)//8)
    rows=[row_mask(T,seed,i,nbits) for i in range(nbits)]
    rhs=[(ab[i//8]>>(i&7))&1 for i in range(nbits)]
    x,free=gf2_solve(rows,rhs,nbits)
    if free: print('free',len(free))
    return bits_to_bytes(x,nbits)
def state(k,S,V,SRC):
    c=str(k).encode()
    return sha(S+b'|k='+c+b'|x='+le8(len(V))+V+b'|src='+le8(32)+SRC)
S=S0
for k in range(1,6):
    found=[]
    for idx in range(2048):
        src=src_of_idx(idx); T=Tk(k,S,src)
        if sha(T)==Dk(k): found.append((idx,src,T))
    print('stage',k,'matches',len(found),[x[0] for x in found])
    if not found: break
    idx,src,T=found[0]
    V=solve_layer(k,T)
    print('V',len(V),V.hex())
    if k==5:
        print('FLAG RAW',repr(V)); print('FLAG',repr(V.rstrip(b'\0')))
    else:S=state(k,S,V,src)
