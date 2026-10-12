#!/usr/bin/env python3
# Quicklime keygen solver.
# Recovers the flag by reconstructing the candidate-independent state chain
# (brute-forcing the 5 reduction-table indices against the baked SHA256(T_k)
# checkpoints -- bypassing the password entirely) and solving stage 5's GF(2)
# linear system, where the dotted vector is the RAW candidate.
import struct, hashlib
from qlib import (elf_reader, sha, DOM, TAG, S0, src_of_idx, header, Dk,
                  answer_bits, R, desc_addr)

MASK=(1<<64)-1
GOLD=0x9e3779b97f4a7c15
C1=0xbf58476d1ce4e5b9
C2=0x94d049bb133111eb

def le8(x): return struct.pack("<Q", x)

def Tk(k, S_prev, SRC):
    c=bytes([0x30+k])
    return sha(DOM+b"|stage="+TAG+b"|layer="+c+b"|t="+S_prev+b"|src="+le8(0x20)+SRC)

def state_update(k, S_prev, SRC, T, r14, index):
    c=bytes([0x30+k])
    bytecount=(r14+7)//8
    vstate=T+le8(index)+le8(r14-1)          # T(32)||index(8LE)||rowcounter(8LE)
    vstate=vstate[:bytecount]
    return sha(S_prev+b"|k="+c+b"|x="+le8(bytecount)+vstate+b"|src="+le8(0x20)+SRC)

def find_idx(k, S_prev):
    """brute the reduction-table block index whose SHA256(T_k)==desc_k[0:32]"""
    target=Dk(k)
    for idx in range(2048):
        SRC=src_of_idx(idx)
        if sha(Tk(k,S_prev,SRC))==target:
            return idx, SRC
    raise RuntimeError(f"no idx match for stage {k}")

def splitmix_words(seed, n):
    st=seed; out=[]
    for _ in range(n):
        st=(st+GOLD)&MASK
        z=st
        z=((z ^ (z>>30))*C1)&MASK
        z=((z ^ (z>>27))*C2)&MASK
        z=z ^ (z>>31)
        out.append(z)
    return out

def row_mask(T, index, i, r14):
    numwords=(r14+63)//64
    key=sha(T+le8(index)+le8(i))            # SHA256(48 bytes)
    seed=0
    for off in (0,8,16,24):
        seed ^= int.from_bytes(key[off:off+8],"little")
    words=splitmix_words(seed, numwords)
    # bit n (n<r14) = bit (n%64) of words[n//64]
    bits=0
    for w,val in enumerate(words):
        bits |= val << (64*w)
    if r14 & 63:
        bits &= (1<<r14)-1
    return bits  # r14-bit integer, bit n = coeff of candidate bit n

def gf2_solve(rows, bvec, ncols):
    """solve rows·x = bvec over GF(2). rows[i] is an int bitmask (bit n), bvec list of {0,1}."""
    # augmented: represent each equation as (mask int, rhs bit)
    eqs=[[rows[i], bvec[i]&1] for i in range(len(rows))]
    pivots={}
    for col in range(ncols):
        pr=None
        for r in range(len(eqs)):
            if r in pivots.values(): continue
            if (eqs[r][0]>>col)&1:
                pr=r; break
        if pr is None: continue
        pivots[col]=pr
        pm,pb=eqs[pr]
        for r in range(len(eqs)):
            if r!=pr and ((eqs[r][0]>>col)&1):
                eqs[r][0]^=pm; eqs[r][1]^=pb
    # check consistency (0=rhs)
    for r in range(len(eqs)):
        if eqs[r][0]==0 and eqs[r][1]!=0:
            raise RuntimeError("inconsistent system")
    x=0
    free=[]
    for col in range(ncols):
        if col in pivots:
            if eqs[pivots[col]][1]&1:
                x|=(1<<col)
        else:
            free.append(col)
    return x, free

def bits_to_bytes(x, ncols):
    nb=(ncols+7)//8
    return bytes((x>>(8*j))&0xff for j in range(nb))

def main():
    print("[*] S0 =", S0.hex())
    S=S0
    chain=[]
    for k in range(1,6):
        r14,index=header(k)
        idx,SRC=find_idx(k,S)
        T=Tk(k,S,SRC)
        assert sha(T)==Dk(k)
        chain.append((k,r14,index,idx,SRC,T,S))
        print(f"[+] stage {k}: idx={idx:4d}  r14_3={r14}  index={index}  T={T.hex()[:16]}  (checkpoint OK)")
        if k<5:
            S=state_update(k,S,SRC,T,r14,index)
    # stage 5 -> linear system, V = raw candidate
    k,r14,index,idx,SRC,T5,Sprev = chain[4]
    print(f"[*] building {r14}x{r14} GF(2) system for stage 5 (T5={T5.hex()[:16]})")
    ab=answer_bits(5,(r14+7)//8)
    rows=[row_mask(T5,index,i,r14) for i in range(r14)]
    bvec=[(ab[i//8]>>(i%8))&1 for i in range(r14)]
    x,free=gf2_solve(rows,bvec,r14)
    print(f"[*] solved. free vars: {len(free)}")
    cand=bits_to_bytes(x,r14)
    print("[*] candidate bytes:", cand)
    try:
        print("[*] as text:", cand.rstrip(b'\x00').decode())
    except: pass

    # ---- verify against stages 1-4 (V = SHA-expansion of candidate) ----
    flag=cand.rstrip(b"\x00")
    ok=verify_all(chain, flag)
    print("[*] stages 1-4 consistency:", "PASS" if ok else "FAIL")
    if ok:
        open("flag.txt","w").write(flag.decode()+"\n")
        print("[+] FLAG:", flag.decode())

def inner_V(k, cand, r14):
    c=bytes([0x30+k]); bytecount=(r14+7)//8
    buf=b""; j=0
    while len(buf) < bytecount:
        blk=sha(DOM+b"|inner|"+TAG+b"|"+c+b"|"+le8(j)+b"|"+cand)
        buf+=blk; j+=1
    v=int.from_bytes(buf[:bytecount],"little")
    if r14 & 63:
        pass
    v &= (1<<r14)-1
    return v

def verify_all(chain, flag):
    allok=True
    for (k,r14,index,idx,SRC,T,S) in chain:
        ab=answer_bits(k,(r14+7)//8)
        bvec=[(ab[i//8]>>(i%8))&1 for i in range(r14)]
        if k==5:
            V=int.from_bytes(flag[:(r14+7)//8].ljust((r14+7)//8,b"\x00"),"little")&((1<<r14)-1)
        else:
            V=inner_V(k,flag,r14)
        good=True
        for i in range(r14):
            Ri=row_mask(T,index,i,r14)
            if bin(Ri & V).count("1")&1 != bvec[i]:
                good=False; break
        print(f"    stage {k}: {'ok' if good else 'MISMATCH'}")
        allok = allok and good
    return allok

if __name__=="__main__":
    main()
