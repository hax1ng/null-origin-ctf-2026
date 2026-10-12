#!/usr/bin/env python3
# Cinder keygen solver (stage of the Null0rigin REV cascade).
#
# Reconstructs the five-stage SHA-256 / splitmix64 GF(2) cascade from the
# `cinder` binary and recovers the flag. Each stage builds a system of XOR
# (GF(2)) equations whose unique solution is the stage vector; stages 1-4 feed
# the running transcript, and stage 5's vector is the raw flag itself.
#
# `srcs` holds the 32-byte per-stage "source" values. srcs[0] is the stage-1
# source captured at a GDB breakpoint (it is produced by the binary's PRNG
# sampling of the embedded .cinderdump); stages 3 and 4 are password-derived
# and can be overridden on argv, but default to the recovered values.
import hashlib,struct,sys
B=open('cinder','rb').read(); D=b'NULL0RIGIN/REV/CASCADE/v1'; TAG=b'21-cinder'; BASE=0x901a8; MASK=(1<<64)-1
srcs=[
'ff68d7321f7f2dc4e40dc01bc7838c4602072e4dc1802ccd52b1348fca82f7e1',
'7f895346c5540722ce760e1d50cda55819698b9f15cde724975180db05f534b6',
sys.argv[1] if len(sys.argv)>1 else '6fb57d1eb7b2178f859c665254601284be2466bafcf679e7f1ed1723790feda1',
sys.argv[2] if len(sys.argv)>2 else '92e0d5bd86df09d2a55b1255e3aff9a4efe6d014883d66d00b4a6a25fe92351b',
'57d30551cb2a072f2a45fb0b2e4a03383146c72951817dfad414dcc9f3807a46']
srcs=list(map(bytes.fromhex,srcs))
def h(*x):return hashlib.sha256(b''.join(x)).digest()
def le(n):return struct.pack('<Q',n)
def desc(k):
 r=BASE+(k-1)*0xd0;n,seed=struct.unpack_from('<II',B,r-8);return n,seed,B[r:r+32],B[r+32:r+32+(n+7)//8]
def T(k,S,src):return h(D,b'|stage=',TAG,b'|layer=',str(k).encode(),b'|t=',S,b'|src=',le(32),src)
def splitmix(z):
 z=((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK;z=((z^(z>>27))*0x94d049bb133111eb)&MASK;return z^(z>>31)
def solve(k,t):
 n,seed,cp,rhs=desc(k); rows=[]
 for i in range(n):
  q=h(t,le(seed),le(i)); st=0
  for j in range(0,32,8):st^=struct.unpack_from('<Q',q,j)[0]
  eq=0
  for w in range((n+63)//64):st=(st+0x9e3779b97f4a7c15)&MASK;eq|=splitmix(st)<<(64*w)
  eq&=(1<<n)-1; rows.append(eq|(((rhs[i//8]>>(i&7))&1)<<n))
 rank=0;piv=[]
 for col in range(n):
  p=next((j for j in range(rank,n) if (rows[j]>>col)&1),None)
  if p is None:continue
  rows[rank],rows[p]=rows[p],rows[rank];pr=rows[rank]
  for j in range(n):
   if j!=rank and ((rows[j]>>col)&1):rows[j]^=pr
  piv.append(col);rank+=1
 if any(not(r&((1<<n)-1)) and ((r>>n)&1) for r in rows):raise ValueError('inconsistent')
 if rank!=n:raise ValueError(('rank',rank,n))
 x=0
 for j,c in enumerate(piv):x|=((rows[j]>>n)&1)<<c
 return x.to_bytes((n+7)//8,'little')
S=h(D,b'|transcript|',TAG)
for k,src in enumerate(srcs,1):
 t=T(k,S,src);n,seed,cp,rhs=desc(k); ok=h(t)==cp
 print('stage',k,'checkpoint',ok,'T',t.hex())
 if not ok:break
 V=solve(k,t);print('V',len(V),V.hex(),repr(V))
 if k==5: print('FLAG',repr(V.rstrip(b'\0')))
 else:S=h(S,b'|k=',str(k).encode(),b'|x=',le(len(V)),V,b'|src=',le(32),src)
