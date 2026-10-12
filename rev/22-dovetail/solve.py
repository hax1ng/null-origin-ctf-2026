#!/usr/bin/env python3
# Dovetail keygen solver (stage of the Null0rigin REV cascade).
#
# Reconstructs the five-stage SHA-256 / splitmix64 GF(2) cascade from the
# `dovetail` binary. Each stage builds a system of XOR (GF(2)) equations whose
# unique solution is the stage vector. Stage 1 is password-independent, so its
# vector is recoverable with no secrets; it is the SHA-256 expansion of the
# flag and acts as an instant flag oracle (see the writeup). `srcs` holds the
# recovered 32-byte per-stage source values (stages 3-4 are password-derived
# and can be overridden on argv).
import hashlib,struct,sys
B=open('dovetail','rb').read(); D=b'NULL0RIGIN/REV/CASCADE/v1'; TAG=b'22-dovetail'; BASE=0x900e8; MASK=(1<<64)-1
srcs=[
'd525bb4a1a40aab8e701b3ee1e2d3c698e137c061ea4033cb3cdd2f9f65ac454',
'59c691bf11565c67f559880483536b1f39f43a582ad23b46e6c1329512a106f3',
sys.argv[1] if len(sys.argv)>1 else '47600bf9d0bf466821eaa232dfe6396f3a9b5e12db871fdfc8519d490ee91d49',
sys.argv[2] if len(sys.argv)>2 else '920f84be757366015259e61ecf2394c35ab3d3d387d71783aae979e5e0330301',
'8159945f6d19d0f82a49c9997d51a9ee528f372f5e262572b2fc90427ebdb9b4']
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
