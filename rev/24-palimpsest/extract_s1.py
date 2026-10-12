#!/usr/bin/env python3
# gdb script: scrape palimpsest's STAGE 1 GF(2) system from live memory.
# Same mask-ready breakpoint (0x401cf7) but filters to stage==1 (read from
# [rsp+0x50]). Writes s1.json for solve.py -- solving it yields the decoy.
# Run: gdb -batch -x extract_s1.py --args ./palimpsest <34-byte cand> <pw> [out.json]
import gdb, struct, json, sys
MASK_READY=0x401cf7
rows={}
meta={}
def rd(a,n): return bytes(gdb.selected_inferior().read_memory(a,n))
gdb.execute("set pagination off")
class B(gdb.Breakpoint):
    def __init__(self): super().__init__("*%#x"%MASK_READY, internal=True)
    def stop(self):
        f=gdb.selected_frame(); rsp=int(f.read_register("rsp"))
        stage=struct.unpack("<Q",rd(rsp+0x50,8))[0]
        if stage!=1: return False
        i=int(f.read_register("r15"))&0xffffffffffffffff
        if not meta:
            meta['M']=struct.unpack("<I",rd(rsp+0xc,4))[0]
            meta['N']=struct.unpack("<I",rd(rsp+0x20,4))[0]
            ep=struct.unpack("<Q",rd(rsp+0x18,8))[0]
            meta['exp']=rd(ep,(meta['N']+7)//8).hex()
        rows[i]=rd(rsp+0xf0, meta['M']*8).hex()
        return False
B()
gdb.execute("run")
out={'M':meta.get('M'),'N':meta.get('N'),'exp':meta.get('exp'),'rows':{str(k):rows[k] for k in sorted(rows)}}
json.dump(out, open(sys.argv[1] if len(sys.argv)>1 else "s1.json","w"))
print("S1 M=%r N=%r rows=%d"%(meta.get('M'),meta.get('N'),len(rows)))
gdb.execute("quit")
