#!/usr/bin/env python3
# gdb script: proof-of-faithful-scrape for palimpsest stage 5. Breaks at the
# per-bit compare (0x401d49) where eax=expected_i and esi=computed_i, and logs
# (i, mask, computed, expected) for every bit to conv.json. Replaying the
# parity in Python against this confirms the scraped matrix matches the
# binary's own computation on all bits.
import gdb, struct, json

FINAL_STAGE = 0x401f23
CMP_PT      = 0x401d49   # cmp %esi,%eax : eax=expected_i, esi=computed_i ; r15=i ; mask@rsp+0xf0

state = {"in5": False}
recs = []

def rd(a,n): return bytes(gdb.selected_inferior().read_memory(a,n))

class F(gdb.Breakpoint):
    def __init__(self): super().__init__("*%#x"%FINAL_STAGE, internal=True)
    def stop(self):
        state["in5"]=True; return False

class C(gdb.Breakpoint):
    def __init__(self): super().__init__("*%#x"%CMP_PT, internal=True)
    def stop(self):
        if not state["in5"]: return False
        f=gdb.selected_frame(); rsp=int(f.read_register("rsp"))
        i=int(f.read_register("r15"))&0xffffffffffffffff
        esi=int(f.read_register("rsi"))&0xffffffff   # computed
        eax=int(f.read_register("rax"))&0xffffffff   # expected
        M=struct.unpack("<I",rd(rsp+0xc,4))[0]
        mask=rd(rsp+0xf0,M*8)
        recs.append((i,mask.hex(),esi,eax))
        return False

F(); C()
gdb.execute("run", to_string=True)
json.dump(recs, open("conv.json","w"))
print("records:", len(recs))
gdb.execute("quit")
