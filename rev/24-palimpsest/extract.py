#!/usr/bin/env python3
# gdb script: scrape palimpsest's stage-5 GF(2) linear system out of live
# memory. Breaks where each row mask is fully built (0x401cf7) inside the
# final stage (entered at 0x401f23), reads the M qwords of the mask plus the
# baked answer vector, and writes the whole system to system.json for solve.py.
# Run: gdb -batch -x extract.py --args ./palimpsest <34-byte candidate> <pw>
import gdb

# Extract stage-5 GF(2) linear system from palimpsest.
# Not PIE -> absolute addresses.
FINAL_STAGE = 0x401f23     # entry of final (stage 5) processing
MASK_READY  = 0x401cf7     # mask fully built in [rsp+0xf0], r15=bit index i

rows = []          # list of (i, mask_bytes)
state = {"in5": False, "M": None, "N": None, "exp": None}

def rd(addr, n):
    return bytes(gdb.selected_inferior().read_memory(addr, n))

class FinalBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*%#x" % FINAL_STAGE, internal=True)
    def stop(self):
        state["in5"] = True
        return False   # don't halt

class MaskBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*%#x" % MASK_READY, internal=True)
    def stop(self):
        if not state["in5"]:
            return False
        frame = gdb.selected_frame()
        rsp = int(frame.read_register("rsp"))
        i   = int(frame.read_register("r15")) & 0xffffffffffffffff
        if state["M"] is None:
            state["M"] = int(rd(rsp+0xc,4).ljust(4,b"\0")[0] | (rd(rsp+0xc,4)[1]<<8) | (rd(rsp+0xc,4)[2]<<16) | (rd(rsp+0xc,4)[3]<<24))
            import struct
            state["M"] = struct.unpack("<I", rd(rsp+0xc,4))[0]
            state["N"] = struct.unpack("<I", rd(rsp+0x20,4))[0]
            expptr = struct.unpack("<Q", rd(rsp+0x18,8))[0]
            state["exp"] = rd(expptr, (state["N"]+7)//8)
        M = state["M"]
        mask = rd(rsp+0xf0, M*8)
        rows.append((i, mask))
        return False

FinalBP()
MaskBP()
gdb.execute("run", to_string=True)

import struct, json
M = state["M"]; N = state["N"]; exp = state["exp"]
print("M(qwords)=%r N(numbits)=%r rows=%d" % (M, N, len(rows)))
# dedupe by i, keep order 0..N-1
byi = {}
for i, mask in rows:
    byi[i] = mask
print("unique bit indices:", len(byi), "min", min(byi) if byi else None, "max", max(byi) if byi else None)
out = {"M": M, "N": N, "exp": exp.hex()}
out["rows"] = {str(i): byi[i].hex() for i in sorted(byi)}
open("system.json","w").write(json.dumps(out))
print("wrote system.json")
gdb.execute("quit")
