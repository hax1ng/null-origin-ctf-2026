# gdb python script: dump per-equation GF(2) matrix rows + target bits for each layer.
# Break at 0x401d17 (after SplitMix64 row fill + mask, before parity loop).
# Regs/stack at that point:
#   r13         = &matrix_row buffer (rax_15 qwords)
#   [rsp+0x0c]  = rax_15 (num 64-bit words per row)     (dword)
#   [rsp+0x20]  = r12_1  (num equations = matrix dim)   (dword)
#   [rsp+0x18]  = target base pointer (var_350)         (qword)
#   r15         = i (0-based equation index)
# Writes ouro_matrix.txt, consumed by solve.py / solve2.py.
import gdb, struct

OUT = open("ouro_matrix.txt", "w")

class BP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*0x401d17", gdb.BP_BREAKPOINT, internal=False)
    def stop(self):
        inf = gdb.selected_inferior()
        rsp = int(gdb.parse_and_eval("$rsp")) & 0xffffffffffffffff
        r13 = int(gdb.parse_and_eval("$r13")) & 0xffffffffffffffff
        r15 = int(gdb.parse_and_eval("$r15")) & 0xffffffffffffffff
        def rd(addr, n): return inf.read_memory(addr, n).tobytes()
        rax15 = struct.unpack("<I", rd(rsp+0x0c, 4))[0]
        r12_1 = struct.unpack("<I", rd(rsp+0x20, 4))[0]
        targ  = struct.unpack("<Q", rd(rsp+0x18, 8))[0]
        i = r15
        row = rd(r13, rax15*8)
        # target bit i from target base
        tb = rd(targ + (i>>3), 1)[0]
        tbit = (tb >> (i & 7)) & 1
        OUT.write("%d %d %d 0x%x %d %s\n" % (r12_1, i, rax15, targ, tbit, row.hex()))
        return False  # continue

BP()
gdb.execute("run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA x")
OUT.close()
gdb.execute("quit")
