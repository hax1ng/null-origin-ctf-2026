#!/usr/bin/env python3
"""
Daybook (Null Origin CTF 2026 - Qualifier, Crypto / Reversing).

The challenge ships a 401 MB Linux core dump of the crashed `daybook` process.
That one dump holds everything we need:

  * the ciphertext, pasted across the middle of the in-memory 64-byte journal
    records (an RW arena mapping),
  * the JIT-generated cipher code (an RWE mapping -- data that is also
    executable, a tell-tale sign of runtime code generation),
  * the cipher's final 40-byte state (a global), whose first 16 bytes match
    the ciphertext's trailing authentication tag.

The stream cipher XORs each 16-byte block with the first 16 bytes of a 40-byte
state that is advanced only by a reversible permutation. So we run the dead
process backwards: strip the trailer mask, invert the trailer permutation
once, invert the permutation once per ciphertext block to recover the initial
state, then replay the (symmetric) JIT stream routine to decrypt.

Requires core.5711 (the core dump) in the working directory; it is far too
large to ship in this repo. Build the inverse helper first:

    gcc -shared -fPIC -O3 -o inv.so inv.c
"""
import ctypes
import mmap
from pathlib import Path

core = Path("core.5711").read_bytes()

# Copy the dumped RWE/JIT segment into executable memory.
code = core[0x19031000:0x19041000]
jit = mmap.mmap(
    -1, len(code),
    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
)
jit.write(code)
jit_address = ctypes.addressof(ctypes.c_char.from_buffer(jit))

# Function at JIT+0x110:  stream(state, output, input, number_of_blocks)
StreamFunction = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
)
stream = StreamFunction(jit_address + 0x110)

# Saved 40-byte state: VA 0x4b4ac0 -> core offset 0x7ac0.
final_state = bytearray(core[0x7ac0:0x7ae8])

# Pull the binary insertion out of the 64-byte journal records.
arena = 0x30000
start = arena + 0x320000 * 64 + 16
end   = arena + 0x3203c1 * 64 + 32
payload = core[start:end]

ciphertext = payload[:-16]
tag = payload[-16:]
assert bytes(final_state[:16]) == tag
assert len(ciphertext) % 16 == 0

# Undo the trailer's XOR (mask "JRNL\xff\xff\xff\xffUTRAITER").
trailer_mask = bytes.fromhex("4a524e4cffffffff5554524149544552")
for i, value in enumerate(trailer_mask):
    final_state[i] ^= value

# Call our inverse permutation helper (built from inv.c).
inverse = ctypes.CDLL("./inv.so")
inverse.invn.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

state = ctypes.create_string_buffer(bytes(final_state))
inverse.invn(state, 1)                     # undo trailer permutation
inverse.invn(state, len(ciphertext) // 16) # undo all stream blocks

# XOR is symmetrical, so the original routine now decrypts the blocks.
source = ctypes.create_string_buffer(ciphertext)
output = ctypes.create_string_buffer(len(ciphertext))
stream(state, output, source, len(ciphertext) // 16)

plaintext = output.raw
Path("daybook.plain").write_bytes(plaintext)
print(plaintext.rstrip(b"\0").decode(errors="replace"))
