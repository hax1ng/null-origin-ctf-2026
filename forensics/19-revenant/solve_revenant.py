#!/usr/bin/env python3
"""Two-time-pad recovery of the Revenant escrow note.

Both suspend images resumed from the same PRNG state, so their stream-cipher
keystream K is identical:

    C_A = P_A XOR K
    C_B = P_B XOR K   ->   P_A = C_A XOR C_B XOR P_B

template.txt is the known plaintext P_B (the pre-rotation note). Sliding it
across both images and keeping the offset that yields a well-formed note locates
the ciphertext (at 0x1000) and recovers the changed ACTIVE note.
"""

from pathlib import Path
import re

a = Path("suspend-A.raw").read_bytes()
b = Path("suspend-B.raw").read_bytes()
known = Path("template.txt").read_bytes()

note_pattern = re.compile(
    rb"KEY-ESCROW-NOTE v1\n"
    rb"holder: kiosk-04\n"
    rb"status: [A-Z_]+ +\n"
    rb"secret: [0-9a-f]{64}\n"
    rb"\x00*"
)

for offset in range(len(a) - len(known) + 1):
    recovered = bytes(
        a[offset + i] ^ b[offset + i] ^ known[i]
        for i in range(len(known))
    )
    if note_pattern.fullmatch(recovered):
        print(f"candidate at 0x{offset:x}")
        print(recovered.rstrip(b"\x00").decode())

# The recovered ACTIVE note proves the two clones reused one keystream because
# the cloned guest's PRNG was never reseeded:
#   Null0rigin{the_clone_never_reseeded_the_rng}
