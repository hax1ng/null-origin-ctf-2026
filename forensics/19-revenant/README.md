# Revenant

**Category:** Forensics | **Difficulty:** Hard | **Points:** 600 | **Flag:** `Null0rigin{the_clone_never_reseeded_the_rng}`

## Challenge Description

> A revenant comes back without permission and without having changed.
> The machine was put to sleep twice.

The download:

```text
suspend-A.raw      # raw suspend image (10,641 bytes)
suspend-B.raw      # raw suspend image (10,641 bytes)
template.txt       # 256-byte escrow note in a known state (included here)
revenant.sealed    # confirmation material
verify             # local checker
```

> Note: part of the internal forensics chain — chain-internal flag format is
> `Null0rigin{...}` (with a zero).

The short version: both suspended machines resumed from the **same** PRNG state,
so they produced the **same** stream-cipher keystream. Reusing a keystream is
fatal — XORing the two encrypted notes cancels the encryption, and the supplied
template lets us reconstruct the changed note.

## Initial Analysis

```bash
ls -l; strings -a suspend-A.raw; strings -a suspend-B.raw
```

Both images are 10,641 bytes and both carry the same two tempting strings:

```text
kiosk-notes: last rotated key was Null0rigin{rotation_log_stale}
HISTORY: PID=901 UID=0 COMMAND=cat escrow.bak # Null0rigin{escrow_backup_wrong}
```

The names *are* the warning — "stale" and "wrong." Planted decoys; don't burn
verifier attempts on them.

`template.txt` is exactly 256 bytes, a note in a known pre-rotation state (the
rest null-padded):

```text
KEY-ESCROW-NOTE v1
holder: kiosk-04
status: PENDING_ROTATION
secret: 0000000000000000000000000000000000000000000000000000000000000000
```

This is our **known plaintext** — what one encrypted 256-byte record said before
the machine was cloned.

## The Vulnerability / Core Concept

A stream cipher is `C = P XOR K`. Safe only if `K` is never reused. Both cloned
machines resumed with the same PRNG state, so both records used the same `K`:

```text
C_A = P_A XOR K
C_B = P_B XOR K
```

XOR the ciphertexts and the keystream cancels:

```text
C_A XOR C_B = P_A XOR P_B
```

XOR that with the known template `P_B` and you recover the other note outright:

```text
P_A = C_A XOR C_B XOR P_B
```

This is the classic **two-time pad** break. Analogy: two messages written under
the same reusable masking sheet — each looks like garbage alone, but comparing
them reveals their differences, and knowing one reconstructs the other.

## Exploitation

The ciphertext sits at offset `0x1000` in both images, 256 bytes long. Rather
than hardcode that, `solve_revenant.py` slides the template across the images
and keeps the offset that yields a well-formed note:

```python
from pathlib import Path
import re

a = Path("suspend-A.raw").read_bytes()
b = Path("suspend-B.raw").read_bytes()
known = Path("template.txt").read_bytes()

note = re.compile(rb"KEY-ESCROW-NOTE v1\nholder: kiosk-04\n"
                  rb"status: [A-Z_]+ +\nsecret: [0-9a-f]{64}\n\x00*")

for off in range(len(a) - len(known) + 1):
    rec = bytes(a[off+i] ^ b[off+i] ^ known[i] for i in range(len(known)))
    if note.fullmatch(rec):
        print(f"candidate at 0x{off:x}"); print(rec.rstrip(b"\x00").decode())
```

```bash
python3 solve_revenant.py
# candidate at 0x1000
# KEY-ESCROW-NOTE v1
# holder: kiosk-04
# status: ACTIVE
# secret: ccb0c74f3673e7f529f1744d812bcca40e2c118803a98f61bbd0e34b6b3e51de
```

The 32-byte `secret` is *supposed* to look random and is **not** itself the
flag. The forensic result is the conclusion it proves: one snapshot holds the
known pre-rotation note, the other holds the changed `ACTIVE` note, both were
encrypted with the same keystream, and that happened because the cloned guest's
PRNG was never reseeded. That is the flag phrase. Verify:

```bash
./verify 'Null0rigin{the_clone_never_reseeded_the_rng}'
# CORRECT.  revenant solved.
```

## Flag

`Null0rigin{the_clone_never_reseeded_the_rng}`

## Key Takeaways

- Snapshotting/cloning a VM copies more than disk and memory — it copies PRNG
  state. Two clones resuming without reseeding emit the same "random" bytes.
- Reused keystream = two-time pad. `C_A XOR C_B = P_A XOR P_B`; a known
  plaintext turns both ciphertexts into fully recovered text.
- Don't chase high-entropy blobs as flags — the `secret` here is a red herring.
  The *evidence relationship* is the answer.
