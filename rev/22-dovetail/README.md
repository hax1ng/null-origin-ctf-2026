# Dovetail

**Category:** Reversing | **Points:** 250 | **Flag:** `Null0rigin{the_loader_never_read_the_label}`

> Chain note: this challenge is stage 2 of the Null Origin reversing chain. Flags use the chain-internal `Null0rigin{...}` format (note the **zero**), distinct from the platform `NullOriginCTF{...}` format.

## Challenge Description

> You thought you were holding a program.
> You are holding one joint of something longer.

## Initial Analysis

`dovetail` is another **keygen-me**: it doesn't compare your input to a stored flag, it checks whether a value *derived* from your candidate satisfies a large system of equations. The folder holds:

```console
$ file dovetail dovetail.png dovetail.shadow verify
dovetail:        ELF 64-bit LSB executable, statically linked, stripped
dovetail.png:    PNG image data, 64 x 64, 8-bit grayscale
dovetail.shadow: ASCII text
verify:          ELF 64-bit LSB executable, statically linked, stripped
```

Two details jump out immediately:

1. The "64×64" PNG is exactly **240 MiB** — far too big to be a thumbnail.
2. `dovetail.shadow` is a Linux `$6$` (SHA-512-crypt) hash for user `lamp`.

The program's interface:

```console
$ ./dovetail
dovetail: usage: dovetail <candidate> <password>
```

Useful strings confirm the family it belongs to:

```text
NULL0RIGIN/REV/CASCADE/v1
22-dovetail
|transcript|   |stage=   |inner|
dovetail.png
dovetail: accepted
dovetail: rejected
```

So there's a password and a giant image on the "intended" route. The good news: we do not need to finish that route to recover the flag.

## The Vulnerability / Core Concept

The stripped binary is a **five-stage cascade**. The stage dispatcher is around `0x4021e0` and the common stage validator around `0x4027a0`. Five fixed-size descriptors start at file offset `0x900e8`, `0xd0` bytes apart. Immediately before each descriptor are two little-endian integers (bit count and a seed); the first 32 bytes of the descriptor are a transcript checkpoint, and the rest are the equations' right-hand sides.

| Stage | Bits | Bytes | Seed | Transcript checkpoint |
|---:|---:|---:|---:|---|
| 1 | 344 | 43 | 6 | `b1878dd1c33376297c4fd605387222f8…` |
| 2 | 320 | 40 | 5 | `c0afe5826095955ef7974f3c019ea6a0…` |
| 3 | 288 | 36 | 5 | `9828370aac6e42436bee920639035228…` |
| 4 | 256 | 32 | 3 | `5d5fccf2ac590c8cfe2144a837f53d85…` |
| 5 | 344 | 43 | 1 | `00299a111f83ad307aaed432552aa125…` |

**Each check is linear algebra over GF(2).** Think of the unknown stage value as a row of light switches; every equation says "XOR of switches {2, 8, 11, 19, …} must be on." XOR arithmetic is arithmetic over GF(2) (only 0 and 1, with `1 + 1 = 0`). There are as many independent equations as unknown bits, so XOR-flavored Gaussian elimination recovers the one value that satisfies all of them.

**The weak link is stage 1.** Its transcript `T1` is built only from a fixed starting state and a fixed, password-independent source value (recovered while tracing the hash-building code):

```text
S0 = SHA256("NULL0RIGIN/REV/CASCADE/v1" + "|transcript|" + "22-dovetail")
T1 = SHA256("…|stage=22-dovetail|layer=1|t=" + S0 + "|src=" + LE64(32) + SRC1)
```

As a sanity check, `SHA256(T1)` equals the stage-1 descriptor's stored checkpoint `b1878dd1…` — so if the reconstructed transcript is even one byte off, the digest is completely different and you know instantly.

Each equation row is a splitmix64 stream seeded from `SHA256(T1 ‖ LE64(seed) ‖ LE64(i))`, and the descriptor supplies the matching answer bit. Solving all 344 rows gives the **43-byte stage-1 vector**:

```text
3d84e2a3fdf3eee63fefd2e412c533b7fa300f2e96104815538b6fc52501e7c8d49bde73be63e631679065
```

### Why that vector leaks the flag

Stage 1 does not test the candidate directly — it tests a SHA-256 **expansion** of it:

```python
block_j = SHA256(b"NULL0RIGIN/REV/CASCADE/v1|inner|22-dovetail|1|" + LE64(j) + b"|" + candidate)
```

The 43-byte stage-1 length is exactly block 0 (32 bytes) plus the first 11 bytes of block 1. So the solved vector *is* `expand(flag)[:43]`, which turns stage 1 into a **free, instant flag oracle** — no password, no giant PNG, no later stages. Test sentence-shaped, challenge-themed candidates against it:

```python
candidate = b"Null0rigin{the_loader_never_read_the_label}"
assert expand(candidate) == target   # both SHA-256 blocks match
```

Both expansion blocks match, so this is cryptographic confirmation, not a lucky guess.

## Exploitation

`solve.py` walks the cascade using the binary's own descriptors and the recovered per-stage sources. In practice the stage-1 vector alone is the whole solve: it reproduces exactly (`stage 1 checkpoint True`, and the recovered `V` is `expand(flag)[:43]`). The cascade only stalls at stage 3, whose source is password-derived — which is precisely why the full "accepted" route needs the `lamp` password while the flag itself does not.

The core (see `solve.py`):

```python
S = h(D, b'|transcript|', TAG)
for k, src in enumerate(srcs, 1):
    t = T(k, S, src); n, seed, cp, rhs = desc(k)
    if h(t) != cp: break            # stage-1..2 pass; stage 3 needs the password
    V = solve(k, t)                 # GF(2) Gaussian elimination
    ...
```

To confirm the flag straight from stage 1's oracle:

```python
target = bytes.fromhex("3d84e2a3fdf3eee63fefd2e412c533b7fa300f2e96104815538b6fc52501e7c8d49bde73be63e631679065")
prefix = b"NULL0RIGIN/REV/CASCADE/v1|inner|22-dovetail|1|"
def expand(c):
    out=b""; j=0
    while len(out)<len(target):
        out+=hashlib.sha256(prefix+struct.pack("<Q",j)+b"|"+c).digest(); j+=1
    return out[:len(target)]
assert expand(b"Null0rigin{the_loader_never_read_the_label}") == target
```

### The PNG and password (the longer route)

They are real, just avoidable. The 240 MiB "PNG" is 240 one-megabyte regions whose high bits form a small base-4 side channel, and its cover documents point at a site-wide **contractor** password standard (set-on seam `49`, see `../credential_standard.txt`). The full route would reconstruct the credential rule, build a wordlist, crack the `$6$` hash on a GPU, feed the password-derived source into stages 3–5, and solve another GF(2) system each time. There's also an anti-debug check reading `/proc/self/status`, and a later stage hashes `/proc/self/exe`, so you patch in GDB memory (e.g. NOP the instruction at `0x401af7`) rather than on disk. None of that improves confidence in a flag the stage-1 oracle already proved.

## Flag

`Null0rigin{the_loader_never_read_the_label}`

## Key Takeaways

- **A keygen doesn't need to store the flag to leak a test for it.** Here stage 1 leaks `SHA256`-expansion bytes of the flag, which is a perfect verifier.
- **The earliest stage is usually the crowbar** — it can't yet depend on later state or on the password, so its matrix is computable and full-rank.
- **Huge scary files can belong to the intended route without being on the shortest one.** A 240 MiB "PNG" is bait when a 344-bit linear system already hands you the answer.
- **Always validate intermediate values against baked checkpoints** (`SHA256(T1)`); a one-byte mistake shows up instantly.
