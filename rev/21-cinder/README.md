# Cinder

**Category:** Reversing | **Difficulty:** Easy | **Points:** 250 | **Flag:** `Null0rigin{you_stepped_where_it_would_not_read}`

> Chain note: this challenge is stage 1 of the Null Origin reversing chain. Flags here use the chain-internal `Null0rigin{...}` format (note the **zero** in `Null0rigin`), which is distinct from the platform-level `NullOriginCTF{...}` format.

## Challenge Description

> The drive was still warm when they pulled it.
> They wrote "recovered artifact, inert", signed it, and went home.

## Initial Analysis

Cinder is the opening act of a seven-stage reversing chain, and it sets the house rules for everything that follows. The chain `README` spells them out: every challenge is a **keygen-me**, not a "print the flag and compare" program. There is no flag sitting in memory to breakpoint — the binary checks a *mathematical property* of whatever candidate you type, and you win by reconstructing that check well enough to produce a value that satisfies it.

The folder ships three things:

| File | What it is |
|------|------------|
| `cinder` | The challenge binary — a ~230 MiB statically-linked, stripped x86-64 ELF. |
| `cinder.shadow` | A Linux shadow entry for user `lamp` — a `$6$` (SHA-512-crypt) password hash. |
| `verify` | A wrapper around the same check. |

Running it blind shows the interface:

```text
./cinder <candidate> <password>
```

Wrong argument count prints usage and exits `2`; a well-formed but invalid attempt prints `cinder: rejected` (exit `1`); the accepted path prints `cinder: accepted` (exit `0`).

Why is a keygen 230 MiB? Because almost all of it is a section called `.cinderdump` — exactly **230 MiB**, which divides perfectly into **230 blocks of 1 MiB**. Crack it open and it is a wall of mining-company paperwork: assay sheets, incident forms, checkweigh registers, shift returns — plus a tempting **4,200 plaintext decoy flags** numbered `0000`–`4199`, and seven "LAMP ACCOUNT" records pointing at account `CD-3-2207`, holder `hatherhague`.

That dump is the trap, and it is where a lot of time can disappear.

## The Vulnerability / Core Concept

### The rabbit hole the flag is laughing at

The embedded dump looks *designed* to be decoded. Treating the pseudorandom regions byte-by-byte, there is a genuinely real-looking covert channel: split each 1 MiB block's bytes into four lanes by position `mod 4`, look at bit 7 (the sign bit), and in every block exactly one lane has its sign bit forced high while the other three stay unbiased. That cleanly encodes **one base-4 symbol per block** — 230 symbols total — and even matches the description's "signed it." The analysis notebook chased this hard: every global lane→digit permutation, byte orderings, six-stream regroupings, LFSR/Berlekamp-Massey whitening, PRNG whitening off the embedded seed `0x5e41c0de1dead00d`, AES trials, zlib/gzip probes. None of it produced a flag. The 4,200 visible decoys were all tested through a password-free stage-1 oracle — **zero** accepted.

The flag body settles the argument: **`you_stepped_where_it_would_not_read`**. The 230 MiB you kept trying to *read* was exactly where you were not supposed to step. Cinder is a keygen just like its six siblings; the dump is atmosphere.

### What the check actually is

Underneath, `cinder` is a **five-stage SHA-256 + splitmix64 cascade over GF(2)** — the same engine used by Dovetail, Quicklime, Palimpsest, Deadman and Hourglass. The pieces, recovered statically:

- Entry `0x401740`, main wrapper `~0x401660`, validator `~0x402410`.
- A stage count of `5` baked at VA `0x490190`, and a parameter table of `0xd0`-byte descriptors starting near `0x4901a8`.
- Domain-separation labels `NULL0RIGIN/REV/CASCADE/v1`, `21-cinder`, `C1NDER/PARAMS/v1`.
- Stage 1 produces its 32-byte "source" by a PRNG-style sampling of `.cinderdump` (seed `0x5e41c0de1dead00d`, 50,000 FNV-mixed samples). Captured once at a debugger breakpoint (`0x402543`), that source is `ff68d7321f7f2dc4…`.

Each stage runs the same recipe. Build a transcript hash `T` from the domain string, the stage number, the running state `S`, and that stage's 32-byte source. Then, for each output bit `i`, derive a pseudo-random row with `SHA256(T ‖ seed ‖ i)` folded into a splitmix64 stream, and require `parity(row AND V) == answer_bit_i`. That is just a linear equation over GF(2) (the two-element field where `1 + 1 = 0`), so `n` of them is a system `M · V = b` with a **unique** full-rank solution. Stages 1–4 fold their solved vector back into `S` for the next stage; **stage 5's vector is the raw flag bytes.**

The one guardrail: each descriptor stores a baked `SHA256(T)` checkpoint. Reconstruct a stage's source wrong and `T` is wrong, the checkpoint fails, and everything downstream is garbage — which is why the password genuinely matters to the binary (stages 3–4 derive their source from the `lamp` credential), even though we never need the plaintext password to *recover* the flag.

## Exploitation

`solve.py` reconstructs the cascade end to end:

1. Seed the transcript: `S = SHA256(domain ‖ "|transcript|" ‖ "21-cinder")`.
2. For each of the five stages, feed in that stage's recovered 32-byte source (stage 1 is the debugger-captured dump sample; stages 3–4 are password-derived). The script verifies each source against the binary's baked `SHA256(T)` checkpoint (`ok = h(t) == cp`) before trusting it.
3. Read the stage descriptor (`n` bits, seed, right-hand-side bits), rebuild the splitmix64 matrix, and solve `M · V = b` with Gauss-Jordan elimination over GF(2).
4. Chain `S` forward for stages 1–4; at stage 5, print `V` — the flag.

The core solver loop (see `solve.py` for the full script):

```python
S = h(D, b'|transcript|', TAG)
for k, src in enumerate(srcs, 1):
    t = T(k, S, src); n, seed, cp, rhs = desc(k); ok = h(t) == cp
    if not ok: break                 # checkpoint confirms the reconstructed source
    V = solve(k, t)                  # GF(2) Gaussian elimination -> unique vector
    if k == 5: print('FLAG', repr(V.rstrip(b'\0')))
    else: S = h(S, b'|k=', str(k).encode(), b'|x=', le(len(V)), V, b'|src=', le(32), src)
```

Stage 5's 32-byte vector decodes straight to ASCII:

```text
Null0rigin{you_stepped_where_it_would_not_read}
```

The password (`lamp`'s SHA-512-crypt hash) follows the chain-wide credential standard — `staff` class, set-on seam `81` (see `../credential_standard.txt`) — and is only needed if you want the unmodified binary to print `accepted`. It is not needed to recover the flag.

## Flag

`Null0rigin{you_stepped_where_it_would_not_read}`

## Key Takeaways

- **A giant embedded blob full of decoys is a time sink by design.** 230 MiB of mining paperwork, 4,200 fake flags and a statistically "real" signed-lane base-4 channel were all misdirection. When a keygen's siblings are all GF(2) cascades, assume this one is too.
- **Keygen checks are linear algebra in disguise.** `parity(V AND row)` over many bits is `M · V = b (mod 2)`; a full-rank system has one solution you can *solve for* instead of guessing.
- **Baked `SHA256(T)` checkpoints are a gift.** They let you confirm each reconstructed stage source (even password-derived ones) without ever cracking the password.
- **Read the flag body as a hint.** "you stepped where it would not read" is a direct wink that the unreadable dump was the dead end.
