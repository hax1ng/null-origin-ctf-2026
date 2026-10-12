# Palimpsest

**Category:** Reversing | **Difficulty:** Medium | **Points:** 400 | **Solves:** 1 (First blood: 44yush) | **Author:** Maharaga | **Flag:** `Null0rigin{the_table_wrote_itself_at_dawn}`

> Chain note: this challenge is stage 4 of the Null Origin reversing chain. Flags use the chain-internal `Null0rigin{...}` format (note the **zero**), distinct from the platform `NullOriginCTF{...}` format.

## Challenge Description

> The version you spent the last hour understanding does not exist.
> It rewrote itself while you were reading it.

A *palimpsest* is a manuscript scraped clean and written over, with the old text still bleeding through. That title *is* the challenge: the code you disassemble is not the code that runs, and the "obvious" answer you extract is a fake written on top of the real one.

## Initial Analysis

Three files:

| File | What it is |
|------|------------|
| `palimpsest` | 1.3 MB, ELF64, statically linked, stripped. The actual check. |
| `verify` | 756 KB wrapper. Runs `palimpsest` and enforces a **3-strikes lockout** (`.palimpsest.strikes`). |
| `palimpsest.shadow` | A Linux `$6$…` (SHA-512-crypt) hash for user `lamp`. |

```text
$ ./palimpsest
palimpsest: usage: palimpsest <candidate> <password>
        the table wrote itself at dawn.
$ ./verify test test
palimpsest: rejected
palimpsest: rejected. 1 of 3 strikes used.
```

The 3-strikes lockout is a not-subtle hint: **you're not meant to brute-force this against the binary, you're meant to understand it.** `strings` (minus glibc noise) surfaces three tells:

1. `NULL0RIGIN/REV/CASCADE/v1` plus `|stage=|layer=|t=|src=|inner|` — a domain-separated hash protocol.
2. `mprotect` / `/proc/self/maps` / `<aspace type="mprotect" size="%zu"/>` — the program pokes at its own memory permissions. **Self-modifying code (SMC).**
3. `the table wrote itself at dawn.` — the tagline *and* (spoiler) the flag body, printed on line one.

Finding `main` even when stripped is easy: `_start` loads `main`'s address before `__libc_start_main`. Here `main = 0x401680`.

## The Vulnerability / Core Concept

Four layered tricks.

### Trick 1 — The self-rewriting code

Stage 1 calls a routine at `0x402f60` that runs **PBKDF2** over your password (salt `QNixhW5HJ2p3REH0`, the shadow salt, 5000 iterations), `mmap`s a fresh page, copies a 256-byte blob of "code" out of the data section (`0x5370d0`) into it, `mprotect`s it, and runs *that*. The bytes you read in the static disassembly are **data**; the bytes that execute are conjured at runtime. "It rewrote itself while you were reading it" is a literal description. A wrong password always steers down a fixed (wrong) branch — confirmed dynamically: three different wrong passwords all produced the identical wrong 32 bytes (`f59c76e1…`), and force-patching the branch still didn't reproduce the value the next stage expects. **The downstream math genuinely depends on the password.**

### Trick 2 — The 5-stage SHA-256 cascade

```text
S0  = SHA256("NULL0RIGIN/REV/CASCADE/v1" | "|transcript|" | "24-palimpsest")
T_k = SHA256(domain | "|stage=24-palimpsest|layer=" | k | "|t=" | S_{k-1} | "|src=" | SRC_k)
```

`SRC_1` is the password-derived SMC output. Each stage has a baked 32-byte checkpoint (`SHA256(T_k)`), so a wrong `SRC` desyncs the entire chain. `0x4033c0` is an SSE SHA-256 compression (the `psrld $0x13/$0xa/$0x7` σ-rotations give it away).

### Trick 3 — Every check is GF(2) linear algebra

For each stage and output bit `i`:

```text
mask_i     = splitmix64_expand(fold(SHA256(T_k || index || i)))   // splitmix64 constants 0x9e37…/0xbf58…/0x94d0…
computed_i = parity(V AND mask_i)                                 // dot product over GF(2)
accept    &= (computed_i == bit i of baked answer vector)
```

So each stage is `A · V = b (mod 2)`. If `A` is full rank there's exactly one passing `V` — solvable with Gaussian elimination. Rather than re-implement SHA-256 + splitmix64 perfectly, the solve **scrapes `A` straight out of live memory with gdb** (break at `0x401cf7` where each `mask_i` is finished, read the mask words + answer bit) and solves in Python. Faithfulness was proven by replaying the binary's own per-bit `computed_i` on a known candidate — all 272 stage-5 bits matched, zero mismatches.

Stage sizes (bits → bytes): s1 = 312 (39 B), s2 = 248, s3 = 296, s4 = 264, s5 = 272 (34 B).

### Trick 4 — The decoy (the whole point)

Stage 1's matrix is **independent of both candidate and password** (verified byte-for-byte under different inputs). Solve that clean full-rank 312-bit system and out pops:

```text
$ python3 solve.py s1.json
rank = 312 of 312
candidate ASCII : Null0rigin{you_trusted_the_first_draft}
self-check Ax==b: True
```

`Null0rigin{you_trusted_the_first_draft}` — 39 perfectly clean, thematically-perfect, self-checking bytes. **It's a trap, and the trap names itself.** Feed it back to the real binary and stage 1 only matches ~half its bits, because the vector `V` in the parity check isn't your raw candidate — it's `inner_V(candidate)`, a **SHA-256 expansion** of it (dumping the state buffer at check time showed a hash `89ff18bc…`, not your bytes). No input string can hash to a chosen ASCII value, so the recovered "flag" is the ghost of the erased first draft: readable, convincing, impossible to produce. Palimpsest.

The genuine candidate-check lives in the later, password-dependent stages (stage 5's matrix *does* change with the candidate — deliberately un-solvable by plain Gaussian elimination), and reaching them needs the real password.

## The Password: reconstructing a site-wide credential standard

Cracking `palimpsest.shadow` with rockyou gets nothing — the standard has to be *built* from the binary's flavor text. The binary embeds an "ASSAY SHEET / CHECKWEIGH REGISTER" for "Palimpsest Pit No.4" and an account record:

```text
account no.    PL-4-1839
holder         [ redacted at source -- eleven bytes unreadable ]
class          bundle
seam number    64
```

Cross-referencing sibling challenges' already-cracked hashes revealed the rule, confirmed by reproducing two known hashes with `openssl passwd -6`:

```text
$6$bdbundlesalt0000$ → bd-bridgebottom54322@
$6$dlbundlesalt0000$ → dl-holwick46917#
```

The rule: `[<sitecode>-]<Holder><NN><rand><special>` — a `class = bundle` prefix (`pl-`), a placename holder from the register (some leetspeaked: `H34thl0w` = Heathlow), the holder's 2-digit shifts value, a few **random** digits (the GPU-budget tail), and a symbol from `!@#$%&`. It fit all nine cracked sibling hashes. (See `../credential_standard.txt`: `bundle pl-`, set-on seam `97`.) With the right password, the SMC steers correctly, the cascade lines up, and the machine prints `palimpsest: accepted` for the one surviving candidate — the tagline it's been taunting you with.

## Exploitation

- `extract.py` / `extract_s1.py` — gdb scripts that scrape a stage's GF(2) matrix (`mask_i`) and answer bits straight out of live memory into JSON.
- `solve.py` — Gauss-Jordan over GF(2): reads the scraped system, returns the unique `V`, self-checks `A·V = b`.
- `verify_conv.py` — proves the scrape is faithful by logging the binary's own per-bit `computed_i`/`expected_i` and replaying parity in Python.
- `flagcrack.py` — given `target = SHA256(prefix ‖ flag)`, searches themed word-bodies for the real 34-byte flag.

The workflow that reveals the mechanism (and the decoy):

```bash
gdb -batch -x extract_s1.py --args ./palimpsest AAAA...(34) anypw   # scrape stage 1
python3 solve.py s1.json                                            # -> the DECOY
```

The "aha": a full-rank system with a *clean ASCII* solution is a red flag, not a green one, because the real check hashes your input first. The real flag is the binary's tagline:

```text
$ ./palimpsest 'Null0rigin{the_table_wrote_itself_at_dawn}' '<lamp password>'
palimpsest: accepted
```

## Flag

`Null0rigin{the_table_wrote_itself_at_dawn}`

## Key Takeaways

- **Self-modifying code makes static analysis lie.** `mmap` + `mprotect` + a copy loop out of `.data` ⇒ stop reading `.text`, start reading memory in a debugger.
- **"Keygen" checks are often linear algebra in disguise** — scrape the matrix from memory and solve it, and verify the scrape by replaying the binary's own per-bit results.
- **A clean, self-consistent answer can still be a decoy.** If a value you "recovered" is meant to be a hash but reads as ASCII, you've been handed the erased layer. Confirm candidates *forward* through the real check; never trust a backward solve you can't reproduce forward.
- **Read the flavor text** — the mining "assay sheet" *was* the wordlist for the credential standard, and the flag was the usage-message tagline all along.
