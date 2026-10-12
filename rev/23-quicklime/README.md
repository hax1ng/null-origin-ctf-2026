# Quicklime

**Category:** Reversing | **Difficulty:** Medium | **Points:** 400 | **Solves:** 1 | **Author:** Maharaga | **Flag:** `Null0rigin{you_kept_the_last_eleven_bits}`

> Chain note: this challenge is stage 3 of the Null Origin reversing chain. Flags use the chain-internal `Null0rigin{...}` format (note the **zero**), distinct from the platform `NullOriginCTF{...}` format.

## Challenge Description

> It has been measuring you since you typed the first command. Not your machine. You.

## Initial Analysis

Another keygen-me. Four files:

| File | What it is |
|------|------------|
| `quicklime` | The challenge binary. Statically linked, stripped x86-64 ELF. Takes `<candidate> <password>`. |
| `verify` | A wrapper that also tracks "3 strikes and you're locked out". |
| `quicklime.shadow` | A Linux shadow entry for user `lamp` — a `$6$` (SHA-512-crypt) hash. |
| `reduction_tables.bin` | A **280 MB** blob the binary reads at runtime. Looks like text about a quicklime pit. |

Blind run:

```text
$ ./quicklime
quicklime: usage: quicklime <candidate> <password>
           the kiln does not care what you meant to burn.
$ ./quicklime test test
quicklime: rejected
```

`strings` on the binary surfaces the now-familiar protocol tokens — `|transcript|`, `|stage=`, `|layer=`, `|t=`, `|src=`, `|inner|`, `23-quicklime` — plus `$6$` / `$rounds=` (SHA-512-crypt) and a note that `reduction_tables.bin` must sit beside the binary. The big blob itself cosplays as chemistry "ASSAY SHEET" lab reports.

## The Vulnerability / Core Concept

`main` reduces to:

```c
table  = load("reduction_tables.bin");                 // mmap the 280 MB blob
result = check(5, argv[1], strlen(argv[1]), argv[2]);  // 5 stages
```

The whole game is in `check(5, candidate, len, password)` — a five-round loop built from three recognizable primitives (spotted by their magic constants): **SHA-256** (IV `6A09E667…`), **splitmix64** (`0x9E3779B97F4A7C15`, `0xBF58476D1CE4E5B9`, `0x94D049BB133111EB`), and a length-prefixed "absorb" helper (`label ‖ 8-byte-length ‖ data`).

Each of the five stages:

1. **Picks a "source" `SRC`.** The 280 MB file is exactly **2048 blocks of 143,360 bytes**; the stage computes an index `0..2047` and sets `SRC = SHA256(block[index])`. For stages 1, 2, 4, 5 the index comes from deterministic floating-point math (`sin`, denormals — the "measuring you" flavor). For **stage 3** the index is derived from the **password**. So the password only ever touches stage 3.
2. **Builds a checkpoint hash** `T = SHA256(domain ‖ "|stage=23-quicklime|layer=" ‖ digit ‖ "|t=" ‖ S ‖ "|src=" ‖ SRC)` and checks `SHA256(T) == D_k`, a baked constant. Wrong password/flag ⇒ checkpoint fails ⇒ the code silently swaps in decoy answer bits and the whole thing fails. This is the anti-cheat.
3. **Tests your candidate with a GF(2) parity system.** Build a vector `V` (for stages 1–4, `V = SHA-256 expansion of the candidate`; for **stage 5**, `V = the raw candidate bytes`). Each matrix row is a splitmix64 stream seeded from `T`, and the stage passes iff `parity(row AND V) == baked answer bit` for every row.
4. **Folds the candidate back into `S`** for the next round.

You can't just solve this forward: stages 1–4 hash the candidate (SHA-256 isn't invertible), and stage 5's matrix depends on `S`, which depends on a hash of the candidate — circular by design.

### The crack: stage 1 is the weak link

**Stage 1 runs before any candidate touches the state.** Its `T_1` is built only from the fixed start state and a fixed floating-point-indexed `SRC` — no password, no candidate. So `T_1` is a constant we can compute, which makes stage 1's entire 352×352 matrix computable. That matrix is **full rank and consistent**, so stage 1 pins down `V_1 = hash(flag)` to exactly one value:

```text
SHA256("NULL0RIGIN/REV/CASCADE/v1|inner|23-quicklime|1|" + b"\x00"*8 + "|" + flag)
    == d53582356cac0cedb5cba4389e8692ccd396957673367ba790b3526d9db474ce
```

That's a **perfect, password-free oracle**: hash a guessed flag with that fixed prefix and compare.

### The haystack trap

`reduction_tables.bin` hides **4,200 fake `Null0rigin{...}` flags** built from a 20-word kiln/lime vocabulary (`grep -aoE "Null0rigin\{[a-z0-9_]+\}"` ⇒ 4,200 unique). Running all 4,200 through the oracle gives **zero matches** — they're pure decoys. Brute-forcing the same grammar with hashcat (mode 1420, `sha256($salt.$pass)`) across k=3..6 word combinations also found nothing, because **the real flag isn't lime/kiln words at all** — it's a themed English sentence:

```text
Null0rigin{you_kept_the_last_eleven_bits}
```

Drop it in the oracle and the hash matches instantly. The decoy grammar was bait to lure you into brute-forcing the wrong keyspace.

## Exploitation

A single hash match is already cryptographic-strength proof, but the repo also rebuilds the *entire* check offline (`verify_full.py`) and runs the flag through all five stages. To do that without the password, each stage's reduction-table index is recovered by brute-forcing which of the 2048 blocks reproduces the baked `SHA256(T_k)` checkpoint — **including stage 3's index (886), which is normally set by the password.** The checkpoints let you sidestep the password entirely:

```text
$ python3 verify_full.py 'Null0rigin{you_kept_the_last_eleven_bits}'
stage 1: checkpoint OK (idx= 364)  parity PASS  (352 rows, V=hash(cand))
stage 2: checkpoint OK (idx= 993)  parity PASS  (320 rows, V=hash(cand))
stage 3: checkpoint OK (idx= 886)  parity PASS  (296 rows, V=hash(cand))
stage 4: checkpoint OK (idx=1194)  parity PASS  (264 rows, V=hash(cand))
stage 5: checkpoint OK (idx=   8)  parity PASS  (328 rows, V=raw candidate)

==> ACCEPTED — flag verified across all 5 stages
```

All five checkpoints match and all 1,560 parity equations hold; change one character (`_bits` → `_bytes`) and it collapses at stage 1.

### Files

- `qlib.py` — ELF vaddr reader, SHA-256 / splitmix64 helpers, reduction-table block reader, descriptor parsing.
- `solve.py` — the full model: reconstructs the state chain by brute-forcing the 5 table indices against the baked checkpoints, then solves stage 5's GF(2) system (where the dotted vector is the raw candidate).
- `solve_sequential.py` — compact per-stage cascade walk (checkpoint match → solve layer → advance state).
- `verify_full.py` — faithful 5-stage re-implementation; the definitive verifier.

> The `lamp` password follows the chain-wide credential standard (`bundle lk-`, set-on seam `31`; see `../credential_standard.txt`). It only gates the binary's "accepted" message — the flag falls out of stage 1's math, and even stage 3's secret index is recoverable from its public checkpoint.

## Flag

`Null0rigin{you_kept_the_last_eleven_bits}`

## Key Takeaways

- **Keygen-mes can have a load-bearing first step.** The earliest stage often can't depend on later state or on secrets, so it's the crowbar. Here stage 1 was password-free and full-rank — a one-shot oracle for the whole flag.
- **Recognize primitives by their constants.** SHA-256's IV, splitmix64's multipliers, `$6$` crypt — spotting these turns scary vectorized assembly into "SHA-256 feeding a PRNG feeding a parity check."
- **GF(2) parity is linear algebra.** `parity(row AND V)` is a dot product mod 2; a full-rank system has a unique solution.
- **Beware the haystack.** 4,200 plausible fake flags with a tidy grammar is bait — don't burn billions of GPU guesses on a keyspace the author *wants* you to search.
