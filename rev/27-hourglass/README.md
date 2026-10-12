# Hourglass (meta)

**Category:** Reversing | **Difficulty:** Insane | **Points:** 1000 | **Author:** Maharaga | **Flag:** `Null0rigin{you_were_the_input_all_along}`

> Chain note: this is the META / stage 7 challenge of the Null Origin reversing chain. It is not opened by any single flag — it needs all six flags from stages 21–26 together, in order, alongside its own candidate and password. Flags use the chain-internal `Null0rigin{...}` format (note the **zero**), distinct from the platform `NullOriginCTF{...}` format.

## Challenge Description

> There was no intruder. The hour was never a threat.

## Initial Analysis

Hourglass is the finale of the seven-part chain. It doesn't compare your input to a stored flag — it combines the exact flags from stages 21–26, boots a tiny guest program, and feeds several guest-produced values into five GF(2) linear systems.

Files:

```text
hourglass          Main validator
hourglass.kernel   Small guest/kernel component
machine-image.bin  Guest machine image and record data
hourglass.shadow   Password hash (user hourglass)
verify             Strike-counting wrapper
```

The program's interface is the first big clue — it's a **meta challenge**:

```text
hourglass <candidate> <password> <flag21,flag22,flag23,flag24,flag25,flag26>
```

The six prerequisite flags (chain order):

```text
21 Cinder:      Null0rigin{you_stepped_where_it_would_not_read}
22 Dovetail:    Null0rigin{the_loader_never_read_the_label}
23 Quicklime:   Null0rigin{you_kept_the_last_eleven_bits}
24 Palimpsest:  Null0rigin{the_table_wrote_itself_at_dawn}
25 Ouroboros:   Null0rigin{you_found_where_it_eats_its_own_tail}
26 Deadman:     Null0rigin{you_held_it_exactly_right}
```

## The Vulnerability / Core Concept

The validator uses the chain domain `D = b"NULL0RIGIN/REV/CASCADE/v1"`. It joins the six earlier flags with pipes and hashes them — note the **hexdigest**, so the metadata is 64 printable hex chars (82 bytes total):

```python
joined = "|".join(flags_21_to_26).encode()
meta = b"27-hourglass|meta|" + sha256(joined).hexdigest().encode()
S0   = SHA256(D + b"|transcript|" + meta)
```

Every stage then builds `T` from the domain, the metadata, the stage number, the previous transcript state, and a 32-byte stage source:

```python
T = SHA256(D + b"|stage=" + meta + b"|layer=" + str(stage) + b"|t=" + S + b"|src=" + le64(len(source)) + source)
```

The binary stores `SHA256(T)` for every layer — a cheap checkpoint: a wrong guest path produces the wrong checkpoint, so you never even solve its matrix.

**Stage descriptors** live at file offset `0xb3ba8`, stride `0xd0`. Each is `… -8: u32 bits, -4: u32 seed, +0: 32-byte SHA256(T) checkpoint, +32: packed RHS bits`. The `(bits, seed)` pairs:

```text
stage 1: (224, 2)    stage 2: (256, 1)    stage 3: (192, 0)
stage 4: (208, 0)    stage 5: (320, 1)
```

Stage 5 is 320 bits = 40 bytes — the final flag length.

**The guest values.** The kernel accepts four override choices, each with three values → `3^4 = 81` execution paths. Each path (captured in `hg_outputs.json`) yields `prefix`, `final`, `nest`, `completion`, and a noisy `tsc`. Those become the five sources:

```python
SRC1 = SHA256(b"hourglass/L1|" + le32(prefix))
SRC2 = SHA256(b"hourglass/L2|" + le32(final))
SRC3 = SHA256(b"hourglass/L3|" + bytes([nest]))
SRC4 = SHA256(b"hourglass/L4|" + bytes([timing_bit]))   # only one derived timing bit matters
SRC5 = SHA256(b"hourglass/L5|" + bytes([completion]))
```

The validator only cares about a single derived **timing bit**, so each of the 81 rows needs just two tries (bit `0` and `1`) — 162 source paths, and the first checkpoint discards nearly all of them.

**The linear algebra.** Each stage asks for a bit vector `V` satisfying a system of XOR equations. For row `i`, `q = SHA256(T ‖ le64(seed) ‖ le64(i))`, its four 64-bit words XORed into a splitmix64 state, and the generated bits form one matrix row with the descriptor's RHS bit. Over GF(2) this is `M · V = rhs`, solved by Gaussian elimination (row addition is just XOR — no floats, no rounding). For stages 1–4 the transcript advances:

```python
S_next = SHA256(S + b"|k=" + str(stage) + b"|x=" + le64(len(V)) + V + b"|src=" + le64(len(source)) + source)
```

The cascade's key property: **you never need to guess what the intermediate vectors mean** — solving the current system gives the exact vector to compute the next state. At stage 5, `V` is no longer opaque — it is the candidate flag itself.

## Exploitation

`solve_hourglass.py` enumerates all 81 guest paths × 2 timing bits, rejects paths by the embedded checkpoints, solves each surviving stage's GF(2) system, and chains the transcript. Only one route survives:

```text
overrides = [3, 3, 2, 3],  timing_bit = 1
```

(`solve_stage_all.py` is a standalone single-layer GF(2) solver used during analysis; `hg_outputs.json` holds the 81 captured guest-output rows the main solver reads.)

Run it with the six flags in chain order:

```bash
python3 solve_hourglass.py \
'Null0rigin{you_stepped_where_it_would_not_read},Null0rigin{the_loader_never_read_the_label},Null0rigin{you_kept_the_last_eleven_bits},Null0rigin{the_table_wrote_itself_at_dawn},Null0rigin{you_found_where_it_eats_its_own_tail},Null0rigin{you_held_it_exactly_right}'
```

```text
overrides: [3, 3, 2, 3] timing_bit: 1
raw: 4e756c6c30726967696e7b796f755f776572655f7468655f696e7075745f616c6c5f616c6f6e677d
candidate: b'Null0rigin{you_were_the_input_all_along}'
flag: Null0rigin{you_were_the_input_all_along}
```

Stage 5's 40-byte vector is plain ASCII — the flag. (Recovering the six chain flags needed a trick for Cinder and Dovetail: their password-derived source routines emit a full SHA-512-crypt string that's already in the shadow files, so you break right after the crypt routine in GDB and overwrite its output buffer with the shadow hash — same downstream state, no password crack.)

## Flag

`Null0rigin{you_were_the_input_all_along}`

## Key Takeaways

- **A meta challenge binds the whole chain** — its transcript is seeded from the six prior flags, so even a correct Hourglass candidate fails if any earlier flag is misspelled.
- **Baked `SHA256(T)` checkpoints turn a search into a filter.** 162 candidate source paths collapse to one almost immediately — no need to solve the matrices for the wrong paths.
- **Don't decode the intermediate vectors — solve for them.** Each stage's GF(2) solution is exactly what you need to advance the transcript; only the last stage has to be meaningful (and it's the flag).
- **"You were the input all along"** — not an intruder, not the clock: the six answers you supplied, the guest route they selected, and the transcript state they created.
