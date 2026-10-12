# Bindery

**Category:** Crypto | **Difficulty:** Easy | **Points:** 250 | **Flag:** `Null0rigin{you_counted_in_a_base_she_never_named}`

## Challenge Description

> Somebody bound this collection by hand, and was careful about it.
> The slips were written before the work was finished.

Bindery is stage `06-bindery` of the Null Origin crypto chain. The stage ships:

```text
bindery.o        unlinked x86-64 ELF object (the cipher implementation)
bindery.sealed   small sealed blob
index.sealed     ~38 MB of apparently-random bytes (the real target)
description.txt
slips.txt        four flag-shaped decoys
verify           flag checker (locks after 3 genuine wrong answers)
```

`slips.txt` contains four very convincing `Null0rigin{...}` strings. They are
bait — and since `verify` locks after three genuine wrong answers, blindly
testing them is exactly the trap. The real flag lives, encrypted, inside
`index.sealed`.

## Initial Analysis

The 38 MB `index.sealed` is high-entropy — `strings`, `grep`, and entropy
checks all get nothing. The thing that actually tells you how it was built is
`bindery.o`, an **unlinked, not-stripped** ELF object:

```bash
$ file bindery.o
bindery.o: ELF 64-bit LSB relocatable, x86-64, not stripped
```

Because it isn't stripped, the symbols hand you the design. Four tiny helpers
just return constants, and those constants are the whole spec:

| Function                  | Value | Meaning                       |
| ------------------------- | ----: | ----------------------------- |
| `bindery_header_cells()`  |    28 | known header length (trits)   |
| `bindery_span()`          |   512 | trits stored per record       |
| `bindery_wide()`          |   110 | bytes occupied per record     |
| `bindery_width()`         |   121 | cipher/LFSR state width       |

A **trit** is a base-3 digit (`0`, `1`, `2`). The verifier's wrong-answer
jab — *"Three symbols. You only ever looked for two"* — is pointing straight at
ternary. The record width checks out against the file size:

```text
37,999,940 / 110 = 345,454 records
```

## The Vulnerability / Core Concept

Three things combine into a clean algebraic break:

**1. The records carry "slack."** `bindery_entry` packs 512 trits into one big
integer (`n = 3*n + trit`) and writes it big-endian into 110 bytes. But 512
trits only need `512 * log2(3) ≈ 811.5` bits, while 110 bytes give 880 bits.
The extra 68 bits are filler that make the dump look random. The useful value
is just the residue modulo `3**512`, so unpacking is straightforward:

```python
x = int.from_bytes(record, "big") % (3**512)
trits = [0] * 512
for i in range(511, -1, -1):
    x, trits[i] = divmod(x, 3)
```

**2. There's a known plaintext header.** The first 28 trits of every record are
overwritten with constants held in `.rodata` (two bit-masks, `0x0102ec11` and
`0x045d10ac`, supply the high/low bit of each trit). They decode to the same
28-trit header on every record:

```text
2011210100221222121110102010
```

**3. The keystream is a linear LFSR over GF(3) that never resets.** The cipher
is simply `ciphertext_trit = plaintext_trit + state_trit (mod 3)`, and the
121-trit state advances by one linear recurrence step per emitted trit:

```text
s[n+121] = c0*s[n] + c1*s[n+1] + ... + c120*s[n+120]   (mod 3)
```

Crucially the state is **not reset between records** — record `r` position `k`
uses stream trit `s[512*r + k]`. So at every known-header position we can read
the keystream straight off:

```text
s[512*r + k] = ciphertext[r][k] - header[k]   (mod 3)
```

Each record yields 28 such equations; five records give 140 equations in the
121 unknown initial-state trits. Solving that linear system over GF(3)
(Gaussian elimination mod 3) recovers the full state at rank 121. After that,
generate the keystream forward and the index decrypts to plain English.

## Exploitation

The full attack is in [`solve.py`](./solve.py). The recovered recurrence taps
(`TAPS`) and the header constant come from `bindery.o`. The flow is:

1. Unpack records mod `3**512` to recover trits.
2. Express each future keystream trit as a GF(3) vector over the 121 unknowns.
3. Build equations from the known header of 5 records; solve mod 3 → initial state.
4. Roll the LFSR forward, subtract the keystream, regroup trits into bytes.

```bash
$ python3 solve.py   # needs index.sealed in the working directory
Recovered state: 2012101001100122122010021102101111000211122221120202000012...
THE LANTERN ARCHIVE -- index, paper I of VIII
...
The notice on paper I is three words: Wrong field. -- O.
Null0rigin{you_counted_in_a_base_she_never_named}
stage 02 -- it died mid-sentence, and the tape kept running
```

The recovered 121-trit initial state is:

```text
2012101001100122122010021102101111000211122221120202000012201110010212102211210210002002222120121100222110010120010220110
```

> Note: `index.sealed` (~38 MB) is the challenge's intrinsic data file and is
> too large to include here. The solver reads it from the working directory.

## Flag

`Null0rigin{you_counted_in_a_base_she_never_named}`

SHA-256 `67caedc458ff184f87dfe898ee4e00cc8ee92c652d3025df376dbc5756cdd7a1`, which
matches the digest embedded in `verify` — submitting it returns
`CORRECT. bindery solved.`

## Key Takeaways

- **An unstripped object file is a gift.** The symbol names and constant-return
  helpers (`bindery_span`, `bindery_width`, ...) handed over the entire format.
- **"Random-looking" ≠ random.** The slack bits were padding; the real data was
  the residue mod `3**512`. When entropy tools fail, question your encoding —
  here the data had to be counted in base 3.
- **Linear + known-plaintext + no re-key = algebra.** A non-resetting LFSR over
  GF(3) plus a repeated known header turns key recovery into a small linear
  solve, no brute force needed.
- **Mind the decoys.** `slips.txt` plus a lock-after-3 verifier is a deliberate
  trap; recover the flag from the ciphertext, don't guess.
