# Deadman

**Category:** Reversing | **Difficulty:** Hard | **Points:** 650 | **Flag:** `Null0rigin{you_held_it_exactly_right}`

> Chain note: this challenge is stage 6 of the Null Origin reversing chain. Flags use the chain-internal `Null0rigin{...}` format (note the **zero**), distinct from the platform `NullOriginCTF{...}` format.

## Challenge Description

> A deadman switch only works while somebody is holding it.
> It is honest about that, which is more than most things here manage.

## Initial Analysis

Three files — `deadman`, `deadman.shadow`, `verify` — both ELFs statically linked and stripped. Three things are designed to grab attention:

1. `deadman.shadow` holds a SHA-512-crypt password hash (user `vault`).
2. `deadman` carries a ~6 MiB section named `.deadmanvault`.
3. The binary is full of signal, timing, trap-flag and `TracerPid` (anti-debug) checks.

The vault is a huge fake mining record store with **900 convincing decoy flags** (`Null0rigin{custody_relay_coil_0000}`, …). Excellent bait; none of them is the answer.

### Reverse `verify` first

`verify` is far smaller than `deadman`, so start there. It checks the candidate with a single hash:

```python
SHA256(b"NULL0RIGIN/REV/VERIFY/v1|26-deadman|" + candidate)
    == c9f23b98332d231f0bd4693da76a2ece082a0c28e19e2415a1e5184471f7c64e
```

That gives two wins: you can test recovered candidates without reproducing all of `deadman`, and you can reject every visible vault flag with a tiny script. (`verify` also checks the password against the shadow file and locks after 3 failures via `.deadman.strikes` — so use the hash formula above, not the binary, for guesses.)

## The Vulnerability / Core Concept

The main validator (`0x402430`) runs five linked stages. Each stage: measure some debugger/signal/timing behavior → turn that measurement into a 32-byte **source** → derive a stage key from the source and the transcript → generate a binary matrix → check a bit vector against it → hash the result into the transcript. Picture five combination locks in a row, each one's output feeding the next.

```python
transcript = SHA256(b"NULL0RIGIN/REV/CASCADE/v1|transcript|26-deadman")   # 916003bb…

field(label, data) = label + LE64(len(data)) + data
K = SHA256(b"NULL0RIGIN/REV/CASCADE/v1|stage=26-deadman|layer=" + str(s) + b"|t=" + transcript + field(b"|src=", source))
# transcript update (easy to misread the labels — they are |k= then |x=):
transcript = SHA256(transcript + b"|k=" + str(stage) + field(b"|x=", vector) + field(b"|src=", source))
```

Each record stores the expected `SHA256(K)`; a wrong environmental source produces a wrong key and a completely different (decoy) matrix, which is why just patching a success branch doesn't work — the math downstream really does depend on holding the switch right.

**The insight: every "ritual" collapses to a small, reproducible value. Reconstruct it statically instead of performing it.**

- **Stage 1** samples `/proc/self/status` twelve times and counts `TracerPid` changes; the intended count is 3: `src1 = SHA256(LE64(3) ‖ LE32(80000) ‖ LE32(12))`.
- **Stage 2** has only two possible sources (fault path false/true + threshold `300000`); the stored `SHA256(K)` tag identifies `true`: `src2 = SHA256(b"\x01" ‖ LE64(300000))`.
- **Stage 3** looks like it forces a password crack: it runs SHA-512-crypt on the password, hashes it, and records 24 CPU-trap-flag checks. But the **correct crypt output is already in `deadman.shadow` and embedded in the binary**, so the good branch is reconstructable without the plaintext. With all 24 trap-flag observations set (mask `0xffffff`): `base = SHA256(SHA256(b"deadman/gate/key|" + crypt_string) ‖ 0^8) XOR embedded_const`, then `src3 = SHA256(LE64(0xffffff) ‖ base)`. The sanity check `SHA256(base)` matches a second embedded constant.
- **Stage 4** is another binary timing choice; the accepted one is `true` + threshold `70000`: `src4 = SHA256(b"\x01" ‖ LE64(70000))`.
- **Stage 5** carries a 16-bit pattern of debugger observations + interval + count. Only 65,536 masks, so brute them all against the embedded stage-5 tag — the winner is `0xf0f0` (an alternating hold/release block pattern — "holding it exactly right"): `src5 = SHA256(LE64(0xf0f0) ‖ LE32(60000) ‖ LE32(16))`.

Each real stage record is `u32 bits ‖ u32 nonce ‖ 32-byte SHA256(K) ‖ packed RHS bits`, with sizes 320 / 256 / 344 / 288 / 296 bits. Every row is a splitmix64 stream seeded from `SHA256(K ‖ LE64(nonce) ‖ LE64(row))`, and the check is parity — i.e. a full-rank GF(2) system with a unique solution. Stages 1–4 yield internal hash-expansion vectors (fed into the transcript); **stage 5's 296-bit vector is the flag itself.**

## Exploitation

`solve.py` reads the five real records out of `deadman` directly, reconstructs each environmental source as above (asserting each against the baked `SHA256(K)` checkpoint), solves each GF(2) system with Gauss-Jordan elimination, chains the transcript, and prints the stage-5 flag:

```text
$ python3 solve.py
stage 5 mask = 0xf0f0
Null0rigin{you_held_it_exactly_right}
verify digest = c9f23b98332d231f0bd4693da76a2ece082a0c28e19e2415a1e5184471f7c64e
```

The `verify` digest matches `verify`'s baked constant, so the flag is confirmed end to end. (The `vault` password — chain standard `contractor`, set-on seam `34`, see `../credential_standard.txt` — is only needed for the binary to print "accepted".)

## Flag

`Null0rigin{you_held_it_exactly_right}`

## Key Takeaways

- **The point of anti-debug theatre is to be reconstructed, not performed.** Every signal/timing/`TracerPid`/trap-flag check here compresses into a few deterministic bytes.
- **A stored crypt string means you don't need the password.** Stage 3's "correct" SHA-512-crypt output is already in the shadow file and the binary, so the password-gated branch is reproducible offline.
- **Small search spaces fall to the checkpoints.** Stage 5's 16-bit environmental mask is just 65,536 tries against a baked `SHA256(K)`.
- **Reverse the small wrapper first.** `verify`'s one-line SHA-256 gave a free candidate oracle and killed all 900 vault decoys instantly.
