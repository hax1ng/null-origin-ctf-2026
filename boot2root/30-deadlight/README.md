# 30-deadlight

**Category:** Boot2Root (Reversing + Crypto) | **Difficulty:** Hard (final box of the 4-box chain) | **Flags:** user `Null0rigin{the_lamp_told_you_by_going_out}` / root `Null0rigin{a_deadlight_is_a_reading_not_a_failure}`

## Challenge Description

> The keeper still signs for everything.

Deadlight is the last machine in the chain. Its root flag isn't a file you can read — it's a **sealed (encrypted) blob** whose decryption key is built partly from *the previous machine's root flag*. The flavor line nudges toward the `keeper`/`seal` signing mechanism that guards it.

## Recon & Initial Analysis

We pulled the disk out of the OVA the reliable way (unpack OVA → convert VMDK → `debugfs rdump` the ext4 filesystem). The key artifacts:

```text
extracted/rootfs/var/lib/lamp/user.txt      <- user flag, in the clear
extracted/rootfs/etc/lamp/sealed.bin        <- ROOT flag, encrypted (50 bytes)
extracted/rootfs/etc/lamp/bench.conf        <- SHA-256 "commitments" for the secrets
extracted/rootfs/usr/local/bin/deadlight    <- the program that seals/unseals
```

`bench.conf` is the MVP of this box. A **commitment** is just a published hash of a secret — a sealed envelope that lets you *check* a candidate without the value being written down:

```ini
seedhash    = 4f971d4e...892b024    # SHA256 of the 16-char seed
roothash    = cc9d836a...1c13c5d    # SHA256 of the root password
sealhash256 = e1deec12...423ddad    # SHA256 of the seal phrase
chainhash   = e38b863b...558679     # SHA256 of the PREVIOUS machine's root flag <- the unknown
```

Three secrets already verified against their envelopes:

```text
seed  OK  C4WSWUHX6IPRF4SZ
root  OK  Chimneystem54449&
seal  OK  F0rdb0th0m94280#
```

So Deadlight was 3/4 solved. The only missing value was the one whose SHA-256 equals `chainhash` — **the 29-stillwater root flag**. `chainhash` is a gift: a perfect oracle. Whatever we recover for Stillwater, we instantly check it against this hash — no guessing, and the chain's many fake flags can't fool it.

The user flag is already plaintext on disk: `Null0rigin{the_lamp_told_you_by_going_out}`.

## Foothold / Core Concept

Two tricks stacked on each other.

### Trick 1 — attack the seal, not the shadow file

Stillwater's root flag lives in `/etc/stillwater/root.seal` (91 bytes). Its `unseal` binary is a static, stripped ELF; we loaded it into Binary Ninja and decompiled `main`. The fastest reversing move: **identify crypto by its magic constants.** A buffer initialized with `67 e6 09 6a  85 ae 67 bb ...` is the **SHA-256 initial state** (`6a09e667 bb67ae85 ...`) in little-endian — so two helpers were obviously "SHA-256 update/finalize" without reading a line of their bodies. (A SHA-1 IV `01 23 45 67 ...` elsewhere was a red herring — the TOTP, see below.)

`main` decoded to:

- **Seed check:** `seal.check == hex(SHA256("stillwater-seed-v1" || seed_bytes))`. Verifying our assembled 24-byte seed reproduced `seal.check` *before* touching the real seal — proof the reversing was right.
- **Decryption key:** `K = SHA256("stillwater-seal-v1" || root_password || chain_key || seed_bytes)`. The root password is an ingredient in the key — that's the crack in the armor.
- **Cipher:** home-rolled stream cipher. Keystream block *n* = `SHA256(K || "ks" || n_BE32)`, plaintext = `ciphertext XOR keystream`; the file is `59B ciphertext + 32B MAC`.

Because the password also feeds `K`, we skip the deliberately-slow `$6$` shadow hash and brute-force the password *against the seal* — a couple of fast SHA-256s per guess, with `chainhash` as the correctness oracle.

### Trick 2 — the TOTP is a gate, not key material

`unseal` also demands a 6-digit `-o` cycle code: a TOTP, truncated `HMAC-SHA1(key=seed, counter=unixtime/300)` (that's what the SHA-1 constants were for). It's checked **separately** and never touches `K`, so for offline decryption we just don't run that path. Same lesson Deadlight itself teaches: a live-only check doesn't mean you need the live machine.

## Privilege Escalation

(Deadlight's own root gate is the seal, not a shell exploit — all three of its local secrets were already recovered and committed in `bench.conf`. The remaining "escalation" is cryptographic: produce the missing chain input.)

### Step 1 — brute-force Stillwater's root password against its seal (`solve_stillwater_seal.py`)

Chain-wide credential standard: `Capitalize(token) + seam(2) + 3 digits + symbol(!@#$%&)`. Stillwater root = `token=wellflash, seam=52, staff` → `Wellflash52NNN[!@#$%&]`, exactly **6000** candidates. Loop each through the seal decryptor and check against `chainhash`:

```text
root password : Wellflash52199%
plaintext     : Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}\n
SHA256("Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}") == e38b863b...558679  ✅
```

Provably correct, not a decoy. (Side note: cracking the `$6$` shadow over the same 6000 candidates came up empty — the seal was the *only* correct oracle. Attack the mechanism that actually gates the goal.)

## Exploitation Walkthrough

### Step 2 — feed the Stillwater flag into Deadlight and decrypt (`solve_deadlight.py`)

Deadlight's decryptor is a sibling of Stillwater's — a SHA-256 rolling-XOR stream keyed by the four secrets in order:

```python
k = hashlib.sha256((chain + rootpw + seal + seed).encode()).digest()
# chain  = "Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}"  (just proven)
# rootpw = "Chimneystem54449&" ; seal = "F0rdb0th0m94280#" ; seed = "C4WSWUHX6IPRF4SZ"
stream = hashlib.sha256(k + b"deadlight-seal").digest()   # roll every 32 bytes
# plaintext = sealed.bin XOR keystream
```

The 50-byte `sealed.bin` decodes to exactly 50 bytes — no padding, no header, so the whole file *is* the flag:

```text
$ python3 solve_deadlight.py
=== Deadlight sealed.bin decrypted ===
'Null0rigin{a_deadlight_is_a_reading_not_a_failure}'
```

Full scripts: `solve_stillwater_seal.py` (recover + prove the chain input), `solve_deadlight.py` (final decrypt). Flags recorded in `flag.txt`.

## Flags

user: `Null0rigin{the_lamp_told_you_by_going_out}`
root: `Null0rigin{a_deadlight_is_a_reading_not_a_failure}`

Recovered en route (submit separately): `29-stillwater` root `Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}` (root password `Wellflash52199%`).

The flag is a wink at the theme: a "deadlight" (a lamp gone out) is *a reading, not a failure* — the lamp going dark is itself the signal, matching the user flag `the_lamp_told_you_by_going_out`.

## Key Takeaways

- **Commitments are your best friend.** Published hashes (`chainhash`, `seal.check`) verify a candidate with zero ambiguity — invaluable in a challenge littered with fake flags. If a value doesn't match its committed hash, it's bait.
- **Attack the mechanism that gates the goal, not the one that looks standard.** The password lived in both a slow `$6$` hash and a fast seal key; the seal won instantly.
- **Reverse crypto by its constants.** The SHA-256 / SHA-1 init vectors (`6a09e667...`, `67452301...`) reveal the primitive set without reading the internals.
- **Verify your reversing on a known value first** (`seal.check`), so a failed decrypt points at the password, not a misread of the binary.
- **Time-based / live-only checks are often just gates** — read enough disassembly to know what's load-bearing and what's theater.
- **Chains reward bookkeeping.** Keep every root flag exactly as submitted — one stray newline and the hash check saves you.
