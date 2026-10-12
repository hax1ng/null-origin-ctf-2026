#!/usr/bin/env python3
"""
30-deadlight -- decrypt the root flag (etc/lamp/sealed.bin) offline.

Deadlight's root flag is a sealed blob, not a readable file. Its decryption key
mixes FOUR secrets, three of which we already verified against the published
SHA-256 commitments in bench.conf (seedhash/roothash/sealhash256). The fourth is
the *previous machine's root flag* (29-stillwater), recovered via
solve_stillwater_seal.py and proven against bench.conf's chainhash.

Key:        K = SHA256(chain || root_password || seal_phrase || seed)
Keystream:  block 0 = SHA256(K || "deadlight-seal"); roll every 32 bytes by
            re-hashing (prev_block || "deadlight-seal"). Plaintext = ct XOR ks.
The 50-byte sealed.bin decodes to exactly 50 bytes -- the whole file is the flag.

Run from the box's extracted rootfs directory (expects extracted/rootfs/...).
"""
import hashlib
from pathlib import Path

chain  = "Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}"  # 29-stillwater root flag
rootpw = "Chimneystem54449&"     # verified vs roothash
seal   = "F0rdb0th0m94280#"      # verified vs sealhash256
seed   = "C4WSWUHX6IPRF4SZ"      # verified vs seedhash

# K = SHA256(chain || root_password || seal_phrase || seed)
k = hashlib.sha256((chain + rootpw + seal + seed).encode()).digest()

ciphertext = Path("extracted/rootfs/etc/lamp/sealed.bin").read_bytes()
stream = hashlib.sha256(k + b"deadlight-seal").digest()

plaintext = bytearray()
for i, byte in enumerate(ciphertext):
    if i and i % 32 == 0:                       # roll to the next 32-byte block
        stream = hashlib.sha256(stream + b"deadlight-seal").digest()
    plaintext.append(byte ^ stream[i % 32])

out = plaintext.decode(errors="replace")
print("=== Deadlight sealed.bin decrypted ===")
print(repr(out))
print(out)
