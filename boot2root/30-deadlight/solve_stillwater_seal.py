#!/usr/bin/env python3
"""
30-deadlight / 29-stillwater -- recover the Stillwater root flag by brute-forcing
the root password directly against Stillwater's sealed root flag.

Why not crack /etc/shadow? The root password feeds BOTH the slow $6$ shadow hash
AND the fast seal key. Attacking the seal is ~6000 pairs of SHA-256 hashes, and
Deadlight's bench.conf gives a perfect correctness oracle (chainhash). Reversing
Stillwater's `unseal` (static, stripped ELF; crypto identified by its SHA-256 IV
"6a09e667 bb67ae85 ...") yielded:

    K  = SHA256("stillwater-seal-v1" || root_pw || chain_key || seed_bytes)
    keystream block n = SHA256(K || "ks" || n_as_4_bytes_BE)
    plaintext = ciphertext XOR keystream        (file = 59B ct + 32B MAC)

Chain-wide policy for root (token=wellflash, seam=52, staff): Wellflash52NNN[!@#$%&]
-> exactly 6000 candidates.

Expects Stillwater's rootfs at rootfs/etc/stillwater/root.seal.
"""
import hashlib, struct

seed  = bytes.fromhex("e94837b2225e9dbfb685186c466bd2ced70f14ea164169a1")  # 24 bytes
chain = "Null0rigin{you_paid_for_every_candidate}"       # 28-blackdamp root flag (feeds Stillwater)
data  = open("rootfs/etc/stillwater/root.seal", "rb").read()
ct, tag = data[:-32], data[-32:]
# published commitment from Deadlight's bench.conf: SHA256(stillwater root flag)
chainhash = "e38b863b9ece6d4233c860f5a4bc8c269f4c2e6d79b51037e9d2865998558679"


def decrypt(rootpw):
    K = hashlib.sha256(b"stillwater-seal-v1" + rootpw.encode()
                       + chain.encode() + seed).digest()
    pt, n = bytearray(), 0
    while len(pt) < len(ct):
        ks = hashlib.sha256(K + b"ks" + struct.pack(">I", n)).digest()
        pt += bytes(a ^ b for a, b in zip(ct[n * 32:(n + 1) * 32], ks))
        n += 1
    return bytes(pt)


for n in range(1000):
    for m in "!@#$%&":
        pw = f"Wellflash52{n:03d}{m}"
        pt = decrypt(pw)
        if pt.startswith(b"Null0rigin{"):
            flag = pt.rstrip(b"\n").decode()
            ok = hashlib.sha256(flag.encode()).hexdigest() == chainhash
            print("root password :", pw)
            print("plaintext     :", repr(pt))
            print("chainhash OK  :", ok)   # True == provably the real flag, not a decoy
            raise SystemExit()
print("not found")
