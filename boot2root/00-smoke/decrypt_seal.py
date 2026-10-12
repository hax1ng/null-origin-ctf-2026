#!/usr/bin/env python3
"""
00-smoke -- decrypt an SMKSEAL1 blob once the plant key (password/material) is known.

Seal format:
    magic   8 bytes  "SMKSEAL1"
    check   4 bytes  SHA256(plaintext)[:4]
    n       2 bytes  little-endian ciphertext length
    c       n bytes  ciphertext

Keystream: block i = SHA256(f"{sha256_hex(key)}:{i}"), XORed over the ciphertext.

Usage: ./decrypt_seal.py <sealed_file> <key_material>
"""
import sys, hashlib, struct

p, key = sys.argv[1:]
b = open(p, 'rb').read()
assert b[:8] == b'SMKSEAL1'
check = b[8:12]
n = struct.unpack('<H', b[12:14])[0]
c = b[14:14 + n]

kh = hashlib.sha256(key.encode()).hexdigest()
ks = b''.join(
    hashlib.sha256(f'{kh}:{i}'.encode()).digest()
    for i in range(0, (n + 31) // 32)
)
pt = bytes(x ^ y for x, y in zip(c, ks))

print('stored check', check.hex(),
      'calc', hashlib.sha256(pt).digest()[:4].hex(), 'n', n)
print(pt)
