#!/usr/bin/env python3
"""
28-blackdamp -- generate the live seal TOTP for the root unseal step.

The three recovered seal fragments concatenate (no separators) into the seed:
    A: ea3f9e5b   B: bda5c910   C: f4c01df2  ->  ea3f9e5bbda5c910f4c01df2

The seal wants a 6-digit RFC 6238 TOTP using SHA-256 and a 30-second step,
with the seed used as ASCII text. Time-based codes add little protection once
the long-term seed has leaked -- generate this immediately before running unseal.
"""
import hashlib, hmac, struct, time

seed = b"ea3f9e5bbda5c910f4c01df2"
counter = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha256).digest()
offset = digest[-1] & 0x0f
number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
print(f"{number % 1_000_000:06d}")
