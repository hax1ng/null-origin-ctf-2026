#!/usr/bin/env python3
"""
29-stillwater -- generate the live "sump-cycle" code for the root unseal step.

The three fragments concatenate (hex) into a 24-byte seed:
    e94837b2225e9dbf + b685186c466bd2ce + d70f14ea164169a1

Reversing unseal's check showed a standard HOTP-style construction:
    counter = unix_time // 300           (5-minute cycle)
    key     = raw 24-byte assembled seed
    digest  = HMAC-SHA1(key, counter as 8-byte big-endian)
    offset  = low nibble of the last digest byte  (dynamic truncation)
    code    = (31-bit value at offset) % 1_000_000

Fully reversible -- the time code adds nothing once the seed is known.
Generate it immediately before calling unseal (it rotates every 5 minutes).
"""
import hashlib, hmac, struct, time

seed = bytes.fromhex("e94837b2225e9dbfb685186c466bd2ced70f14ea164169a1")
cycle = int(time.time()) // 300
digest = hmac.new(seed, struct.pack(">Q", cycle), hashlib.sha1).digest()
offset = digest[-1] & 0x0f
value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
print(f"{value % 1_000_000:06d}")
