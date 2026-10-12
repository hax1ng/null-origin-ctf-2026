#!/usr/bin/env python3
"""
00-smoke -- offline brute-forcer for the SMKSEAL1 user/root flag seals.

The site password policy turns each account into a tiny keyspace:
    base word (from the pit-record vocabulary) + fixed transform
    + 2-digit seam + 3-digit shot + one marker from !@#$%&

Rather than cracking the slow $6$ shadow hash, we attack the seal directly:
the same password feeds the seal key, and the plaintext always starts with
"Null0rigin{", so the first keystream block is a perfect correctness oracle.

Usage:
    ./seal_oracle.py user <sealed_file> <vocab.txt>
    ./seal_oracle.py root <sealed_file> <vocab.txt>
"""
import hashlib, struct, sys

mode, sealed, vocab = sys.argv[1:]
b = open(sealed, 'rb').read()
check = b[8:12]
n = struct.unpack('<H', b[12:14])[0]
c = b[14:14 + n]
markers = '!@#$%&'

if mode == 'user':
    words = [x.strip() for x in open(vocab) if x.strip()]
    # bundle class: lowercase word, "sk-" prefix, seam 96
    def make(w, n, m): return f'sk-{w}96{n:03d}{m}'
    def material(p): return 'assay:' + p
elif mode == 'root':
    words = [x.strip() for x in open(vocab) if x.strip()]
    # staff class: capitalize first letter, seam 48
    def make(w, n, m): return f'{w[0].upper()}{w[1:]}48{n:03d}{m}'
    # the two seal fragments recovered on-box (lamp fault code + office code)
    frag1, frag2 = '93563208e2ee', '602f63e441f2'
    def material(p): return frag1 + ':' + frag2 + ':' + p
else:
    raise SystemExit()

for wi, w in enumerate(words):
    for num in range(1000):
        for mark in markers:
            p = make(w, num, mark)
            kh = hashlib.sha256(material(p).encode()).hexdigest()
            # cheap oracle: only the first 11 keystream bytes vs "Null0rigin{"
            ks = hashlib.sha256((kh + ':0').encode()).digest()
            if bytes(x ^ y for x, y in zip(c[:11], ks[:11])) != b'Null0rigin{':
                continue
            # candidate passed -- confirm with full decrypt + stored checksum
            fullks = b''.join(
                hashlib.sha256(f'{kh}:{i}'.encode()).digest()
                for i in range((n + 31) // 32)
            )
            pt = bytes(x ^ y for x, y in zip(c, fullks))
            if hashlib.sha256(pt).digest()[:4] == check:
                print('FOUND', p, repr(pt), flush=True)
                raise SystemExit()
    if wi % 100 == 0:
        print('progress', wi, w, flush=True)
print('not found')
