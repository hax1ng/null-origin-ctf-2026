#!/usr/bin/env python3
"""
29-stillwater -- generate the ~6000-candidate password list for one account.

Site policy: transformed site word + 2-digit seam + 3-digit shot + marker(!@#$%&).
Class transforms:
    staff       capitalize the first letter
    contractor  capitalize, then a/e/i/o/s -> 4/3/1/0/5
    bundle      keep lowercase, prefix district code "sw-"

Because the personnel file leaks holder + seam + class for each account, the
word is fixed and only (shot x marker) = 1000 x 6 = 6000 candidates remain.

Usage: ./make_candidates.py <token> <seam> <staff|contractor|bundle>
Example: ./make_candidates.py wellflash 52 staff > root-candidates.txt
"""
import sys

token, seam, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3]

if kind == "staff":
    prefix = token.capitalize()
elif kind == "contractor":
    prefix = token.capitalize().translate(str.maketrans("aeios", "43105"))
elif kind == "bundle":
    prefix = "sw-" + token.lower()
else:
    raise SystemExit("class must be staff, contractor, or bundle")

for shot in range(1000):
    for marker in "!@#$%&":
        print(f"{prefix}{seam:02d}{shot:03d}{marker}")
