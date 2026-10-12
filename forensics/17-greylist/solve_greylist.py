#!/usr/bin/env python3
"""Recover the GreyList flag from a hidden, un-mapped physical page.

The process's self-reported VMA list omits a large-page mapping backed by
physical address 0xa00000. That page holds three 1-bpp framebuffers. The two
related buffers were masked with the same keystream, so XORing them cancels the
mask and leaves the rendered flag text.
"""

from itertools import combinations
from pathlib import Path

mem = Path("physmem.img").read_bytes()

WIDTH = 0x240               # 576 pixels
HEIGHT = 0x24               # 36 pixels
SIZE = WIDTH * HEIGHT // 8  # 0xa20 bytes per 1-bpp buffer

# The hidden physical page starts at file offset 0xa00018 (0x18 = custom dump
# header/state area that precedes the page contents).
BASE = 0xA00018
buffers = [mem[BASE + i * SIZE : BASE + (i + 1) * SIZE] for i in range(3)]

for i, j in combinations(range(3), 2):
    result = bytes(a ^ b for a, b in zip(buffers[i], buffers[j]))
    out = Path(f"pair-{i}-{j}.pbm")
    out.write_bytes(f"P4\n{WIDTH} {HEIGHT}\n".encode() + result)
    print(f"wrote {out}")

# pair-0-1.pbm (orphaned first buffer XOR second buffer) reads:
#   Null0rigin{the_second_buffer_never_ran}
print("Open pair-0-1.pbm -- it reads: Null0rigin{the_second_buffer_never_ran}")
