#!/usr/bin/env python3
"""
29-stillwater -- find the "impossible" negative reading in levels.dat.

/var/lib/stillwater/levels.dat is an array of fixed 96-byte records:
    0   4   sequence (u32 LE)
    4   4   timestamp (u32 LE)
    8   4   level     (i32 LE, signed)
    12  4   flags
    16  80  NUL-padded note

A real float cannot go below the sill, yet exactly one record has a negative
level -- and its note carries seal fragment 2.

Usage: ./levels_parse.py levels.dat
"""
import struct, sys

data = open(sys.argv[1], "rb").read()

for off in range(0, len(data), 96):
    if off + 96 > len(data):
        break
    seq, timestamp, level, flags = struct.unpack_from("<IIiI", data, off)
    note = data[off + 16:off + 96].split(b"\0", 1)[0].decode(errors="replace")
    if level < 0:
        print(seq, timestamp, level, flags, note)
