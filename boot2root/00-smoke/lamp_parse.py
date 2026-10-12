#!/usr/bin/env python3
"""
00-smoke -- parse /var/lib/assay/lamp.log and recover the first root-seal fragment.

The log is an array of fixed 32-byte records:
    u32 entry | u32 time | f32 reading | char[8] seam | char[12] tag

STANDING-ORDER-14 says any reading above 20.00 is an instrument fault, and the
12-byte tag of that record holds the fault code (seal fragment).

Usage: ./lamp_parse.py <lamp.log>
"""
import struct, sys

data = open(sys.argv[1], "rb").read()

for offset in range(0, len(data), 32):
    chunk = data[offset:offset + 32]
    if len(chunk) < 32:
        break
    entry, timestamp, reading, seam, tag = struct.unpack("<IIf8s12s", chunk)
    if reading > 20.0:
        print("entry:    ", entry)
        print("reading:  ", reading)
        print("seam:     ", seam.rstrip(b" \x00").decode())
        print("fault code:", tag.rstrip(b"\x00").decode())
