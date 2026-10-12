#!/usr/bin/env python3
"""Render Slackwater's orphan-cluster allocation map as a PBM image."""

from pathlib import Path
import struct


IMAGE = Path("card.img")
OUTPUT = Path("slackwater_fat_map.pbm")
START_CLUSTER = 100
WIDTH = 792
HEIGHT = 36


disk = IMAGE.read_bytes()

# FAT32 BIOS Parameter Block fields.
bytes_per_sector = struct.unpack_from("<H", disk, 11)[0]
sectors_per_cluster = disk[13]
reserved_sectors = struct.unpack_from("<H", disk, 14)[0]
fat_count = disk[16]
total_sectors = struct.unpack_from("<I", disk, 32)[0]
sectors_per_fat = struct.unpack_from("<I", disk, 36)[0]

fat_offset = reserved_sectors * bytes_per_sector
fat_size = sectors_per_fat * bytes_per_sector
data_start_sector = reserved_sectors + fat_count * sectors_per_fat
data_clusters = (total_sectors - data_start_sector) // sectors_per_cluster
last_cluster = data_clusters + 1

fat = struct.unpack_from(f"<{fat_size // 4}I", disk, fat_offset)

# From cluster 100 onward, a nonzero FAT entry is one black pixel and a free
# cluster is one white pixel. The last eight clusters are unused padding.
available = last_cluster - START_CLUSTER + 1
assert available == WIDTH * HEIGHT + 8

pixels = [
    1 if (fat[cluster] & 0x0FFFFFFF) != 0 else 0
    for cluster in range(START_CLUSTER, START_CLUSTER + WIDTH * HEIGHT)
]

rows = [
    " ".join(str(pixel) for pixel in pixels[y * WIDTH : (y + 1) * WIDTH])
    for y in range(HEIGHT)
]
OUTPUT.write_text(f"P1\n{WIDTH} {HEIGHT}\n" + "\n".join(rows) + "\n")

print(f"Wrote {OUTPUT} ({WIDTH}x{HEIGHT})")
print("The allocation map reads: Null0rigin{ink_before_dawn}")
