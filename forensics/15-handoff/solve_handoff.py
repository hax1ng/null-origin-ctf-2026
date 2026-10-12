#!/usr/bin/env python3
"""Reassemble the marker-selected RTP scanlines from handoff.pcap."""

from collections import defaultdict
from pathlib import Path
import struct

from PIL import Image
from scapy.all import UDP, rdpcap


PCAP = Path("handoff.pcap")
OUTPUT = Path("handoff_scanlines.png")
RTP_PORT = 5004
SCALE = 3


# streams[SSRC][sequence] = (marker bit, timestamp, pixel payload)
streams = defaultdict(dict)

for packet in rdpcap(str(PCAP)):
    if UDP not in packet or packet[UDP].dport != RTP_PORT:
        continue

    rtp = bytes(packet[UDP].payload)
    if len(rtp) < 12 or rtp[0] >> 6 != 2:
        continue

    csrc_count = rtp[0] & 0x0F
    header_length = 12 + 4 * csrc_count
    if rtp[0] & 0x10:  # RTP header extension
        _, extension_words = struct.unpack_from(">HH", rtp, header_length)
        header_length += 4 + 4 * extension_words

    marker = bool(rtp[1] & 0x80)
    sequence = int.from_bytes(rtp[2:4], "big")
    timestamp = int.from_bytes(rtp[4:8], "big")
    ssrc = int.from_bytes(rtp[8:12], "big")
    streams[ssrc][sequence] = (marker, timestamp, rtp[header_length:])

print("RTP streams:")
for ssrc, packets in sorted(streams.items()):
    markers = {entry[0] for entry in packets.values()}
    lengths = {len(entry[2]) for entry in packets.values()}
    print(
        f"  0x{ssrc:08x}: {len(packets)} packets, "
        f"sequence {min(packets)}..{max(packets)}, "
        f"marker={markers}, payload lengths={lengths}"
    )

# The competing SSRC has M=0 on every packet. The active handoff stream is the
# only one whose packets all carry the RTP marker bit.
selected = [
    (ssrc, packets)
    for ssrc, packets in streams.items()
    if packets and all(entry[0] for entry in packets.values())
]
assert len(selected) == 1, "expected exactly one marker-selected RTP stream"

ssrc, packets = selected[0]
sequences = sorted(packets)
assert sequences == list(range(36)), "expected scanline sequences 0 through 35"

rows = [packets[sequence][2] for sequence in sequences]
assert len({len(row) for row in rows}) == 1, "scanline widths differ"
assert set().union(*(set(row) for row in rows)) <= {0x00, 0xFF}

width, height = len(rows[0]), len(rows)
image = Image.frombytes("L", (width, height), b"".join(rows))
image = image.resize((width * SCALE, height * SCALE), Image.Resampling.NEAREST)
image.save(OUTPUT)

print(f"Selected SSRC 0x{ssrc:08x}")
print(f"Wrote {OUTPUT} ({width * SCALE}x{height * SCALE})")
