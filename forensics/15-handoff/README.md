# Handoff

**Category:** Forensics | **Flag:** `Null0rigin{the_right_feed_never_lied}`

## Challenge Description

> A handoff is the moment a thing stops being one party's problem.
> It is also the moment nobody is quite watching.

We get `handoff.pcap`, a local checker, and a sealed confirmation file. The flag
comes out of the capture; the sealed file isn't needed.

> Note: part of the internal forensics chain — chain-internal flag format is
> `Null0rigin{...}` (with a zero).

## Initial Analysis

The capture is loud with decoys. Following the short TCP streams and decoding
the DNS traffic hands you four different flag-shaped strings:

```text
Null0rigin{handoff_incomplete}         # HTTP User-Agent
Null0rigin{wrong_stream_wrong_flag}    # HTTP response body
Null0rigin{buffered_not_broadcast}     # Base32 labels before .tun.io (DNS)
Null0rigin{the_call_dropped_first}     # fake FTP banner
```

All planted. The checker locks after three genuine wrong answers, so throwing
strings at it is how you lose. The real evidence is the traffic nobody bothers
to look at: 72 UDP packets to **UDP/5004**, the RTP rendezvous port. Wireshark
won't auto-decode a dynamic payload type as RTP, so force the dissector and pull
the header fields:

```bash
tshark -r handoff.pcap -d udp.port==5004,rtp -Y rtp \
  -T fields -e rtp.ssrc -e rtp.marker -e rtp.p_type \
  -e rtp.seq -e rtp.timestamp -e rtp.payload
```

That exposes **two** synchronization sources sharing the destination, with
identical sequence numbers and timestamps:

```text
SSRC          M      PT   packets   sequence   timestamps      payload
0x7e11a0c1    True   96      36       0..35     0..105000       1092 bytes
0x7e115ca0    False  96      36       0..35     0..105000       1092 bytes
```

Two kiosks streaming the same screen. What distinguishes the right feed from the
wrong one is the **SSRC** and the **RTP marker bit**.

## The Vulnerability / Core Concept

Every 1,092-byte media payload is made entirely of `00` and `ff` bytes, and each
SSRC has 36 packets with sequence numbers 0–35. That's a raster image hiding in
plain sight:

```text
width  = 1092   (bytes per payload = one scanline)
height = 36     (sequence numbers = rows)
```

Each payload is one 8-bit black-and-white scanline. Rows must be ordered by RTP
**sequence number**, not capture order. Reassembling *either* SSRC draws
readable text — but the competing `0x7e115ca0` stream renders yet another decoy,
`Null0rigin{the_ghost_signal_observed}`. The active handoff feed is the one the
marker bit selects: every packet in `0x7e11a0c1` has `M=1`, every packet in the
other has `M=0`. "The right feed never lied" — pick by the marker, not by
whichever string looks flag-ish.

## Exploitation

`solve_handoff.py` parses RTP out of each UDP payload (handling CSRC and header
extensions), groups by SSRC, selects the all-marker-bit stream, sorts its 36
scanlines by sequence, and renders them:

```python
rows = [packets[seq][2] for seq in sorted(packets)]   # marker-selected SSRC
image = Image.frombytes("L", (1092, 36), b"".join(rows))
image = image.resize((1092*3, 36*3), Image.Resampling.NEAREST)
```

```bash
python3 solve_handoff.py
# Selected SSRC 0x7e11a0c1
# Wrote handoff_scanlines.png (3276x108)
```

![RTP scanlines containing the flag](handoff_scanlines.png)

Verify:

```bash
./verify 'Null0rigin{the_right_feed_never_lied}'
# CORRECT.  handoff solved.
# next: stage 03 -- the clock lied, and it lied consistently
```

## Flag

`Null0rigin{the_right_feed_never_lied}`

## Key Takeaways

- Loud application-layer "flags" (HTTP/DNS/FTP) are a classic distraction. The
  evidence was in the transport nobody decodes by default — raw RTP.
- RTP structure carries the answer: split by **SSRC**, use the **marker bit** to
  pick the active feed, sort by **sequence number**, treat each binary payload
  as one scanline.
- `tshark -d udp.port==N,rtp` forces the RTP dissector when the payload type is
  dynamic and Wireshark won't guess it.
