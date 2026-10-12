# Driftwood

**Category:** Steganography | **Difficulty:** Easy | **Points:** 250 | **Flag:** `Null0rigin{what_the_negative_kept_from_the_print}`

Stage 1 of the 8-part **Null0rigin Stego Chain**. Each later stage is encrypted
with the exact flag from the stage before it, so this flag is also the key that
unlocks stage 2 (SafeLight).

## Challenge Description

`description.txt` is empty. The flavor and the real instructions live in
`plate-card.txt`, an in-universe "archive index card" that tells you how the
plate room stores data and, crucially, how to tell a genuine entry from a plant:

> The plate room does not write on plates. When the plate room puts something
> INTO a plate it goes in as a WORKS ENTRY ... `PL8` the works stamp ... a
> check over the entry ... If you have pulled something out of a plate and it
> does not begin with the stamp, and the check over it does not come out, then
> it is not a works entry. It is somebody's handwriting.

That last part is the whole challenge: the image is stuffed with believable
flags, and only one of them is real.

## Initial Analysis

Standard first pass on the carrier:

```bash
file driftwood.png       # PNG 900x620, RGBA
exiftool driftwood.png
```

The image is **900x620 RGBA** — four channels per pixel (red, green, blue, and
alpha/transparency). That extra alpha channel is a classic place to hide data.

Three plausible flags surface almost immediately, and all three are decoys:

- **PNG metadata:** `NullOrigin{the_tide_returns_what_it_took}` — note the wrong
  `NullOrigin` (no zero), a tell that it is fake.
- **Appended ZIP** after the PNG `IEND`: `Null0rigin{recovered_from_the_shingle}`.
- **Red-channel LSB** (`zsteg -a driftwood.png`):
  `b1,r,lsb,xy .. text: "Null0rigin{pit_head_plate_number_four}"`.

None of them begins with the `PL8` stamp or carries a matching checksum, so by
the card's rule none of them is a works entry.

## The Vulnerability / Core Concept

The card defines a fixed binary record, the **PL8 works entry**:

```text
PL8     3-byte stamp
.       1-byte issue number
..      2-byte payload length, little-endian ("low first")
....    4-byte CRC32 over the payload, little-endian
....    the payload itself
```

"The check is the ordinary one" means a standard **CRC32**. A real flag must
(1) start with `PL8`, (2) declare a sane length, (3) have exactly that many
payload bytes, and (4) have a CRC32 that matches. That turns "which string do I
trust?" from a guess into a verifiable test.

Where is it hidden? The card's header line `SLEEVE 4` points at the image's
**fourth channel — alpha** — and "emulsion lifting at the corner" says to start
from a corner. `zsteg` confirms the channel: the genuine stream is the
least-significant bit of the alpha channel read in column-major (`yx`) order:

```bash
zsteg -E 'b1,a,lsb,yx' driftwood.png | head -c 80 | xxd -g1
```

```text
00000000: 50 4c 38 01 3a 00 eb c2 a0 ba 4e 75 6c 6c 30 72  PL8.:.....Null0r
00000010: 69 67 69 6e 7b 77 68 61 74 5f 74 68 65 5f 6e 65  igin{what_the_ne
...
```

It begins with `PL8` — the first real signal in the whole room.

## Exploitation

`solve_driftwood.py` reproduces the extraction without trusting `zsteg` to
interpret the bytes: it reads the alpha-LSB plane column-major, packs the bits
MSB-first, then parses and CRC-verifies the PL8 record.

```python
bits = [image.getpixel((x, y))[3] & 1
        for x in range(image.width) for y in range(image.height)]
data = bytes(sum(bits[i + j] << (7 - j) for j in range(8))
             for i in range(0, len(bits) - 7, 8))
stamp, issue, length, stored_crc = struct.unpack("<3sBHI", data[:10])
payload = data[10:10 + length]
assert stamp == b"PL8"
assert zlib.crc32(payload) & 0xFFFFFFFF == stored_crc
```

Header fields parse as: stamp `PL8`, issue `1`, length `58`, CRC32 `baa0c2eb` —
and the computed CRC32 matches exactly:

```text
Payload: b'Null0rigin{what_the_negative_kept_from_the_print}\x1f\x9eL\x1a\xf0\xd3\xb2vQ'
```

The nine trailing bytes after the closing brace are binary padding (they stay
inside the CRC-protected payload but are not part of the flag). From Mordant
onward these trailing "shares" turn out to matter — keep them.

## Flag

`Null0rigin{what_the_negative_kept_from_the_print}`

## Key Takeaways

- A flag-shaped string is not a flag. When a challenge hands you an objective
  validator (here a magic stamp + CRC32), use it to separate signal from the
  deliberately planted decoys.
- RGBA's alpha channel is an easy-to-overlook LSB carrier; `zsteg -a` sweeps all
  bit planes and channel orders at once.
- Metadata flags and appended archives are the oldest traps in the book. Check
  them, but never stop there.
