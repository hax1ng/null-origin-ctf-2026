# Winnow

**Category:** Steganography | **Flag:** `Null0rigin{nothing_takes_until_it_is_fixed}`

Stage 6 of the Null0rigin Stego Chain. Previous seal (the key):
`Null0rigin{keep_the_grain_and_burn_the_chaff}`.

## Challenge Description

`description.txt` is empty; `contact-sheet.txt` describes a photographic contact
sheet and spells out the authentication scheme almost verbatim:

> Sixty-four across, thirty-two down ... They were shot IN PAIRS ... Each frame
> of a pair carries one bit and the two bits disagree, always, by design. One of
> the two is the truth and the other was put there to be found ... Every frame
> carries its own SEAL ... `seal = SHA-256( k, then the frame number as two
> octets high first, then the one octet that is the bit )` ... only the first
> two octets of that are kept ... Read the sheet straight through without
> sorting it and you will get something. ... All of it was put there for the man
> who does not sort.

## Initial Analysis

```bash
file sheet.png        # PNG 2048x1024, 8-bit grayscale
identify sheet.png
exiftool sheet.png
```

Two well-formed decoys, both intended to tempt a shortcut:

- PNG comment: `Null0rigin{the_sheet_was_never_contact_printed}`.
- A tiny real **QR code** hidden among the mini-images scans to
  `Null0rigin{one_thousand_and_twenty_four_grains}`.

Both have the correct flag format, which is exactly why you can't trust format
alone — the real answer has to survive the keyed seal check and a later CRC.

## The Vulnerability / Core Concept

2048/64 = 32 and 1024/32 = 32, so the sheet is a grid of **2,048 frames of
32x32 pixels**, numbered in reading order. Frames are paired `(0,1), (2,3), ...`
and the two frames in a pair carry opposite bits.

Each frame hides data in pixel **LSBs** (a 1-level shade change, invisible on a
noisy sheet):

```text
LSB of pixel 0      = the frame's data bit
LSBs of pixels 1..16 = a 2-byte seal, MSB-first
```

**Winnowing** (the title) = separating grain from chaff using the seal as the
filter. For frame `n` carrying bit `b`:

```python
expected = sha256(key + n.to_bytes(2, "big") + bytes([b])).digest()[:2]
```

Compute it for both frames of a pair; exactly one matches the stored seal in the
record-bearing region. Keep that bit, discard its partner. When a pair has *no*
valid member, the authenticated record is over and the rest is filler — the
solver stops there. That stopping point is exactly byte-aligned (496 bits = 62
bytes) and yields a valid CRC, which confirms it's deliberate, not a collision.

The 62 selected bytes are still ciphertext; decrypt with the chain keystream
(`k = SHA256(previous flag)`).

## Exploitation

`solve_winnow.py` reshapes the sheet into frames with NumPy, runs the seal
filter per pair, then decrypts and validates:

```python
frames = image.reshape(32, 32, 64, 32).transpose(0, 2, 1, 3).reshape(2048, 1024)
for pair_start in range(0, 2048, 2):
    matches = []
    for n in (pair_start, pair_start + 1):
        lsb = frames[n] & 1
        bit = int(lsb[0]); seal = np.packbits(lsb[1:17], bitorder="big").tobytes()
        if seal == sha256(key + n.to_bytes(2, "big") + bytes([bit])).digest()[:2]:
            matches.append(bit)
    if not matches: break               # record done; rest is chaff
    selected_bits.append(matches[0])
```

Output:

```text
Selected bits: 496   Encrypted bytes: 62
Stamp: b'PL8'   Issue: 1   Payload length: 52
Stored CRC32: 3aea68cd   Actual CRC32: 3aea68cd
Payload: b'Null0rigin{nothing_takes_until_it_is_fixed}\x1f\x07\xe5\xcb2\x19\xd6\xf4\x8b'
```

(Winnow's share for Mordant is the trailing `07e5cb3219d6f48b`.)

## Flag

`Null0rigin{nothing_takes_until_it_is_fixed}`

## Key Takeaways

- Keyed per-item authentication tags (here a truncated SHA-256 seal) let a
  challenge plant perfectly-valid-looking chaff that only the right key can
  distinguish from grain.
- `np.ndarray.reshape(...).transpose(...)` cleanly tiles a big image into frames
  without carving thousands of files.
- A well-formed decoy inside a QR code is still a decoy — in this chain, trust
  the keyed seal and the CRC, never the shape of the string.
