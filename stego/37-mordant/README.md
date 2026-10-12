# Mordant

**Category:** Steganography | **Difficulty:** Insane | **Points:** 1000 | **Flag:** `Null0rigin{he_set_two_sorts_where_one_would_do}`

Stage 7 of the Null0rigin Stego Chain. This is the stage that cashes in the
"shares" quietly carried through stages 1-6. Previous seal:
`Null0rigin{nothing_takes_until_it_is_fixed}` (Winnow).

## Challenge Description

`description.txt` is empty; `mordant-notes.txt` is a dye-house working note in
two parts. On the page:

> Nothing is written on this page ... But a page has to be LAID DOWN before it
> can be rolled up ... there are five ways to lay a line ... Four of the five
> ways say something. The fifth says the same as the first.

And on the key — a two-lock "mordant":

> A mordant is not one thing. Ours is SIX ... The works has been handing you the
> six one at a time since the first sleeve. Every entry you have opened ...
> carried its seal, and then a separator, and then eight octets that were not
> the seal ... Go back and get them. The order is the order you took them in.
> The card's key opens the page. The six open what is on it.

Plus a trap warning: there is a **seventh** valid-looking share, deliberately
unused.

## Initial Analysis

```bash
file mordant.png        # PNG 1400x1900, 8-bit grayscale
exiftool mordant.png
zsteg -a mordant.png
```

Three decoys, each more convincing than the last:

- `exiftool` comment: `Null0rigin{alum_and_cream_of_tartar}`.
- An appended ZIP (`assay.txt`): `Null0rigin{the_dye_was_never_the_secret}`.
- The pixel LSB stream (`zsteg -E 'b1,r,lsb,xy'`) is a **fully valid PL8 record**
  whose CRC32 even checks out — but the flag inside reads `Null0rlgin{...}` with
  a lowercase `l` for `i`. Its trailing 8 bytes `c8b41d7e93502af6` are the
  **seventh share** the notes tell you *not* to use. A valid checksum proves an
  entry was copied correctly; it does not prove the challenge wants it.

## The Vulnerability / Core Concept

The real channel is the sequence of **PNG scanline filter bytes**. Before zlib
compression, every row is prefixed with a filter type (0 None, 1 Sub, 2 Up, 3
Average, 4 Paeth). The filters only affect compression; a decoder reverses them,
so two PNGs can show identical pixels with different filter choices.

1900 rows = 1900 filter bytes, with a very unnatural distribution (0:64, 1:456,
2:504, 3:453, 4:423). The notes say "four of five say something; the fifth says
the same as the first," i.e. map `digit = filter_type % 4` (filter 4 -> 0). Each
base-4 digit is 2 bits, so **4 rows = 1 byte**, MSB-first -> 1900/4 = 475 bytes.

Then comes the two-lock mordant — the first XOR layer alone still looks random:

- **Lock 1:** keystream from `k = SHA256(previous Winnow flag)`.
- **Lock 2:** keystream from `SHA256(` the six 8-byte shares concatenated in
  stage order 31->36 `)`. The shares are used as **raw bytes**, not hex ASCII:

  | Order | Stage | Share |
  |---:|---|---|
  | 1 | Driftwood | `9e4c1af0d3b27651` |
  | 2 | SafeLight | `2a77be05c4198d3f` |
  | 3 | Moire | `f10983dd6b5ec4a2` |
  | 4 | UnderTone | `55c2e79140ab3d08` |
  | 5 | Pentimento | `bd3f60a8e2749c15` |
  | 6 | Winnow | `07e5cb3219d6f48b` |

Apply both layers and the plaintext finally starts with `PL8`.

## Exploitation

`solve_mordant.py` parses the PNG by hand (so no library normalizes the
filters), extracts the filter bytes, builds the base-4 stream, then applies both
XOR layers:

```python
filters = [scanlines[y * stride] for y in range(height)]    # one per row
for pos in range(0, len(filters), 4):                        # 4 rows -> 1 byte
    value = 0
    for f in filters[pos:pos+4]:
        value = (value << 2) | (f % 4)                       # filter 4 -> digit 0
    encoded.append(value)
page    = xor(encoded, chain_stream(PREVIOUS_SEAL, n))       # lock 1
decoded = xor(page,    chain_stream(b"".join(SHARES), n))    # lock 2
```

Output:

```text
Image: 1400 x 1900   Encoded bytes: 475
Issue: 1   Payload length: 47
Stored CRC32: 29eb2d30   Actual CRC32: 29eb2d30
Payload: b'Null0rigin{he_set_two_sorts_where_one_would_do}'
```

## Flag

`Null0rigin{he_set_two_sorts_where_one_would_do}`

## Key Takeaways

- PNG **scanline filter choice** is a steganographic channel invisible to pixel
  inspection — parse the raw `IDAT`/zlib stream and read the per-row filter byte.
- This is the payoff of a long-con chain: the "junk padding" after each earlier
  flag was really a **secret-share** feeding a second key layer. Save every byte
  a challenge hands you, even the apparently meaningless ones.
- A valid CRC confirms integrity, not intent. The seventh share sits inside a
  perfectly checksummed decoy specifically to punish "the check passed, ship it."
