# Moire

**Category:** Steganography | **Difficulty:** Medium | **Points:** 400 | **Flag:** `Null0rigin{a_carrier_laid_across_the_whole_room}`

Stage 3 of the Null0rigin Stego Chain. Previous seal (the key):
`Null0rigin{two_cells_of_equal_weight_are_not_equal}`.

## Challenge Description

`description.txt` is empty; the clues are in `screen-notes.txt`, written as a
print-shop "process room" job card:

> The screen is set FOUR TO THE CELL, and the cell is square. Every cell on the
> plate is laid to a weight and the weight is the number of dots that fall black
> in it ... a cell of a given weight can be SET more than one way ... The
> machine lays the cells as the ox ploughs. Down one furrow, and back along the
> next ... Do not look for it in the sheet. It is in what the sheet had to be
> broken into before a press could take it.

## Initial Analysis

```bash
file moire.png                      # PNG 1024x768, 1-bit black & white
strings -a moire.png | grep -i null
```

The image is **1-bit (pure black/white)**, 1024x768. Two decoys:

- PNG comment: `Null0rigin{the_screen_was_turned_fifteen_degrees}`.
- Text appended after `IEND` dressed up as PostScript, containing
  `Null0rlgin{two_cells_of_equal_weight}` — note the lowercase `l` where
  `Null0rigin` has an `i`. A deliberate near-miss.

## The Vulnerability / Core Concept

Decoding the old-fashioned notes almost literally:

1. Divide the image into **4x4 pixel cells** ("four to the cell"). 1024/4 = 256
   across, 768/4 = 192 down = 49,152 cells.
2. A cell's **weight** = number of black pixels in it.
3. For the middle weights (5-11), the same weight can be drawn two visually
   identical ways; that choice stores one bit. Weight 4 and weights 12-16 have
   only one form, so they carry nothing and are skipped. Example, two weight-8
   patterns that look equally dark:

   ```text
   ..##    .#.#
   ##..    #.#.
   ..##    .#.#
   ##..    #.#.
   ```

4. Read cells in **boustrophedon** order ("as the ox ploughs"): row 0 left to
   right, row 1 right to left, and so on.

Keeping the weight constant is the point — from a foot away the sheet looks
identical; only the internal arrangement changes. There are 35,569 two-form
cells, far more than the record needs.

Two subtleties:

- The bytes are encrypted with the chain's keystream, so they look random until
  XORed with `SHA256(k || counter)` where `k = SHA256(previous seal)`.
- Sorting the two patterns of a weight doesn't tell you which is `0` and which
  is `1`. But there are only seven two-form weights (5-11), so just **brute-force
  all 2^7 = 128 polarity assignments**. The right one is the only one that yields
  a `PL8` header with a matching CRC32 — no guessing needed.

## Exploitation

`solve_moire.py` catalogs every 4x4 cell, keeps the two-form cells in
ox-plough order, and tries all 128 polarities against the decrypted PL8 check:

```python
for polarity in range(1 << 7):
    bits = [bit ^ ((polarity >> (weight - 5)) & 1)
            for bit, weight in zip(raw_bits[:8192], weights[:8192])]
    encoded = pack_msb(bits)
    decoded = xor(encoded, stream)
    if decoded[:3] != b"PL8":
        continue
    # verify length + CRC32, then extract the flag
```

Output:

```text
Two-form cells: 35569
Issue: 1   Length: 57   Stored CRC32: 5552ca1c   Calculated CRC: 5552ca1c
Payload: b'Null0rigin{a_carrier_laid_across_the_whole_room}\x1f\xf1\t\x83\xddk^\xc4\xa2'
```

(Moire's share for Mordant is the trailing `f10983dd6b5ec4a2`.)

## Flag

`Null0rigin{a_carrier_laid_across_the_whole_room}`

## Key Takeaways

- Halftone/dither steganography hides data in *pattern* while preserving
  *density*, so it's invisible to the eye and to simple histograms.
- When an orientation/polarity is ambiguous but the search space is tiny
  (2^7 here), brute-force it and let a checksum pick the winner.
- "Read it in the order the ox ploughs" = boustrophedon ordering — a recurring
  CTF trick for linearizing a 2-D grid.
