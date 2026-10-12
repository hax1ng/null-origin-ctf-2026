# SafeLight

**Category:** Steganography | **Difficulty:** Easy | **Points:** 250 | **Flag:** `Null0rigin{two_cells_of_equal_weight_are_not_equal}`

Stage 2 of the Null0rigin Stego Chain. This is the stage that formally
introduces the chain's **key schedule**, carried on `keycard.txt`.

## Challenge Description

`description.txt` is empty. `keycard.txt` is the "operator's card" that defines
how every stage after the first is keyed off the previous flag (the "seal"):

> The seal you took off the last run IS the key to this one ... `k = SHA-256`
> over the previous seal, exactly as it was written, braces and all, nothing
> stripped, nothing re-cased, no newline ... A seal that is one character out is
> not nearly right. It is a different key and it will give you nothing at all.

So the key here is the previous stage's flag, hashed exactly:

```text
previous seal: Null0rigin{what_the_negative_kept_from_the_print}
k = SHA256(seal) = e25693cd804a819d8638171adf44e60fae61fa4a8616e117ace7362f2011aa13
```

## Initial Analysis

```bash
file negative.png print.png   # both PNG 900x620, 8-bit grayscale
exiftool negative.png print.png
```

Two grayscale images of the same industrial scene: one is a photographic
**negative**, the other the **print**. Two decoys again:

- `print.png` metadata: `Null0rigin{developed_under_a_red_lamp}`.
- Inverting the negative and highlighting the large differences literally
  *draws* `Null0rigin{what_the_print_kept_from_the_negative}` — the previous
  flag with "negative" and "print" swapped, so it looks very convincing.

## The Vulnerability / Core Concept

An 8-bit grayscale pixel runs 0 (black) to 255 (white). A perfect negative `N`
and its print `P` should satisfy:

```text
P = 255 - N      =>      N + P = 255
```

So compute `difference = negative + print - 255`. Most pixels are exactly 0.
The nonzero ones split into two populations:

```text
difference  0: 553860 pixels
difference  3:   3580 pixels   <- draws the loud "drawn" decoy
difference -1:    290 pixels   <- the real channel
difference  1:    270 pixels   <- the real channel
```

The eye-catching `+3` pixels paint the decoy. The genuine channel is the
**+/-1** pixels — deviations so small they are invisible — read left-to-right,
top-to-bottom, with `-1 -> bit 0` and `+1 -> bit 1`. That is 560 bits = 70
bytes. Those bytes look random because the chain encrypts them with the keyed
SHA-256 counter stream:

```text
stream = SHA256(k || 00000000) || SHA256(k || 00000001) || ...   (4-byte BE counter)
plaintext = ciphertext XOR stream
```

## Exploitation

`solve_safelight.py` does the full pipeline: load both PNGs as signed arrays,
keep only the +/-1 pixels, pack MSB-first, build the keystream, XOR, and verify
the PL8 record.

```python
difference = negative + printed - 255          # signed int16
bits = [0 if v == -1 else 1 for v in difference.ravel() if v in (-1, 1)]
# -> 560 bits -> 70 bytes
k = sha256(PREVIOUS_SEAL).digest()
# stream = SHA256(k || counter)...  then decoded = encoded XOR stream
```

Result:

```text
Stamp: b'PL8'   Issue: 1   Length: 60   Stored CRC: 58c28ba1   Calculated CRC: 58c28ba1
Payload: b'Null0rigin{two_cells_of_equal_weight_are_not_equal}\x1f*w\xbe\x05\xc4\x19\x8d?'
```

The matching CRC32 (`58c28ba1`) proves the previous-stage key, the extraction
order, and the +/-1 interpretation are all correct. (Save the trailing
`2a77be05c4198d3f` — it is SafeLight's "share" for Mordant.)

## Flag

`Null0rigin{two_cells_of_equal_weight_are_not_equal}`

## Key Takeaways

- A negative and its print should sum to 255 everywhere; any residual is a
  hidden channel. Use a **signed** array type so negative deltas survive.
- Loud, hand-drawn difference art is bait. The real payload hides in the
  smallest possible deviation (+/-1) that still survives a lossless format.
- This stage pins down the chain's crypto: `k = SHA256(exact previous flag)`,
  keystream `= SHA256(k || BE32 counter)`, combined by XOR. Every later stage
  reuses it verbatim.
