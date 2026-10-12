# Pentimento

**Category:** Steganography | **Difficulty:** Hard | **Points:** 600 | **Flag:** `Null0rigin{keep_the_grain_and_burn_the_chaff}`

Stage 5 of the Null0rigin Stego Chain. Previous seal (the key):
`Null0rigin{the_order_of_the_colours_is_the_message}`.

## Challenge Description

`description.txt` is empty; `dish-notes.txt` is a darkroom "colourman" note. The
key insight is that the data is in the palette, not the picture:

> The frames are not where this is kept. Stack them, difference them, pull them
> apart to the last dot - you will be taking apart a picture of a plate ...
> What is not the same from frame to frame is the TRAY ... There is an order
> they OUGHT to lie in ... darkest to lightest ... red before green before blue.
> Ours does not lay them in that order. He works two to a slot and he is
> careless which of the two goes on the left ... When a colour moves, the
> picture does not, because he moves the picture with it.

## Initial Analysis

```bash
file pentimento.gif        # GIF, 11 frames
identify pentimento.gif
exiftool pentimento.gif
```

Two strong decoys:

- GIF comment: `Null0rigin{eleven_frames_and_none_of_them_true}`.
- The 11 frame **delays**, read as ASCII, spell `SEE FRAME 6`; near there sits
  another comment `Null0rigin{the_delay_between_frames_is_the_message}`.

The notes warn that the frames (and the planted delay/comment trail) are a dead
end.

## The Vulnerability / Core Concept

An indexed GIF stores a **palette** (numbered colour list) plus pixels that are
just indices into it. Swap palette entries 20 and 21 *and* swap every pixel
numbered 20 with every pixel numbered 21, and the displayed image is byte-for-
byte identical — only the bookkeeping changed. That is the hidden channel.

Here every frame has its own 256-entry **local colour table**, deliberately
reordered:

1. Sort each frame's 256 colours into their "ought" order using the key
   `(r + g + b, r, g, b)` — brightness, with RGB as tie-breaker.
2. The file stores them as 128 **adjacent pairs**. A pair in intended order is
   `0`, a reversed pair is `1`.
3. 128 bits/frame = 16 bytes; 11 frames = **176 encrypted bytes**, read low index
   to high and frames in animation order.

Decrypt with the chain keystream (`k = SHA256(previous flag)`). The notes'
final warning matters operationally: any image tool that "optimizes" or rebuilds
the palette on save destroys the ordering while leaving the picture intact — so
the solver must parse the raw GIF bytes, never load-and-resave.

## Exploitation

`solve_pentimento.py` walks the GIF container by hand (header, logical screen
descriptor, extensions, image descriptors), grabs each frame's raw local colour
table, and decodes the pair directions:

```python
intended = sorted(colours, key=lambda rgb: (sum(rgb), *rgb))
rank = {c: i for i, c in enumerate(intended)}
current = [rank[c] for c in colours]
for i in range(0, 256, 2):
    assert set(current[i:i+2]) == {i, i+1}       # must be an adjacent swap
    bits.append(int(current[i] == i + 1))        # intended=0, swapped=1
```

Then XOR with the keystream and verify:

```text
Stamp: b'PL8'   Issue: 1   Payload length: 54
Stored CRC32: aafa72c7   Actual CRC32: aafa72c7
Payload: b'Null0rigin{keep_the_grain_and_burn_the_chaff}\x1f\xbd?`\xa8\xe2t\x9c\x15'
```

(Pentimento's share for Mordant is the trailing `bd3f60a8e2749c15`.)

## Flag

`Null0rigin{keep_the_grain_and_burn_the_chaff}`

## Key Takeaways

- Indexed-image palette *order* is a hidden channel: permuting palette entries
  and remapping pixel indices leaves the rendered image unchanged.
- Parse the container format directly when the hidden state is fragile; loading
  via Pillow/ImageMagick and re-saving will silently normalize the palette and
  wipe the data.
- GIF frame delays, comments, and animation tricks are classic bait — here they
  even form a readable `SEE FRAME 6` breadcrumb to pull you off course.
