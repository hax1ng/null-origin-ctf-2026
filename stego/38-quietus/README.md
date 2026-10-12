# Quietus

**Category:** Steganography | **Difficulty:** Insane | **Points:** 1000 | **Flag:** `Null0rigin{the_channel_closes_from_the_inside}`

Stage 8 — the **final** stage of the Null0rigin Stego Chain. Previous seal (the
key): `Null0rigin{he_set_two_sorts_where_one_would_do}` (Mordant).

## Challenge Description

`description.txt` is empty; `press-notes.txt` is a composing-room note where
nearly every printing metaphor maps to a piece of DEFLATE compression:

> When the sort he wants next is one he has ALREADY SET ... he may take it from
> there - or he may go to the case and set it fresh. Both give the same line ...
> THREE CHARACTERS MAKE A LIGATURE. Never two, never four ... AND HE ALWAYS
> REACHED FOR THE NEAREST ONE ... note whether he did. That is the message.

| Printing clue | DEFLATE meaning |
|---|---|
| Pull a proof | Decompress to the plain bytes |
| A sort already set in the stick | Bytes already in the output history |
| Take it from there | Emit a back-reference |
| Go to the case and set it fresh | Emit a literal byte |
| Three characters make a ligature | Every match has length 3 |
| Always the nearest one | Smallest valid back-reference distance |
| Note whether he did | Back-ref vs literal = one hidden bit |

## Initial Analysis

```bash
file quietus.png        # PNG 320x240, 8-bit grayscale
exiftool quietus.png
pngcheck -vt quietus.png
```

One very convincing decoy in a `tEXt` comment:
`forme 3, set and locked up - Null0rigin{the_compositor_went_home_at_six}` —
reinforced by the note's closing line "He went home at six." As always in this
chain, a formatted string in metadata is not evidence; the real answer must come
out of the described channel and pass the PL8 CRC.

## The Vulnerability / Core Concept

PNG stores its filtered scanlines in a zlib/DEFLATE stream. DEFLATE describes
output two ways: a **literal** ("write this byte") or a **back-reference**
("copy bytes already written"). When the next 3 output bytes already exist in
the 32 KiB window, the compressor *could* use a length-3 back-reference to the
**nearest** distance, or it could spell them out as literals — both produce
identical bytes. That choice is the hidden bit:

```text
literal byte            -> 0
length-3 back-reference -> 1
```

`zlib.decompress` only gives the "proof" (final bytes) and throws the choices
away, so you need a **custom fixed-Huffman DEFLATE parser** that keeps the token
list. One easy-to-miss detail: DEFLATE back-references may **overlap** what
they're producing, so distances 1 and 2 are legal even when the full triple
wasn't present before the current position — and lots of runs of a dark pixel
value use distance-1 matches. Miss that and thousands of real matches look
invalid and the record won't decode.

Walking the tokens: at each point where a nearest-distance length-3 match was
possible, record whether the original stream took it. Those ~38,423 choice bits,
packed MSB-first, are decrypted with the chain keystream (`k = SHA256(previous
flag)`); only the leading PL8 record is meaningful.

## Exploitation

`solve_quietus.py` extracts the `IDAT` zlib stream, decodes the single final
fixed-Huffman block while retaining tokens, cross-checks the output against
`zlib.decompress`, derives the choice bits (handling overlapping distances 1-2),
decrypts, and validates:

```python
output, tokens = deflate_tokens(zlib_stream[2:-4])     # custom parser keeps tokens
assert output == zlib.decompress(zlib_stream)          # parser sanity check
bits = extract_choice_bits(output, tokens)             # literal=0, len-3 match=1
decoded = xor(pack_msb(bits), chain_stream(PREVIOUS_FLAG, n))
```

Output:

```text
Decompressed bytes: 77040   DEFLATE tokens: 38560   Choice bits: 38423
Record stamp: b'PL8'   Issue: 1   Payload length: 46
Stored CRC32: fbf8d730   Actual CRC32: fbf8d730
Flag: Null0rigin{the_channel_closes_from_the_inside}
```

The decompressed size matches the PNG geometry exactly
(`240 * (1 + 320) = 77040`), a good check that the custom parser is reading the
real stream.

## Flag

`Null0rigin{the_channel_closes_from_the_inside}`

## Key Takeaways

- The deepest layer of this chain hides data in **compressor decisions** — the
  literal-vs-back-reference choices DEFLATE makes — which survive decompression
  only if you parse the token stream yourself.
- Don't forget overlapping matches (distances 1-2); they're the common case for
  runs and are easy to wrongly reject.
- A fitting finale: even after the image decodes perfectly, the message lives in
  choices a normal decoder is designed to forget.
