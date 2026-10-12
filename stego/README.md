# Null Origin CTF 2026 — Steganography

An eight-stage **stego chain** by Maharaga. The stages are meant to be solved in
order: each flag is the key to the next. The chain shares a single, consistent
design that's worth internalizing before diving in:

- **Everything is keyed off the previous flag.** The operator's card
  (introduced in [SafeLight](32-safelight/README.md)) defines the schedule:
  `k = SHA256(previous_flag_exactly_as_written)`, and a keystream
  `SHA256(k || counter)` with a 4-byte big-endian counter, combined with the
  extracted bytes by XOR. A seal one character off is simply a different key and
  yields nothing — no partial credit, no signal.
- **Every genuine payload is a `PL8` record.** 3-byte `PL8` stamp, 1-byte issue,
  2-byte little-endian length, 4-byte little-endian CRC32, then the payload. The
  stamp + CRC are the *only* trustworthy proof you found the real flag.
- **The decoys are excellent.** Every stage plants correctly-formatted fake
  flags in metadata, appended archives, LSBs, QR codes, even valid-CRC records.
  Format alone proves nothing; the keyed record is what counts.
- **Carriers are fragile — never re-save.** Several stages hide data in state
  that image tools normalize away (GIF palette order, PNG scanline filters,
  DEFLATE token choices). Parse the raw bytes; don't round-trip through an
  image library.
- **Keep the "junk."** Each PL8 payload carries 8 trailing bytes after the flag.
  They look like padding, but stages 1-6 each contribute one as a secret
  **share** that [Mordant](37-mordant/README.md) combines into a second key.

## Challenges

| # | Challenge | Difficulty | Points | Flag | Hidden channel |
|---|-----------|-----------|--------|------|----------------|
| 31 | [Driftwood](31-driftwood/README.md) | Easy | 250 | `Null0rigin{what_the_negative_kept_from_the_print}` | Alpha-channel LSB |
| 32 | [SafeLight](32-safelight/README.md) | Easy | 250 | `Null0rigin{two_cells_of_equal_weight_are_not_equal}` | Negative/print +/-1 deltas |
| 33 | [Moire](33-moire/README.md) | Medium | 400 | `Null0rigin{a_carrier_laid_across_the_whole_room}` | 4x4 halftone cell patterns |
| 34 | [UnderTone](34-undertone/README.md) | Medium | 400 | `Null0rigin{the_order_of_the_colours_is_the_message}` | Spread-spectrum audio |
| 35 | [Pentimento](35-pentimento/README.md) | Hard | 600 | `Null0rigin{keep_the_grain_and_burn_the_chaff}` | GIF palette ordering |
| 36 | [Winnow](36-winnow/README.md) | — | — | `Null0rigin{nothing_takes_until_it_is_fixed}` | Keyed per-frame LSB seals |
| 37 | [Mordant](37-mordant/README.md) | Insane | 1000 | `Null0rigin{he_set_two_sorts_where_one_would_do}` | PNG scanline filters + 6 shares |
| 38 | [Quietus](38-quietus/README.md) | Insane | 1000 | `Null0rigin{the_channel_closes_from_the_inside}` | DEFLATE literal/back-ref choices |

Each stage directory contains a full writeup (`README.md`), a cleaned,
self-contained solve script, and the in-universe "notes"/"card" text file that
holds the clues. Carrier media (PNG/GIF/WAV) are not included.
