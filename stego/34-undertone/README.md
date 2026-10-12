# UnderTone

**Category:** Steganography | **Difficulty:** Medium | **Points:** 400 | **Flag:** `Null0rigin{the_order_of_the_colours_is_the_message}`

Stage 4 of the Null0rigin Stego Chain. Previous seal (the key):
`Null0rigin{a_carrier_laid_across_the_whole_room}`.

## Challenge Description

`description.txt` is empty; `line-notes.txt` is a telephone engineer's note. The
load-bearing lines:

> The left leg is where the work is. You will not find the message in any one
> part of the left leg ... It is laid down the whole length, thin enough to sit
> under the noise ... Adding a great many seconds of it together, with the right
> thing to add them against, will.

And a gift — a worked example recording keyed on a known phrase:

> LINETEST ... is keyed on its own name and nothing else - the two words LINE
> TEST, capitals, one space ... It says: `NULL0RIGIN LINE TEST 1 OF 1`

## Initial Analysis

```bash
file *.wav
# both: RIFF WAVE, Microsoft PCM, 16 bit, stereo 44100 Hz
exiftool undertone.wav
```

`exiftool` dangles a decoy in the metadata:
`Comment: line 4 pair 2, tone only - NullOrigin{a_carrier_laid_across_the_room}`
— wrong `NullOrigin` (no zero) and the wrong words. The notes explicitly say the
**right channel is just tone** and that someone already tampered with it; the
real work is in the **left channel**.

## The Vulnerability / Core Concept

"Laid down the whole length, thin enough to sit under the noise" plus "add many
seconds together against the right thing" describes **direct-sequence spread
spectrum (DSSS)**:

- The hidden signal is far quieter than the line noise.
- A secret pseudo-random chip sequence is mixed in.
- One sample tells you nothing; but if you reproduce the same chip sequence and
  correlate over thousands of samples, the noise averages out while the hidden
  bit accumulates.

The chip sequence comes from the chain's usual schedule — `k = SHA256(secret)`,
then `SHA256(k || BE32 counter)` bits — mapped to **+1/-1 chips** (bit 0 -> +1,
bit 1 -> -1).

**`linetest.wav` is the Rosetta Stone.** Keyed on `LINE TEST` with known
plaintext `NULL0RIGIN LINE TEST 1 OF 1`, it lets you nail down every unknown
(channel, chip polarity, integration length, bit order) before touching the real
file. The decoder that works on it:

1. `k = SHA256("LINE TEST")`; expand the counter keystream to bits.
2. Map bits to +1/-1 chips.
3. Multiply each left-channel sample by its chip (despread — squaring +/-1
   removes the chip, so a true data bit keeps one sign across its block while
   noise cancels).
4. Average every **2,048 samples** into one score; score > 0 -> bit 0, < 0 -> 1.
5. Pack MSB-first; parse the PL8 record (CRC32 `c14f017d` over
   `NULL0RIGIN LINE TEST 1 OF 1` confirms the whole method).

## Exploitation

`solve_undertone.py` applies the identical method to `undertone.wav`, swapping
the key input from `LINE TEST` to the previous flag:

```python
left = wavfile.read("undertone.wav")[1][:, 0].astype(np.float64)
key = sha256(PREVIOUS_SEAL).digest()
chips = 1.0 - 2.0 * np.unpackbits(np.frombuffer(stream, np.uint8))[:len(left)]
scores = (left * chips)[:bits*2048].reshape(bits, 2048).mean(axis=1)
bits = (scores < 0).astype(np.uint8)        # positive -> 0, negative -> 1
```

Output:

```text
Sample rate: 44100   Issue: 1   Payload length: 60
Stored CRC32: 794445c1   Calculated CRC: 794445c1
Payload: b'Null0rigin{the_order_of_the_colours_is_the_message}\x1fU\xc2\xe7\x91@\xab=\x08'
```

(UnderTone's share for Mordant is the trailing `55c2e79140ab3d08`.)

## Flag

`Null0rigin{the_order_of_the_colours_is_the_message}`

## Key Takeaways

- Spread-spectrum audio stego can't be found by staring at a spectrogram — you
  must **correlate against the exact chip sequence** and integrate over a block.
- Multiplying by a +/-1 chip twice cancels it (`(+/-1)^2 = 1`); that's why
  despreading recovers a sign-stable data bit while uncorrelated noise averages
  toward zero.
- A provided "test" artifact with known key *and* known plaintext is a worked
  example — solve the small one first, then rerun with the real key.
