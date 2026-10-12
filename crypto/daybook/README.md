# Daybook

**Category:** Crypto / Reversing | **Difficulty:** Easy | **Points:** 250 | **Flag:** `Null0rigin{you_ran_a_dead_process_backwards}`

## Challenge Description

> A daybook is what you keep when you do not trust your memory of the day.
> This one stops mid-sentence.

Stage `07-daybook` of the Null Origin crypto chain. What you get:

```text
core.5711        401 MB Linux core dump, "from './daybook'"
daybook.sealed   398-byte custom encrypted-looking file
verify           flag checker (statically linked, stripped)
description.txt
```

```console
$ file core.5711 daybook.sealed verify
core.5711:      ELF 64-bit LSB core file, x86-64, from './daybook'
daybook.sealed: data
verify:         ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

A **core dump is a frozen photograph of a program's memory**. The original
`daybook` binary is missing, but anything it had loaded, generated, or was
processing at the crash is still in the dump. That fits the flavor text: the
process stopped, but its memory of the day survived. (`daybook.sealed` turns
out to be a red herring — everything needed is in the core.)

## Initial Analysis

The reflex — `strings` / `grep` — finds flags, but they're all bait:

```console
$ grep -aob 'Null0rigin{' core.5711
196624:Null0rigin{
138050704:Null0rigin{
...
Null0rigin{close_enough_to_waste_ten_minutes_on}
Null0rigin{grep_is_not_reverse_engineering}
Null0rigin{the_string_is_not_the_secret}
Null0rigin{if_it_was_this_easy_it_would_not_be_here}
```

So inspect the memory layout instead. `readelf -l core.5711` shows two
interesting regions:

```text
offset 0x00030000  VA 0x7f3294000000  size 0x19001000  RW    <- huge data arena
offset 0x19031000  VA 0x7f32ad001000  size 0x10000     RWE   <- JIT code!
```

The first is an enormous writable allocation full of neat 64-byte journal
records:

```text
                ENT 0031ffff  q=eb59  p=fda5  ref=32f6ab\n
```

The second is readable, writable **and executable**. Normal data doesn't need
execute permission, so this is runtime-generated (JIT) machine code — the
cipher the program built for itself.

## The Vulnerability / Core Concept

Three pieces of the crashed process line up perfectly:

**1. The ciphertext is pasted into the journal.** Splitting the big arena into
64-byte records and scanning for the longest run that *isn't* the normal text
format reveals a binary payload spanning records `0x320000`..`0x3203c1`:

```python
arena = 0x30000
start = arena + 0x320000 * 64 + 16   # 0x0c830010
end   = arena + 0x3203c1 * 64 + 32   # 0x0c83f060
payload = core[start:end]            # 61,520 bytes
```

The last 16 bytes are an authentication tag; the remaining 61,504 bytes are
`61504 / 16 = 3844` cipher blocks — a clean block count, confirming we found
the intended ciphertext.

**2. The cipher is a reversible keystream.** Disassembling the JIT segment
(`objdump -D -b binary -m i386:x86-64 jit.bin`) gives four routines:

| JIT offset | Purpose                                   |
| ---------: | ----------------------------------------- |
|    `0x000` | permute a 40-byte state over 12 rounds    |
|    `0x0c0` | CRC32C                                     |
|    `0x110` | encrypt/decrypt a 16-byte block           |
|    `0x190` | produce the final 16-byte trailer / tag   |

The stream routine at `0x110` is essentially:

```text
for each 16-byte block:
    state  = permutation(state)
    output = input XOR state[0:16]
```

The input is XORed in and immediately restored, so it never permanently
changes the state — only the permutation advances it. Because XOR is
symmetric, the *same* routine decrypts given the right starting state.

**3. The process left its final state behind.** A 40-byte global at VA
`0x4b4ac0` (core offset `0x7ac0`) holds the state at crash time, and its first
16 bytes equal the payload's tag — proof the state and ciphertext belong
together. The trailer routine at `0x190` does one extra permutation then XORs
the first 16 state bytes with the constants:

```text
4a 52 4e 4c ff ff ff ff 55 54 52 41 49 54 45 52
J  R  N  L              U  T  R  A  I  T  E  R
```

So there's **no key to find** — the whole state is sitting in the dump. The
route back to the initial state is: strip the trailer mask, invert the
permutation once (undo the trailer), invert it 3,844 more times (one per
block), then replay the stream routine to decrypt. We literally run the dead
process backwards.

## Exploitation

The permutation uses only reversible ops (XOR, rotations, boolean combos), so
one inverse round undoes it exactly. [`inv.c`](./inv.c) implements the inverse
rounds; [`solve.py`](./solve.py) maps the JIT bytes as executable memory,
reverses the state via `inv.so`, and calls the recovered stream routine.

```console
$ gcc -shared -fPIC -O3 -o inv.so inv.c
$ python3 solve.py          # needs core.5711 in the working directory
day 1. the index went out this morning. three words on the notice.
day 2. the register is the wrong shape and I am leaving it that way.
day 3. not a confession. a specification. each flaw chosen and sized.
day 4. Null0rigin{you_ran_a_dead_process_backwards}
day 5. stage 03 -- the bench notes are on the wire, not in any file
...
```

The decrypted data is a stream of proper `JRNL` entries (see
[`daybook.plain`](./daybook.plain)); the flag repeats across them, so it's not
an accidental string.

> Note: `core.5711` (401 MB) is the challenge's intrinsic data file and is too
> large to include here. The solver reads it from the working directory.

## Flag

`Null0rigin{you_ran_a_dead_process_backwards}`

SHA-256 `c631b7304917a87b2d36d25a8d857ce66a6b6a40af4db61953648e5eeaade131`,
matching `verify` — `./verify 'Null0rigin{...}'` returns `CORRECT. daybook solved.`

## Key Takeaways

- **A core dump is a crime scene with everything left in place.** Ciphertext,
  the generated cipher code, the auth trailer, and the final state were all in
  one 401 MB file.
- **`RWE` memory screams JIT.** Writable *and* executable mappings are almost
  always runtime-generated code — disassemble them.
- **Reversible permutations run backwards.** If every round op is invertible
  (XOR/rotate/boolean-recoverable), you can walk a keystream cipher's state
  back to its origin — no key search required.
- **`grep` is not reverse engineering.** The plaintext decoys were there to
  waste time; the real flag only falls out of actually decrypting.
