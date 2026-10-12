# GreyList

**Category:** Forensics | **Flag:** `Null0rigin{the_second_buffer_never_ran}`

## Challenge Description

> A greylist is the space between allowed and forbidden.
> This is what was in the machine's head when the power went.

We're given:

- `physmem.img` — a small physical-memory dump
- `vma_list.txt` — the process's *self-reported* virtual-memory map
- `greylist.sealed` — confirmation material for after solving
- `verify` — the local flag checker

> Note: part of the internal forensics chain — chain-internal flag format is
> `Null0rigin{...}` (with a zero).

The short version: the process lied by omission. Its VMA list doesn't mention
every mapped region. Walking the page tables exposes a hidden memory area full
of bitmap buffers, and two of them XOR into an image of the flag.

## Initial Analysis

`strings` looks promising and is entirely a trap:

```bash
strings -a -t x physmem.img | head -20
```

```text
800018 session[0] cache entry -- last seen flag guess: Null0rigin{cached_and_wrong}
800065 session[1] cache entry -- last seen flag guess: Null0rigin{a_stale_pointer_smiled}
8000b8 session[2] cache entry -- last seen flag guess: Null0rigin{the_allocator_lied_once}
...
```

Six planted decoys, and a checker that allows only three real wrong attempts.
Don't feed it string soup.

## The Vulnerability / Core Concept

The supplied `vma_list.txt` claims process 4821 has exactly two regions — and
then protests a little too much (see the file, included here):

```text
0000000000400000-0000000000600000 r-xp  [kioskd binary]
0000000000600000-0000000000800000 rw-p  [heap]
# note: no third region below this line. there never was one.
```

That last line is practically an instruction: ignore the self-report and walk
the hardware's own translation tables instead. The dump opens with a `GREYMEM1`
marker and a deliberately simple page-table layout. Reading the page-table
entries:

```bash
xxd -g8 -s 0x200000 -l 0x40 physmem.img
xxd -g8 -s 0x400000 -l 0x60 physmem.img
```

```text
0x400007  0x600087  0x800087  0xa00087
```

Low bits are page flags; clear them and you get physical frame addresses.
Besides the binary and heap, there's a large-page mapping backed by physical
`0xa00000` — **not in `vma_list.txt` at all**. Thanks to the custom dump header,
that page's contents start at file offset `0xa00018`.

Near the end of the hidden page sit two little-endian `FBM1` framebuffer
descriptors:

```bash
xxd -s 0xa01e78 -l 0x40 physmem.img
```

```text
arena base:  0xa00000
pointer 1:   0xa01440
pointer 2:   0xa00a20
height:      0x24  = 36 pixels
width:       0x240 = 576 pixels
```

These are 1-bit-per-pixel buffers of `576 * 36 / 8 = 2592` (`0xa20`) bytes each.
Three candidate buffers sit back-to-back in the hidden allocation — at virtual
`0xa00000`, `0xa00a20`, `0xa01440`, i.e. file offsets `0xa00018`, `0xa00a38`,
`0xa01458`.

The trick: the first buffer is an **orphan** — no live descriptor still names
it, but its bytes are intact. Both the orphan and the second buffer were masked
with essentially the same random-looking material. XOR cancels what they share
and leaves the rendered difference: the flag text. (The third buffer is a decoy;
XOR against it is noise.)

## Exploitation

`solve_greylist.py` slices out all three buffers and writes every XOR pair as a
raw P4 PBM:

```python
from itertools import combinations
from pathlib import Path

mem = Path("physmem.img").read_bytes()
width, height = 0x240, 0x24
size = width * height // 8          # 0xa20
base = 0xA00018
buffers = [mem[base + i*size : base + (i+1)*size] for i in range(3)]

for i, j in combinations(range(3), 2):
    result = bytes(a ^ b for a, b in zip(buffers[i], buffers[j]))
    Path(f"pair-{i}-{j}.pbm").write_bytes(f"P4\n{width} {height}\n".encode() + result)
```

```bash
python3 solve_greylist.py
convert pair-0-1.pbm -scale 400% flag.png   # optional enlarge
```

`pair-0-2.pbm` and `pair-1-2.pbm` are noise. `pair-0-1.pbm` (orphan XOR second
buffer) reads the flag as pixel text. Verify:

```bash
./verify 'Null0rigin{the_second_buffer_never_ran}'
# CORRECT.  greylist solved.
```

## Flag

`Null0rigin{the_second_buffer_never_ran}`

## Key Takeaways

- A process's self-reported memory map can be incomplete or dishonest. The page
  tables are ground truth — walk PTEs, mask off flag bits, find the frame.
- Watch for custom dump headers: here a `0x18`-byte prefix shifted every
  physical-address → file-offset translation.
- Two buffers masked with the same keystream are a two-time pad: `XOR` cancels
  the shared mask and reveals the difference. A graphics framebuffer is a
  perfect carrier for that difference as readable text.
