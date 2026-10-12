# Null Origin CTF 2026 — Qualifier

Writeups, solve scripts, and exploits for the challenges solved during the **Null Origin CTF 2026 Qualifier** — a 12‑hour qualifier run by the CyberHX community.

| | |
|---|---|
| **Event** | Null Origin CTF 2026 — Qualifier |
| **Dates** | 18 September 2026, 00:30 – 12:30 EDT (12‑hour window) |
| **Player** | [hax1ng](https://github.com/hax1ng) |
| **Solved** | **30 challenges** across 7 categories |
| **Flag format** | `NullOriginCTF{...}` (see note below) |

> **Flag‑format note.** The platform format is `NullOriginCTF{...}`. Several of the event's multi‑stage *chains* (reversing, stego, forensics, boot2root, crypto) instead emit an internal **`Null0rigin{...}`** seal — note the **zero** and the missing `CTF`. These are reproduced verbatim in each writeup; they are the real per‑stage flags, not typos.

---

## Overview

The qualifier was unusually chain‑heavy: instead of standalone tasks, most points lived in **linked multi‑stage chains** where each stage's answer feeds the next. The recurring design trick across the whole event was **misdirection at scale** — enormous "evidence" blobs (hundreds of MB), planted decoy flags, self‑modifying code, and anti‑debug theatre layered on top of a small, clean mathematical core. The winning move was almost always to *ignore the bulk* and find the few bytes that actually mattered.

Highlights by chain:

- **Reversing** — a seven‑stage keygen chain built on one shared engine: a five‑round SHA‑256 + splitmix64 cascade whose per‑stage checks reduce to **GF(2) linear systems**. Giant dumps, base‑4 stego, and thousands of decoy flags are all bait.
- **Steganography** — an eight‑stage chain over a shared "PL8 record" format and a SHA‑256 key schedule, hiding data everywhere from alpha‑channel LSBs to GIF palette ordering to **DEFLATE literal/back‑reference choices**.
- **Forensics** — filesystem and capture forensics: FAT allocation‑pattern bitmaps, RTP marker‑bit stream selection, page‑table‑hidden framebuffers, ext4 deleted‑inode extent recovery, and a two‑time‑pad break from a cloned VM that never reseeded its PRNG.
- **Boot2Root** — a four‑box Linux chain (`smoke → blackdamp → stillwater → deadlight`) where each box's root flag partially keys the next box's final seal.
- **Crypto**, **OSINT**, and **Web** rounded out the board.

---

## Solved Challenges

### 🔧 Reversing — `rev/`
A single 7‑stage keygen chain. Flags use the internal `Null0rigin{...}` format. [Chain overview →](rev/README.md)

| # | Challenge | Difficulty | Points | Flag | Writeup |
|--:|-----------|------------|-------:|------|---------|
| 21 | cinder | Easy | 250 | `Null0rigin{you_stepped_where_it_would_not_read}` | [→](rev/21-cinder/README.md) |
| 22 | dovetail | — | 250 | `Null0rigin{the_loader_never_read_the_label}` | [→](rev/22-dovetail/README.md) |
| 23 | quicklime | Medium | 400 | `Null0rigin{you_kept_the_last_eleven_bits}` | [→](rev/23-quicklime/README.md) |
| 24 | palimpsest | Medium | 400 | `Null0rigin{the_table_wrote_itself_at_dawn}` | [→](rev/24-palimpsest/README.md) |
| 25 | ouroboros | Hard | 650 | `Null0rigin{you_found_where_it_eats_its_own_tail}` | [→](rev/25-ouroboros/README.md) |
| 26 | deadman | Hard | 650 | `Null0rigin{you_held_it_exactly_right}` | [→](rev/26-deadman/README.md) |
| 27 | hourglass *(meta)* | Insane | 1000 | `Null0rigin{you_were_the_input_all_along}` | [→](rev/27-hourglass/README.md) |

### 🖼️ Steganography — `stego/`
An 8‑stage chain over a shared record format and key schedule. [Chain overview →](stego/README.md)

| # | Challenge | Difficulty | Points | Flag | Writeup |
|--:|-----------|------------|-------:|------|---------|
| 31 | driftwood | Easy | 250 | `Null0rigin{what_the_negative_kept_from_the_print}` | [→](stego/31-driftwood/README.md) |
| 32 | safelight | Easy | 250 | `Null0rigin{two_cells_of_equal_weight_are_not_equal}` | [→](stego/32-safelight/README.md) |
| 33 | moire | Medium | 400 | `Null0rigin{a_carrier_laid_across_the_whole_room}` | [→](stego/33-moire/README.md) |
| 34 | undertone | Medium | 400 | `Null0rigin{the_order_of_the_colours_is_the_message}` | [→](stego/34-undertone/README.md) |
| 35 | pentimento | Hard | 600 | `Null0rigin{keep_the_grain_and_burn_the_chaff}` | [→](stego/35-pentimento/README.md) |
| 36 | winnow | — | — | `Null0rigin{nothing_takes_until_it_is_fixed}` | [→](stego/36-winnow/README.md) |
| 37 | mordant | Insane | 1000 | `Null0rigin{he_set_two_sorts_where_one_would_do}` | [→](stego/37-mordant/README.md) |
| 38 | quietus | Insane | 1000 | `Null0rigin{the_channel_closes_from_the_inside}` | [→](stego/38-quietus/README.md) |

### 🔬 Forensics — `forensics/`
[Chain overview →](forensics/README.md)

| # | Challenge | Difficulty | Points | Flag | Writeup |
|--:|-----------|------------|-------:|------|---------|
| 14 | slackwater | Easy | 250 | `Null0rigin{ink_before_dawn}` | [→](forensics/14-slackwater/README.md) |
| 15 | handoff | — | — | `Null0rigin{the_right_feed_never_lied}` | [→](forensics/15-handoff/README.md) |
| 17 | greylist | — | — | `Null0rigin{the_second_buffer_never_ran}` | [→](forensics/17-greylist/README.md) |
| 18 | carrier | Hard | 600 | `Null0rigin{the_extents_outlived_the_name}` | [→](forensics/18-carrier/README.md) |
| 19 | revenant | Hard | 600 | `Null0rigin{the_clone_never_reseeded_the_rng}` | [→](forensics/19-revenant/README.md) |

### 🖥️ Boot2Root — `boot2root/`
A 4‑box chain; each box exposes a **user** and a **root** flag, and each root flag helps key the next box. [Chain overview →](boot2root/README.md)

| # | Box | Difficulty | Flags (user / root) | Writeup |
|--:|-----|------------|---------------------|---------|
| 1 | smoke | Entry | `the_wordlist_was_the_target_all_along` / `two_figures_off_a_payroll_sheet` | [→](boot2root/00-smoke/README.md) |
| 2 | blackdamp | Medium–Hard | `the_seam_number_was_two_of_the_four` / `you_paid_for_every_candidate` | [→](boot2root/28-blackdamp/README.md) |
| 3 | stillwater | Hard | `you_rode_the_cycle_instead_of_reading_it` / `the_sump_empties_on_its_own_schedule_not_yours` | [→](boot2root/29-stillwater/README.md) |
| 4 | deadlight | Hard (rev + crypto) | `the_lamp_told_you_by_going_out` / `a_deadlight_is_a_reading_not_a_failure` | [→](boot2root/30-deadlight/README.md) |

*(Boot2Root flags are shown without the `Null0rigin{…}` wrapper to keep the table readable; full flags are in each writeup.)*

### 🔐 Crypto — `crypto/`
[Category overview →](crypto/README.md)

| Challenge | Difficulty | Points | Flag | Writeup |
|-----------|------------|-------:|------|---------|
| Bindery | Easy | 250 | `Null0rigin{you_counted_in_a_base_she_never_named}` | [→](crypto/bindery/README.md) |
| Daybook | Easy | 250 | `Null0rigin{you_ran_a_dead_process_backwards}` | [→](crypto/daybook/README.md) |

### 🔎 OSINT — `osint/`
[Category overview →](osint/README.md)

| Challenge | Difficulty | Points | Flag | Writeup |
|-----------|------------|-------:|------|---------|
| The Forgotten Frames | Hard | 300 | `NullOriginCTF{lia_toklikishvili}` | [→](osint/forgotten-frames/README.md) |
| The Forgotten Alias | Insane | 500 | `NullOriginCTF{mastermind_Cyph3rWa1t}` | [→](osint/forgotten-alias/README.md) |
| Sanity - 3 | Easy | 150 | `Null0rigin{A_R3view_T0_R3m3mb3r}` | [→](osint/sanity-3/README.md) |

### 🌐 Web — `web/`
[Category overview →](web/README.md)

| Challenge | Difficulty | Points | Flag | Writeup |
|-----------|------------|-------:|------|---------|
| CTFCeption | Medium | 200 | `NullOrigin{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}` | [→](web/ctfception/README.md) |

---

## Notable solves

- **hourglass** *(Reversing, Insane / 1000)* — the chain's meta capstone: its challenge transcript is seeded from **all six prior reversing flags**. Solving it means enumerating 81 guest execution paths × a timing bit and letting the embedded checkpoints filter down to the single valid route.
- **mordant** & **quietus** *(Stego, Insane / 1000 each)* — mordant hides data in PNG **scanline‑filter bytes** behind two XOR locks (the previous flag *and* six 8‑byte shares from earlier stages); quietus encodes bits in **DEFLATE literal‑vs‑backreference choices**, requiring a custom fixed‑Huffman parser.
- **The Forgotten Alias** *(OSINT, Insane / 500)* — a multi‑hop identity pivot from a CTF captain → a years‑old LinkedIn post → an old leaderboard screenshot that yields two linked aliases.
- **revenant** *(Forensics, Hard / 600)* — a clean **two‑time‑pad** break: a cloned VM resumed without reseeding its PRNG, so two framebuffers shared a keystream.

---

## Repository layout

```
null-origin-ctf-2026/
├── rev/          # 7-stage reversing keygen chain
├── stego/        # 8-stage steganography chain
├── forensics/    # filesystem / capture forensics
├── boot2root/    # 4-box Linux privilege-escalation chain
├── crypto/       # custom cipher recovery
├── osint/        # investigation / attribution
└── web/          # client-side crypto chain
```

Each challenge directory contains a `README.md` writeup plus the final solve script(s) and any small, relevant source/clue artifacts. Every category folder has its own index `README.md`.

## Notes

- Large original challenge artifacts (disk images, memory dumps, multi‑hundred‑MB "evidence" blobs, media carriers, and challenge binaries) are **not** committed — they are described in the writeups, and the solve scripts read them from the working directory when run locally.
- All material has been scrubbed of infrastructure details (internal IPs, hostnames, credentials, tokens, keys). Target IPs in the boot2root writeups are shown as `<TARGET_IP>`. Any credentials that remain are **challenge‑intrinsic values** for ephemeral lab VMs that no longer exist.
- Challenge content, flavor text, and author handles belong to the Null Origin / CyberHX organizers and challenge authors.

*Writeups are published for educational purposes.*
