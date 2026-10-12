# Forensics — Null Origin CTF 2026 (Qualifier)

Writeups for the solved challenges in the **Forensics** chain. These challenges
share a running theme: every one buries you in plausible, flag-shaped decoys and
hides the real answer in the structure everyone overlooks — FAT allocation
state, RTP transport headers, page tables, deleted-inode extents, and reused
keystreams. The verifier locks after three genuine wrong guesses, so the skill
being tested is *filtering signal from planted noise*.

> These challenges use the chain-internal flag format `Null0rigin{...}` (with a
> zero), which differs from the event's public `NullOriginCTF{...}` format.

| # | Challenge | Difficulty | Points | Flag |
|---|-----------|------------|--------|------|
| 14 | [Slackwater](14-slackwater/README.md) | Easy | 250 | `Null0rigin{ink_before_dawn}` |
| 15 | [Handoff](15-handoff/README.md) | — | — | `Null0rigin{the_right_feed_never_lied}` |
| 17 | [GreyList](17-greylist/README.md) | — | — | `Null0rigin{the_second_buffer_never_ran}` |
| 18 | [Carrier](18-carrier/README.md) | Hard | 600 | `Null0rigin{the_extents_outlived_the_name}` |
| 19 | [Revenant](19-revenant/README.md) | Hard | 600 | `Null0rigin{the_clone_never_reseeded_the_rng}` |

## One-line summaries

- **Slackwater** — FAT32 card where the flag is drawn in the *allocation
  pattern* of orphan clusters (one bit per cluster → a bitmap), not in any file.
- **Handoff** — two RTP video streams in a pcap; the marker bit selects the real
  feed, whose payloads reassemble into scanlines of the flag.
- **GreyList** — a memory dump with a page-table-only (un-mapped) region holding
  two framebuffers masked with the same keystream; XOR reveals the flag.
- **Carrier** — ext4 image where the flag was split one char per file and
  deleted; recover the in-incident-window inodes by extent (`lsdel` + `icat`).
- **Revenant** — two VM suspends with an un-reseeded PRNG reuse one keystream; a
  two-time-pad break against a known template recovers the note.
