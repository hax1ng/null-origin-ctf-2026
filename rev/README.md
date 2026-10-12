# Reversing — Null Origin CTF 2026 (Qualifier)

A seven-stage reverse-engineering **chain**. Every challenge is a *keygen-me*: it never stores the flag, it checks a mathematical property of the candidate you supply. Under the hood they share one engine — a five-stage **SHA-256 + splitmix64 cascade** whose per-stage checks are **linear systems over GF(2)** (binary XOR algebra). The recurring break is that the earliest stage can't depend on the password or later state, so its full-rank system is solvable on its own and hands you the flag (or a perfect flag oracle); the rest of each binary — giant embedded blobs, thousands of decoy flags, self-modifying code, anti-debug theatre — is misdirection.

Stages open in order (21 → 26); **27-hourglass** is the meta, requiring all six prior flags together. Several stages also gate an "accepted" message behind a `$6$` SHA-512-crypt password built to a shared **site-wide credential standard** (see [`credential_standard.txt`](./credential_standard.txt)) — needed for the binary to say yes, never needed to recover the flag.

> **Flag format:** these challenges use the **chain-internal** `Null0rigin{...}` format — note the **zero** in `Null0rigin`. This is distinct from the platform-level `NullOriginCTF{...}` format used elsewhere in the event.

| # | Challenge | Difficulty | Points | Flag |
|---|-----------|------------|-------:|------|
| 21 | [cinder](./21-cinder/README.md) | Easy | 250 | `Null0rigin{you_stepped_where_it_would_not_read}` |
| 22 | [dovetail](./22-dovetail/README.md) | — | 250 | `Null0rigin{the_loader_never_read_the_label}` |
| 23 | [quicklime](./23-quicklime/README.md) | Medium | 400 | `Null0rigin{you_kept_the_last_eleven_bits}` |
| 24 | [palimpsest](./24-palimpsest/README.md) | Medium | 400 | `Null0rigin{the_table_wrote_itself_at_dawn}` |
| 25 | [ouroboros](./25-ouroboros/README.md) | Hard | 650 | `Null0rigin{you_found_where_it_eats_its_own_tail}` |
| 26 | [deadman](./26-deadman/README.md) | Hard | 650 | `Null0rigin{you_held_it_exactly_right}` |
| 27 | [hourglass](./27-hourglass/README.md) (meta) | Insane | 1000 | `Null0rigin{you_were_the_input_all_along}` |
