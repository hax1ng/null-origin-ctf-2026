# Boot2Root — Null Origin CTF 2026 (Qualifier)

A four-machine **boot-to-root chain** themed as a decaying colliery ("Smokeholt / Blackdamp / StillWater / Deadlight"). Each box is a self-contained VM you attack over the network — no console, no given credentials — and each has **two** flags:

- **user.txt** — awarded for a foothold.
- **root.txt** — awarded for full compromise. On every box the root flag is a **sealed (encrypted) blob**: becoming root is necessary but not sufficient to open it, and the box tells you what the seal wants.

**The chain gates ROOT only.** You can work any box to its *user* flag independently, but opening a box's *root* seal requires the **previous box's root flag, exactly as submitted**, as a decryption-key ingredient:

```
00-smoke  ──root──▶  28-blackdamp  ──root──▶  29-stillwater  ──root──▶  30-deadlight
```

Recurring themes across all four boxes:

- A chain-wide **password policy** (`transformed site word + 2-digit seam + 3-digit shot + marker !@#$%&`) that, combined with leaked personnel records, collapses every account to a ~6000-candidate keyspace.
- **Restricted-shell escapes** via an over-powerful allowed program (`awk`, a pager's `!`, `sort -o`).
- A **4-second writable-window race** that lets you overwrite a script that's about to run as another user.
- **Path-traversal / off-by-one** bugs in small privileged services for arbitrary root-readable file access.
- Home-rolled **seal crypto** (SHA-256 keystream XOR) plus live-only gates (TOTP, boot-id) that *look* mandatory but never feed the decryption key.
- Lots of convincing **decoy flags** — only sealed files (and, on Deadlight, published commitment hashes) separate real from bait.

> **Flag format note:** the public CTF flag format is `NullOriginCTF{...}`, but this internal chain uses `Null0rigin{...}` (with a zero) for its chain-internal seal flags — preserved exactly as the boxes emit them.

## Boxes

| # | Box | Difficulty | Points | Flag(s) |
|---|-----|-----------|--------|---------|
| 1 | [00-smoke](00-smoke/README.md) | Entry | — | user `Null0rigin{the_wordlist_was_the_target_all_along}` · root `Null0rigin{two_figures_off_a_payroll_sheet}` |
| 2 | [28-blackdamp](28-blackdamp/README.md) | Medium–Hard | — | user `Null0rigin{the_seam_number_was_two_of_the_four}` · root `Null0rigin{you_paid_for_every_candidate}` |
| 3 | [29-stillwater](29-stillwater/README.md) | Hard | — | user `Null0rigin{you_rode_the_cycle_instead_of_reading_it}` · root `Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}` |
| 4 | [30-deadlight](30-deadlight/README.md) | Hard | — | user `Null0rigin{the_lamp_told_you_by_going_out}` · root `Null0rigin{a_deadlight_is_a_reading_not_a_failure}` |

Each box directory contains a full write-up (`README.md`) and the cleaned solve scripts. Target IP addresses are redacted as `<TARGET_IP>` (and listener addresses as `<ATTACKER_IP>`); the ephemeral lab VMs no longer exist, so the cracked challenge credentials are kept inline as part of the educational walkthrough.
