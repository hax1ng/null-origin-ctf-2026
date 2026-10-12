# Crypto

Cryptography challenges from **Null Origin CTF 2026 — Qualifier**.

Both challenges below are stages of the "crypto chain": a sequence of sealed
puzzles solved in order. Each one hides its real flag inside an encrypted blob
and seeds the area with convincing decoy flags, so the intended path is always
to *break the scheme*, never to `grep` for `Null0rigin{`.

| Challenge | Difficulty | Points | Flag |
| --------- | ---------- | -----: | ---- |
| [Bindery](./bindery/) | Easy | 250 | `Null0rigin{you_counted_in_a_base_she_never_named}` |
| [Daybook](./daybook/) | Easy | 250 | `Null0rigin{you_ran_a_dead_process_backwards}` |

- **Bindery** — a huge "random" file is really a base-3 document behind a
  ternary LFSR stream cipher over GF(3). A repeated known-plaintext header plus
  a state that never resets turns key recovery into a small linear solve mod 3.
- **Daybook** — a 401 MB core dump of a crashed process holds the ciphertext,
  the JIT-generated cipher code, and the cipher's final state. Invert the
  reversible permutation to run the dead process backwards and decrypt the
  journal.
