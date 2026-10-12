# The Forgotten Alias

**Category:** OSINT | **Difficulty:** Insane | **Points:** 500 | **Flag:** `NullOriginCTF{mastermind_Cyph3rWa1t}`

## Challenge Description

> It happened about two years ago. Exactly two people played together. Their team appeared at Position 77. One of them would later become the captain.
>
> Names change. Teams disappear. Profiles are abandoned.

**Flag format:** `NullOriginCTF{username1_username2}`

No download, no binary, no ciphertext. This is a pure OSINT identity-and-attribution hunt: the evidence lives somewhere public on the internet, and we have to reconstruct a long-forgotten event from a handful of abstract clues.

## Initial Analysis

The description hands us four concrete facts to anchor on:

1. The event happened **two years ago** (the CTF ran in 2026, so ~2024).
2. Exactly **two people** played together (a pair, not a full team).
3. Their team placed at **Position 77**.
4. One of the two players **later became a captain**.

Crucially, the goal is **not** the players' real names. We need the two **usernames/aliases they used at that specific event**. The closing lines — *"Names change. Teams disappear. Profiles are abandoned."* — are a warning that current profiles will be a dead end. The answer is frozen in an *old* artifact, not a live page.

The hardest part of an OSINT chain like this is the *entry point*. "Rank 77 at some 2024 CTF" matches thousands of teams. We need a clue specific enough to collapse the search space — and that's clue #4.

## The Investigation (Core Pivots)

The solve hinges on recognizing which clue is the "key" and which are "confirmation":

- **Pivot 1 — the captain (the key).** "Would later become the captain" is the only clue tied to a *named role* we can look up directly. Identify the captain and the entire problem shrinks from "every 2024 CTF" to "one specific person's history."
- **Pivot 2 — the abandoned trail.** Current profiles use newer handles, so we follow the captain's *older* social media, where the forgotten event is still documented.
- **Pivot 3 — the screenshot, not the names.** The old post contains the real names, but it *also* contains screenshots of the original leaderboard. The flag is in the screenshot's member table, not in the prose.

## Walkthrough

### Step 1 — Identify "the captain"

This challenge comes from the Null Origin / **CyberHX** community, and the author handle is `Charlie01`, so the natural place to start is CyberHX's own team leadership.

The CyberHX website (`https://cyberhx.com/`) names **Mithun M. Achary** as the captain of the team **CyberXoX**. His more recent CTF identity is **Charlie001** — which lines up neatly with the challenge author `Charlie01`. That's a strong confirmation we have the right person.

With the captain identified, the question transforms from an impossible broad search into something tractable:

> Which older CTF did Mithun play in a **two-person** pairing, and what aliases did they use?

### Step 2 — Follow the captain's older trail

Live profiles weren't directly useful — handles and team pages had been updated and mostly showed recent events. That's exactly what *"Names change. Teams disappear. Profiles are abandoned."* predicted. So we dig into **older** posts.

Searching Mithun's older CTF activity surfaces a LinkedIn post:

- `https://www.linkedin.com/posts/mithun-m-achary-68aba0235_ctf-cybersecurity-teamwork-activity-7190046981925335040-1zwc`

The post reads (paraphrased): *as a bit of fun and to experience more CTF scenarios, he and a teammate teamed up for the SpringForward CTF and solved some challenges together.*

That one sentence is basically the challenge description written in plain English:

- it names the **event** (SpringForward CTF),
- it describes a **two-person** partnership,
- and it frames it as a small, fun side mission rather than a major campaign — matching the "forgotten" tone.

CTFtime's event page (`https://ctftime.org/event/2348/`) confirms **SpringForwardCTF** ran online **April 26–28, 2024** — squarely in the "about two years ago" window. Clue #1 confirmed.

### Step 3 — Do not stop at the real names

The post gives us the two real people who paired up. But those are **not** the requested flag values — the challenge explicitly wants the *aliases used during that event*.

Fortunately, the LinkedIn post includes **screenshots from the event itself**. One is the old CTF team page, showing:

```text
admin
77th place
2064 points
```

That matches clue #3 (Position 77) exactly. Below it is the member table:

| User name | Score |
|---|---:|
| `mastermind` | 1606 |
| `Cyph3rWa1t` | 458 |

A quick sanity check on the arithmetic:

```text
1606 + 458 = 2064   # matches the team total — this is the right screenshot
```

Everything lines up:

- **Event:** SpringForwardCTF 2024
- **Team:** `admin` (deliberately too-generic to search for on its own — another reason the captain clue was the real key)
- **Position:** 77th
- **Members:** `mastermind` and `Cyph3rWa1t`

One gotcha to read carefully: the second alias is `Cyph3rWa1t` — that's a **digit `1`** in `Wa1t`, not a lowercase `L`. Capital `C` as well.

## Why this was "Insane"

The difficulty wasn't reading the final screenshot — it was reaching it. The trail was built to be easy to lose:

- The captain has used several handles over time (e.g. `Charlie001`), so you can't just search one name.
- The team was called `admin` — hopelessly generic to search by itself.
- Brute-forcing every 2024 CTF leaderboard for a rank-77 team returns endless unrelated results.
- The original hosted CTF service is no longer a reliable starting point.

The intended shortcut is the captain clue. Once you identify the future captain, a single old social-media post preserves the forgotten event, the partnership, the position, and both aliases all in one place.

## Flag

Reading the member list top to bottom:

```text
NullOriginCTF{mastermind_Cyph3rWa1t}
```

`NullOriginCTF{mastermind_Cyph3rWa1t}`

## Key Takeaways

- **Find the one clue that names a lookup-able entity.** Of four clues, only "the captain" pointed at something directly searchable. Spend your energy on the key clue and use the rest as confirmation.
- **Old artifacts over live profiles.** When a challenge warns that names/teams/profiles change, the answer is frozen in an archived post, an old screenshot, or a cached page — not a current page.
- **Social media preserves CTF history.** Players love posting leaderboard screenshots. A LinkedIn/Twitter brag post is often the cleanest primary source for a "forgotten" event.
- **Verify with arithmetic.** The member scores summing to the team total (1606 + 458 = 2064) confirmed the screenshot was authentic and complete.
- **Read aliases character by character.** `1` vs `l`, `0` vs `O`, capitalization — all matter in a flag. `Cyph3rWa1t` has a one, not an ell.

## Sources

- CyberHX — captain/team information: `https://cyberhx.com/`
- Mithun's SpringForwardCTF LinkedIn post (with the leaderboard screenshots): `https://www.linkedin.com/posts/mithun-m-achary-68aba0235_ctf-cybersecurity-teamwork-activity-7190046981925335040-1zwc`
- SpringForwardCTF 2024 on CTFtime: `https://ctftime.org/event/2348/`
