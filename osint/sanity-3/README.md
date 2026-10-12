# Sanity - 3

**Category:** OSINT (Sanity) | **Difficulty:** Easy | **Points:** 150 | **Flag:** `Null0rigin{A_R3view_T0_R3m3mb3r}`

> **Flag format note:** this challenge uses the `Null0rigin{}` format (with a zero), *not* the event's usual `NullOriginCTF{}` prefix. Always submit exactly what the challenge specifies.

## Challenge Description

> Not every review is just a review.
>
> Curious about CyberHX?
>
> You know where to look. Find us, explore us, and maybe leave a little something behind.

## Initial Analysis

This is an easy "sanity" OSINT warm-up, and the whole challenge is in the wording. OSINT (Open-Source Intelligence) just means the answer is sitting in publicly available information online — no exploitation required, just knowing *where* to look.

Pulling the key words apart:

- **CyberHX** — the organization to investigate.
- **Find us** — go find its public business presence / location.
- **Review** — check customer reviews.
- **Leave a little something behind** — again points at a place where the public leaves reviews.

"Find a business, read its reviews, somewhere you can leave one" almost unambiguously describes a **Google Maps business listing**.

## The Investigation (Core Pivots)

- **Pivot 1 — locate the business.** Turn the org name into a physical/listed entity (website → city → Maps listing).
- **Pivot 2 — read *everything*, including replies.** "Not every review is just a review" is the real instruction: the payload isn't in a review's text, it's hidden in an **owner response** attached to a review.
- **Pivot 3 — recognize and decode the encoding.** The hidden string is Base64; decoding it yields the flag.

## Walkthrough

### 1. Find CyberHX on Google Maps

A quick search for CyberHX turns up its website:

- `https://cyberhx.com/`

The site lists CyberHX as based in **Bhopal, India**. Searching Google Maps for **CyberHX Bhopal** lands on its business listing:

- `https://www.google.com/maps?cid=1819986222520608165`

At solve time the listing had only a handful of reviews, so going through them by hand was quick.

### 2. Inspect the reviews — and their replies

Most reviews looked totally mundane:

```text
Good work
Happy hacking
Best cyber courses
```

But the description says **not every review is just a review**, which nudges us to also read the **owner's responses**, not just the review bodies.

The review titled **"Best cyber courses"** had a reply from the business owner that, instead of a normal sentence, contained a suspicious string:

```text
TnVsbDByaWdpbntBX1Izdmlld19UMF9SM20zbWIzcn0=
```

That has every hallmark of **Base64**: only letters/digits, length is a multiple of four, and it ends in `=` (padding).

### 3. Decode it

Base64 isn't encryption — it's just a printable-character representation of bytes, so a one-liner decodes it:

```bash
echo 'TnVsbDByaWdpbntBX1Izdmlld19UMF9SM20zbWIzcn0=' | base64 -d
```

Output:

```text
Null0rigin{A_R3view_T0_R3m3mb3r}
```

That matches the required `Null0rigin{}` format, confirming it's the flag.

## Flag

```text
Null0rigin{A_R3view_T0_R3m3mb3r}
```

`Null0rigin{A_R3view_T0_R3m3mb3r}`

## Key Takeaways

- **Read OSINT prompts literally.** "Find us," "review," and "leave something behind" were not flavor text — they were step-by-step directions to a Google Maps listing.
- **Check replies, not just the main content.** The flag was hidden in the *owner's response* to a review, which is exactly the kind of secondary field people forget to inspect. "Not every review is just a review."
- **Learn to eyeball Base64.** Alphanumeric string, length divisible by four, trailing `=` padding → decode it before assuming it's random noise.
- **Submit the exact format given.** This one used `Null0rigin{}` (zero), not the standard `NullOriginCTF{}` prefix — reading the per-challenge format mattered.
