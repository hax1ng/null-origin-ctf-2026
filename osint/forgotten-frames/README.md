# THE FORGOTTEN FRAMES

**Category:** OSINT | **Difficulty:** Hard | **Points:** 300 | **Flag:** `NullOriginCTF{lia_toklikishvili}`

## Challenge Description

> Five fragments of a fading breath. The lens remembers what the valley forgets. To find the voice, first find the stranger's stone. When the reel ends, look past the visible hands. The architect of the words wears two faces. One is seen. One is unseen.

**Flag format:** `NullOriginCTF{firstname_lastname}`

We're handed a ZIP that unpacks to five JPEG images: most show a remote green valley and the people living in it, and two show a badly damaged, weathered gravestone.

## Initial Analysis

First instinct on any image challenge is to check whether the answer is sitting in the file itself:

```bash
unzip Forgotten_Frames.zip
file Forgotten_Frames/*
exiftool Forgotten_Frames/*
```

All five files came back as ordinary JPEG screenshots. No useful GPS/EXIF location, no camera model, no author tag, no appended archive, no obvious stego payload. That's an important negative result: it tells us this is an **image-identification and research** challenge, not a metadata or steganography one. The flag lives out on the open internet, and these pictures are just our breadcrumbs.

So we turn to the one place the challenge practically begs us to look — the poem. The most actionable line is:

> To find the voice, first find the stranger's stone.

The mountain scenery is gorgeous but generic (hard to pin down a specific valley from grass and ridgelines). The gravestone, on the other hand, carries *text*, and text is searchable. That's our starting pivot.

## The Investigation (Core Pivots)

The whole solve is a chain of "decode the metaphor, then do the lookup." Each line of the poem maps to a concrete investigative step:

| Clue | Meaning | Action |
|---|---|---|
| "the stranger's stone" | a foreigner's grave | read the name off the gravestone |
| "the lens remembers" / "when the reel ends" | these are *video frames*, not photos | find the source film |
| "look past the visible hands" | don't stop at the on-screen credits | watch the *closing* credits |
| "the architect of the words wears two faces" | the screenwriter who appears in two credit roles | cross-reference the credit lists |

The genius (and the difficulty) is that none of these steps are guessable in isolation — each one only makes sense *after* you've nailed the previous one.

## Walkthrough

### 1. Read the stranger's stone

The fourth image showed the inscription most clearly. Bumping the contrast up made the Latin letters legible, and the key line was a name:

```text
ELFRIEDE KURELLA
```

Searching that name alongside context terms (`grave`, `Georgia`, `Khevsureti`, `Arkhoti`) surfaces the story of **Elfriede (also called Elpide) Kurella** — a German visitor who died in a horse-riding accident in the Georgian mountains in 1957. She and her husband, the German writer Alfred Kurella, had agreed that whoever died while travelling in the mountains would be buried there, so her grave remains in the **Arkhoti valley** in Georgia's **Khevsureti** region.

A Georgian article about the grave also drops two names that become useful a step later — folklorists **Amiran Arabuli** and **Eter Tataraidze**:

- Story of Elpide Kurella and the grave: `https://www.ambebi.ge/article/281951-xevsuretze-sheqvarebuli-germaneli-col-kmris-mistiur/`

At this point the five anonymous screenshots have a home: Arkhoti, Khevsureti, Georgia. "The voice of the valley" is no longer abstract.

### 2. Find the original reel

The vocabulary of the poem — `lens`, `frames`, `voice`, and especially *"when the reel ends"* — is a strong tell that these images are **stills pulled from a video**, not someone's photo album.

Searching for the grave, Arkhoti, and the folklorists named in the article leads to a Georgian Public Broadcaster documentary:

```text
გამაგრდით არხოტიონნო
```

Rendered in English as **"Stay Strong, Arkhotians."** Official page:

- `https://1tvplay.ge/movie/overview/gamagrdit-arkhotionno-filmi`

The documentary is about the culture and the disappearing settlements of the Arkhoti valley. Watching it confirms the hypothesis cleanly: all five supplied images are frames from this film — the valley, the gravestone, and the two men speaking outdoors.

The page lists these credits:

- **Authors:** Eter Tataraidze, Amiran Arabuli, and Lia Toklikishvili
- **Screenplay:** Lia Toklikishvili
- **Director:** Besik Gaprindashvili
- **Technical producer:** Nana Urushadze

Tempting to stop here — but the poem explicitly warns against it: *"When the reel ends, look past the visible hands."* The webpage credits are the "visible hands." The real answer is in the film's *closing* credits.

### 3. Read the end credits carefully

Two sections of the Georgian end credits matter:

**Film authors — `ფილმის ავტორები`**
```text
Lia Toklikishvili
Eter Tataraidze
Amiran Arabuli
```

**Screenplay authors — `სცენარის ავტორები`**
```text
Lia Toklikishvili
Giorgi Kekelidze
```

Here's the trap. The screenplay list on the end credits differs from the short credit on the webpage — it adds **Giorgi Kekelidze**. It's very tempting to conclude "the extra name is the answer." That's wrong, and the poem tells us why:

> The architect of the words wears two faces.

The "architect of the words" is a screenplay writer. But we specifically need the one who wears **two faces** — i.e., appears in *two* roles across these credits. Cross-referencing the two lists:

```text
Film author list       Screenplay author list
----------------       ----------------------
Lia Toklikishvili  <-> Lia Toklikishvili      <-- appears in BOTH
Eter Tataraidze        Giorgi Kekelidze
Amiran Arabuli
```

**Lia Toklikishvili** is both a visible film author *and* a behind-the-scenes screenplay author — she's the person with two faces. Giorgi Kekelidze appears only in the screenplay list, so he's "one face" and fails the clue. One seen role, one unseen role: exactly what *"One is seen. One is unseen."* describes.

## Flag

The required format is a lowercase first name and surname joined by an underscore:

```text
NullOriginCTF{lia_toklikishvili}
```

Accepted by the platform.

`NullOriginCTF{lia_toklikishvili}`

## Key Takeaways

- **Negative results are results.** `exiftool`/`file` coming back empty wasn't a dead end — it reframed the challenge from "metadata puzzle" to "research puzzle."
- **Searchable text beats pretty scenery.** When several images are generic, zero in on the one with readable text (a gravestone, a sign, a document). Boost contrast if the inscription is faded.
- **"Frames" and "reel" are literal.** OSINT poems often describe the medium of the evidence. These were video stills, which is why the end credits — not the images — held the answer.
- **Decode every clause of the prompt.** Each metaphorical line mapped to one concrete lookup. "Two faces" was a cross-reference instruction, and ignoring it leads straight to the decoy name (Giorgi Kekelidze).
- **Don't stop at the first credit you find.** The webpage credits and the full end-roll credits differed; the challenge specifically rewarded reading all the way through.
