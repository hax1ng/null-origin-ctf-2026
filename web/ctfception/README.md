# CTFCeption

**Category:** Web | **Difficulty:** Medium | **Points:** 200 | **Solves:** 3 | **Flag:** `NullOrigin{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}`

> **Flag-format note:** this challenge decrypts to a literal `NullOrigin{...}` prefix (no `CTF`). The scoreboard's canonical wrapper is `NullOriginCTF{...}`, so the submitted flag was `NullOriginCTF{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}`. Both are shown here honestly; always confirm the expected prefix against the challenge description before submitting.

## Challenge Description

A single URL: `https://ctfception.onrender.com/` — a static web app dressed up as a clandestine intelligence dashboard ("CTFCEPTION ARCHIVE ENGINE"), themed around Indian independence leader Lokmanya Bal Gangadhar Tilak and curated by a fictional archivist, "PRX02." The tagline is *"Every archive hides another archive"* — hence **CTFCeption**.

The dossier doesn't hide the intended path; it prints it out in plain English:

> Download `/downloads/kesari_vault_1908.zip`, unlock it with the historical work passphrase, decode the telegraph beacon, and run `reconstruct <KEY>` in the site's web terminal.

So the site practically holds your hand. The work is in *knowing* the passphrase (a history question), *knowing* which tools handle each layer, and realizing that the "terminal" button is just a thin wrapper around client-side JavaScript crypto you can replicate offline.

## Initial Analysis

First move on any web challenge with an HTML front end: read the page source. Challenge authors love hiding breadcrumbs in comments, and this one is no exception:

```html
<!-- PRX02 ARCHIVE NODE: Signal carrier frequency 25.09 MHz - Check /archive/evidence/telemetry.json -->
<!-- Special historical tribute: 'Lokmanya Gatha' releasing on 25th Sept. Explore PRX02 on YouTube! -->
```

Two things pop out:

1. A JSON file at `/archive/evidence/telemetry.json`. **This is the real lead.**
2. The "25.09 MHz carrier frequency" / "25th Sept" framing — this *sounds* like an audio/SSTV stego teaser, but it's flavor. `25.09` just encodes the date September 25th, which resurfaces later as the number `2509`.

Fetching `telemetry.json` gives the actual roadmap (`src/telemetry.json` in this repo):

```json
"access_key_hint": "The vault passphrase is the romanized title of Tilak's monumental philosophical work composed secretly by pencil inside Mandalay Jail between 1908 and 1914 (lowercase, single word, 11 letters).",
"telegraph_cipher_hint": "Once inside the vault, the telegraph beacon payload requires the chronicle launch coordinate key (DDMM format: 2509).",
"terminal_command": "reconstruct <DECODED_BEACON_KEY>"
```

Both keys are handed to us: a history lookup for the zip passphrase, and `2509` for the cipher. The path is clear.

## The Vulnerability / Core Concept

The core trick is that **the entire site is static and client-side** — hosted on a static web host, with no server validating anything. The AES-256-GCM ciphertext, the IV, and all decryption logic live in `js/crypto.js`, which ships verbatim to every visitor (see `src/crypto.js`). The only thing between you and the flag is knowing the correct input to the decryption function.

The challenge layers three stages of obscurity — the "inception" — each feeding the next:

1. **Layer 1 — Zip encryption.** `kesari_vault_1908.zip` uses WinZip-AES encryption. Standard `unzip` and Python's `zipfile` can't open it; you need `pyzipper`. Passphrase comes from a history clue.
2. **Layer 2 — XOR cipher.** Inside the zip, the beacon phrase is base64-encoded and then XOR'd with a repeating key (`2509`). Classic repeating-key XOR — trivially reversible once you have the key.
3. **Layer 3 — AES-256-GCM.** The decoded beacon phrase is run through `SHA-256()` to produce the AES-256 key. The ciphertext + IV are hardcoded in `crypto.js`.

No individual layer is cryptographically strong. The "security" is only in the key-derivation chain, and because every constant ships to the client, the whole thing unravels offline the moment you spot the comment pointing to `telemetry.json`. The flag itself is never in plaintext anywhere — `crypto.js` even brags about this — but that doesn't matter when you can reconstruct the key yourself.

**Red herring:** the "25.09 MHz radio carrier," the waveform canvas, the audio toggle, the `@prx02` YouTube link — all atmosphere. No audio/stego analysis is needed. `25.09` is just September 25th re-encoded, reused as the XOR key `2509` and baked into the IV.

## Exploitation

The full end-to-end reproduction is in [`solve.py`](./solve.py). Here's the chain, layer by layer.

### Step 1 — Find the vault passphrase

The hint: *"the romanized title of Tilak's monumental philosophical work composed secretly by pencil inside Mandalay Jail between 1908 and 1914 (lowercase, single word, 11 letters)."*

Tilak was imprisoned in Mandalay Jail (Burma) from 1908–1914 and wrote his magnum opus there: *Shrimadh Bhagavad Gita Rahasya*. The short title is *Gita Rahasya* → romanized, lowercase, no spaces: **`gitarahasya`**. Count: `g-i-t-a-r-a-h-a-s-y-a` = 11 letters. ✔

### Step 2 — Unlock the vault (WinZip-AES → pyzipper)

Standard `unzip` bounces on WinZip-AES. `pyzipper` is the drop-in fix (the challenge even ships a helper, `src/extract_vault.py`, that does exactly this):

```python
import pyzipper

with pyzipper.AESZipFile('kesari_vault_1908.zip') as zf:
    zf.setpassword(b'gitarahasya')
    zf.extractall('kesari_vault_contents')
```

This yields three files: `MANDALAY_DISPATCH_1908.txt` (flavor that re-confirms the key `2509`), `telegraph_decoder.py`, and `beacon_payload.enc`.

### Step 3 — Decode the telegraph beacon (base64 + repeating-key XOR)

`beacon_payload.enc` holds one base64 string:

```
fnp7dHN7aXhtcnFtenRvenpnf3d7dnx8bQQJCQo=
```

`telegraph_decoder.py` base64-decodes it, then XORs each byte against the repeating key `"2509"`. Because XOR is its own inverse, the same operation encrypts and decrypts:

```python
import base64

data = base64.b64decode("fnp7dHN7aXhtcnFtenRvenpnf3d7dnx8bQQJCQo=")
kb = b"2509"
beacon = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data)).decode()
# -> "LOKMANYA_GATHA_CHRONICLE_1908"
```

Beacon phrase recovered: `LOKMANYA_GATHA_CHRONICLE_1908`.

### Step 4 — Decrypt the flag offline (AES-256-GCM)

Now replicate what `crypto.js` does in the browser, in Python. The JS source gives us everything:

- **Key:** `SHA-256(beaconPhrase)` → the AES-256 key.
- **IV:** `190825091881191618931897` (hex, 12 bytes). Read as `1908 2509 1881 1916 1893 1897` — historical years from Tilak's life; flavor.
- **Ciphertext:** `e60d10ce…996b19d7` (hex). **Key detail:** WebCrypto appends the 16-byte GCM authentication tag to the ciphertext, so the last 16 bytes are the tag and must be split off before decrypting.

```python
import hashlib
from Crypto.Cipher import AES

key = hashlib.sha256(b"LOKMANYA_GATHA_CHRONICLE_1908").digest()
data = bytes.fromhex(CT_HEX)      # ciphertext + appended GCM tag
iv   = bytes.fromhex(IV_HEX)
ct, tag = data[:-16], data[-16:]  # split off the 16-byte auth tag

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
flag = cipher.decrypt_and_verify(ct, tag).decode()
```

If the beacon phrase were wrong, `decrypt_and_verify` would raise `ValueError` on the tag mismatch. It succeeding *is* the proof the key is right — no guessing.

### Running it

```
$ python3 solve.py
[+] Decoded beacon phrase : LOKMANYA_GATHA_CHRONICLE_1908
[+] FLAG                  : NullOrigin{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}
```

The GCM tag verified. Flag captured.

## Flag

`NullOrigin{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}`

(Submitted on the scoreboard as `NullOriginCTF{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}` — see the flag-format note at the top.)

## Key Takeaways

- **Static sites can't hide secrets.** Anything on a static host (Render, GitHub Pages, Netlify) ships all its logic to the browser. If the flag is derived from client-side crypto, every constant you need is in the JS source — the intended UI path is optional, you can always replicate the crypto offline.
- **`pyzipper` for WinZip-AES.** Standard `unzip` and Python's `zipfile` don't support WinZip's AES format. `pip install pyzipper` any time a zip bounces `unzip` with a crypto error.
- **WebCrypto's GCM tag convention.** The WebCrypto `AES-GCM` API appends the 16-byte auth tag to the ciphertext. When decrypting with pycryptodome, split off the last 16 bytes as the tag before calling `decrypt_and_verify`.
- **Check the files before trusting the theme.** The "25.09 MHz radio carrier" dressing screams audio/SSTV stego, but the actual artifacts told a different story. When a challenge cosplays as a radio/audio puzzle, look at what's actually downloadable before reaching for `sox`/`audacity`.
- **Read the dossier.** The challenge printed its own solve path. Authors often embed the steps in flavor text — but you still have to *know* Gita Rahasya, *know* to use pyzipper, and *know* to replicate WebCrypto offline. The map is handed to you; the journey still takes work.

## Files in this directory

| File | What it is |
|---|---|
| [`solve.py`](./solve.py) | Full offline solve — zip passphrase → XOR beacon decode → AES-256-GCM flag recovery. |
| [`src/crypto.js`](./src/crypto.js) | Client-side AES-256-GCM engine shipped by the site; holds the hardcoded ciphertext + IV. |
| [`src/telemetry.json`](./src/telemetry.json) | The roadmap JSON with both hints (passphrase + `2509` cipher key). |
| [`src/extract_vault.py`](./src/extract_vault.py) | Site's own `pyzipper` helper for unlocking the WinZip-AES vault. |
| [`src/telegraph_decoder.py`](./src/telegraph_decoder.py) | Vault's base64 + repeating-key-XOR decoder (recovers the beacon phrase). |
| [`src/beacon_payload.enc`](./src/beacon_payload.enc) | The base64/XOR beacon payload from inside the vault. |
| [`src/MANDALAY_DISPATCH_1908.txt`](./src/MANDALAY_DISPATCH_1908.txt) | In-vault flavor dispatch that re-confirms the chronicle key `2509`. |

> The site's static assets (images, CSS, the large `index.html`, and the encrypted `kesari_vault_1908.zip` itself) are omitted to keep this lean. The small source files above are the ones that carry the actual solve chain.
