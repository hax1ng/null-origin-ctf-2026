# Web

Web challenges solved during the Null Origin CTF 2026 Qualifier.

| Challenge | Difficulty | Points | Flag | Writeup |
|-----------|------------|-------:|------|---------|
| CTFCeption | Medium | 200 | `NullOrigin{L0km4ny4_G4th4_25S3pt_Sw4r4jy4_PRX02_}` | [writeup](ctfception/README.md) |

> **CTFCeption** ships its entire decryption chain to the browser, so it is fully solvable offline: crack a WinZip-AES archive with a historical-trivia passphrase, base64 + repeating-key-XOR decode the "telegraph beacon", then derive an AES-256-GCM key to unlock the hardcoded ciphertext in `crypto.js`.
