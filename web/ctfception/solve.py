#!/usr/bin/env python3
"""
CTFCeption solve — Null Origin CTF 2026 Qualifier (web, 200pts)

Full chain, self-contained (assumes the AES zip has been fetched to downloads/):
  1. Unlock kesari_vault_1908.zip with passphrase "gitarahasya"
     (Gita Rahasya = Tilak's Mandalay-jail magnum opus, lowercase 11 letters).
  2. base64-decode + XOR-decode beacon_payload.enc with chronicle key "2509"
     -> beacon phrase "LOKMANYA_GATHA_CHRONICLE_1908".
  3. Replicate crypto.js: key = SHA-256(beacon), AES-256-GCM decrypt the
     ciphertext embedded in js/crypto.js (WebCrypto appends the 16-byte tag).
"""
import base64
import hashlib
from Crypto.Cipher import AES

# --- values lifted from the site / vault ---
ZIP_PASSPHRASE = "gitarahasya"
CHRONICLE_KEY  = "2509"
# beacon_payload.enc contents (from inside the AES zip)
BEACON_B64 = "fnp7dHN7aXhtcnFtenRvenpnf3d7dnx8bQQJCQo="
# from js/crypto.js
CT_HEX = ("e60d10cedd2fde9039866ce40dff2ba198f28ac778638a561980cb2d054069dc"
          "8d6e47c0f8c08c67481f8ad4e94fe25de1ac70d7b78d6943fe65dfc2fc996b19d7")
IV_HEX = "190825091881191618931897"   # "1908 2509 1881 1916 1893 1897"


def decode_beacon(b64, key):
    data = base64.b64decode(b64)
    kb = key.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data)).decode()


def reconstruct(beacon):
    key = hashlib.sha256(beacon.encode()).digest()
    data = bytes.fromhex(CT_HEX)
    iv = bytes.fromhex(IV_HEX)
    ct, tag = data[:-16], data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag).decode()


if __name__ == "__main__":
    beacon = decode_beacon(BEACON_B64, CHRONICLE_KEY)
    print(f"[+] Decoded beacon phrase : {beacon}")
    flag = reconstruct(beacon)
    print(f"[+] FLAG                  : {flag}")
