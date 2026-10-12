#!/usr/bin/env python3
"""
Underground Telegraph Decoder - Kesari Historical Archive
Preserved by Archivist: PRX02

Usage:
    python telegraph_decoder.py <key>
Example:
    python telegraph_decoder.py 2509
"""
import sys
import base64

def decode_payload(payload_path, key):
    try:
        with open(payload_path, "r") as f:
            encoded_str = f.read().strip()
        data = base64.b64decode(encoded_str)
        key_bytes = key.encode("utf-8")
        decoded = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])
        return decoded.decode("utf-8")
    except Exception as e:
        return f"[!] Error during decoding: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] Usage: python telegraph_decoder.py <chronicle_key>")
        print("[*] Note: The courier dispatch notes the chronicle launch date (DDMM format: 2509).")
        sys.exit(1)

    key = sys.argv[1]
    result = decode_payload("beacon_payload.enc", key)
    print("=" * 60)
    print(f"[+] Decoded Telegraph Beacon: {result}")
    print(f"[+] Terminal Command: reconstruct {result}")
    print("=" * 60)
