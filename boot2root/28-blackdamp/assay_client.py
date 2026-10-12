#!/usr/bin/env python3
"""
28-blackdamp -- authenticate to the status page + assay plant (port 7731),
list objects, and download the encrypted assay bundle (lamp-assay.7z).

Auth chain:
  * Status page wants header X-Shift-Code = first 16 bytes of
    HMAC-SHA256(key = plant key as 64 ASCII chars, msg = current unix hour) as hex.
  * The /status body carries a changing "gas:" figure (2 decimals).
  * The assay binary protocol (big-endian) wants the CRC-32 of that exact
    decimal string as the HELLO token. The token is time-sensitive: if it
    fails, re-fetch /status and reconnect rather than reusing an old figure.

The 64-char plant key comes from the repaired firmware (etc/assay/SHIFT-KEY.txt)
and is used as ASCII text, NOT as 32 decoded hex bytes.

Usage: ./assay_client.py <TARGET_IP>
"""
import hashlib, hmac, re, socket, struct, sys, time, urllib.request, zlib

IP = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PLANT_KEY = b"ad407faa2a73c210ef371b23c0d7983c534357525a595339da714a4a760c9640"

hour = str(int(time.time()) // 3600).encode()
shift = hmac.new(PLANT_KEY, hour, hashlib.sha256).digest()[:16].hex()

req = urllib.request.Request(f"http://{IP}/status", headers={"X-Shift-Code": shift})
status_text = urllib.request.urlopen(req).read().decode()
print(status_text)

gas = re.search(r"^gas:\s+([0-9]+\.[0-9]{2})$", status_text, re.M).group(1)
token = zlib.crc32(gas.encode()) & 0xffffffff
print(f"gas={gas!r}, CRC32={token:08x}")


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("connection closed")
        data += part
    return data


def command(sock, operation, name=b"", token=0):
    sock.sendall(struct.pack(">BBHI", operation, 0, len(name), token) + name)
    status, _r1, _r2, length = struct.unpack(">BBHI", recv_exact(sock, 8))
    payload = recv_exact(sock, length)
    if status != 0:
        raise RuntimeError(f"server status {status}: {payload!r}")
    return payload


with socket.create_connection((IP, 7731)) as sock:
    greeting = recv_exact(sock, 16)
    assert greeting[:8] == b"BDASSAY\x01"
    command(sock, 1, token=token)                  # HELLO
    print(command(sock, 2).decode())               # LIST
    bundle = command(sock, 3, b"lamp-assay.7z")    # FETCH
    open("lamp-assay.7z", "wb").write(bundle)
    print("wrote lamp-assay.7z")
