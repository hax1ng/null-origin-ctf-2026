from hashlib import sha256
from scipy.io import wavfile
import numpy as np
import re
import struct
import zlib

PREVIOUS_SEAL = b"Null0rigin{a_carrier_laid_across_the_whole_room}"
CHIP_SAMPLES = 2048

sample_rate, audio = wavfile.read("undertone.wav")
left = audio[:, 0].astype(np.float64)

key = sha256(PREVIOUS_SEAL).digest()
byte_count = (len(left) + 7) // 8
stream = b"".join(
    sha256(key + counter.to_bytes(4, "big")).digest()
    for counter in range((byte_count + 31) // 32)
)[:byte_count]
chips = 1.0 - 2.0 * np.unpackbits(np.frombuffer(stream, dtype=np.uint8))[:len(left)]

despread = left * chips
bit_count = len(despread) // CHIP_SAMPLES
scores = despread[:bit_count * CHIP_SAMPLES].reshape(bit_count, CHIP_SAMPLES).mean(axis=1)
bits = (scores < 0).astype(np.uint8)
decoded = np.packbits(bits[:bit_count - bit_count % 8]).tobytes()

print("sample rate:", sample_rate)
print("complete bits:", bit_count)
print("score range:", float(scores.min()), float(scores.max()))
print("decoded:", repr(decoded))

if decoded[:3] != b"PL8":
    raise SystemExit("PL8 header not found")
issue, length, stored_crc = struct.unpack("<BHI", decoded[3:10])
payload = decoded[10:10 + length]
calculated_crc = zlib.crc32(payload) & 0xffffffff
print("issue:", issue)
print("length:", length)
print("stored CRC32:", f"{stored_crc:08x}")
print("calculated CRC32:", f"{calculated_crc:08x}")
print("payload:", repr(payload))
match = re.search(rb"Null0rigin\{[a-z0-9_]+\}", payload)
if match:
    print("flag:", match.group().decode())
