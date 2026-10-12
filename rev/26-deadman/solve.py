#!/usr/bin/env python3
# Deadman keygen solver.
#
# The binary turns a pile of anti-debug / signal / timing rituals into five
# 32-byte "stage source" values, then runs a five-stage SHA-256 + splitmix64
# GF(2) cascade. Rather than perform the rituals, we reconstruct each source
# statically:
#   stage 1: exactly 3 TracerPid changes over 12 samples
#   stage 2: fault-path "true" + embedded threshold 300000
#   stage 3: the correct SHA-512-crypt output is already in deadman.shadow /
#            embedded in the binary, so the "good password" branch is known
#            without cracking the password; trap-flag mask = 0xffffff
#   stage 4: slow-timing "true" + threshold 70000
#   stage 5: 16-bit debugger-sample mask, brute-forced (0..0xffff) against the
#            embedded checkpoint -> 0xf0f0
# Each stage is a full-rank GF(2) system; stage 5's solution is the raw flag.
import hashlib
import struct

H = lambda x: hashlib.sha256(x).digest()
LE64 = lambda x: struct.pack("<Q", x)
MASK64 = (1 << 64) - 1

PREFIX = b"NULL0RIGIN/REV/CASCADE/v1"
CHALLENGE = b"26-deadman"

raw = open("deadman", "rb").read()
records = [
    raw[0x90020 + i * 0xd0 : 0x90020 + (i + 1) * 0xd0]
    for i in range(5)
]

def field(label, data):
    return label + LE64(len(data)) + data

def stage_key(stage, transcript, source):
    return H(
        PREFIX
        + b"|stage=" + CHALLENGE
        + b"|layer=" + str(stage).encode()
        + b"|t=" + transcript
        + field(b"|src=", source)
    )

def update_transcript(transcript, stage, vector, source):
    return H(
        transcript
        + b"|k=" + str(stage).encode()
        + field(b"|x=", vector)
        + field(b"|src=", source)
    )

def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z ^= z >> 31
    return state, z

def solve_record(stage, key):
    record = records[stage - 1]
    nbits, nonce = struct.unpack_from("<II", record)
    answers = record[40:104]
    rows = []

    for row_number in range(nbits):
        digest = H(key + LE64(nonce) + LE64(row_number))
        state = 0
        for i in range(4):
            state ^= int.from_bytes(digest[i * 8:(i + 1) * 8], "little")

        coefficients = 0
        for word_number in range((nbits + 63) // 64):
            state, word = splitmix64(state)
            coefficients |= word << (64 * word_number)

        coefficients &= (1 << nbits) - 1
        rhs = (answers[row_number // 8] >> (row_number & 7)) & 1
        rows.append(coefficients | (rhs << nbits))

    # Reduced row-echelon form over GF(2).
    rank = 0
    for column in range(nbits):
        pivot = next(i for i in range(rank, nbits) if (rows[i] >> column) & 1)
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(nbits):
            if i != rank and ((rows[i] >> column) & 1):
                rows[i] ^= rows[rank]
        rank += 1

    assert rank == nbits
    solution = 0
    coefficient_mask = (1 << nbits) - 1
    for row in rows:
        coefficient = row & coefficient_mask
        if (row >> nbits) & 1:
            solution |= coefficient

    return solution.to_bytes((nbits + 7) // 8, "little")

transcript = H(PREFIX + b"|transcript|" + CHALLENGE)

# Stage 1: exactly three TracerPid changes.
src1 = H(struct.pack("<QII", 3, 80000, 12))
k1 = stage_key(1, transcript, src1)
assert H(k1) == records[0][8:40]
v1 = solve_record(1, k1)
transcript = update_transcript(transcript, 1, v1, src1)

# Stage 2: true timing/fault result.
src2 = H(b"\x01" + LE64(300000))
k2 = stage_key(2, transcript, src2)
assert H(k2) == records[1][8:40]
v2 = solve_record(2, k2)
transcript = update_transcript(transcript, 2, v2, src2)

# Stage 3: derive the good password branch from the stored crypt string.
crypt_string = raw[0x9049c : raw.index(b"\x00", 0x9049c)]
d = H(b"deadman/gate/key|" + crypt_string)
h1 = H(d + b"\x00" * 8)
base3 = bytes(a ^ b for a, b in zip(h1, raw[0x90444:0x90464]))
assert H(base3) == raw[0x90464:0x90484]

src3 = H(LE64(0xffffff) + base3)
k3 = stage_key(3, transcript, src3)
assert H(k3) == records[2][8:40]
v3 = solve_record(3, k3)
transcript = update_transcript(transcript, 3, v3, src3)

# Stage 4: true timing result.
src4 = H(b"\x01" + LE64(70000))
k4 = stage_key(4, transcript, src4)
assert H(k4) == records[3][8:40]
v4 = solve_record(4, k4)
transcript = update_transcript(transcript, 4, v4, src4)

# Stage 5: only 2^16 environmental masks.
target5 = records[4][8:40]
for mask in range(1 << 16):
    src5 = H(struct.pack("<QII", mask, 60000, 16))
    k5 = stage_key(5, transcript, src5)
    if H(k5) == target5:
        print(f"stage 5 mask = {mask:#06x}")
        break
else:
    raise RuntimeError("stage 5 mask not found")

flag = solve_record(5, k5)
print(flag.decode())

verify_digest = H(
    b"NULL0RIGIN/REV/VERIFY/v1|26-deadman|" + flag
).hex()
print("verify digest =", verify_digest)
