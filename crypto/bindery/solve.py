#!/usr/bin/env python3
"""
Bindery (Null Origin CTF 2026 - Qualifier, Crypto).

Decrypts index.sealed, a base-3 document hidden behind a ternary stream
cipher. Each 110-byte record packs 512 trits (base-3 digits); every record
begins with the same known 28-trit header. The cipher state is a 121-trit
LFSR over GF(3) that is NOT reset between records, so the known headers from a
handful of records give enough GF(3) equations to recover the 121-trit initial
state. From there the whole keystream -- and the index -- decrypt.

Requires index.sealed (the ~38 MB sealed index) in the working directory; it
is too large to ship in this repo. Taps and header constants were recovered
from the unstripped bindery.o object file.
"""
from pathlib import Path

RECORD_BYTES = 110
SPAN = 512
WIDTH = 121
HEADER = [int(x) for x in "2011210100221222121110102010"]
MODULUS = 3**SPAN

data = Path("index.sealed").read_bytes()
assert len(data) % RECORD_BYTES == 0


def unpack_record(record_number):
    """Remove the slack and return one record as 512 trits."""
    start = record_number * RECORD_BYTES
    raw = data[start:start + RECORD_BYTES]
    value = int.from_bytes(raw, "big") % MODULUS

    result = [0] * SPAN
    for i in range(SPAN - 1, -1, -1):
        value, result[i] = divmod(value, 3)
    return result


# Nonzero recurrence coefficients recovered from bindery.o.
# Each tuple is (state position, coefficient modulo 3).
TAPS = [
    (0, 2), (1, 2), (2, 2), (3, 1), (4, 2), (5, 2),
    (6, 2), (7, 1), (10, 2), (11, 2), (12, 1), (16, 1),
    (18, 1), (21, 2), (24, 1), (25, 2), (26, 1), (27, 1),
    (30, 1), (31, 2), (33, 1), (34, 1), (36, 1), (37, 2),
    (42, 1), (45, 1), (46, 1), (47, 1), (50, 1), (53, 1),
    (57, 1), (58, 1), (60, 2), (61, 1), (62, 2), (64, 1),
    (67, 2), (68, 1), (69, 2), (70, 2), (72, 1), (74, 1),
    (75, 1), (76, 2), (78, 2), (79, 1), (81, 2), (82, 1),
    (84, 2), (85, 1), (87, 2), (88, 2), (90, 1), (91, 2),
    (92, 2), (95, 1), (96, 1), (97, 1), (98, 1), (99, 2),
    (100, 1), (102, 1), (103, 2), (104, 2), (105, 2),
    (106, 1), (107, 2), (112, 1), (113, 1), (114, 1),
    (115, 2), (119, 2), (120, 1),
]


def solve_gf3(matrix, unknowns):
    """Gaussian elimination where every operation is modulo 3."""
    row = 0
    pivots = []

    for column in range(unknowns):
        pivot = next(
            (r for r in range(row, len(matrix)) if matrix[r][column]),
            None,
        )
        if pivot is None:
            continue

        matrix[row], matrix[pivot] = matrix[pivot], matrix[row]

        # The inverse of 2 modulo 3 is also 2.
        if matrix[row][column] == 2:
            matrix[row] = [(2 * x) % 3 for x in matrix[row]]

        for r in range(len(matrix)):
            if r == row or matrix[r][column] == 0:
                continue
            factor = matrix[r][column]
            matrix[r] = [
                (x - factor*y) % 3
                for x, y in zip(matrix[r], matrix[row])
            ]

        pivots.append(column)
        row += 1

    if row != unknowns:
        raise RuntimeError(f"state system has rank {row}, expected {unknowns}")

    solution = [0] * unknowns
    for r, column in enumerate(pivots):
        solution[column] = matrix[r][-1]
    return solution


# Express each future stream trit as a vector of coefficients applied
# to the 121 unknown initial state trits.
OBSERVATION_RECORDS = 5
basis_sequence = [
    [1 if i == j else 0 for i in range(WIDTH)]
    for j in range(WIDTH)
]

for n in range(WIDTH, OBSERVATION_RECORDS * SPAN):
    vector = [0] * WIDTH
    for tap, coefficient in TAPS:
        previous = basis_sequence[n - WIDTH + tap]
        for i in range(WIDTH):
            vector[i] = (vector[i] + coefficient * previous[i]) % 3
    basis_sequence.append(vector)


# Build equations using the known 28-trit header from five records.
equations = []
for record_number in range(OBSERVATION_RECORDS):
    encrypted = unpack_record(record_number)
    for k, known_plaintext in enumerate(HEADER):
        stream_trit = (encrypted[k] - known_plaintext) % 3
        equations.append(
            basis_sequence[record_number * SPAN + k][:] + [stream_trit]
        )

initial_state = solve_gf3(equations, WIDTH)
print("Recovered state:", "".join(map(str, initial_state)))


# Only four records are needed to reach the flag, although the same
# method can decrypt the entire index.
records_to_decrypt = 4
stream = initial_state[:]

while len(stream) < records_to_decrypt * SPAN:
    n = len(stream)
    next_trit = sum(
        coefficient * stream[n - WIDTH + tap]
        for tap, coefficient in TAPS
    ) % 3
    stream.append(next_trit)


plaintext = bytearray()
for record_number in range(records_to_decrypt):
    encrypted = unpack_record(record_number)
    offset = record_number * SPAN
    decrypted = [
        (encrypted[k] - stream[offset + k]) % 3
        for k in range(SPAN)
    ]

    assert decrypted[:len(HEADER)] == HEADER

    # The remaining 484 trits encode one 95-byte document chunk.
    value = 0
    for trit in decrypted[len(HEADER):]:
        value = 3*value + trit
    plaintext.extend(value.to_bytes(95, "big"))

print(plaintext.decode("ascii", errors="replace"))
