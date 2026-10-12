/*
 * Inverse of the daybook JIT permutation (12 rounds over a 40-byte / 5x u64
 * state). Every round uses only reversible ops (XOR, rotations, boolean
 * combinations), so the round can be run backwards exactly.
 *
 * Build:  gcc -shared -fPIC -O3 -o inv.so inv.c
 */
#include <stdint.h>

static inline uint64_t rol(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t ror(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static void invround(uint64_t *s, uint64_t k) {
    uint64_t na = s[0], nb = s[1], nc = s[2], nd = s[3], ne = s[4];

    uint64_t x0 = ror(nc, 7);
    uint64_t x1 = ror(nd, 19);
    uint64_t e  = rol(nb, 7)  ^ (x0 & x1);
    uint64_t d  = rol(na, 21) ^ (x0 | e);
    uint64_t c  = ror(ne, 31) ^ ((~e) & d);
    uint64_t b  = x1 ^ (c | d);
    uint64_t a  = x0 ^ (c & b);

    s[0] = a;
    s[1] = b;
    s[2] = c ^ k;
    s[3] = d;
    s[4] = e;
}

void invn(uint64_t *s, uint64_t count) {
    while (count--) {
        uint64_t k = 0x1a19181716151413ULL;
        for (int i = 0; i < 12; i++, k -= 0x0101010101010101ULL)
            invround(s, k);
    }
}
