#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#define ROUNDS 8
#define MASK_5BIT 0x1F
#define MASK_10BIT 0x3FF
#define MASK_30BIT 0x3FFFFFFF
#define MASK_60BIT 0x0FFFFFFFFFFFFFFF

static inline int rotate5(int x, int r) {
    return ((x << r) | (x >> (5 - r))) & MASK_5BIT;
}

static inline int S(int input) {
    static const uint8_t sbox5bit[32] = {
        0, 2, 4, 12, 8, 14, 24, 21,
        16, 19, 28, 5, 17, 20, 11, 23,
        1, 6, 7, 26, 25, 18, 10, 27,
        3, 13, 9, 29, 22, 30, 15, 31
    };
    return sbox5bit[input & MASK_5BIT];
}

static inline int G(int x, uint32_t key) {
    int t[5];
    for (int i = 0; i < 5; ++i) {
        t[i] = rotate5(x, i);
    }

    int k[5];
    for (int i = 0; i < 5; ++i) {
        k[i] = (key >> (5 * i)) & MASK_5BIT;
    }

    int result = t[0] & k[0];
    for (int i = 1; i < 5; ++i) {
        result ^= t[i] & k[i];
    }
    result ^= t[1] & t[2];
    return result & MASK_5BIT;
}

static inline int round_function(int x, uint64_t key, int is_final) {
    uint32_t SK0 = key & 0x1FFFFFF;
    uint8_t SK1 = (key >> 25) & MASK_5BIT;

    int xL = (x >> 5) & MASK_5BIT;
    int xR = x & MASK_5BIT;

    int temp = xL;
    if (!is_final) {
        xL = xR ^ G(temp, SK0);
        xR = S(temp ^ SK1);
    } else {
        xR = xR ^ G(temp, SK0);
        xL = S(temp) ^ SK1;
    }
    return ((xL & MASK_5BIT) << 5) | (xR & MASK_5BIT);
}

static inline uint64_t expand(uint64_t tweak) {
    uint64_t result = 0;
    for (int i = 11; i >= 0; i--) {
        uint64_t nibble = (tweak >> (i * 4)) & 0xF;
        result = (result << 5) | nibble;
    }
    return result;
}

static inline uint64_t shift_left(uint64_t input) {
    uint64_t output = 0;
    for (int i = 0; i < 12; i++) {
        int val = (input >> (i * 5)) & MASK_5BIT;
        int s = S(val);
        output |= ((uint64_t)s << (i * 5));
    }
    return output;
}

static inline uint64_t rotate60(uint64_t x, int r) {
    return ((x << r) | (x >> (60 - r))) & MASK_60BIT;
}

static inline uint64_t Sigma(uint64_t x) {
    return x ^ rotate60(x, 6) ^ rotate60(x, 12) ^ rotate60(x, 19) ^
           rotate60(x, 29) ^ rotate60(x, 43) ^ rotate60(x, 51);
}

static inline uint64_t pi(uint64_t input) {
    static const uint8_t P[60] = {
        0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55,
        1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56,
        2, 7, 12, 17, 22, 27, 32, 37, 42, 47, 52, 57,
        3, 8, 13, 18, 23, 28, 33, 38, 43, 48, 53, 58,
        4, 9, 14, 19, 24, 29, 34, 39, 44, 49, 54, 59
    };
    uint64_t output = 0;
    for (int i = 0; i < 60; i++) {
        if ((input >> i) & 1ULL) {
            output |= (1ULL << P[i]);
        }
    }
    return output;
}

void tweak_schedule(uint64_t tweak, uint64_t k3, uint64_t k2, uint64_t k1, uint64_t k0, uint64_t round_keys[ROUNDS]) {
    uint64_t T1 = expand(tweak) ^ k0;
    T1 &= MASK_60BIT;
    uint64_t T2 = shift_left(T1);
    uint64_t T3 = Sigma(T2) ^ k1;
    T3 &= MASK_60BIT;
    uint64_t T4 = shift_left(T3) ^ k2;
    uint64_t T5 = pi(T4);
    uint64_t T6 = shift_left(T5) & MASK_60BIT;
    uint64_t T7 = Sigma(T6) ^ k3;
    uint64_t T8 = shift_left(T7) & MASK_60BIT;

    round_keys[0] = T1 & MASK_30BIT;
    round_keys[1] = (T1 >> 30) & MASK_30BIT;
    round_keys[2] = T3 & MASK_30BIT;
    round_keys[3] = (T3 >> 30) & MASK_30BIT;
    round_keys[4] = T6 & MASK_30BIT;
    round_keys[5] = (T6 >> 30) & MASK_30BIT;
    round_keys[6] = T8 & MASK_30BIT;
    round_keys[7] = (T8 >> 30) & MASK_30BIT;
}

int scarf(int plaintext, uint64_t k3, uint64_t k2, uint64_t k1, uint64_t k0, uint64_t tweak) {
    uint64_t round_keys[ROUNDS];
    tweak_schedule(tweak, k3, k2, k1, k0, round_keys);
    int x = plaintext;
    for (int i = 0; i < ROUNDS - 1; ++i) {
        x = round_function(x, round_keys[i], 0);
    }
    x = round_function(x, round_keys[ROUNDS - 1], 1);
    return x & MASK_10BIT;
}

int main() {
    int plaintext = 8;
    uint64_t key0 = 0x28ff19d89275cac;
    uint64_t key1 = 0xa1b81946e5682b0;
    uint64_t key2 = 0x91db14bd40976c4;
    uint64_t key3 = 0xbf6867b5ee98d17;
    uint64_t tweak = 0x7d907fc2789d & 0xFFFFFFFFFFFFULL;

    for (int plaintext = 0; plaintext < 1024; ++plaintext) {
        int ciphertext = scarf(plaintext, key3, key2, key1, key0, tweak);

        printf("0x%03X -> 0x%03X\n", plaintext, ciphertext);
    }
    return 0;
}

