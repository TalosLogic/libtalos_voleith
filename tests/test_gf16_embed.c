/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf16_embed.c - alpha16 subfield-embedding validation (T5.2).
 *
 * Validates that voleith_gf16_embed is a field homomorphism from GF(2^16)
 * (core/field16.c) into GF(2^lambda) (core/field.c) for each lambda:
 *
 *     embed(a + b) == embed(a) + embed(b)
 *     embed(a * b) == embed(a) * embed(b)
 *
 * with the left-hand operations taken in GF(2^16) and the right-hand ones in
 * GF(2^lambda).  This is the correctness gate on the alpha16 tables emitted
 * by tools/gen_alpha16 (T5.1): the additive law is structural (embed is a
 * GF(2)-linear combination of the beta powers), but the multiplicative law
 * holds only if beta is a genuine root of m16 = x^16 + x^12 + x^3 + x + 1, so
 * it is the real check that the embedded generator is correct.
 *
 * field16.c is the independent GF(2^16) reference for the left-hand products;
 * it shares no code with the alpha16 tables.
 */

#include "field.h"
#include "field16.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-50s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

/* splitmix64: deterministic 16-bit sample stream. */
static uint64_t sm_state;

static uint16_t
sm_next16(void)
{
    uint64_t z = (sm_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    return (uint16_t)(z & 0xffff);
}

static int
nbytes(int lambda)
{
    return lambda / 8;
}

/* out = a + b in GF(2^lambda) (byte-wise XOR over nbytes(lambda)). */
static void
gflam_add(int lambda, uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    int nb = nbytes(lambda);
    for (int i = 0; i < nb; i++)
        out[i] = a[i] ^ b[i];
}

/* out = a * b in GF(2^lambda) via the per-width library multiply. */
static void
gflam_mul(int lambda, uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    if (lambda == 128) {
        voleith_gf128_t x, y, z;
        voleith_gf128_from_bytes(&x, a);
        voleith_gf128_from_bytes(&y, b);
        voleith_gf128_mul(&z, &x, &y);
        voleith_gf128_to_bytes(out, &z);
    } else if (lambda == 192) {
        voleith_gf192_t x, y, z;
        voleith_gf192_from_bytes(&x, a);
        voleith_gf192_from_bytes(&y, b);
        voleith_gf192_mul(&z, &x, &y);
        voleith_gf192_to_bytes(out, &z);
    } else {
        voleith_gf256_t x, y, z;
        voleith_gf256_from_bytes(&x, a);
        voleith_gf256_from_bytes(&y, b);
        voleith_gf256_mul(&z, &x, &y);
        voleith_gf256_to_bytes(out, &z);
    }
}

static int
gflam_eq(int lambda, const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, (size_t)nbytes(lambda)) == 0;
}

/* Checks embed(a + b) == embed(a) + embed(b) for one pair. */
static int
add_law(int lambda, uint16_t a, uint16_t b)
{
    uint8_t ea[32], eb[32], esum[32], lhs[32], rhs[32];

    voleith_gf16_embed(ea, a, lambda);
    voleith_gf16_embed(eb, b, lambda);
    voleith_gf16_embed(esum, voleith_gf16_add(a, b), lambda);
    gflam_add(lambda, rhs, ea, eb);
    memcpy(lhs, esum, (size_t)nbytes(lambda));
    return gflam_eq(lambda, lhs, rhs);
}

/* Checks embed(a * b) == embed(a) * embed(b) for one pair. */
static int
mul_law(int lambda, uint16_t a, uint16_t b)
{
    uint8_t ea[32], eb[32], eprod[32], rhs[32];

    voleith_gf16_embed(ea, a, lambda);
    voleith_gf16_embed(eb, b, lambda);
    voleith_gf16_embed(eprod, voleith_gf16_mul(a, b), lambda);
    gflam_mul(lambda, rhs, ea, eb);
    return gflam_eq(lambda, eprod, rhs);
}

/*
 * Runs the full homomorphism battery for one lambda: identities, then the
 * additive and multiplicative laws over all 256 basis-element pairs
 * (1<<i, 1<<j) plus a deterministic random sweep.  Returns 1 on success.
 */
static int
homomorphism_holds(int lambda)
{
    uint8_t e0[32], e1[32], zero[32], one[32];

    /* embed(0) == 0, embed(1) == 1 (the GF(2^lambda) identity). */
    memset(zero, 0, sizeof(zero));
    memset(one, 0, sizeof(one));
    one[0] = 1;
    voleith_gf16_embed(e0, 0, lambda);
    voleith_gf16_embed(e1, 1, lambda);
    if (!gflam_eq(lambda, e0, zero))
        return 0;
    if (!gflam_eq(lambda, e1, one))
        return 0;

    /* Structured: every pair of polynomial-basis elements 1<<i, 1<<j. */
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            uint16_t a = (uint16_t)(1u << i);
            uint16_t b = (uint16_t)(1u << j);
            if (!add_law(lambda, a, b) || !mul_law(lambda, a, b))
                return 0;
        }
    }

    /* Random sweep. */
    sm_state = UINT64_C(0x5E16ED) ^ (uint64_t)lambda;
    for (int n = 0; n < 8192; n++) {
        uint16_t a = sm_next16();
        uint16_t b = sm_next16();
        if (!add_law(lambda, a, b) || !mul_law(lambda, a, b))
            return 0;
    }
    return 1;
}

static void
test_embed_homomorphism(int lambda)
{
    char name[64];

    snprintf(name, sizeof(name), "gf16 embed: homomorphism over GF(2^%d)",
             lambda);
    TEST(name);
    if (!homomorphism_holds(lambda)) {
        FAIL("embed is not a homomorphism");
        return;
    }
    PASS();
}

static void
test_embed_invalid_lambda(void)
{
    uint8_t out[32];

    TEST("gf16 embed: rejects invalid lambda");
    if (voleith_gf16_embed(out, 0x1234, 64) != -1) {
        FAIL("lambda 64 should be rejected");
        return;
    }
    PASS();
}

int
main(void)
{
    printf("=== GF(2^16) Subfield-Embedding (alpha16) Tests ===\n");
    test_embed_homomorphism(128);
    test_embed_homomorphism(192);
    test_embed_homomorphism(256);
    test_embed_invalid_lambda();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
