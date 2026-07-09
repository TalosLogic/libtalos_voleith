/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gen_alpha16.c - GF(2^16) subfield-embedding table emitter (T5.1).
 *
 * Emits the alpha16 tables: the powers beta^1 .. beta^15 of a root beta of
 * the canonical GF(2^16) defining polynomial
 *
 *     m16 = x^16 + x^12 + x^3 + x + 1   (0x1100B)
 *
 * embedded in GF(2^lambda) for lambda in {128, 192, 256}.  beta^0 = 1 is
 * implicit, so 15 entries per lambda (mirrors the gf8 alpha tables, which
 * carry alpha^1 .. alpha^7).  These let the gf16 element-level prover embed
 * a GF(2^16) value v into GF(2^lambda) as
 *
 *     embed(v) = sum_i v_bit_i * beta^i.
 *
 * This is the canonical generator: it links the project's own core/field.c
 * GF(2^lambda) arithmetic, so the emitted limb encoding matches the library
 * by construction.  It needs no external dependency and never factors
 * 2^lambda - 1 (only 65535 = 3 * 5 * 17 * 257, trivially).  A SageMath
 * script (crosscheck.sage) reproduces the same tables independently; see
 * README.md for the build, the deterministic root rule, and the derivation.
 *
 * Run ONCE; redirect stdout to a paste-ready block for core/field.c.  This
 * tool is NEVER linked into the library or its tests (faest-ref posture).
 *
 * Algorithm, for each lambda:
 *   1. Project random GF(2^lambda) elements into the GF(2^16) subfield (the
 *      fixed field of the Frobenius x -> x^(2^16)) via the relative trace
 *      P(x) = sum_{i=0}^{m-1} x^(2^(16 i)), m = lambda / 16.
 *   2. Find a multiplicative generator g of the order-65535 subfield group.
 *   3. Enumerate the 65535 nonzero subfield elements g^0 .. g^65534, collect
 *      the 16 roots of m16, and pick the root with the smallest encoding (its
 *      to_bytes() little-endian serialization read as an unsigned integer,
 *      byte 0 least significant).  Zero is never a root (m16(0) = 1).
 *   4. Emit beta^1 .. beta^15.
 * The root set is independent of g; g only fixes the enumeration order.
 */

#include "field.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * A field element held generically as four limbs.  Only the low lambda/64
 * limbs are significant; the rest stay zero so add/eq/is_zero can ignore
 * the width.
 */
typedef struct {
    uint64_t v[4];
} gfx_t;

static const uint64_t SUB_ORDER = 65535;
static const uint64_t sub_order_primes[4] = {3, 5, 17, 257};

static int
limbs_for(int lambda)
{
    return lambda / 64;
}

static gfx_t
gfx_one(void)
{
    gfx_t r;
    memset(&r, 0, sizeof(r));
    r.v[0] = 1;
    return r;
}

static int
gfx_is_zero(const gfx_t *a)
{
    return (a->v[0] | a->v[1] | a->v[2] | a->v[3]) == 0;
}

static int
gfx_eq(const gfx_t *a, const gfx_t *b)
{
    for (int i = 0; i < 4; i++)
        if (a->v[i] != b->v[i])
            return 0;
    return 1;
}

/*
 * Compares two elements by their canonical encoding: the to_bytes()
 * little-endian byte string read as an unsigned integer (byte 0 is least
 * significant).  Returns -1, 0, 1.  The high limb is the most significant.
 */
static int
gfx_cmp(int lambda, const gfx_t *a, const gfx_t *b)
{
    for (int i = limbs_for(lambda) - 1; i >= 0; i--) {
        if (a->v[i] < b->v[i])
            return -1;
        if (a->v[i] > b->v[i])
            return 1;
    }
    return 0;
}

static void
gfx_add(gfx_t *c, const gfx_t *a, const gfx_t *b)
{
    for (int i = 0; i < 4; i++)
        c->v[i] = a->v[i] ^ b->v[i];
}

/* Dispatches the multiply to the library's per-width GF(2^lambda) routine. */
static void
gfx_mul(int lambda, gfx_t *c, const gfx_t *a, const gfx_t *b)
{
    gfx_t r;
    memset(&r, 0, sizeof(r));
    if (lambda == 128) {
        voleith_gf128_t aa, bb, cc;
        memcpy(aa.v, a->v, 16);
        memcpy(bb.v, b->v, 16);
        voleith_gf128_mul(&cc, &aa, &bb);
        memcpy(r.v, cc.v, 16);
    } else if (lambda == 192) {
        voleith_gf192_t aa, bb, cc;
        memcpy(aa.v, a->v, 24);
        memcpy(bb.v, b->v, 24);
        voleith_gf192_mul(&cc, &aa, &bb);
        memcpy(r.v, cc.v, 24);
    } else {
        voleith_gf256_t aa, bb, cc;
        memcpy(aa.v, a->v, 32);
        memcpy(bb.v, b->v, 32);
        voleith_gf256_mul(&cc, &aa, &bb);
        memcpy(r.v, cc.v, 32);
    }
    *c = r;
}

/* out = base^e by square-and-multiply. */
static void
gfx_pow(int lambda, gfx_t *out, const gfx_t *base, uint64_t e)
{
    gfx_t r = gfx_one();
    gfx_t b = *base;

    while (e != 0) {
        if (e & 1)
            gfx_mul(lambda, &r, &r, &b);
        gfx_mul(lambda, &b, &b, &b);
        e >>= 1;
    }
    *out = r;
}

/* out = x^(2^16): the Frobenius that fixes the GF(2^16) subfield. */
static void
frob16(int lambda, gfx_t *out, const gfx_t *x)
{
    gfx_t t = *x;

    for (int i = 0; i < 16; i++)
        gfx_mul(lambda, &t, &t, &t);
    *out = t;
}

/*
 * Projects x into the GF(2^16) subfield via the relative trace
 * P(x) = sum_{i=0}^{m-1} (Frobenius^16)^i (x), m = lambda / 16.  The image
 * lies in the fixed field of the Frobenius, i.e. GF(2^16).
 */
static void
project(int lambda, gfx_t *out, const gfx_t *x)
{
    int m = lambda / 16;
    gfx_t acc, cur = *x;

    memset(&acc, 0, sizeof(acc));
    for (int i = 0; i < m; i++) {
        gfx_add(&acc, &acc, &cur);
        frob16(lambda, &cur, &cur);
    }
    *out = acc;
}

/* splitmix64: deterministic candidate stream, seeded per lambda. */
static uint64_t sm_state;

static uint64_t
sm_next(void)
{
    uint64_t z = (sm_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

/*
 * Returns 1 if s generates the order-65535 subfield group: s is nonzero and
 * s^(65535/p) != 1 for every prime p dividing 65535.
 */
static int
is_generator(int lambda, const gfx_t *s)
{
    gfx_t one = gfx_one();

    if (gfx_is_zero(s))
        return 0;
    for (int i = 0; i < 4; i++) {
        gfx_t t;
        gfx_pow(lambda, &t, s, SUB_ORDER / sub_order_primes[i]);
        if (gfx_eq(&t, &one))
            return 0;
    }
    return 1;
}

/* Finds a multiplicative generator of the GF(2^16) subfield. */
static void
find_generator(int lambda, gfx_t *g)
{
    sm_state = UINT64_C(0xA1F16C0DE0000000) ^ (uint64_t)lambda;
    for (;;) {
        gfx_t r, s;
        memset(&r, 0, sizeof(r));
        for (int i = 0; i < limbs_for(lambda); i++)
            r.v[i] = sm_next();
        project(lambda, &s, &r);
        if (is_generator(lambda, &s)) {
            *g = s;
            return;
        }
    }
}

/* Returns 1 if b is a root of m16 = x^16 + x^12 + x^3 + x + 1. */
static int
is_m16_root(int lambda, const gfx_t *b)
{
    gfx_t b3, b12, b16, acc, one = gfx_one();

    gfx_pow(lambda, &b3, b, 3);
    gfx_pow(lambda, &b12, b, 12);
    gfx_pow(lambda, &b16, b, 16);
    memset(&acc, 0, sizeof(acc));
    gfx_add(&acc, &acc, &b16);
    gfx_add(&acc, &acc, &b12);
    gfx_add(&acc, &acc, &b3);
    gfx_add(&acc, &acc, b);
    gfx_add(&acc, &acc, &one);
    return gfx_is_zero(&acc);
}

/*
 * Enumerates the subfield, collecting the roots of m16, and writes the one
 * with the smallest encoding to beta.  Returns the number of roots found
 * (must be 16 for a correct run).
 */
static int
find_root(int lambda, gfx_t *beta)
{
    gfx_t g, cur, best;
    int found = 0, count = 0;

    find_generator(lambda, &g);
    cur = gfx_one();
    memset(&best, 0, sizeof(best));
    for (uint64_t j = 0; j < SUB_ORDER; j++) {
        if (is_m16_root(lambda, &cur)) {
            count++;
            if (!found || gfx_cmp(lambda, &cur, &best) < 0) {
                best = cur;
                found = 1;
            }
        }
        gfx_mul(lambda, &cur, &cur, &g);
    }
    *beta = best;
    return count;
}

/* Prints beta^1 .. beta^15 as a paste-ready core/field.c table. */
static void
emit_table(int lambda, const gfx_t *beta)
{
    int L = limbs_for(lambda);
    gfx_t p = *beta;

    printf("static const voleith_gf%d_t gf%d_alpha16[15] = {\n", lambda,
           lambda);
    for (int e = 1; e <= 15; e++) {
        printf("    {{");
        for (int i = 0; i < L; i++) {
            printf("UINT64_C(0x%016" PRIx64 ")", p.v[i]);
            if (i + 1 < L) {
                printf(",");
                if (i == 1)
                    printf("\n      ");
                else
                    printf(" ");
            }
        }
        printf("}},\n");
        gfx_mul(lambda, &p, &p, beta);
    }
    printf("};\n\n");
}

int
main(void)
{
    int lambdas[3] = {128, 192, 256};

    printf("/*\n");
    printf(" * GF(2^16) subfield-embedding tables (alpha16).  Generated by\n");
    printf(" * tools/gen_alpha16; do not edit by hand.  beta is the smallest"
           "-encoding\n");
    printf(" * root of m16 = x^16 + x^12 + x^3 + x + 1 in GF(2^lambda); the\n");
    printf(" * entries are beta^1 .. beta^15 (beta^0 = 1 implicit).  See\n");
    printf(" * tools/gen_alpha16/README.md for the derivation.\n");
    printf(" */\n\n");

    for (int t = 0; t < 3; t++) {
        int lambda = lambdas[t];
        gfx_t beta;
        int count = find_root(lambda, &beta);

        if (count != 16) {
            fprintf(stderr, "lambda %d: expected 16 roots of m16, found %d\n",
                    lambda, count);
            return 1;
        }
        fprintf(stderr, "lambda %d: 16 roots, picked smallest-encoding beta\n",
                lambda);
        emit_table(lambda, &beta);
    }
    return 0;
}
