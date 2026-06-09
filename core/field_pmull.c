/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field_pmull.c - ARMv8 PMULL implementations of GF(2^128/192/256) mul.
 *
 * Compiled with -march=armv8-a+crypto (if needed) per-TU; the rest of the
 * library does not require that flag.  This file compiles to an empty object
 * when VOLEITH_HAVE_PMULL is not defined.
 */

#ifdef VOLEITH_HAVE_PMULL

#include "field_dispatch.h"

#include <arm_neon.h>

/*
 * 64x64 -> 128-bit carry-less multiply using ARMv8 PMULL instruction.
 */
static inline void
pmull64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);
    *lo = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
    *hi = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 1);
}

/* ========================================================================
 * GF(2^128) - PMULL path
 * P_128 = x^128 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_pmull_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                      const voleith_gf128_t *b)
{
    uint64_t p00h, p00l, p01h, p01l, p10h, p10l, p11h, p11l;
    pmull64(a->v[0], b->v[0], &p00h, &p00l);
    pmull64(a->v[0], b->v[1], &p01h, &p01l);
    pmull64(a->v[1], b->v[0], &p10h, &p10l);
    pmull64(a->v[1], b->v[1], &p11h, &p11l);

    uint64_t c0 = p00l;
    uint64_t c1 = p00h ^ p01l ^ p10l;
    uint64_t c2 = p01h ^ p10h ^ p11l;
    uint64_t c3 = p11h;

    /* Reduce modulo P_128 = x^128 + x^7 + x^2 + x + 1. */
    c1 ^= c3 ^ (c3 << 1) ^ (c3 << 2) ^ (c3 << 7);
    c2 ^= (c3 >> 57) ^ (c3 >> 62) ^ (c3 >> 63);
    c0 ^= c2 ^ (c2 << 1) ^ (c2 << 2) ^ (c2 << 7);
    c1 ^= (c2 >> 57) ^ (c2 >> 62) ^ (c2 >> 63);

    c->v[0] = c0;
    c->v[1] = c1;
}

/* ========================================================================
 * GF(2^192) - PMULL path
 * P_192 = x^192 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_pmull_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                      const voleith_gf192_t *b)
{
    uint64_t d[6] = {0};

    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            uint64_t hi, lo;
            pmull64(a->v[i], b->v[j], &hi, &lo);
            d[i + j] ^= lo;
            d[i + j + 1] ^= hi;
        }
    }

    /* Reduce modulo P_192 = x^192 + x^7 + x^2 + x + 1. */
    d[2] ^= d[5] ^ (d[5] << 1) ^ (d[5] << 2) ^ (d[5] << 7);
    d[3] ^= (d[5] >> 57) ^ (d[5] >> 62) ^ (d[5] >> 63);
    d[1] ^= d[4] ^ (d[4] << 1) ^ (d[4] << 2) ^ (d[4] << 7);
    d[2] ^= (d[4] >> 57) ^ (d[4] >> 62) ^ (d[4] >> 63);
    d[0] ^= d[3] ^ (d[3] << 1) ^ (d[3] << 2) ^ (d[3] << 7);
    d[1] ^= (d[3] >> 57) ^ (d[3] >> 62) ^ (d[3] >> 63);

    c->v[0] = d[0];
    c->v[1] = d[1];
    c->v[2] = d[2];
}

/* ========================================================================
 * GF(2^256) - PMULL path
 * P_256 = x^256 + x^10 + x^5 + x^2 + 1
 * ======================================================================== */

static void
field_pmull_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                      const voleith_gf256_t *b)
{
    uint64_t d[8] = {0};

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            uint64_t hi, lo;
            pmull64(a->v[i], b->v[j], &hi, &lo);
            d[i + j] ^= lo;
            d[i + j + 1] ^= hi;
        }
    }

    /* Reduce modulo P_256 = x^256 + x^10 + x^5 + x^2 + 1. */
    d[3] ^= d[7] ^ (d[7] << 2) ^ (d[7] << 5) ^ (d[7] << 10);
    d[4] ^= (d[7] >> 54) ^ (d[7] >> 59) ^ (d[7] >> 62);
    d[2] ^= d[6] ^ (d[6] << 2) ^ (d[6] << 5) ^ (d[6] << 10);
    d[3] ^= (d[6] >> 54) ^ (d[6] >> 59) ^ (d[6] >> 62);
    d[1] ^= d[5] ^ (d[5] << 2) ^ (d[5] << 5) ^ (d[5] << 10);
    d[2] ^= (d[5] >> 54) ^ (d[5] >> 59) ^ (d[5] >> 62);
    d[0] ^= d[4] ^ (d[4] << 2) ^ (d[4] << 5) ^ (d[4] << 10);
    d[1] ^= (d[4] >> 54) ^ (d[4] >> 59) ^ (d[4] >> 62);

    c->v[0] = d[0];
    c->v[1] = d[1];
    c->v[2] = d[2];
    c->v[3] = d[3];
}

/* ========================================================================
 * Ops table
 * ======================================================================== */

const voleith_field_ops_t voleith_field_ops_pmull = {
    .gf128_mul = field_pmull_gf128_mul,
    .gf192_mul = field_pmull_gf192_mul,
    .gf256_mul = field_pmull_gf256_mul,
    .name = "pmull",
};

#endif /* VOLEITH_HAVE_PMULL */
