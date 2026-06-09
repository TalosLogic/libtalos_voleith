/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field_clmul.c - CLMUL/PCLMULQDQ implementations of GF(2^128/192/256) mul.
 *
 * Compiled with -mpclmul -msse2 -msse4.1 per-TU; the rest of the library
 * does not require those flags.  This file compiles to an empty object when
 * VOLEITH_HAVE_CLMUL is not defined.
 */

#ifdef VOLEITH_HAVE_CLMUL

#include "field_dispatch.h"

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

/* ========================================================================
 * GF(2^128) - CLMUL path
 * P_128 = x^128 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_clmul_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                      const voleith_gf128_t *b)
{
    __m128i va = _mm_loadu_si128((const __m128i *)a->v);
    __m128i vb = _mm_loadu_si128((const __m128i *)b->v);

    __m128i p00 = _mm_clmulepi64_si128(va, vb, 0x00);
    __m128i p11 = _mm_clmulepi64_si128(va, vb, 0x11);
    __m128i p01 = _mm_clmulepi64_si128(va, vb, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(va, vb, 0x10);

    __m128i mid = _mm_xor_si128(p01, p10);

    uint64_t c0 = (uint64_t)_mm_extract_epi64(p00, 0);
    uint64_t c1 = (uint64_t)_mm_extract_epi64(p00, 1) ^
                  (uint64_t)_mm_extract_epi64(mid, 0);
    uint64_t c2 = (uint64_t)_mm_extract_epi64(p11, 0) ^
                  (uint64_t)_mm_extract_epi64(mid, 1);
    uint64_t c3 = (uint64_t)_mm_extract_epi64(p11, 1);

    /* Reduce modulo P_128 = x^128 + x^7 + x^2 + x + 1. */
    c1 ^= c3 ^ (c3 << 1) ^ (c3 << 2) ^ (c3 << 7);
    c2 ^= (c3 >> 57) ^ (c3 >> 62) ^ (c3 >> 63);
    c0 ^= c2 ^ (c2 << 1) ^ (c2 << 2) ^ (c2 << 7);
    c1 ^= (c2 >> 57) ^ (c2 >> 62) ^ (c2 >> 63);

    c->v[0] = c0;
    c->v[1] = c1;
}

/* ========================================================================
 * GF(2^192) - CLMUL path
 * P_192 = x^192 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_clmul_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                      const voleith_gf192_t *b)
{
    __m128i va0 = _mm_set_epi64x(0, (long long)a->v[0]);
    __m128i va1 = _mm_set_epi64x(0, (long long)a->v[1]);
    __m128i va2 = _mm_set_epi64x(0, (long long)a->v[2]);
    __m128i vb0 = _mm_set_epi64x(0, (long long)b->v[0]);
    __m128i vb1 = _mm_set_epi64x(0, (long long)b->v[1]);
    __m128i vb2 = _mm_set_epi64x(0, (long long)b->v[2]);

    __m128i p00 = _mm_clmulepi64_si128(va0, vb0, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(va0, vb1, 0x00);
    __m128i p02 = _mm_clmulepi64_si128(va0, vb2, 0x00);
    __m128i p10 = _mm_clmulepi64_si128(va1, vb0, 0x00);
    __m128i p11 = _mm_clmulepi64_si128(va1, vb1, 0x00);
    __m128i p12 = _mm_clmulepi64_si128(va1, vb2, 0x00);
    __m128i p20 = _mm_clmulepi64_si128(va2, vb0, 0x00);
    __m128i p21 = _mm_clmulepi64_si128(va2, vb1, 0x00);
    __m128i p22 = _mm_clmulepi64_si128(va2, vb2, 0x00);

    uint64_t d[6] = {0};
    d[0] = (uint64_t)_mm_extract_epi64(p00, 0);
    d[1] = (uint64_t)_mm_extract_epi64(p00, 1) ^
           (uint64_t)_mm_extract_epi64(p01, 0) ^
           (uint64_t)_mm_extract_epi64(p10, 0);
    d[2] = (uint64_t)_mm_extract_epi64(p01, 1) ^
           (uint64_t)_mm_extract_epi64(p10, 1) ^
           (uint64_t)_mm_extract_epi64(p02, 0) ^
           (uint64_t)_mm_extract_epi64(p11, 0) ^
           (uint64_t)_mm_extract_epi64(p20, 0);
    d[3] = (uint64_t)_mm_extract_epi64(p02, 1) ^
           (uint64_t)_mm_extract_epi64(p11, 1) ^
           (uint64_t)_mm_extract_epi64(p20, 1) ^
           (uint64_t)_mm_extract_epi64(p12, 0) ^
           (uint64_t)_mm_extract_epi64(p21, 0);
    d[4] = (uint64_t)_mm_extract_epi64(p12, 1) ^
           (uint64_t)_mm_extract_epi64(p21, 1) ^
           (uint64_t)_mm_extract_epi64(p22, 0);
    d[5] = (uint64_t)_mm_extract_epi64(p22, 1);

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
 * GF(2^256) - CLMUL path
 * P_256 = x^256 + x^10 + x^5 + x^2 + 1
 * ======================================================================== */

static void
field_clmul_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                      const voleith_gf256_t *b)
{
    uint64_t d[8] = {0};

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            __m128i ai = _mm_set_epi64x(0, (long long)a->v[i]);
            __m128i bj = _mm_set_epi64x(0, (long long)b->v[j]);
            __m128i p = _mm_clmulepi64_si128(ai, bj, 0x00);
            d[i + j] ^= (uint64_t)_mm_extract_epi64(p, 0);
            d[i + j + 1] ^= (uint64_t)_mm_extract_epi64(p, 1);
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

const voleith_field_ops_t voleith_field_ops_clmul = {
    .gf128_mul = field_clmul_gf128_mul,
    .gf192_mul = field_clmul_gf192_mul,
    .gf256_mul = field_clmul_gf256_mul,
    .name = "clmul",
};

#endif /* VOLEITH_HAVE_CLMUL */
