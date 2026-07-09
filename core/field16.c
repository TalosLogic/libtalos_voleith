/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field16.c - Finite field arithmetic for GF(2^16)
 *
 * GF(2^16) element arithmetic for the RLNC transport-layer erasure codes
 * (docs/ERASURE_CODES_DESIGN.md).  Mirrors the GF(2^64) compile-time
 * dispatch pattern in core/field.c: CLMUL / PMULL fast paths and a
 * constant-time software fallback, with a shared branchless reduction.
 *
 * m16 = x^16 + x^12 + x^3 + x + 1, reduction constant 0x100B.
 *
 * Constant-time by construction (no secret-dependent branch, no
 * secret-indexed memory) so that private RLNC coefficients remain possible
 * in a future proving use case.
 *
 * Clean-room implementation.
 */

#include "field16.h"

#ifdef VOLEITH_HAVE_CLMUL
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif

#ifdef VOLEITH_HAVE_PMULL
#include <arm_neon.h>
#endif

/* ========================================================================
 * Constant-time helper
 *
 * The optimizer-barrier idiom (`__asm__ volatile ("" : "+r"(x))`) prevents
 * the compiler from re-deriving a conditional branch from a {0, ~0}
 * bitmask.  It compiles to zero instructions.  Matches the ct_barrier_u64
 * helper in core/field.c.
 * ======================================================================== */

#if !(defined(__GNUC__) || defined(__clang__))
#error "Constant-time field path currently requires gcc or clang " \
         "(inline-asm optimizer barrier)."
#endif

static inline uint32_t
ct_barrier_u32(uint32_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
}

/* ========================================================================
 * Reduction
 *
 * Reduces a degree-<= 30 carryless product modulo m16.  Each fold folds
 * the high half down via x^16 = x^12 + x^3 + x + 1 (the bit positions of
 * VOLEITH_GF16_REDUCE = 0x100B): a coefficient at position 16 + j
 * contributes x^(j+12) + x^(j+3) + x^(j+1) + x^j.
 *
 * The x^12 term means one fold of a degree-d term lands at degree d - 4,
 * so the degree drops by 4 per fold: 30 -> 26 -> 22 -> 18 -> <= 15.  Four
 * folds are sufficient and the loop count is fixed (constant-time).
 * ======================================================================== */

static inline voleith_gf16_t
gf16_reduce(uint32_t p)
{
    int i;

    for (i = 0; i < 4; i++) {
        uint32_t hi = p >> 16;
        p = (p & 0xFFFFu) ^ (hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 12));
    }
    return (voleith_gf16_t)(p & 0xFFFFu);
}

/* ========================================================================
 * Carryless 16-bit product (the only path-specific step)
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

static inline uint32_t
clmul16(voleith_gf16_t a, voleith_gf16_t b)
{
    __m128i va = _mm_set_epi64x(0, (long long)a);
    __m128i vb = _mm_set_epi64x(0, (long long)b);
    __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);
    return (uint32_t)_mm_extract_epi64(prod, 0);
}

#elif defined(VOLEITH_HAVE_PMULL)

static inline uint32_t
clmul16(voleith_gf16_t a, voleith_gf16_t b)
{
    poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);
    return (uint32_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
}

#else /* Constant-time software path */

static uint32_t
clmul16(voleith_gf16_t a, voleith_gf16_t b)
{
    uint32_t aw = (uint32_t)a;
    uint32_t bw = (uint32_t)b;
    uint32_t r = 0;
    int i;

    for (i = 0; i < 16; i++) {
        uint32_t mask = ct_barrier_u32(-(bw & 1u));
        r ^= (aw << i) & mask;
        bw >>= 1;
    }
    return r;
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * Public operations
 * ======================================================================== */

voleith_gf16_t
voleith_gf16_mul(voleith_gf16_t a, voleith_gf16_t b)
{
    return gf16_reduce(clmul16(a, b));
}

voleith_gf16_t
voleith_gf16_inv(voleith_gf16_t a)
{
    voleith_gf16_t pw[16];
    voleith_gf16_t r;
    int i;

    /* pw[i] = a^(2^i); inv(a) = a^(2^16 - 2) = product of a^(2^i), i=1..15. */
    pw[1] = voleith_gf16_mul(a, a);
    for (i = 2; i < 16; i++)
        pw[i] = voleith_gf16_mul(pw[i - 1], pw[i - 1]);

    r = pw[1];
    for (i = 2; i < 16; i++)
        r = voleith_gf16_mul(r, pw[i]);
    return r;
}
