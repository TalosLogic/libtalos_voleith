/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field.c - Finite field arithmetic for F_{2^k}
 *
 * Implements multiplication in GF(2^k) for k = 8, 64, 128, 192, 256.
 *
 * Each multiplication has three possible implementations, selected by
 * preprocessor in this order of preference:
 *
 *   1. VOLEITH_HAVE_CLMUL          - CLMUL hardware path (constant-time
 *                                    on x86_64; highest performance).
 *   2. VOLEITH_ALLOW_VARIABLE_TIME_FIELD
 *                                  - variable-time shift-and-reduce
 *                                    (Russian peasant).  Compiled in
 *                                    only when explicitly opted into.
 *                                    Reference code; not constant-time;
 *                                    NOT for production.  See
 *                                    docs/SECURITY_REVIEW.md C-2.
 *   3. (default)                   - constant-time mask-based software
 *                                    fallback.  Used when CLMUL is
 *                                    unavailable and the variable-time
 *                                    path has not been opted into.
 *
 * Clean-room implementation from the FAEST v2.0 specification.
 */

#include "field.h"

#ifdef VOLEITH_HAVE_CLMUL
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif

#ifdef VOLEITH_HAVE_PMULL
#include <arm_neon.h>

/*
 * 64x64 → 128-bit carry-less multiply using ARMv8 PMULL instruction.
 * Equivalent to x86 PCLMULQDQ; same reduction formulas apply.
 */
static inline void
pmull64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);
    *lo = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
    *hi = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 1);
}
#endif

#ifdef VOLEITH_ALLOW_VARIABLE_TIME_FIELD
#pragma message("voleith: field.c built with variable-time software path "     \
                "(VOLEITH_ALLOW_VARIABLE_TIME_FIELD).  TEST/DEBUG only.")
#endif

/* ========================================================================
 * Constant-time helpers
 *
 * Used by the constant-time software arms (the default when CLMUL is
 * unavailable).  Not referenced when VOLEITH_HAVE_CLMUL or
 * VOLEITH_ALLOW_VARIABLE_TIME_FIELD is defined; gated to avoid
 * unused-function warnings under those configurations.
 *
 * The optimizer-barrier idiom (`__asm__ volatile ("" : "+r"(x))`) is
 * the standard cryptographic-library technique for preventing a
 * sufficiently smart compiler from re-deriving a conditional branch
 * from a bitmask of {0, ~0}.  Compiles to zero instructions; tells
 * the compiler the value is opaque after this point.
 * ======================================================================== */

#if !defined(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)

#if !(defined(__GNUC__) || defined(__clang__))
#error "Constant-time field path currently requires gcc or clang " \
         "(inline-asm optimizer barrier).  If you need a different " \
         "toolchain, set -DVOLEITH_ALLOW_VARIABLE_TIME_FIELD=ON as a " \
         "temporary measure - but note that path is variable-time and " \
         "NOT for production.  See docs/SECURITY_REVIEW.md C-2."
#endif

static inline uint64_t
ct_barrier_u64(uint64_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
}

#if !defined(VOLEITH_HAVE_CLMUL)
/*
 * Multi-limb constant-time bit accessor.  Returns 0 or ~0 depending
 * on bit `pos` of `v`.  Only used by the multi-limb (128/192/256)
 * constant-time arms, so gated behind !HAVE_CLMUL to avoid unused-
 * function warnings on a hardware-CLMUL build.
 */
static inline uint64_t
limbs_get_bit_mask(const uint64_t *v, int pos)
{
    /* `pos` is loop-counter-controlled (public).  v[] may carry a
     * secret; the bit-extract becomes a mask via unary minus. */
    uint64_t bit = (v[pos / 64] >> (pos % 64)) & 1ULL;
    return -bit;
}
#endif /* !VOLEITH_HAVE_CLMUL */

#endif /* !VOLEITH_ALLOW_VARIABLE_TIME_FIELD */

/* ========================================================================
 * GF(2^8) - AES field
 * P_8 = x^8 + x^4 + x^3 + x + 1, reduction constant 0x1B
 * ======================================================================== */

#ifdef VOLEITH_ALLOW_VARIABLE_TIME_FIELD

/*
 * Variable-time reference implementation.  Branches on bits of the
 * multiplier and on the high bit of the running shifted value; both
 * become cache/timing side channels when either operand is secret.
 * Compiled in only when explicitly opted into; see
 * docs/SECURITY_REVIEW.md finding C-2.
 */
voleith_gf8_t
voleith_gf8_mul(voleith_gf8_t a, voleith_gf8_t b)
{
    voleith_gf8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi)
            a ^= VOLEITH_GF8_REDUCE;
        b >>= 1;
    }
    return result;
}

#else /* Constant-time default */

/*
 * Constant-time mask-based implementation.  Each conditional XOR is
 * replaced by an AND with a {0, ~0} mask derived from the relevant
 * bit; the mask passes through ct_barrier_u64 to block the optimizer
 * from re-deriving a branch.  Performs the same Russian-peasant
 * algorithm; output identical to the variable-time form for every
 * input.
 */
voleith_gf8_t
voleith_gf8_mul(voleith_gf8_t a, voleith_gf8_t b)
{
    uint64_t aw = (uint64_t)a;
    uint64_t bw = (uint64_t)b;
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t mask = ct_barrier_u64(-(bw & 1ULL));
        result ^= aw & mask;
        uint64_t hi = (aw >> 7) & 1ULL;
        uint64_t reduce_mask = ct_barrier_u64(-hi);
        aw = ((aw << 1) ^ (VOLEITH_GF8_REDUCE & reduce_mask)) & 0xFFULL;
        bw >>= 1;
    }
    return (voleith_gf8_t)result;
}

#endif /* VOLEITH_ALLOW_VARIABLE_TIME_FIELD */

/* ========================================================================
 * GF(2^64)
 * P_64 = x^64 + x^4 + x^3 + x + 1, reduction constant 0x1B
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

/*
 * CLMUL-accelerated GF(2^64) multiplication.
 * Uses a single PCLMULQDQ instruction for the 64x64 carry-less multiply,
 * then reduces the 128-bit product modulo P_64.
 */
voleith_gf64_t
voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b)
{
    __m128i va = _mm_set_epi64x(0, (long long)a);
    __m128i vb = _mm_set_epi64x(0, (long long)b);
    __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);

    uint64_t lo = (uint64_t)_mm_extract_epi64(prod, 0);
    uint64_t hi = (uint64_t)_mm_extract_epi64(prod, 1);

    /* Reduce: x^64 ≡ x^4+x^3+x+1. Process hi bits. */
    lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    /* Overflow from shifts: at most 4 bits above position 64 */
    uint64_t overflow = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^= overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    return lo;
}

#elif defined(VOLEITH_HAVE_PMULL)

/*
 * PMULL-accelerated GF(2^64) multiplication.
 * Uses a single vmull_p64 for the 64x64 carry-less product; same
 * reduction as the CLMUL path (the polynomial irreducible is the same).
 */
voleith_gf64_t
voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b)
{
    uint64_t lo, hi;
    pmull64(a, b, &hi, &lo);

    lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    uint64_t overflow = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^= overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    return lo;
}

#else /* Software path - variable-time or constant-time arm below */

#ifdef VOLEITH_ALLOW_VARIABLE_TIME_FIELD

/*
 * Variable-time software carry-less multiply.  Branches on bits of b;
 * the secondary `if (i > 0)` branch is on the loop counter only and
 * is therefore safe - it exists to avoid the undefined `a >> 64`.
 */
static void
clmul64_soft(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t rlo = 0, rhi = 0;
    for (int i = 0; i < 64; i++) {
        if ((b >> i) & 1) {
            rlo ^= a << i;
            if (i > 0)
                rhi ^= a >> (64 - i);
        }
    }
    *lo = rlo;
    *hi = rhi;
}

#else /* Constant-time default */

/*
 * Constant-time software carry-less multiply.  The conditional XOR on
 * `(b >> i) & 1` becomes an AND with a mask through ct_barrier_u64.
 * The `i == 0` branch is on the loop counter (public) and is needed
 * because C makes shifts by the width of the type undefined behavior.
 */
static void
clmul64_soft(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t rlo = 0, rhi = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t mask = ct_barrier_u64(-((b >> i) & 1ULL));
        rlo ^= (a << i) & mask;
        rhi ^= ((i == 0) ? 0ULL : (a >> (64 - i))) & mask;
    }
    *lo = rlo;
    *hi = rhi;
}

#endif /* VOLEITH_ALLOW_VARIABLE_TIME_FIELD */

voleith_gf64_t
voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b)
{
    uint64_t hi, lo;
    clmul64_soft(a, b, &hi, &lo);

    /* Reduce: x^64 ≡ x^4+x^3+x+1.  Branch-free, no secret-dependent
     * memory access. */
    lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    uint64_t overflow = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^= overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    return lo;
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * Multi-limb helpers for GF(2^128), GF(2^192), GF(2^256)
 *
 * These fields use the "Russian peasant" / shift-and-reduce approach:
 * iterate over bits of b, conditionally XOR shifted a into accumulator,
 * doubling a (with reduction) at each step.
 * ======================================================================== */

/*
 * Shift a multi-limb value left by 1 bit.
 * Returns the overflow bit (the bit shifted out of the top limb).
 */
static inline uint64_t
limbs_shl1(uint64_t *v, int n)
{
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t next_carry = v[i] >> 63;
        v[i] = (v[i] << 1) | carry;
        carry = next_carry;
    }
    return carry;
}

/* XOR src into dst, n limbs. */
static inline void
limbs_xor(uint64_t *dst, const uint64_t *src, int n)
{
    for (int i = 0; i < n; i++)
        dst[i] ^= src[i];
}

/* Test bit at position pos in a multi-limb value. */
static inline int
limbs_test_bit(const uint64_t *v, int pos)
{
    return (int)((v[pos / 64] >> (pos % 64)) & 1);
}

/* ========================================================================
 * GF(2^128) multiplication
 * P_128 = x^128 + x^7 + x^2 + x + 1
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

/*
 * CLMUL-accelerated GF(2^128) multiplication.
 * Schoolbook 128x128 → 256-bit product using 4 PCLMULQDQ, then reduce.
 */
void
voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                  const voleith_gf128_t *b)
{
    __m128i va = _mm_loadu_si128((const __m128i *)a->v);
    __m128i vb = _mm_loadu_si128((const __m128i *)b->v);

    /* Schoolbook: a = a1:a0, b = b1:b0 */
    __m128i p00 = _mm_clmulepi64_si128(va, vb, 0x00); /* a0*b0 */
    __m128i p11 = _mm_clmulepi64_si128(va, vb, 0x11); /* a1*b1 */
    __m128i p01 = _mm_clmulepi64_si128(va, vb, 0x01); /* a0*b1 */
    __m128i p10 = _mm_clmulepi64_si128(va, vb, 0x10); /* a1*b0 */

    /* Cross terms */
    __m128i mid = _mm_xor_si128(p01, p10);

    /* Assemble 256-bit product in [c0, c1, c2, c3] */
    uint64_t c0 = (uint64_t)_mm_extract_epi64(p00, 0);
    uint64_t c1 = (uint64_t)_mm_extract_epi64(p00, 1) ^
                  (uint64_t)_mm_extract_epi64(mid, 0);
    uint64_t c2 = (uint64_t)_mm_extract_epi64(p11, 0) ^
                  (uint64_t)_mm_extract_epi64(mid, 1);
    uint64_t c3 = (uint64_t)_mm_extract_epi64(p11, 1);

    /*
     * Reduce modulo P_128 = x^128 + x^7 + x^2 + x + 1.
     * x^128 ≡ x^7 + x^2 + x + 1.
     *
     * Step 1: Fold c3 (bits 192..255).
     *   c3 * x^192 = c3 * x^64 * x^128 ≡ c3 * x^64 * (x^7+x^2+x+1)
     *   Contributes to c1 with overflow into c2.
     */
    c1 ^= c3 ^ (c3 << 1) ^ (c3 << 2) ^ (c3 << 7);
    c2 ^= (c3 >> 57) ^ (c3 >> 62) ^ (c3 >> 63);

    /*
     * Step 2: Fold c2 (bits 128..191).
     *   c2 * x^128 ≡ c2 * (x^7+x^2+x+1)
     */
    c0 ^= c2 ^ (c2 << 1) ^ (c2 << 2) ^ (c2 << 7);
    c1 ^= (c2 >> 57) ^ (c2 >> 62) ^ (c2 >> 63);

    c->v[0] = c0;
    c->v[1] = c1;
}

#elif defined(VOLEITH_HAVE_PMULL)

/*
 * PMULL-accelerated GF(2^128) multiplication.
 * Schoolbook 128x128 → 256-bit product using 4 vmull_p64 calls; same
 * reduction as the CLMUL path.
 */
void
voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
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

#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)

/*
 * Variable-time software GF(2^128) multiplication.  Branches on bits
 * of b via limbs_test_bit() and on the shift-overflow bit.  Reference
 * code only; see docs/SECURITY_REVIEW.md C-2.
 */
void
voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                  const voleith_gf128_t *b)
{
    uint64_t result[2] = {0, 0};
    uint64_t shifted[2] = {a->v[0], a->v[1]};

    for (int i = 0; i < 128; i++) {
        if (limbs_test_bit(b->v, i))
            limbs_xor(result, shifted, 2);
        uint64_t overflow = limbs_shl1(shifted, 2);
        if (overflow)
            shifted[0] ^= VOLEITH_GF128_REDUCE;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
}

#else /* Constant-time default */

/*
 * Constant-time software GF(2^128) multiplication.  Each conditional
 * XOR is replaced by AND with a {0, ~0} mask routed through
 * ct_barrier_u64.  Output is bit-for-bit identical to the
 * variable-time form for every input.
 */
void
voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                  const voleith_gf128_t *b)
{
    uint64_t result[2] = {0, 0};
    uint64_t shifted[2] = {a->v[0], a->v[1]};

    for (int i = 0; i < 128; i++) {
        uint64_t mask = ct_barrier_u64(limbs_get_bit_mask(b->v, i));
        result[0] ^= shifted[0] & mask;
        result[1] ^= shifted[1] & mask;
        uint64_t overflow = limbs_shl1(shifted, 2);
        uint64_t omask = ct_barrier_u64(-(overflow & 1ULL));
        shifted[0] ^= VOLEITH_GF128_REDUCE & omask;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * GF(2^192) multiplication
 * P_192 = x^192 + x^7 + x^2 + x + 1
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

/*
 * CLMUL-accelerated GF(2^192) multiplication.
 * Schoolbook 192x192 → 384-bit product using 9 PCLMULQDQ, then reduce.
 * a = [a0, a1, a2], b = [b0, b1, b2] (each 64-bit limbs)
 */
void
voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                  const voleith_gf192_t *b)
{
    /* 9 carry-less 64x64 multiplies for schoolbook */
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

    /* Accumulate into 6 limbs [d0..d5] */
    uint64_t d[6] = {0};

    /* d0 = p00_lo */
    d[0] = (uint64_t)_mm_extract_epi64(p00, 0);

    /* d1 = p00_hi + p01_lo + p10_lo */
    d[1] = (uint64_t)_mm_extract_epi64(p00, 1) ^
           (uint64_t)_mm_extract_epi64(p01, 0) ^
           (uint64_t)_mm_extract_epi64(p10, 0);

    /* d2 = p01_hi + p10_hi + p02_lo + p11_lo + p20_lo */
    d[2] = (uint64_t)_mm_extract_epi64(p01, 1) ^
           (uint64_t)_mm_extract_epi64(p10, 1) ^
           (uint64_t)_mm_extract_epi64(p02, 0) ^
           (uint64_t)_mm_extract_epi64(p11, 0) ^
           (uint64_t)_mm_extract_epi64(p20, 0);

    /* d3 = p02_hi + p11_hi + p20_hi + p12_lo + p21_lo */
    d[3] = (uint64_t)_mm_extract_epi64(p02, 1) ^
           (uint64_t)_mm_extract_epi64(p11, 1) ^
           (uint64_t)_mm_extract_epi64(p20, 1) ^
           (uint64_t)_mm_extract_epi64(p12, 0) ^
           (uint64_t)_mm_extract_epi64(p21, 0);

    /* d4 = p12_hi + p21_hi + p22_lo */
    d[4] = (uint64_t)_mm_extract_epi64(p12, 1) ^
           (uint64_t)_mm_extract_epi64(p21, 1) ^
           (uint64_t)_mm_extract_epi64(p22, 0);

    /* d5 = p22_hi */
    d[5] = (uint64_t)_mm_extract_epi64(p22, 1);

    /*
     * Reduce modulo P_192 = x^192 + x^7 + x^2 + x + 1.
     * x^192 ≡ x^7+x^2+x+1, so fold d[5], d[4], d[3] into d[2], d[1], d[0].
     * Process from top (d[5]) to bottom (d[3]).
     */

    /* d5 at bit offset 320: x^320 = x^128 * x^192 ≡ x^128 * R */
    d[2] ^= d[5] ^ (d[5] << 1) ^ (d[5] << 2) ^ (d[5] << 7);
    d[3] ^= (d[5] >> 57) ^ (d[5] >> 62) ^ (d[5] >> 63);

    /* d4 at bit offset 256: x^256 = x^64 * x^192 ≡ x^64 * R */
    d[1] ^= d[4] ^ (d[4] << 1) ^ (d[4] << 2) ^ (d[4] << 7);
    d[2] ^= (d[4] >> 57) ^ (d[4] >> 62) ^ (d[4] >> 63);

    /* d3 at bit offset 192: x^192 ≡ R */
    d[0] ^= d[3] ^ (d[3] << 1) ^ (d[3] << 2) ^ (d[3] << 7);
    d[1] ^= (d[3] >> 57) ^ (d[3] >> 62) ^ (d[3] >> 63);

    c->v[0] = d[0];
    c->v[1] = d[1];
    c->v[2] = d[2];
}

#elif defined(VOLEITH_HAVE_PMULL)

/*
 * PMULL-accelerated GF(2^192) multiplication.
 * Schoolbook 192x192 → 384-bit product using 9 vmull_p64 calls.
 * Identical reduction to the CLMUL path.
 */
void
voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
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

#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)

/*
 * Variable-time software GF(2^192) multiplication.  See C-2.
 */
void
voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                  const voleith_gf192_t *b)
{
    uint64_t result[3] = {0, 0, 0};
    uint64_t shifted[3] = {a->v[0], a->v[1], a->v[2]};

    for (int i = 0; i < 192; i++) {
        if (limbs_test_bit(b->v, i))
            limbs_xor(result, shifted, 3);
        uint64_t overflow = limbs_shl1(shifted, 3);
        if (overflow)
            shifted[0] ^= VOLEITH_GF192_REDUCE;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
    c->v[2] = result[2];
}

#else /* Constant-time default */

void
voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                  const voleith_gf192_t *b)
{
    uint64_t result[3] = {0, 0, 0};
    uint64_t shifted[3] = {a->v[0], a->v[1], a->v[2]};

    for (int i = 0; i < 192; i++) {
        uint64_t mask = ct_barrier_u64(limbs_get_bit_mask(b->v, i));
        result[0] ^= shifted[0] & mask;
        result[1] ^= shifted[1] & mask;
        result[2] ^= shifted[2] & mask;
        uint64_t overflow = limbs_shl1(shifted, 3);
        uint64_t omask = ct_barrier_u64(-(overflow & 1ULL));
        shifted[0] ^= VOLEITH_GF192_REDUCE & omask;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
    c->v[2] = result[2];
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * GF(2^256) multiplication
 * P_256 = x^256 + x^10 + x^5 + x^2 + 1
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

/*
 * CLMUL-accelerated GF(2^256) multiplication.
 * Schoolbook 256x256 → 512-bit product using 16 PCLMULQDQ, then reduce.
 */
void
voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                  const voleith_gf256_t *b)
{
    /* 16 carry-less 64x64 multiplies for 4x4 schoolbook */
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

    /*
     * Reduce modulo P_256 = x^256 + x^10 + x^5 + x^2 + 1.
     * x^256 ≡ x^10 + x^5 + x^2 + 1.
     * Fold d[7]..d[4] into d[3]..d[0].
     */

    /* d7 at bit offset 448: x^448 = x^192 * x^256 ≡ x^192 * R */
    d[3] ^= d[7] ^ (d[7] << 2) ^ (d[7] << 5) ^ (d[7] << 10);
    d[4] ^= (d[7] >> 54) ^ (d[7] >> 59) ^ (d[7] >> 62);

    /* d6 at bit offset 384: x^384 = x^128 * x^256 ≡ x^128 * R */
    d[2] ^= d[6] ^ (d[6] << 2) ^ (d[6] << 5) ^ (d[6] << 10);
    d[3] ^= (d[6] >> 54) ^ (d[6] >> 59) ^ (d[6] >> 62);

    /* d5 at bit offset 320: x^320 = x^64 * x^256 ≡ x^64 * R */
    d[1] ^= d[5] ^ (d[5] << 2) ^ (d[5] << 5) ^ (d[5] << 10);
    d[2] ^= (d[5] >> 54) ^ (d[5] >> 59) ^ (d[5] >> 62);

    /* d4 at bit offset 256: x^256 ≡ R */
    d[0] ^= d[4] ^ (d[4] << 2) ^ (d[4] << 5) ^ (d[4] << 10);
    d[1] ^= (d[4] >> 54) ^ (d[4] >> 59) ^ (d[4] >> 62);

    c->v[0] = d[0];
    c->v[1] = d[1];
    c->v[2] = d[2];
    c->v[3] = d[3];
}

#elif defined(VOLEITH_HAVE_PMULL)

/*
 * PMULL-accelerated GF(2^256) multiplication.
 * Schoolbook 256x256 → 512-bit product using 16 vmull_p64 calls.
 * Identical reduction to the CLMUL path.
 */
void
voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
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

#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)

/*
 * Variable-time software GF(2^256) multiplication.  See C-2.
 */
void
voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                  const voleith_gf256_t *b)
{
    uint64_t result[4] = {0, 0, 0, 0};
    uint64_t shifted[4] = {a->v[0], a->v[1], a->v[2], a->v[3]};

    for (int i = 0; i < 256; i++) {
        if (limbs_test_bit(b->v, i))
            limbs_xor(result, shifted, 4);
        uint64_t overflow = limbs_shl1(shifted, 4);
        if (overflow)
            shifted[0] ^= VOLEITH_GF256_REDUCE;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
    c->v[2] = result[2];
    c->v[3] = result[3];
}

#else /* Constant-time default */

void
voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                  const voleith_gf256_t *b)
{
    uint64_t result[4] = {0, 0, 0, 0};
    uint64_t shifted[4] = {a->v[0], a->v[1], a->v[2], a->v[3]};

    for (int i = 0; i < 256; i++) {
        uint64_t mask = ct_barrier_u64(limbs_get_bit_mask(b->v, i));
        result[0] ^= shifted[0] & mask;
        result[1] ^= shifted[1] & mask;
        result[2] ^= shifted[2] & mask;
        result[3] ^= shifted[3] & mask;
        uint64_t overflow = limbs_shl1(shifted, 4);
        uint64_t omask = ct_barrier_u64(-(overflow & 1ULL));
        shifted[0] ^= VOLEITH_GF256_REDUCE & omask;
    }
    c->v[0] = result[0];
    c->v[1] = result[1];
    c->v[2] = result[2];
    c->v[3] = result[3];
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * ByteCombine - FAEST spec Section 3.2, Figure 3.4
 *
 * Combines 8 bits x[0..7] (from a byte) into a single element of F_{2^lambda}:
 *   result = x[0] + x[1]*alpha^1 + x[2]*alpha^2 + ... + x[7]*alpha^7
 *
 * where alpha^i are precomputed powers of the F_{2^8} generator embedded
 * in F_{2^lambda}. Values from FAEST spec Appendix A.1, verified against
 * faest-ref (used as test oracle only).
 * ======================================================================== */

/*
 * Precomputed alpha^1 through alpha^7 for GF(2^128).
 * alpha[0] = alpha_8^1, alpha[1] = alpha_8^2, ..., alpha[6] = alpha_8^7
 */
static const voleith_gf128_t gf128_alpha[7] = {
    {{UINT64_C(0xa13fe8ac5560ce0d), UINT64_C(0x053d8555a9979a1c)}},
    {{UINT64_C(0xec7759ca3488aee1), UINT64_C(0x4cf4b7439cbfbb84)}},
    {{UINT64_C(0xbfcf02ae363946a8), UINT64_C(0x35ad604f7d51d2c6)}},
    {{UINT64_C(0x6b8330483c2e9849), UINT64_C(0x0dcb364640a222fe)}},
    {{UINT64_C(0x252b49277b1b82b4), UINT64_C(0x549810e11a88dea5)}},
    {{UINT64_C(0xc72bf2ef2521ff22), UINT64_C(0xd681a5686c0c1f75)}},
    {{UINT64_C(0x7a7a8e94e136f9bc), UINT64_C(0x0950311a4fb78fe0)}},
};

/* Precomputed alpha^1 through alpha^7 for GF(2^192). */
static const voleith_gf192_t gf192_alpha[7] = {
    {{UINT64_C(0xccc8a3d56f389763), UINT64_C(0xe665d76c966ebdea),
      UINT64_C(0x310bc8140e6b3662)}},
    {{UINT64_C(0xb233619e7cf450bb), UINT64_C(0x7bf61f19d5633f26),
      UINT64_C(0xda933726d491db34)}},
    {{UINT64_C(0x9c6d2c13f5398a0d), UINT64_C(0x8232e37706328d19),
      UINT64_C(0x0c3b0d703c754ef6)}},
    {{UINT64_C(0xdd20747cbd2bf75d), UINT64_C(0x7a5542ab0058d22e),
      UINT64_C(0x45ec519c94bc1251)}},
    {{UINT64_C(0xd8d50ce28ace2bf8), UINT64_C(0x08168cb767debe84),
      UINT64_C(0xd67d146a4ba67045)}},
    {{UINT64_C(0x970f9c76eed5e1ba), UINT64_C(0xf3eaf7ae5fd72048),
      UINT64_C(0x29a6bd5f696cea43)}},
    {{UINT64_C(0xf5945dc265068571), UINT64_C(0x6019fd623906e9d3),
      UINT64_C(0xc77c56540f87c4b0)}},
};

/* Precomputed alpha^1 through alpha^7 for GF(2^256). */
static const voleith_gf256_t gf256_alpha[7] = {
    {{UINT64_C(0x969788420bdefee7), UINT64_C(0xbed68d38a0474e67),
      UINT64_C(0xdf229845f8f1e16a), UINT64_C(0x04c9a8cf20c95833)}},
    {{UINT64_C(0xa95af52ad52289c1), UINT64_C(0x2ba5c48d2c42072f),
      UINT64_C(0xd14a0d376c00b0ea), UINT64_C(0x064e4d699c5b4af1)}},
    {{UINT64_C(0x55dab3833f809d1d), UINT64_C(0x1771831e533b0f57),
      UINT64_C(0xfb96573fad3fac10), UINT64_C(0x6195e3db7011f68d)}},
    {{UINT64_C(0xde010519b01bcdd5), UINT64_C(0x752758911a30e3f6),
      UINT64_C(0x2a0778b6489ea03f), UINT64_C(0x56c24fd64f768838)}},
    {{UINT64_C(0x98c2f529e98a30b6), UINT64_C(0x1bc4dbd440f18482),
      UINT64_C(0x2fbe09947d49a981), UINT64_C(0x22270b6d71574ffc)}},
    {{UINT64_C(0x9e75afb9de44670b), UINT64_C(0xaced66c666f1afbc),
      UINT64_C(0xf001253ff2991f7e), UINT64_C(0xc03d372fd1fa29f3)}},
    {{UINT64_C(0xba43b698b332e88b), UINT64_C(0x5237c4d625b86f0d),
      UINT64_C(0x2f652b2af4e81545), UINT64_C(0x133eea09d26b7bb8)}},
};

#ifdef VOLEITH_ALLOW_VARIABLE_TIME_FIELD

/*
 * Variable-time reference implementation.  Branches on bits of x[],
 * which carry secrets in the prover's call graph (embed of witness
 * bits into the working field).  Reference code only; see
 * docs/SECURITY_REVIEW.md finding C-3.
 */
int
voleith_byte_combine(uint8_t *out, const uint8_t x[8], int lambda)
{
    if (lambda == 128) {
        voleith_gf128_t result = voleith_gf128_zero();
        /* x[0] * alpha^0 = x[0] * 1, embedded as a bit in the low position */
        if (x[0] & 1)
            result.v[0] ^= 1;
        for (int i = 1; i < 8; i++) {
            if (x[i] & 1) {
                voleith_gf128_add(&result, &result, &gf128_alpha[i - 1]);
            }
        }
        voleith_gf128_to_bytes(out, &result);
    } else if (lambda == 192) {
        voleith_gf192_t result = voleith_gf192_zero();
        if (x[0] & 1)
            result.v[0] ^= 1;
        for (int i = 1; i < 8; i++) {
            if (x[i] & 1) {
                voleith_gf192_add(&result, &result, &gf192_alpha[i - 1]);
            }
        }
        voleith_gf192_to_bytes(out, &result);
    } else if (lambda == 256) {
        voleith_gf256_t result = voleith_gf256_zero();
        if (x[0] & 1)
            result.v[0] ^= 1;
        for (int i = 1; i < 8; i++) {
            if (x[i] & 1) {
                voleith_gf256_add(&result, &result, &gf256_alpha[i - 1]);
            }
        }
        voleith_gf256_to_bytes(out, &result);
    } else {
        return -1;
    }

    return 0;
}

#else /* Constant-time default */

/*
 * Constant-time mask-based implementation.  Each `if (x[i] & 1) ...`
 * is replaced by AND with a {0, ~0} mask derived from the bit and
 * routed through ct_barrier_u64.  The per-limb XOR is inlined so the
 * mask AND fuses naturally with the table-constant load.
 *
 * The lambda dispatch itself (128 / 192 / 256) is a public choice,
 * fixed at proof-system parameter selection - not secret-dependent -
 * so branching on it is fine.
 *
 * Note: the unrolled i=0 case (mask the constant 1 into v[0] of the
 * zeroed result) is folded into the same loop by starting from i=0
 * and treating alpha^0 = 1 specially via an inline constant.
 */
int
voleith_byte_combine(uint8_t *out, const uint8_t x[8], int lambda)
{
    if (lambda == 128) {
        uint64_t r0 = 0, r1 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)x[0] & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 8; i++) {
            uint64_t mask = ct_barrier_u64(-((uint64_t)x[i] & 1ULL));
            r0 ^= gf128_alpha[i - 1].v[0] & mask;
            r1 ^= gf128_alpha[i - 1].v[1] & mask;
        }
        voleith_gf128_t result = {{r0, r1}};
        voleith_gf128_to_bytes(out, &result);
    } else if (lambda == 192) {
        uint64_t r0 = 0, r1 = 0, r2 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)x[0] & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 8; i++) {
            uint64_t mask = ct_barrier_u64(-((uint64_t)x[i] & 1ULL));
            r0 ^= gf192_alpha[i - 1].v[0] & mask;
            r1 ^= gf192_alpha[i - 1].v[1] & mask;
            r2 ^= gf192_alpha[i - 1].v[2] & mask;
        }
        voleith_gf192_t result = {{r0, r1, r2}};
        voleith_gf192_to_bytes(out, &result);
    } else if (lambda == 256) {
        uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)x[0] & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 8; i++) {
            uint64_t mask = ct_barrier_u64(-((uint64_t)x[i] & 1ULL));
            r0 ^= gf256_alpha[i - 1].v[0] & mask;
            r1 ^= gf256_alpha[i - 1].v[1] & mask;
            r2 ^= gf256_alpha[i - 1].v[2] & mask;
            r3 ^= gf256_alpha[i - 1].v[3] & mask;
        }
        voleith_gf256_t result = {{r0, r1, r2, r3}};
        voleith_gf256_to_bytes(out, &result);
    } else {
        return -1;
    }

    return 0;
}

#endif /* VOLEITH_ALLOW_VARIABLE_TIME_FIELD */
