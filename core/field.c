/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field.c - Finite field arithmetic for F_{2^k}
 *
 * GF(2^8):  constant-time software only (not on the dispatch hot path).
 * GF(2^64): compile-time dispatch (CLMUL / PMULL / software).
 * GF(2^128/192/256): one-line forwarders through voleith_field_ops.
 *
 * The three GF(2^N) backends live in:
 *   core/field_clmul.c   (PCLMULQDQ; compiled with -mpclmul -msse2 -msse4.1)
 *   core/field_pmull.c   (ARMv8 PMULL; compiled with -march=armv8-a+crypto)
 *   core/field_scalar.c  (constant-time software; always compiled)
 *
 * Clean-room implementation from the FAEST v2.0 specification.
 */

#include "field.h"
#include "field_dispatch.h"
#include "cpu.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef VOLEITH_HAVE_CLMUL
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif

#ifdef VOLEITH_HAVE_PMULL
#include <arm_neon.h>
#endif

/* ========================================================================
 * Constant-time helpers
 *
 * The optimizer-barrier idiom (`__asm__ volatile ("" : "+r"(x))`) is
 * the standard cryptographic-library technique for preventing a
 * sufficiently smart compiler from re-deriving a conditional branch
 * from a bitmask of {0, ~0}.  Compiles to zero instructions; tells
 * the compiler the value is opaque after this point.
 * ======================================================================== */

#if !(defined(__GNUC__) || defined(__clang__))
#error "Constant-time field path currently requires gcc or clang " \
         "(inline-asm optimizer barrier)."
#endif

static inline uint64_t
ct_barrier_u64(uint64_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
}

/* ========================================================================
 * GF(2^8) - AES field
 * P_8 = x^8 + x^4 + x^3 + x + 1, reduction constant 0x1B
 * ======================================================================== */

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

voleith_gf8_t
voleith_gf8_inv(voleith_gf8_t a)
{
    voleith_gf8_t a2 = voleith_gf8_mul(a, a);
    voleith_gf8_t a4 = voleith_gf8_mul(a2, a2);
    voleith_gf8_t a8 = voleith_gf8_mul(a4, a4);
    voleith_gf8_t a16 = voleith_gf8_mul(a8, a8);
    voleith_gf8_t a32 = voleith_gf8_mul(a16, a16);
    voleith_gf8_t a64 = voleith_gf8_mul(a32, a32);
    voleith_gf8_t a128 = voleith_gf8_mul(a64, a64);

    voleith_gf8_t r = voleith_gf8_mul(a2, a4);
    r = voleith_gf8_mul(r, a8);
    r = voleith_gf8_mul(r, a16);
    r = voleith_gf8_mul(r, a32);
    r = voleith_gf8_mul(r, a64);
    r = voleith_gf8_mul(r, a128);
    return r;
}

/* ========================================================================
 * GF(2^64) - compile-time dispatch (not on the runtime dispatch hot path)
 * P_64 = x^64 + x^4 + x^3 + x + 1, reduction constant 0x1B
 * ======================================================================== */

#ifdef VOLEITH_HAVE_CLMUL

voleith_gf64_t
voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b)
{
    __m128i va = _mm_set_epi64x(0, (long long)a);
    __m128i vb = _mm_set_epi64x(0, (long long)b);
    __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);

    uint64_t lo = (uint64_t)_mm_extract_epi64(prod, 0);
    uint64_t hi = (uint64_t)_mm_extract_epi64(prod, 1);

    lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    uint64_t overflow = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^= overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    return lo;
}

#elif defined(VOLEITH_HAVE_PMULL)

static inline void
pmull64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);
    *lo = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
    *hi = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 1);
}

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

#else /* Constant-time software path */

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

voleith_gf64_t
voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b)
{
    uint64_t hi, lo;
    clmul64_soft(a, b, &hi, &lo);

    lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    uint64_t overflow = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^= overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    return lo;
}

#endif /* VOLEITH_HAVE_CLMUL */

/* ========================================================================
 * GF(2^128/192/256) dispatch table
 * ======================================================================== */

_Atomic(const voleith_field_ops_t *) voleith_field_ops = NULL;

static atomic_flag s_field_warn_once = ATOMIC_FLAG_INIT;

void
voleith_field_dispatch_init(void)
{
    if (atomic_load_explicit(&voleith_field_ops, memory_order_acquire) != NULL)
        return;
    unsigned feat = voleith_cpu_features();
    const voleith_field_ops_t *pick = NULL;
#ifdef VOLEITH_HAVE_CLMUL
    if (pick == NULL && (feat & VOLEITH_CPU_CLMUL))
        pick = &voleith_field_ops_clmul;
#endif
#ifdef VOLEITH_HAVE_PMULL
    if (pick == NULL && (feat & VOLEITH_CPU_PMULL))
        pick = &voleith_field_ops_pmull;
#endif
    if (pick == NULL)
        pick = &voleith_field_ops_scalar;

#ifndef VOLEITH_HAVE_CLMUL
    if ((feat & VOLEITH_CPU_CLMUL) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_field_warn_once))
        fputs("voleith: notice: host CPU has CLMUL but the clmul backend"
              " was not compiled in; running on scalar fallback."
              " Rebuild with -DVOLEITH_CLMUL=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif
#ifndef VOLEITH_HAVE_PMULL
    if ((feat & VOLEITH_CPU_PMULL) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_field_warn_once))
        fputs("voleith: notice: host CPU has PMULL but the pmull backend"
              " was not compiled in; running on scalar fallback."
              " Rebuild with -DVOLEITH_PMULL=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif

    const voleith_field_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&voleith_field_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

void
voleith_field_dispatch_reset(void)
{
    atomic_store_explicit(&voleith_field_ops, NULL, memory_order_release);
}

/* ========================================================================
 * GF(2^128) public forwarder
 * ======================================================================== */

void
voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                  const voleith_gf128_t *b)
{
    if (atomic_load_explicit(&voleith_field_ops, memory_order_acquire) == NULL)
        voleith_field_dispatch_init();
    voleith_field_ops->gf128_mul(c, a, b);
}

/* ========================================================================
 * GF(2^192) public forwarder
 * ======================================================================== */

void
voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                  const voleith_gf192_t *b)
{
    if (atomic_load_explicit(&voleith_field_ops, memory_order_acquire) == NULL)
        voleith_field_dispatch_init();
    voleith_field_ops->gf192_mul(c, a, b);
}

/* ========================================================================
 * GF(2^256) public forwarder
 * ======================================================================== */

void
voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                  const voleith_gf256_t *b)
{
    if (atomic_load_explicit(&voleith_field_ops, memory_order_acquire) == NULL)
        voleith_field_dispatch_init();
    voleith_field_ops->gf256_mul(c, a, b);
}

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

static const voleith_gf128_t gf128_alpha[7] = {
    {{UINT64_C(0xa13fe8ac5560ce0d), UINT64_C(0x053d8555a9979a1c)}},
    {{UINT64_C(0xec7759ca3488aee1), UINT64_C(0x4cf4b7439cbfbb84)}},
    {{UINT64_C(0xbfcf02ae363946a8), UINT64_C(0x35ad604f7d51d2c6)}},
    {{UINT64_C(0x6b8330483c2e9849), UINT64_C(0x0dcb364640a222fe)}},
    {{UINT64_C(0x252b49277b1b82b4), UINT64_C(0x549810e11a88dea5)}},
    {{UINT64_C(0xc72bf2ef2521ff22), UINT64_C(0xd681a5686c0c1f75)}},
    {{UINT64_C(0x7a7a8e94e136f9bc), UINT64_C(0x0950311a4fb78fe0)}},
};

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
