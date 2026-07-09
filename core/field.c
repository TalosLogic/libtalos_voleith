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

static const voleith_gf128_t gf128_alpha16[15] = {
    {{UINT64_C(0x63ea7b028543cbf0), UINT64_C(0x0074037f8fbf5037)}},
    {{UINT64_C(0xab196026a747c4eb), UINT64_C(0x140fb73417d4c00e)}},
    {{UINT64_C(0x32476112da5f3033), UINT64_C(0x4008ada5f3658963)}},
    {{UINT64_C(0xc9d72f4ce0107fe9), UINT64_C(0xcb352a4945e99764)}},
    {{UINT64_C(0x9551a583464a7e5c), UINT64_C(0xb27066416627a690)}},
    {{UINT64_C(0x78d57583e44d6fa6), UINT64_C(0x750431f6e115d5d8)}},
    {{UINT64_C(0xbbafede459f94914), UINT64_C(0x7c5aa435d961eaeb)}},
    {{UINT64_C(0x2cdc8c6658b4246e), UINT64_C(0xc318c2e03b81411f)}},
    {{UINT64_C(0x53566ea4c12a68e1), UINT64_C(0x41562760b0323e48)}},
    {{UINT64_C(0x767a068cc3194739), UINT64_C(0x1807fa0b22753088)}},
    {{UINT64_C(0xde53320e6f309b47), UINT64_C(0x4595eaf2146332b1)}},
    {{UINT64_C(0xf8979f8f2b8b57e2), UINT64_C(0xf6b759638ebd6142)}},
    {{UINT64_C(0x2836202285524adf), UINT64_C(0xa63efbb3b09d76cd)}},
    {{UINT64_C(0x070c39ed9fb68b7d), UINT64_C(0x87fd90aa8023c7ce)}},
    {{UINT64_C(0xbe3cd67329c4b0ee), UINT64_C(0xee53b060eb5a92cc)}},
};

static const voleith_gf192_t gf192_alpha16[15] = {
    {{UINT64_C(0xf85ca5cde9be576f), UINT64_C(0x19de76a5b1b74f1d),
      UINT64_C(0x119e9d800838ddf3)}},
    {{UINT64_C(0xf22f59f2f05ac0a2), UINT64_C(0x7482abb95a0d79ca),
      UINT64_C(0xc2a729987e43c151)}},
    {{UINT64_C(0xf443bbe047db3241), UINT64_C(0x179b863911769a8b),
      UINT64_C(0x8a42b4590d52b5cb)}},
    {{UINT64_C(0xb651d37baf782a1c), UINT64_C(0x95a076e7a1cea289),
      UINT64_C(0xa37bd6b82827368e)}},
    {{UINT64_C(0x4d848d95220cbda1), UINT64_C(0x37829c11a9a85932),
      UINT64_C(0xfb6834f57126a7e0)}},
    {{UINT64_C(0x9ddf353fcf6aba21), UINT64_C(0x7c2fe53a169bc75b),
      UINT64_C(0xe2d5672b123c9602)}},
    {{UINT64_C(0x691a08fe6ed0d218), UINT64_C(0xeb250d24a6993753),
      UINT64_C(0x744a732d1fa01470)}},
    {{UINT64_C(0x0b81c94ae503b6d2), UINT64_C(0x78d607e8c048fec8),
      UINT64_C(0x9a909826794b3a83)}},
    {{UINT64_C(0x8fba1b22247094a9), UINT64_C(0x5ad41e06b0c337be),
      UINT64_C(0xb7718e3de10c9e00)}},
    {{UINT64_C(0x95cec26d2be1d6d7), UINT64_C(0xfbd4565f9691ed13),
      UINT64_C(0x4c100982821a26f9)}},
    {{UINT64_C(0x6475a71087f04234), UINT64_C(0x714cbbc305616bde),
      UINT64_C(0xd22cd9c62dea0d7c)}},
    {{UINT64_C(0x92e72344e1b1a98c), UINT64_C(0xc44fe3c4487d0743),
      UINT64_C(0xaf217eb836fc2e1e)}},
    {{UINT64_C(0x09a9b60a0ec5d208), UINT64_C(0x4a1531890b49ff7c),
      UINT64_C(0x5406ebda77fcc139)}},
    {{UINT64_C(0x9b0d45f778311006), UINT64_C(0xb849dd448f3abe7f),
      UINT64_C(0xa76c1297ec8c2432)}},
    {{UINT64_C(0x18bfdf201ab8fbc0), UINT64_C(0x9acd6d0974fe8880),
      UINT64_C(0x8afadc4a41f3dd75)}},
};

static const voleith_gf256_t gf256_alpha16[15] = {
    {{UINT64_C(0xd097564120152efa), UINT64_C(0x7f43bbe727097150),
      UINT64_C(0x9c7fe7d74be4f1a5), UINT64_C(0x107ede188b2a0edc)}},
    {{UINT64_C(0x48aac61ea068d7a5), UINT64_C(0x7f47feefc2ba73a3),
      UINT64_C(0x59f58d944fcb6e1c), UINT64_C(0x3002abcf2bc4795d)}},
    {{UINT64_C(0x2688a3ab6a7de908), UINT64_C(0xf327601a7a9d1324),
      UINT64_C(0xb41bf715c9fb2c68), UINT64_C(0x450f09ca6403088e)}},
    {{UINT64_C(0x4aeb19e2ce9478c5), UINT64_C(0x697aa2395e2c2647),
      UINT64_C(0xd8be1743f9277e77), UINT64_C(0xa45501999def1be5)}},
    {{UINT64_C(0x2f929dc2eeff5bcd), UINT64_C(0xd7fb01a5a2266075),
      UINT64_C(0x223e1e7af783482a), UINT64_C(0x500d40c8d8189d4f)}},
    {{UINT64_C(0x087fa9b18b03cc0a), UINT64_C(0xb74179eeb3e0267a),
      UINT64_C(0x931455e1094d1e89), UINT64_C(0x43715bb5182f08c2)}},
    {{UINT64_C(0x2497dc2f28433fc5), UINT64_C(0xef161b464ed2d923),
      UINT64_C(0xcf838be9faf0c5ee), UINT64_C(0x368f55a5aef6821f)}},
    {{UINT64_C(0xfc2183a6af96a5ad), UINT64_C(0x2d18fec572e211eb),
      UINT64_C(0x3a3bdff43dbed32e), UINT64_C(0x82572631412d6c28)}},
    {{UINT64_C(0x7f5e094e1eed992e), UINT64_C(0xe91250bac2311061),
      UINT64_C(0x016f87eab9c9963d), UINT64_C(0x26b9f35f00e55153)}},
    {{UINT64_C(0xa2bc01a74815cc1b), UINT64_C(0x80d4ab853f82a98f),
      UINT64_C(0x784129583e761aa0), UINT64_C(0x24141a32514b5c1f)}},
    {{UINT64_C(0x36ad13ccaaa8d5e6), UINT64_C(0xb17e9d42131de8da),
      UINT64_C(0xf17bdb973e93ada2), UINT64_C(0x22c106f1cb6e1c5b)}},
    {{UINT64_C(0x4d631f352fdd4c2b), UINT64_C(0x71f57243766fc525),
      UINT64_C(0x69549fa00c1f14dd), UINT64_C(0x01f2f5637cade324)}},
    {{UINT64_C(0xd3d72e16511bb3e5), UINT64_C(0x7667fbeb4c8d1eb9),
      UINT64_C(0x77d24bd8b8ca1ada), UINT64_C(0x82c019a2f4d665a1)}},
    {{UINT64_C(0xbdcbb04e527add51), UINT64_C(0x4ab814ac0dfb8c6e),
      UINT64_C(0x9e8fa3c901d07fee), UINT64_C(0xb6991ef333298379)}},
    {{UINT64_C(0xc59a3ac4e6261df2), UINT64_C(0xa43de50c84f407bd),
      UINT64_C(0x056b976a60d32528), UINT64_C(0x21c5243b0493b793)}},
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

/*
 * GF16Embed(val; lambda) - embeds a GF(2^16) element into F_{2^lambda} as
 *
 *     embed(val) = sum_{i=0}^{15} val_bit_i * beta^i
 *
 * where beta is the alpha16 generator (the smallest-encoding root of m16
 * embedded in F_{2^lambda}; see tools/gen_alpha16) and beta^0 = 1 is
 * implicit.  This is the GF(2^16) analogue of voleith_byte_combine and the
 * subfield map used by the gf16 element-level QuickSilver prover/verifier to
 * lift GF(2^16) values and products into the lambda-bit VOLE tag field.  The
 * masked accumulation is constant-time in val, matching voleith_byte_combine.
 */
int
voleith_gf16_embed(uint8_t *out, uint16_t val, int lambda)
{
    if (lambda == 128) {
        uint64_t r0 = 0, r1 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)val & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 16; i++) {
            uint64_t mask = ct_barrier_u64(-(((uint64_t)val >> i) & 1ULL));
            r0 ^= gf128_alpha16[i - 1].v[0] & mask;
            r1 ^= gf128_alpha16[i - 1].v[1] & mask;
        }
        voleith_gf128_t result = {{r0, r1}};
        voleith_gf128_to_bytes(out, &result);
    } else if (lambda == 192) {
        uint64_t r0 = 0, r1 = 0, r2 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)val & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 16; i++) {
            uint64_t mask = ct_barrier_u64(-(((uint64_t)val >> i) & 1ULL));
            r0 ^= gf192_alpha16[i - 1].v[0] & mask;
            r1 ^= gf192_alpha16[i - 1].v[1] & mask;
            r2 ^= gf192_alpha16[i - 1].v[2] & mask;
        }
        voleith_gf192_t result = {{r0, r1, r2}};
        voleith_gf192_to_bytes(out, &result);
    } else if (lambda == 256) {
        uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
        uint64_t m0 = ct_barrier_u64(-((uint64_t)val & 1ULL));
        r0 ^= 1ULL & m0;
        for (int i = 1; i < 16; i++) {
            uint64_t mask = ct_barrier_u64(-(((uint64_t)val >> i) & 1ULL));
            r0 ^= gf256_alpha16[i - 1].v[0] & mask;
            r1 ^= gf256_alpha16[i - 1].v[1] & mask;
            r2 ^= gf256_alpha16[i - 1].v[2] & mask;
            r3 ^= gf256_alpha16[i - 1].v[3] & mask;
        }
        voleith_gf256_t result = {{r0, r1, r2, r3}};
        voleith_gf256_to_bytes(out, &result);
    } else {
        return -1;
    }

    return 0;
}
