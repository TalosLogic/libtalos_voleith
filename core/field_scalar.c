/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field_scalar.c - Constant-time scalar software implementations of
 * GF(2^128/192/256) multiplication.
 *
 * This TU is always compiled and provides the universal fallback.
 * Uses the mask-based Russian-peasant algorithm with an optimizer barrier
 * to prevent the compiler from reintroducing secret-dependent branches.
 */

#include "field_dispatch.h"

#if !(defined(__GNUC__) || defined(__clang__))
#error "Constant-time field path currently requires gcc or clang " \
         "(inline-asm optimizer barrier)."
#endif

/*
 * Optimizer barrier for the constant-time masking idiom.  Compiles to
 * zero instructions; tells the compiler the value is opaque after this
 * point so it cannot re-derive a conditional branch from a bitmask.
 */
static inline uint64_t
ct_barrier_u64(uint64_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
}

/*
 * Multi-limb constant-time bit accessor.  Returns 0 or ~0 depending on
 * bit `pos` of `v`.
 */
static inline uint64_t
limbs_get_bit_mask(const uint64_t *v, int pos)
{
    uint64_t bit = (v[pos / 64] >> (pos % 64)) & 1ULL;
    return -bit;
}

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

/* ========================================================================
 * GF(2^128) - scalar path
 * P_128 = x^128 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_scalar_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
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

/* ========================================================================
 * GF(2^192) - scalar path
 * P_192 = x^192 + x^7 + x^2 + x + 1
 * ======================================================================== */

static void
field_scalar_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
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

/* ========================================================================
 * GF(2^256) - scalar path
 * P_256 = x^256 + x^10 + x^5 + x^2 + 1
 * ======================================================================== */

static void
field_scalar_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
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

/* ========================================================================
 * Ops table
 * ======================================================================== */

const voleith_field_ops_t voleith_field_ops_scalar = {
    .gf128_mul = field_scalar_gf128_mul,
    .gf192_mul = field_scalar_gf192_mul,
    .gf256_mul = field_scalar_gf256_mul,
    .name = "scalar",
};
