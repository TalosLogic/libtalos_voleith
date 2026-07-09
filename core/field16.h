/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field16.h - Finite field arithmetic for GF(2^16)
 *
 * GF(2^16) element arithmetic used by the RLNC (Random Linear Network
 * Coding) transport-layer erasure codes (see docs/ERASURE_CODES_DESIGN.md).
 * GF(2^8) (core/field.h) is sufficient for Reed-Solomon storage codes, but
 * RLNC needs a larger field to avoid the coupon-collector wall at scale, so
 * this is the first field size added beyond the FAEST-mandated set.
 *
 * Canonical irreducible polynomial:
 *   m16 = x^16 + x^12 + x^3 + x + 1
 *
 * This is constructed constant-time from day one (branchless shift-reduce
 * software fallback, CLMUL / PMULL fast paths) so that private RLNC
 * coefficients remain possible in a future proving use case.
 *
 * Elements are stored in little-endian bit ordering: bit 0 is the
 * coefficient of x^0 (the constant term).  The byte form is 2-byte
 * little-endian.
 */

#ifndef VOLEITH_FIELD16_H
#define VOLEITH_FIELD16_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Reduction constant: the low 16 bits of m16 (the polynomial with its
 * x^16 term dropped).  m16 = x^16 + x^12 + x^3 + x + 1, so the full
 * encoding is 0x1100B and the reduction constant is 0x100B.
 */
#define VOLEITH_GF16_REDUCE UINT16_C(0x100B) /* x^12 + x^3 + x + 1 */

/* ========================================================================
 * Type definition
 * ======================================================================== */

/* GF(2^16) - RLNC coefficient field */
typedef uint16_t voleith_gf16_t;

/* ========================================================================
 * GF(2^16) operations
 * ======================================================================== */

/* Returns a + b in GF(2^16). */
static inline voleith_gf16_t
voleith_gf16_add(voleith_gf16_t a, voleith_gf16_t b)
{
    return a ^ b;
}

/* Returns a * b in GF(2^16) modulo m16. */
voleith_gf16_t voleith_gf16_mul(voleith_gf16_t a, voleith_gf16_t b);

/*
 * Returns a^{-1} in GF(2^16) for nonzero a, and 0 for a == 0.
 *
 * Implemented via Fermat's little theorem: a^{-1} = a^(2^16 - 2) for
 * nonzero a (since a^(2^16 - 1) = 1).  At a == 0 the chain produces 0.
 *
 * Constant-time by construction: a fixed addition chain of squarings and
 * multiplications via voleith_gf16_mul, the same work regardless of input.
 */
voleith_gf16_t voleith_gf16_inv(voleith_gf16_t a);

/* Loads a GF(2^16) element from a 2-byte little-endian buffer. */
static inline voleith_gf16_t
voleith_gf16_from_bytes(const uint8_t buf[2])
{
    return (voleith_gf16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));
}

/* Stores a GF(2^16) element to a 2-byte little-endian buffer. */
static inline void
voleith_gf16_to_bytes(uint8_t buf[2], voleith_gf16_t a)
{
    buf[0] = (uint8_t)(a & 0xff);
    buf[1] = (uint8_t)((a >> 8) & 0xff);
}

#endif /* VOLEITH_FIELD16_H */
