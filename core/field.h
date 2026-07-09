/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field.h - Finite field arithmetic for F_{2^k}
 *
 * Implements GF(2^k) arithmetic for all field sizes used in the VOLEitH
 * protocol, as specified in the FAEST v2.0 spec (Section 3.2, Appendix A).
 *
 * Irreducible polynomials (from FAEST spec):
 *   P_8   = x^8   + x^4  + x^3 + x   + 1
 *   P_64  = x^64  + x^4  + x^3 + x   + 1
 *   P_128 = x^128 + x^7  + x^2 + x   + 1
 *   P_192 = x^192 + x^7  + x^2 + x   + 1
 *   P_256 = x^256 + x^10 + x^5 + x^2 + 1
 *
 * Elements are stored in little-endian bit ordering: bit 0 of byte 0 is the
 * coefficient of alpha^0 (the constant term).
 */

#ifndef VOLEITH_FIELD_H
#define VOLEITH_FIELD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Reduction constants (low bits of irreducible polynomial, excluding x^k term) */
#define VOLEITH_GF8_REDUCE UINT8_C(0x1B)     /* x^4+x^3+x+1 */
#define VOLEITH_GF64_REDUCE UINT64_C(0x1B)   /* x^4+x^3+x+1 */
#define VOLEITH_GF128_REDUCE UINT64_C(0x87)  /* x^7+x^2+x+1 */
#define VOLEITH_GF192_REDUCE UINT64_C(0x87)  /* x^7+x^2+x+1 */
#define VOLEITH_GF256_REDUCE UINT64_C(0x425) /* x^10+x^5+x^2+1 */

/* ========================================================================
 * Type definitions
 * ======================================================================== */

/* GF(2^8) - AES field */
typedef uint8_t voleith_gf8_t;

/* GF(2^64) - used in universal hashing */
typedef uint64_t voleith_gf64_t;

/* GF(2^128) - security level lambda=128 */
typedef struct {
    uint64_t v[2];
} voleith_gf128_t;

/* GF(2^192) - security level lambda=192 */
typedef struct {
    uint64_t v[3];
} voleith_gf192_t;

/* GF(2^256) - security level lambda=256 */
typedef struct {
    uint64_t v[4];
} voleith_gf256_t;

/* ========================================================================
 * GF(2^8) operations
 * ======================================================================== */

/* Returns a + b in GF(2^8). */
static inline voleith_gf8_t
voleith_gf8_add(voleith_gf8_t a, voleith_gf8_t b)
{
    return a ^ b;
}

/* Returns a * b in GF(2^8) modulo P_8. */
voleith_gf8_t voleith_gf8_mul(voleith_gf8_t a, voleith_gf8_t b);

/*
 * Returns a^{-1} in GF(2^8) for nonzero a, and 0 for a == 0.
 *
 * Implemented via Fermat's little theorem: a^{-1} = a^254 in GF(2^8)
 * for nonzero a (since a^255 = 1).  At a = 0 the chain produces 0,
 * matching the convention used by the AES S-box circuit (Proposition
 * 6.4 fix-up).
 *
 * Constant-time by construction: a fixed addition chain of 7
 * squarings + 6 multiplications via voleith_gf8_mul, the same work
 * regardless of input.  Suitable for witness-builder use on secret
 * S-box inputs.
 */
voleith_gf8_t voleith_gf8_inv(voleith_gf8_t a);

/* ========================================================================
 * GF(2^64) operations
 * ======================================================================== */

/* Returns a + b in GF(2^64). */
static inline voleith_gf64_t
voleith_gf64_add(voleith_gf64_t a, voleith_gf64_t b)
{
    return a ^ b;
}

/* Returns a * b in GF(2^64) modulo P_64. */
voleith_gf64_t voleith_gf64_mul(voleith_gf64_t a, voleith_gf64_t b);

/* ========================================================================
 * GF(2^128) operations
 * ======================================================================== */

/* Returns the zero element. */
static inline voleith_gf128_t
voleith_gf128_zero(void)
{
    voleith_gf128_t r = {{0, 0}};
    return r;
}

/* Returns the identity element (1). */
static inline voleith_gf128_t
voleith_gf128_one(void)
{
    voleith_gf128_t r = {{1, 0}};
    return r;
}

/* Sets c = a + b in GF(2^128). */
static inline void
voleith_gf128_add(voleith_gf128_t *c, const voleith_gf128_t *a,
                  const voleith_gf128_t *b)
{
    c->v[0] = a->v[0] ^ b->v[0];
    c->v[1] = a->v[1] ^ b->v[1];
}

/* Sets c = a * b in GF(2^128) modulo P_128. */
void voleith_gf128_mul(voleith_gf128_t *c, const voleith_gf128_t *a,
                       const voleith_gf128_t *b);

/* Loads a GF(2^128) element from a 16-byte little-endian buffer. */
static inline void
voleith_gf128_from_bytes(voleith_gf128_t *r, const uint8_t buf[16])
{
    memcpy(r->v, buf, 16);
}

/* Stores a GF(2^128) element to a 16-byte little-endian buffer. */
static inline void
voleith_gf128_to_bytes(uint8_t buf[16], const voleith_gf128_t *a)
{
    memcpy(buf, a->v, 16);
}

/* Returns 1 if a == b, 0 otherwise. Not constant-time. */
static inline int
voleith_gf128_eq(const voleith_gf128_t *a, const voleith_gf128_t *b)
{
    return (a->v[0] == b->v[0]) && (a->v[1] == b->v[1]);
}

/* ========================================================================
 * GF(2^192) operations
 * ======================================================================== */

static inline voleith_gf192_t
voleith_gf192_zero(void)
{
    voleith_gf192_t r = {{0, 0, 0}};
    return r;
}

static inline voleith_gf192_t
voleith_gf192_one(void)
{
    voleith_gf192_t r = {{1, 0, 0}};
    return r;
}

static inline void
voleith_gf192_add(voleith_gf192_t *c, const voleith_gf192_t *a,
                  const voleith_gf192_t *b)
{
    c->v[0] = a->v[0] ^ b->v[0];
    c->v[1] = a->v[1] ^ b->v[1];
    c->v[2] = a->v[2] ^ b->v[2];
}

void voleith_gf192_mul(voleith_gf192_t *c, const voleith_gf192_t *a,
                       const voleith_gf192_t *b);

static inline void
voleith_gf192_from_bytes(voleith_gf192_t *r, const uint8_t buf[24])
{
    memcpy(r->v, buf, 24);
}

static inline void
voleith_gf192_to_bytes(uint8_t buf[24], const voleith_gf192_t *a)
{
    memcpy(buf, a->v, 24);
}

static inline int
voleith_gf192_eq(const voleith_gf192_t *a, const voleith_gf192_t *b)
{
    return (a->v[0] == b->v[0]) && (a->v[1] == b->v[1]) && (a->v[2] == b->v[2]);
}

/* ========================================================================
 * GF(2^256) operations
 * ======================================================================== */

static inline voleith_gf256_t
voleith_gf256_zero(void)
{
    voleith_gf256_t r = {{0, 0, 0, 0}};
    return r;
}

static inline voleith_gf256_t
voleith_gf256_one(void)
{
    voleith_gf256_t r = {{1, 0, 0, 0}};
    return r;
}

static inline void
voleith_gf256_add(voleith_gf256_t *c, const voleith_gf256_t *a,
                  const voleith_gf256_t *b)
{
    c->v[0] = a->v[0] ^ b->v[0];
    c->v[1] = a->v[1] ^ b->v[1];
    c->v[2] = a->v[2] ^ b->v[2];
    c->v[3] = a->v[3] ^ b->v[3];
}

void voleith_gf256_mul(voleith_gf256_t *c, const voleith_gf256_t *a,
                       const voleith_gf256_t *b);

static inline void
voleith_gf256_from_bytes(voleith_gf256_t *r, const uint8_t buf[32])
{
    memcpy(r->v, buf, 32);
}

static inline void
voleith_gf256_to_bytes(uint8_t buf[32], const voleith_gf256_t *a)
{
    memcpy(buf, a->v, 32);
}

static inline int
voleith_gf256_eq(const voleith_gf256_t *a, const voleith_gf256_t *b)
{
    return (a->v[0] == b->v[0]) && (a->v[1] == b->v[1]) &&
           (a->v[2] == b->v[2]) && (a->v[3] == b->v[3]);
}

/* ========================================================================
 * Conversion utilities (FAEST spec Section 3.2, Figure 3.4)
 * ======================================================================== */

/*
 * ByteCombine(x; lambda) - Combines 8 bytes into a single F_{2^lambda} element
 * using powers of the F_{2^8} generator alpha_8 embedded in F_{2^lambda}.
 * See FAEST spec Appendix A.1 for the generator elements.
 *
 * x:      array of 8 bytes (the 8 coefficients)
 * lambda: security parameter (128, 192, or 256)
 * out:    output buffer of lambda/8 bytes
 *
 * Returns 0 on success, -1 on invalid lambda.
 */
int voleith_byte_combine(uint8_t *out, const uint8_t x[8], int lambda);

/*
 * GF16Embed(val; lambda) - embeds a GF(2^16) element into F_{2^lambda} using
 * powers of the alpha16 generator beta (the embedded root of m16):
 *   embed(val) = sum_{i=0}^{15} val_bit_i * beta^i.
 * The GF(2^16) analogue of voleith_byte_combine, used by the gf16
 * element-level QuickSilver layer.
 *
 * val:    a GF(2^16) element (uint16_t; see core/field16.h)
 * lambda: security parameter (128, 192, or 256)
 * out:    output buffer of lambda/8 bytes
 *
 * Returns 0 on success, -1 on invalid lambda.
 */
int voleith_gf16_embed(uint8_t *out, uint16_t val, int lambda);

#endif /* VOLEITH_FIELD_H */
