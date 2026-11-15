/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_product3_compat.c - REQUIRED one-shot PRODUCT3 faest-ref compat gate.
 *
 * PRODUCT3 (the three-way product a*b*c == d, GF8_CONSTRAINT_PRODUCT3) is the
 * single FAEST-EM-compat-frozen shared surface of the norm S-box release: its
 * folded coefficients feed the a_tilde values in the proof and its
 * serialization enters every fingerprint that uses it.  Before it freezes, its
 * coefficient-folding algebra must match the faest-ref reference VALUE-EXACT,
 * so a future byte-exact FAEST-EM compat mode is never forced to revise it.
 *
 * This test pins that guarantee.  It recomputes, with voleith's own GF(2^lambda)
 * arithmetic, the three prover coefficient streams (a0/a1/a2) and the single
 * verifier value for the norm relation y * a^2 * a^16 = a (spec Fig 6.19), and
 * asserts they equal vectors captured from faest-ref
 * aes_SSS_inv_norm_constraints_{prover,verifier}.  The two sides are
 * independent computations in the same field (voleith here vs faest-ref
 * offline), so agreement is a genuine cross-check, not a tautology.  The
 * voleith moduli equal the faest-ref ones (x^128+x^7+x^2+x+1,
 * x^192+x^7+x^2+x+1, x^256+x^10+x^5+x^2+1), and both sides serialize field
 * elements little-endian over 16/24/32 bytes.
 *
 * Scope: this gate validates the coefficient-folding ALGEBRA against faest-ref
 * in the shared field.  That the live prover/verifier (proof/gf8_prover.c,
 * proof/gf8_verifier.c) WIRE this algebra up soundly is covered separately by
 * the PRODUCT3 round-trip and forgery tests in test_gf8_quicksilver.c.
 *
 * It is a one-shot bring-up gate, not a maintained KAT: once PRODUCT3 is
 * confirmed spec-exact and frozen, re-running buys nothing.  faest-ref is NOT
 * linked into this build (it never is); the EXP_* vectors are captured offline
 * with tools/faest-ref-diagnostics/diag_norm_constraints.c and pasted below.
 *
 * TO PIN (once): build and run diag_norm_constraints against the faest-ref
 * tree (see that file's header), then replace each EXP_* array below with the
 * matching a0/a1/a2/vexp bytes it prints for that lambda.  Until pinned, the
 * all-zero placeholders will not match and this test fails BY DESIGN.
 */

#include "field.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Set to 1 after pasting the faest-ref vectors below (see the file header).
 * While 0, the EXP_* arrays are unpinned placeholders and the test builds as a
 * loud SKIP so the suite stays green; the gate is REQUIRED before PRODUCT3
 * freezes, so this must be flipped to 1 (with real vectors) at that point.
 */
#define PRODUCT3_COMPAT_PINNED 1

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/*
 * Fixed deterministic field-element inputs.  These MUST be byte-identical to
 * the IN_* arrays in tools/faest-ref-diagnostics/diag_norm_constraints.c; the
 * leading nbytes are used per lambda.  Roles: a=y, b=a^2, c=a^16, d=a (target).
 */
static const uint8_t IN_VAL_Y[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54,
    0x76, 0x98, 0xba, 0xdc, 0xfe, 0x02, 0x46, 0x8a, 0xce, 0x13, 0x57,
    0x9b, 0xdf, 0x20, 0x64, 0xa8, 0xec, 0x31, 0x75, 0xb9, 0xfd};
static const uint8_t IN_TAG_Y[32] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
    0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};
static const uint8_t IN_VAL_B[32] = {
    0xa5, 0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x69, 0x96, 0x12, 0x21, 0x34,
    0x43, 0x56, 0x65, 0x78, 0x87, 0x9a, 0xa9, 0xbc, 0xcb, 0xde, 0xed,
    0x01, 0x10, 0x23, 0x32, 0x45, 0x54, 0x67, 0x76, 0x89, 0x98};
static const uint8_t IN_TAG_B[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a,
    0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00};
static const uint8_t IN_VAL_C[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa,
    0xce, 0xd0, 0x0d, 0xbe, 0xef, 0x13, 0x37, 0x42, 0x24, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11};
static const uint8_t IN_TAG_C[32] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5,
    0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
static const uint8_t IN_VAL_D[32] = {
    0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x33, 0xcc, 0x33,
    0xcc, 0x33, 0xcc, 0x33, 0xcc, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0,
    0x0f, 0xf0, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5};
static const uint8_t IN_TAG_D[32] = {
    0xc0, 0xff, 0xee, 0x00, 0xc0, 0xff, 0xee, 0x00, 0xde, 0xca, 0xfb,
    0xad, 0xde, 0xca, 0xfb, 0xad, 0xba, 0xdc, 0x0f, 0xfe, 0xba, 0xdc,
    0x0f, 0xfe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
static const uint8_t IN_DELTA[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0,
    0x60, 0x5c, 0xed, 0xc8, 0x34, 0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2,
    0x72, 0x51, 0xf8, 0x6c, 0x6a, 0x11, 0xd0, 0xc1, 0x8e, 0x95};

/* ---------------------------------------------------------------------
 * faest-ref captured expected vectors (PLACEHOLDERS until pinned; see the
 * file header).  Each is the little-endian field element printed by
 * diag_norm_constraints for that lambda.
 * ------------------------------------------------------------------- */
static const uint8_t EXP_128_A0[16] = {0xe5, 0x5d, 0x4a, 0xa0, 0xb9, 0xb5,
                                       0x57, 0xaf, 0x32, 0xf5, 0xad, 0x13,
                                       0x10, 0x05, 0xce, 0x04};
static const uint8_t EXP_128_A1[16] = {0x82, 0xce, 0x8f, 0xd6, 0x29, 0x59,
                                       0xb5, 0xe3, 0x94, 0x24, 0x68, 0x68,
                                       0x06, 0xaf, 0x4f, 0x2f};
static const uint8_t EXP_128_A2[16] = {0x96, 0x2c, 0xb9, 0x5f, 0xea, 0xe0,
                                       0x35, 0x89, 0xb0, 0xae, 0x07, 0x74,
                                       0xf4, 0x76, 0xce, 0xaa};
static const uint8_t EXP_128_V[16] = {0x68, 0xa4, 0x3e, 0x11, 0xd4, 0x5b,
                                      0x3b, 0x49, 0xc5, 0xf6, 0x64, 0x9e,
                                      0x99, 0x8c, 0xd4, 0x57};

static const uint8_t EXP_192_A0[24] = {
    0x78, 0xc3, 0x61, 0xa7, 0x17, 0xfd, 0xf9, 0x1c, 0x31, 0xaa, 0xef, 0x94,
    0xe2, 0xc1, 0x58, 0x21, 0x7b, 0x8f, 0x0e, 0xb4, 0x96, 0x4d, 0x87, 0x28};
static const uint8_t EXP_192_A1[24] = {
    0xc7, 0x72, 0xcb, 0xa2, 0xa1, 0xc8, 0xe9, 0xd4, 0xca, 0x4e, 0x8b, 0x3d,
    0x9a, 0xf5, 0x1a, 0x62, 0x95, 0xf6, 0x13, 0xec, 0xfe, 0xbb, 0x12, 0xb1};
static const uint8_t EXP_192_A2[24] = {
    0x29, 0xe8, 0xd1, 0x8d, 0x4f, 0x76, 0xa0, 0x21, 0xd2, 0x5b, 0x6a, 0x16,
    0x0f, 0xdf, 0x6c, 0x69, 0xc7, 0x75, 0xea, 0x51, 0x3a, 0x1e, 0x03, 0x78};
static const uint8_t EXP_192_V[24] = {
    0xdd, 0x25, 0x3b, 0x6b, 0x0f, 0x56, 0x16, 0xae, 0xfa, 0x6e, 0xa8, 0xdc,
    0x7b, 0xe3, 0x84, 0x06, 0x4d, 0x17, 0x45, 0x91, 0xc2, 0xec, 0x0e, 0x3f};

static const uint8_t EXP_256_A0[32] = {
    0x42, 0x40, 0xa7, 0xb0, 0xca, 0x2a, 0xce, 0x54, 0x54, 0x8c, 0x65,
    0xb9, 0xe2, 0x85, 0x81, 0x36, 0x41, 0x53, 0xb4, 0x9f, 0x0c, 0x6c,
    0x8b, 0xba, 0x2a, 0xc0, 0x1d, 0x9e, 0xd5, 0xa2, 0xaf, 0xe7};
static const uint8_t EXP_256_A1[32] = {
    0xbb, 0x4b, 0xa7, 0xa9, 0xc7, 0x20, 0xf6, 0xdc, 0x4d, 0xe2, 0x7f,
    0x79, 0x62, 0x19, 0xe4, 0x6d, 0x1c, 0xb0, 0x69, 0x9c, 0xcd, 0xc3,
    0x2b, 0x42, 0xe7, 0xca, 0x3c, 0x84, 0xcc, 0x80, 0xb3, 0x24};
static const uint8_t EXP_256_A2[32] = {
    0xb4, 0x5e, 0x0a, 0x8c, 0xd4, 0xe4, 0x1d, 0x54, 0xb1, 0x43, 0xef,
    0xf6, 0x91, 0x91, 0x87, 0x7c, 0xd2, 0x58, 0x05, 0xb2, 0x3f, 0xda,
    0x09, 0x33, 0xd1, 0x34, 0xea, 0xc5, 0x8f, 0x92, 0x97, 0x98};
static const uint8_t EXP_256_V[32] = {
    0x43, 0xe9, 0xc2, 0x3b, 0xe7, 0xf8, 0xa0, 0x92, 0xdf, 0x55, 0xe9,
    0xb9, 0xb0, 0xbc, 0x30, 0xbe, 0x8c, 0x49, 0xef, 0x6f, 0x62, 0x7b,
    0x63, 0x77, 0xcb, 0x5d, 0x21, 0x0b, 0x86, 0x28, 0xd8, 0xd1};

/*
 * One checker per lambda.  Recomputes the PRODUCT3 coefficient streams and the
 * verifier value exactly as proof/gf8_prover.c and proof/gf8_verifier.c do,
 * but over raw field elements (byte_combine/embed are identity on operands fed
 * directly as field elements), then compares against the faest-ref vectors.
 *   a0 = ty*tb*tc
 *   a1 = vy*tb*tc + ty*vb*tc + ty*tb*vc
 *   a2 = ty*vb*vc + vy*tb*vc + vy*vb*tc + td
 *   verifier: key_x = tag_x + delta*val_x; value = ka*kb*kc + kd*delta^2
 */
#define GEN_CHECK(W, NB)                                                       \
    static void check_##W(void)                                                \
    {                                                                          \
        voleith_gf##W##_t vy, ty, vb, tb, vc, tc, vd, td, de;                  \
        voleith_gf##W##_t t1, t2, a0, a1, a2, ka, kb, kc, kd, vv, dsq;         \
        uint8_t out[NB];                                                       \
        voleith_gf##W##_from_bytes(&vy, IN_VAL_Y);                             \
        voleith_gf##W##_from_bytes(&ty, IN_TAG_Y);                             \
        voleith_gf##W##_from_bytes(&vb, IN_VAL_B);                             \
        voleith_gf##W##_from_bytes(&tb, IN_TAG_B);                             \
        voleith_gf##W##_from_bytes(&vc, IN_VAL_C);                             \
        voleith_gf##W##_from_bytes(&tc, IN_TAG_C);                             \
        voleith_gf##W##_from_bytes(&vd, IN_VAL_D);                             \
        voleith_gf##W##_from_bytes(&td, IN_TAG_D);                             \
        voleith_gf##W##_from_bytes(&de, IN_DELTA);                             \
                                                                               \
        /* a0 = ty*tb*tc */                                                    \
        voleith_gf##W##_mul(&t1, &ty, &tb);                                    \
        voleith_gf##W##_mul(&a0, &t1, &tc);                                    \
                                                                               \
        /* a1 = vy*tb*tc + ty*vb*tc + ty*tb*vc */                              \
        voleith_gf##W##_mul(&t1, &vy, &tb);                                    \
        voleith_gf##W##_mul(&a1, &t1, &tc);                                    \
        voleith_gf##W##_mul(&t1, &ty, &vb);                                    \
        voleith_gf##W##_mul(&t2, &t1, &tc);                                    \
        voleith_gf##W##_add(&a1, &a1, &t2);                                    \
        voleith_gf##W##_mul(&t1, &ty, &tb);                                    \
        voleith_gf##W##_mul(&t2, &t1, &vc);                                    \
        voleith_gf##W##_add(&a1, &a1, &t2);                                    \
                                                                               \
        /* a2 = ty*vb*vc + vy*tb*vc + vy*vb*tc + td */                         \
        voleith_gf##W##_mul(&t1, &ty, &vb);                                    \
        voleith_gf##W##_mul(&a2, &t1, &vc);                                    \
        voleith_gf##W##_mul(&t1, &vy, &tb);                                    \
        voleith_gf##W##_mul(&t2, &t1, &vc);                                    \
        voleith_gf##W##_add(&a2, &a2, &t2);                                    \
        voleith_gf##W##_mul(&t1, &vy, &vb);                                    \
        voleith_gf##W##_mul(&t2, &t1, &tc);                                    \
        voleith_gf##W##_add(&a2, &a2, &t2);                                    \
        voleith_gf##W##_add(&a2, &a2, &td);                                    \
                                                                               \
        /* keys and verifier value */                                          \
        voleith_gf##W##_mul(&t1, &de, &vy);                                    \
        voleith_gf##W##_add(&ka, &ty, &t1);                                    \
        voleith_gf##W##_mul(&t1, &de, &vb);                                    \
        voleith_gf##W##_add(&kb, &tb, &t1);                                    \
        voleith_gf##W##_mul(&t1, &de, &vc);                                    \
        voleith_gf##W##_add(&kc, &tc, &t1);                                    \
        voleith_gf##W##_mul(&t1, &de, &vd);                                    \
        voleith_gf##W##_add(&kd, &td, &t1);                                    \
        voleith_gf##W##_mul(&t1, &ka, &kb);                                    \
        voleith_gf##W##_mul(&vv, &t1, &kc);                                    \
        voleith_gf##W##_mul(&dsq, &de, &de);                                   \
        voleith_gf##W##_mul(&t1, &kd, &dsq);                                   \
        voleith_gf##W##_add(&vv, &vv, &t1);                                    \
                                                                               \
        voleith_gf##W##_to_bytes(out, &a0);                                    \
        check("product3 compat lambda=" #W ": a0 == faest-ref",                \
              memcmp(out, EXP_##W##_A0, NB) == 0);                             \
        voleith_gf##W##_to_bytes(out, &a1);                                    \
        check("product3 compat lambda=" #W ": a1 == faest-ref",                \
              memcmp(out, EXP_##W##_A1, NB) == 0);                             \
        voleith_gf##W##_to_bytes(out, &a2);                                    \
        check("product3 compat lambda=" #W ": a2 == faest-ref",                \
              memcmp(out, EXP_##W##_A2, NB) == 0);                             \
        voleith_gf##W##_to_bytes(out, &vv);                                    \
        check("product3 compat lambda=" #W ": verifier value == faest-ref",    \
              memcmp(out, EXP_##W##_V, NB) == 0);                              \
    }

GEN_CHECK(128, 16)
GEN_CHECK(192, 24)
GEN_CHECK(256, 32)

int
main(void)
{
    printf("test_product3_compat: starting\n");
#if !PRODUCT3_COMPAT_PINNED
    printf("  SKIP: faest-ref PRODUCT3 compat vectors not yet pinned.\n");
    printf(
        "  Run tools/faest-ref-diagnostics/diag_norm_constraints, paste the\n");
    printf("  a0/a1/a2/vexp bytes into the EXP_* arrays, and set\n");
    printf(
        "  PRODUCT3_COMPAT_PINNED to 1.  REQUIRED before PRODUCT3 freezes.\n");
    (void)check;
    (void)check_128;
    (void)check_192;
    (void)check_256;
    return 0;
#else
    check_128();
    check_192();
    check_256();
    printf("test_product3_compat: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
#endif
}