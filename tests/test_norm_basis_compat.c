/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_norm_basis_compat.c - one-shot faest-ref compat gate for the norm
 * S-box GF(2^4) nibble basis.
 *
 * The norm S-box builders commit the inverse subfield norm as a 4-bit value
 * whose bits are coordinates in a fixed GF(2^4) basis of GF(2^8).  voleith's
 * voleith_gf8_add_norm_embed embeds those bits via the basis bytes
 * {0x01, 0x50, 0xb0, 0x0c} (proof/gf8_circuit.c gf8_norm_nibble_basis).  Those
 * bytes were derived to MATCH faest-ref's basis so the committed nibble bits
 * are the same GF(2^4) coordinates FAEST uses, which lets a future byte-exact
 * FAEST-EM compat mode reuse this embedding unchanged.
 *
 * This test pins that match VALUE-EXACT.  faest-ref maps the four norm bits to
 * the lambda field with the constant tables bfSSS_beta_squares[0..1] and
 * bfSSS_beta_cubes[0] (faest_aes.c.in); those three lambda elements are the
 * images of basis elements 1, 2, 3 (basis element 0 is the field one).  Here
 * we recompute voleith's own byte_combine embedding (core/field.c, the same
 * embed(byte) = sum_i byte_i * alpha^i the gf8 prover uses) of each basis byte
 * and assert it equals the faest-ref constant captured offline.  Agreement
 * confirms both that the basis matches FAEST and that voleith's embed equals
 * FAEST's byte_combine; a mismatch means a future compat packer could not
 * reuse this basis, or a field constant drifted.
 *
 * One-shot bring-up gate, not a maintained KAT.  faest-ref is NOT linked into
 * this build; the EXP_*_BETA* vectors are captured offline with
 * tools/faest-ref-diagnostics/diag_norm_basis.c and pasted below.  That same
 * tool also asserts the basis is consistent across lambda and inverts exactly.
 */

#include "field.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Set to 1 once the EXP_*_BETA* vectors below are pinned from faest-ref. */
#define NORM_BASIS_COMPAT_PINNED 1

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
 * The GF(2^4) nibble basis as GF(2^8) bytes, mirroring
 * proof/gf8_circuit.c::gf8_norm_nibble_basis.  Basis element 0 is the field
 * one (embed(0x01)); elements 1/2/3 map to the faest-ref beta images below.
 */
static const uint8_t NORM_NIBBLE_BASIS[4] = {0x01, 0x50, 0xb0, 0x0c};

/*
 * faest-ref basis images as lambda byte-arrays, captured from
 * diag_norm_basis.c: EXP_W_BETA{0,1,2} are bfSSS_beta_squares[0],
 * bfSSS_beta_squares[1], bfSSS_beta_cubes[0] at lambda = W, i.e. the lambda
 * embeddings of basis elements 1, 2, 3.
 */
static const uint8_t EXP_128_BETA0[16] = {
    0x6b, 0x67, 0x0f, 0x19, 0xa7, 0xc2, 0xa8, 0xac,
    0x8b, 0x3d, 0xae, 0x2c, 0x2e, 0x93, 0x4a, 0xdb,
};
static const uint8_t EXP_128_BETA1[16] = {
    0x41, 0xe3, 0x03, 0xa6, 0xfb, 0xf7, 0xd2, 0x34,
    0xbb, 0x73, 0x9d, 0x15, 0xbd, 0x17, 0x03, 0x50,
};
static const uint8_t EXP_128_BETA2[16] = {
    0x49, 0xe8, 0xb1, 0x02, 0x64, 0x5b, 0xb8, 0x53,
    0x42, 0x69, 0xee, 0xe1, 0x0c, 0xd7, 0x59, 0x79,
};
static const uint8_t EXP_192_BETA0[24] = {
    0xe7, 0x16, 0xfe, 0x53, 0x0a, 0xe8, 0x2f, 0x4a, 0x66, 0xf2, 0x8f, 0x5f,
    0x05, 0xb5, 0xbf, 0x89, 0x12, 0xf8, 0xd0, 0xfd, 0xc3, 0xec, 0x4a, 0x6c,
};
static const uint8_t EXP_192_BETA1[24] = {
    0xd4, 0x59, 0xe3, 0x52, 0x5c, 0x25, 0x61, 0xf0, 0x79, 0x85, 0x80, 0x5e,
    0x7e, 0x33, 0x5a, 0x12, 0xa4, 0xa6, 0x9d, 0xd0, 0xa2, 0x13, 0xed, 0x54,
};
static const uint8_t EXP_192_BETA2[24] = {
    0xb6, 0xda, 0xcd, 0x89, 0x8d, 0x4d, 0x5e, 0x2e, 0x3f, 0xb2, 0x51, 0xd3,
    0x6e, 0xfc, 0xc4, 0xf9, 0xc2, 0x95, 0xe4, 0xe8, 0x56, 0x3a, 0xa8, 0xd6,
};
static const uint8_t EXP_256_BETA0[32] = {
    0xde, 0xaa, 0x5f, 0x6e, 0xa0, 0xaa, 0x74, 0x40, 0x4a, 0x4c, 0xc1,
    0x7c, 0x57, 0x3e, 0xca, 0xd9, 0x41, 0xbf, 0x07, 0xba, 0x89, 0x5d,
    0x06, 0xda, 0xcb, 0xa1, 0x8c, 0x9e, 0xf9, 0x78, 0xff, 0x96,
};
static const uint8_t EXP_256_BETA1[32] = {
    0xe8, 0x15, 0xa3, 0xea, 0xa8, 0x46, 0x80, 0xfc, 0x79, 0x08, 0x79,
    0x7f, 0x93, 0x47, 0xd4, 0x3c, 0xfb, 0x1c, 0x3f, 0xc1, 0x08, 0x5a,
    0xdc, 0x2a, 0x7c, 0xbc, 0x4a, 0xec, 0xb2, 0xae, 0xdb, 0x67,
};
static const uint8_t EXP_256_BETA2[32] = {
    0xdc, 0x14, 0xa2, 0xea, 0xa9, 0x46, 0x80, 0xfc, 0x78, 0x08, 0x79,
    0x7f, 0x93, 0x47, 0xd4, 0x3c, 0xfa, 0x1c, 0x3f, 0xc1, 0x08, 0x5a,
    0xdc, 0x2a, 0x7c, 0xbc, 0x4a, 0xec, 0xb2, 0xae, 0xdb, 0x67,
};

/*
 * Embed a GF(2^8) byte into GF(2^lambda) via voleith_byte_combine: the same
 * embed(byte) = sum_i byte_i * alpha^i used by the gf8 prover.
 */
static int
embed(uint8_t *out, uint8_t byte, int lambda)
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++)
        bits[i] = (uint8_t)((byte >> i) & 1u);
    return voleith_byte_combine(out, bits, lambda);
}

#define GEN_CHECK(W, NB)                                                       \
    static void check_##W(void)                                                \
    {                                                                          \
        uint8_t out[NB], one[NB];                                              \
                                                                               \
        /* Basis element 0 embeds to the field one (byte 0x01). */             \
        memset(one, 0, NB);                                                    \
        one[0] = 0x01;                                                         \
        check("norm basis lambda=" #W ": basis[0] embeds to one",              \
              embed(out, NORM_NIBBLE_BASIS[0], W) == 0 &&                      \
                  memcmp(out, one, NB) == 0);                                  \
                                                                               \
        /* Basis elements 1/2/3 match the faest-ref beta images. */            \
        check("norm basis lambda=" #W ": basis[1] == faest beta_sq[0]",        \
              embed(out, NORM_NIBBLE_BASIS[1], W) == 0 &&                      \
                  memcmp(out, EXP_##W##_BETA0, NB) == 0);                      \
        check("norm basis lambda=" #W ": basis[2] == faest beta_sq[1]",        \
              embed(out, NORM_NIBBLE_BASIS[2], W) == 0 &&                      \
                  memcmp(out, EXP_##W##_BETA1, NB) == 0);                      \
        check("norm basis lambda=" #W ": basis[3] == faest beta_cube[0]",      \
              embed(out, NORM_NIBBLE_BASIS[3], W) == 0 &&                      \
                  memcmp(out, EXP_##W##_BETA2, NB) == 0);                      \
    }

GEN_CHECK(128, 16)
GEN_CHECK(192, 24)
GEN_CHECK(256, 32)

int
main(void)
{
    printf("test_norm_basis_compat: starting\n");
#if !NORM_BASIS_COMPAT_PINNED
    printf("  SKIP: faest-ref norm-basis vectors not yet pinned.\n");
    (void)check;
    (void)check_128;
    (void)check_192;
    (void)check_256;
    return 0;
#else
    check_128();
    check_192();
    check_256();
    printf("test_norm_basis_compat: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
#endif
}
