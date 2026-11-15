/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Diagnostic: print the FAEST norm S-box constraint coefficients (spec
 * Fig 6.19, y * a^2 * a^16 = a) as computed by the faest-ref reference, for
 * lambda = 128, 192, 256.  Used to capture the one-shot PRODUCT3 compat gate
 * vectors embedded in tests/test_product3_compat.c.
 *
 * This mirrors the three coefficient streams that faest-ref
 * aes_SSS_inv_norm_constraints_prover pushes into zk_hash_SSS_3_update, and the
 * single value aes_SSS_inv_norm_constraints_verifier pushes into
 * zk_hash_SSS_update.  Oracle use only: this reproduces faest-ref's own field
 * expressions in a standalone tool; nothing is copied into the voleith library.
 *
 * Roles (PRODUCT3 operands a*b*c = d applied to the norm relation):
 *   a = y        (committed inverse F2^4-norm)
 *   b = a^2      (conjugate index 1)
 *   c = a^16     (conjugate index 4)
 *   d = a        (conjugate index 0, the parked target)
 * Each role has a value (val_*) and a tag (tag_*).  The verifier works over
 * the VOLE keys key_* = tag_* + delta * val_* (one line evaluated at delta).
 *
 * Build (from the faest-ref directory, after building faest-ref with meson):
 *   cp tools/faest-ref-diagnostics/diag_norm_constraints.c third_party/faest-ref/
 *   cd third_party/faest-ref
 *   gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_norm_constraints.c \
 *       -o build/diag_norm_constraints build/libfaest_no_random.a build/libfaest.a
 * Run:
 *   ./build/diag_norm_constraints
 * Paste the printed blocks into tests/test_product3_compat.c.
 */

#include "fields.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Fixed deterministic field-element inputs, one distinct byte pattern per
 * role x subrole, filling the full byte width of the largest field (32).  The
 * per-lambda runs use the leading nbytes of each buffer.  The patterns are
 * arbitrary but fixed; the gate checks the coefficient-folding algebra, which
 * must agree regardless of the operand values.
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

static void
print_c_array(const char *name, const uint8_t *data, size_t len)
{
    printf("    static const uint8_t %s[] = {", name);
    for (size_t i = 0; i < len; i++) {
        if (i % 12 == 0)
            printf("\n        ");
        printf("0x%02x,", data[i]);
        if (i % 12 != 11 && i + 1 < len)
            printf(" ");
    }
    printf("\n    };\n");
}

/*
 * One block per lambda.  bf##W##_load/store are little-endian over nbytes,
 * matching voleith_gf##W##_from_bytes/to_bytes.  The three prover coefficients
 * replicate aes_SSS_inv_norm_constraints_prover; the verifier value replicates
 * aes_SSS_inv_norm_constraints_verifier (key_* = tag_* + delta*val_*).
 */
#define GEN_BLOCK(W, NB)                                                         \
    static void run_##W(void)                                                    \
    {                                                                            \
        uint8_t out[NB];                                                         \
        bf##W##_t vy = bf##W##_load(IN_VAL_Y), ty = bf##W##_load(IN_TAG_Y);      \
        bf##W##_t vb = bf##W##_load(IN_VAL_B), tb = bf##W##_load(IN_TAG_B);      \
        bf##W##_t vc = bf##W##_load(IN_VAL_C), tc = bf##W##_load(IN_TAG_C);      \
        bf##W##_t vd = bf##W##_load(IN_VAL_D), td = bf##W##_load(IN_TAG_D);      \
        bf##W##_t de = bf##W##_load(IN_DELTA);                                   \
                                                                                 \
        /* Prover coefficient streams (a=y, b, c; target tag td). */             \
        bf##W##_t a0 = bf##W##_mul(bf##W##_mul(ty, tb), tc);                     \
        bf##W##_t a1 =                                                           \
            bf##W##_add(bf##W##_add(bf##W##_mul(bf##W##_mul(vy, tb), tc),        \
                                    bf##W##_mul(bf##W##_mul(ty, tb), vc)),       \
                        bf##W##_mul(bf##W##_mul(ty, vb), tc));                   \
        bf##W##_t a2 = bf##W##_add(                                              \
            bf##W##_add(bf##W##_add(bf##W##_mul(bf##W##_mul(vy, vb), tc),        \
                                    bf##W##_mul(bf##W##_mul(vy, tb), vc)),       \
                        bf##W##_mul(bf##W##_mul(ty, vb), vc)),                   \
            td);                                                                 \
                                                                                 \
        /* Verifier value: keys ka..kd = tag + delta*val, then                 \
         * ka*kb*kc + kd*delta^2. */ \
        bf##W##_t ka = bf##W##_add(ty, bf##W##_mul(de, vy));                     \
        bf##W##_t kb = bf##W##_add(tb, bf##W##_mul(de, vb));                     \
        bf##W##_t kc = bf##W##_add(tc, bf##W##_mul(de, vc));                     \
        bf##W##_t kd = bf##W##_add(td, bf##W##_mul(de, vd));                     \
        bf##W##_t vv = bf##W##_add(bf##W##_mul(bf##W##_mul(ka, kb), kc),         \
                                   bf##W##_mul(kd, bf##W##_mul(de, de)));        \
                                                                                 \
        printf("    /* lambda=%d */\n", W);                                      \
        printf("    {\n");                                                       \
        bf##W##_store(out, a0);                                                  \
        print_c_array("a0", out, NB);                                            \
        bf##W##_store(out, a1);                                                  \
        print_c_array("a1", out, NB);                                            \
        bf##W##_store(out, a2);                                                  \
        print_c_array("a2", out, NB);                                            \
        bf##W##_store(out, vv);                                                  \
        print_c_array("vexp", out, NB);                                          \
        printf("    }\n\n");                                                     \
    }

GEN_BLOCK(128, 16)
GEN_BLOCK(192, 24)
GEN_BLOCK(256, 32)

int
main(void)
{
    printf(
        "/* PRODUCT3 norm-constraint compat vectors (faest-ref oracle). */\n");
    run_128();
    run_192();
    run_256();
    return 0;
}
