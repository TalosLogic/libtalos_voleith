/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Diagnostic: recover FAEST's GF(2^4) norm-nibble basis as GF(2^8) bytes.
 *
 * FAEST commits the inverse subfield norm as a 4-bit value whose bits are
 * coordinates in a fixed GF(2^4) basis of GF(2^8).  faest-ref's
 * aes_SSS_inv_norm_to_conjugates maps those 4 bits to the norm's conjugates
 * via the lambda-field constant tables bfSSS_beta_squares / bfSSS_beta_cubes.
 * The identity conjugate y[0] for a single set bit b_k is exactly the lambda
 * embedding of that basis element:
 *
 *   b0 -> from_bit(1)        = embed(0x01)
 *   b1 -> bfSSS_beta_squares[0]
 *   b2 -> bfSSS_beta_squares[1]
 *   b3 -> bfSSS_beta_cubes[0]
 *
 * Since faest-ref's bf##W##_byte_combine_bits(byte) computes the same
 * embedding voleith uses (embed(byte) = sum_i byte_i * alpha^i, FAEST spec
 * Appendix A.1), we recover each basis byte by brute-forcing the 256 bytes
 * until byte_combine_bits matches the target lambda constant.  The recovered
 * bytes are a property of the fixed GF(2^4) subfield element, so they MUST
 * agree across lambda = 128/192/256; the harness asserts that.  A clean
 * inversion existing at all also confirms voleith's embed == FAEST's
 * byte_combine.
 *
 * Oracle use only: the beta constants below are copied verbatim from faest-ref
 * faest_aes.c.in (they are static there, so not linkable) solely to invert
 * them here.  Nothing is copied into the voleith library; only the resulting
 * four bytes are pinned, in voleith's own GF(2^8) basis.
 *
 * Build (from the faest-ref directory, after building faest-ref with meson):
 *   cp tools/faest-ref-diagnostics/diag_norm_basis.c third_party/faest-ref/
 *   cd third_party/faest-ref
 *   gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_norm_basis.c \
 *       -o build/diag_norm_basis build/libfaest_no_random.a build/libfaest.a
 * Run:
 *   ./build/diag_norm_basis
 */

#include "fields.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* faest-ref bfSSS_beta_squares[0], bfSSS_beta_squares[1], bfSSS_beta_cubes[0]
 * for each lambda, copied from faest_aes.c.in (oracle only). */
static const bf128_t beta_128[3] = {
    BF128C(UINT64_C(0xaca8c2a7190f676b), UINT64_C(0xdb4a932e2cae3d8b)),
    BF128C(UINT64_C(0x34d2f7fba603e341), UINT64_C(0x500317bd159d73bb)),
    BF128C(UINT64_C(0x53b85b6402b1e849), UINT64_C(0x7959d70ce1ee6942)),
};
static const bf192_t beta_192[3] = {
    BF192C(UINT64_C(0x4a2fe80a53fe16e7), UINT64_C(0x89bfb5055f8ff266),
           UINT64_C(0x6c4aecc3fdd0f812)),
    BF192C(UINT64_C(0xf061255c52e359d4), UINT64_C(0x125a337e5e808579),
           UINT64_C(0x54ed13a2d09da6a4)),
    BF192C(UINT64_C(0x2e5e4d8d89cddab6), UINT64_C(0xf9c4fc6ed351b23f),
           UINT64_C(0xd6a83a56e8e495c2)),
};
static const bf256_t beta_256[3] = {
    BF256C(UINT64_C(0x4074aaa06e5faade), UINT64_C(0xd9ca3e577cc14c4a),
           UINT64_C(0xda065d89ba07bf41), UINT64_C(0x96ff78f99e8ca1cb)),
    BF256C(UINT64_C(0xfc8046a8eaa315e8), UINT64_C(0x3cd447937f790879),
           UINT64_C(0x2adc5a08c13f1cfb), UINT64_C(0x67dbaeb2ec4abc7c)),
    BF256C(UINT64_C(0xfc8046a9eaa214dc), UINT64_C(0x3cd447937f790878),
           UINT64_C(0x2adc5a08c13f1cfa), UINT64_C(0x67dbaeb2ec4abc7c)),
};

/* Brute-force the byte b with byte_combine_bits(b) == target.  Returns the
 * byte, or -1 if none (which would mean embed != byte_combine). */
#define DEFINE_INVERT(W, NB)                                                   \
    static int invert_##W(bf##W##_t target)                                    \
    {                                                                          \
        uint8_t tb[NB], cb[NB];                                                \
        bf##W##_store(tb, target);                                             \
        for (int b = 0; b < 256; b++) {                                        \
            bf##W##_store(cb, bf##W##_byte_combine_bits((uint8_t)b));          \
            if (memcmp(tb, cb, NB) == 0)                                       \
                return b;                                                      \
        }                                                                      \
        return -1;                                                             \
    }

DEFINE_INVERT(128, 16)
DEFINE_INVERT(192, 24)
DEFINE_INVERT(256, 32)

static void
print_bytes(const char *name, int idx, const uint8_t *data, size_t len)
{
    printf("static const uint8_t %s%d[] = {", name, idx);
    for (size_t i = 0; i < len; i++) {
        if (i % 12 == 0)
            printf("\n    ");
        printf("0x%02x,", data[i]);
        if (i % 12 != 11 && i + 1 < len)
            printf(" ");
    }
    printf("\n};\n");
}

int
main(void)
{
    int basis[4];
    int b192[4], b256[4];

    /* e0 is the one element: byte 0x01. e1/e2/e3 invert the three betas. */
    basis[0] = 0x01;
    basis[1] = invert_128(beta_128[0]);
    basis[2] = invert_128(beta_128[1]);
    basis[3] = invert_128(beta_128[2]);

    b192[0] = 0x01;
    b192[1] = invert_192(beta_192[0]);
    b192[2] = invert_192(beta_192[1]);
    b192[3] = invert_192(beta_192[2]);

    b256[0] = 0x01;
    b256[1] = invert_256(beta_256[0]);
    b256[2] = invert_256(beta_256[1]);
    b256[3] = invert_256(beta_256[2]);

    int ok = 1;
    for (int i = 0; i < 4; i++) {
        if (basis[i] < 0 || b192[i] < 0 || b256[i] < 0) {
            printf("FAIL: no byte inverts basis image %d "
                   "(128=%d 192=%d 256=%d): embed != byte_combine\n",
                   i, basis[i], b192[i], b256[i]);
            ok = 0;
        } else if (basis[i] != b192[i] || basis[i] != b256[i]) {
            printf("FAIL: basis byte %d differs across lambda "
                   "(128=0x%02x 192=0x%02x 256=0x%02x)\n",
                   i, basis[i], b192[i], b256[i]);
            ok = 0;
        }
    }
    if (!ok)
        return 1;

    printf("/* FAEST GF(2^4) norm-nibble basis, as GF(2^8) bytes (AES field).\n"
           " * nibble bit i is the coefficient of basis element i:\n"
           " *   c = b0*basis[0] + b1*basis[1] + b2*basis[2] + b3*basis[3]\n"
           " * Agrees across lambda=128/192/256; inversion exact (embed ==\n"
           " * byte_combine). */\n");
    printf("static const uint8_t FAEST_NORM_NIBBLE_BASIS[4] = {\n");
    printf("    0x%02x, 0x%02x, 0x%02x, 0x%02x,\n", basis[0], basis[1],
           basis[2], basis[3]);
    printf("};\n\n");

    /*
     * The three non-trivial basis images as faest-ref lambda byte-arrays, for
     * the companion voleith-side gate (tests/test_norm_basis_compat.c): it
     * recomputes voleith's byte_combine of the pinned basis bytes and asserts
     * it reproduces these faest-ref constants value-exact.
     */
    printf("/* faest-ref beta basis images (lambda byte-arrays), for the\n"
           " * voleith companion gate. */\n");
    uint8_t b[32];
    for (int i = 0; i < 3; i++) {
        bf128_store(b, beta_128[i]);
        print_bytes("EXP_128_BETA", i, b, 16);
    }
    for (int i = 0; i < 3; i++) {
        bf192_store(b, beta_192[i]);
        print_bytes("EXP_192_BETA", i, b, 24);
    }
    for (int i = 0; i < 3; i++) {
        bf256_store(b, beta_256[i]);
        print_bytes("EXP_256_BETA", i, b, 32);
    }
    return 0;
}
