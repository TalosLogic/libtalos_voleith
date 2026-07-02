/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * vole_hash.c - VOLEHash universal hash
 *
 * Clean-room implementation from the FAEST v2.0 specification, Section
 * 4.3.3 ("VOLE Universal Hash"), Figure 4.4.  Field byte conventions
 * (little-endian bit ordering, irreducible polynomials) follow
 * core/field.h.
 *
 * VOLEHash(sd, (x0, x1)) with x0 in {0,1}^(ell + 2*lambda) and x1 in
 * {0,1}^(lambda + B):
 *
 *   Parse sd = (r0 || r1 || r2 || r3 || s || t), with r0..r3, s in
 *     F(2^lambda) and t in F(2^64).
 *   l'  = lambda * ceil((ell + 2*lambda) / lambda)   (pad x0 to a
 *         whole number of lambda-bit chunks)
 *   h0  = sum_{i=0}^{l'/lambda - 1} s^(l'/lambda - 1 - i) * x0_chunk[i]
 *         in F(2^lambda)
 *   h1  = sum_{i=0}^{l'/64 - 1}     t^(l'/64 - 1 - i)     * x0_word[i]
 *         in F(2^64)
 *   h1' = h1 zero-extended to lambda bits
 *   h2  = r0 * h0 + r1 * h1'
 *   h3  = r2 * h0 + r3 * h1'
 *   h   = (ToBits(h2) || ToBits(h3)[0..B)) XOR x1
 *
 * In the little-endian layout, chunk 0 (bytes [0..lambda/8)) is the
 * least-significant chunk and so carries the highest power of s; the
 * final (most-significant) chunk carries s^0.  The two Horner
 * accumulators below therefore feed chunks / words in ascending
 * significance, leaving the most-significant unit multiplied by the
 * zeroth power.  Independent known-answer vectors for this algorithm
 * are produced by tools/gen_vole_hash_kats.py.
 */

#include "vole_hash.h"
#include "../core/field.h"
#include "../core/util.h"

#include <string.h>
#include <stdint.h>

/* =====================================================================
 * Internal GF(2^lambda) multiply dispatch
 * ===================================================================== */

static void
gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b, unsigned int lambda)
{
    if (lambda == 128) {
        voleith_gf128_t A, B, C;
        voleith_gf128_from_bytes(&A, a);
        voleith_gf128_from_bytes(&B, b);
        voleith_gf128_mul(&C, &A, &B);
        voleith_gf128_to_bytes(out, &C);
    } else if (lambda == 192) {
        voleith_gf192_t A, B, C;
        voleith_gf192_from_bytes(&A, a);
        voleith_gf192_from_bytes(&B, b);
        voleith_gf192_mul(&C, &A, &B);
        voleith_gf192_to_bytes(out, &C);
    } else {
        voleith_gf256_t A, B, C;
        voleith_gf256_from_bytes(&A, a);
        voleith_gf256_from_bytes(&B, b);
        voleith_gf256_mul(&C, &A, &B);
        voleith_gf256_to_bytes(out, &C);
    }
}

/* =====================================================================
 * VOLEHash
 * ===================================================================== */

void
voleith_vole_hash(uint8_t *h_out, const uint8_t *sd, const uint8_t *x,
                  size_t ell, unsigned int lambda)
{
    unsigned int nb = lambda / 8;

    /* Parse sd into the five lambda-bit fields and one 64-bit field. */
    const uint8_t *r0 = sd + 0 * nb;
    const uint8_t *r1 = sd + 1 * nb;
    const uint8_t *r2 = sd + 2 * nb;
    const uint8_t *r3 = sd + 3 * nb;
    const uint8_t *s = sd + 4 * nb;
    const uint8_t *t = sd + 5 * nb; /* 8 bytes, GF(2^64) */

    /*
     * x splits into x0 (the first ell + 2*lambda bits) and the masking
     * tail x1 (lambda + B bytes).  Pad x0 up to a whole number of
     * lambda-bit chunks.
     */
    size_t x0_bits = ell + 2u * (size_t)lambda;
    const uint8_t *x1 = x + x0_bits / 8u;

    unsigned int n_chunks = (unsigned int)((x0_bits + lambda - 1u) / lambda);
    unsigned int partial_bits = (unsigned int)(x0_bits % lambda);
    unsigned int last_bytes = (partial_bits == 0u) ? nb : partial_bits / 8u;

    /*
     * Single pass over the n_chunks lambda-bit chunks, accumulating both
     * Horner sums in ascending significance:
     *   h0 = h0 * s + chunk          (in GF(2^lambda))
     *   h1 = h1 * t + word           (in GF(2^64), per 64-bit word)
     */
    uint8_t chunk[32];
    uint8_t h0[32], tmp[32];
    voleith_gf64_t h1 = 0;
    voleith_gf64_t t_key;

    memset(h0, 0, nb);
    memcpy(&t_key, t, 8);

    for (unsigned int ci = 0; ci < n_chunks; ci++) {
        unsigned int nbytes = (ci + 1u < n_chunks) ? nb : last_bytes;

        memset(chunk, 0, nb);
        memcpy(chunk, x + (size_t)ci * nb, nbytes);

        /* h0 = h0 * s + chunk */
        gf_mul(tmp, h0, s, lambda);
        for (unsigned int k = 0; k < nb; k++)
            h0[k] = tmp[k] ^ chunk[k];

        /* h1 = h1 * t + word, for each 64-bit word low to high */
        for (unsigned int off = 0; off < nb; off += 8) {
            voleith_gf64_t word;
            memcpy(&word, chunk + off, 8);
            h1 = voleith_gf64_add(voleith_gf64_mul(h1, t_key), word);
        }
    }

    /* h1 zero-extended to lambda bits is the low 8 bytes, rest zero. */
    uint8_t h1_ext[32];
    memset(h1_ext, 0, nb);
    memcpy(h1_ext, &h1, 8);

    /*
     * h2 = r0 * h0 + r1 * h1'
     * h3 = r2 * h0 + r3 * h1'
     */
    uint8_t h2[32], h3[32], term0[32], term1[32];

    gf_mul(term0, r0, h0, lambda);
    gf_mul(term1, r1, h1_ext, lambda);
    for (unsigned int k = 0; k < nb; k++)
        h2[k] = term0[k] ^ term1[k];

    gf_mul(term0, r2, h0, lambda);
    gf_mul(term1, r3, h1_ext, lambda);
    for (unsigned int k = 0; k < nb; k++)
        h3[k] = term0[k] ^ term1[k];

    /* Output = (h2 || h3[0..B)) XOR x1. */
    for (unsigned int k = 0; k < nb; k++)
        h_out[k] = h2[k] ^ x1[k];
    for (unsigned int k = 0; k < VOLEITH_VOLE_HASH_B; k++)
        h_out[nb + k] = h3[k] ^ x1[nb + k];

    /*
     * P-13: every local below carried an intermediate value of a hash
     * over secret data (x is the prover's u or a V-matrix row).  chunk
     * holds plaintext chunks of x; h0 / h1 are the Horner accumulators;
     * tmp / term0 / term1 are field-mul intermediates; t_key is the
     * GF(2^64) Horner key; h1_ext / h2 / h3 are the final accumulators.
     */
    voleith_secure_zero(chunk, sizeof(chunk));
    voleith_secure_zero(h0, sizeof(h0));
    voleith_secure_zero(tmp, sizeof(tmp));
    voleith_secure_zero(h1_ext, sizeof(h1_ext));
    voleith_secure_zero(h2, sizeof(h2));
    voleith_secure_zero(h3, sizeof(h3));
    voleith_secure_zero(term0, sizeof(term0));
    voleith_secure_zero(term1, sizeof(term1));
    voleith_secure_zero(&h1, sizeof(h1));
    voleith_secure_zero(&t_key, sizeof(t_key));
}
