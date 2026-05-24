/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * vole_hash.c - VOLEHash universal hash (FAEST spec Section 4.3.3, Figure 4.4)
 *
 * Ported from faest-ref universal_hashing.c (MIT licensed), adapted for
 * the voleith library's GF arithmetic API.
 *
 * Algorithm:
 *   h0 = sum_{i=0}^{length_lambda-1} s^i * chunk[length_lambda-1-i]
 *        (Horner in GF(2^lambda), starting from last chunk)
 *   h1 = sum_{k=0}^{n_words-1} t^k * word[n_words-1-k]
 *        (Horner in GF(2^64), last 64-bit word first)
 *   h2 = r0*h0 + r1*(h1 zero-extended to GF(2^lambda))
 *   h3 = r2*h0 + r3*(h1 zero-extended to GF(2^lambda))
 *   output = (h2 || h3[0..1]) XOR x1
 */

#include "vole_hash.h"
#include "../core/field.h"
#include "../core/util.h"

#include <string.h>
#include <stdint.h>

/* =====================================================================
 * Internal GF helpers
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

/*
 * Multiply GF(2^lambda) element a by GF(2^64) element b_val.
 * b_val is zero-extended to lambda_bytes for the GF(2^lambda) multiplication.
 */
static void
gf_mul_64(uint8_t *out, const uint8_t *a, voleith_gf64_t b_val,
          unsigned int lambda)
{
    uint8_t b_ext[32];
    memset(b_ext, 0, sizeof(b_ext));
    memcpy(b_ext, &b_val, 8);
    gf_mul(out, a, b_ext, lambda);
    /* P-13: b_ext mirrors b_val (a GF(2^64) Horner accumulator over
     * secret-derived data); zero before returning. */
    voleith_secure_zero(b_ext, sizeof(b_ext));
}

/* =====================================================================
 * VOLEHash
 * ===================================================================== */

void
voleith_vole_hash(uint8_t *h_out, const uint8_t *sd, const uint8_t *x,
                  size_t ell, unsigned int lambda)
{
    unsigned int nb = lambda / 8;

    const uint8_t *r0 = sd;
    const uint8_t *r1 = sd + 1 * nb;
    const uint8_t *r2 = sd + 2 * nb;
    const uint8_t *r3 = sd + 3 * nb;
    const uint8_t *s = sd + 4 * nb;
    const uint8_t *t = sd + 5 * nb; /* 8 bytes (GF(2^64)) */
    const uint8_t *x1 = x + (ell + 2 * lambda) / 8;

    /* Number of lambda-bit chunks in x0 = ceil((ell + lambda) / lambda)
     * = floor((ell + 2*lambda - 1) / lambda) but we use (ell + 3*lambda - 1)/lambda
     * which matches the total coverage of x0 (ell + 2*lambda bits) rounded up. */
    unsigned int length_lambda =
        (unsigned int)((ell + 3u * lambda - 1u) / lambda);

    /* ------------------------------------------------------------------
     * h0: Horner eval in GF(2^lambda).
     *
     * Copy the last chunk (possibly partial) into a zero-padded buffer,
     * then iterate:
     *   h0 = last_chunk
     *   for i in 1 .. length_lambda-1:
     *     h0 += running_s * chunk[length_lambda-1-i]
     *     running_s *= s
     * ------------------------------------------------------------------ */
    uint8_t last_chunk[32];
    memset(last_chunk, 0, nb);
    {
        /* Number of meaningful bytes in the last chunk:
         * (ell + lambda) mod lambda == 0 → full chunk, else partial */
        unsigned int partial = (unsigned int)((ell + lambda) % lambda);
        unsigned int last_bytes = (partial == 0u) ? nb : (partial / 8u);
        memcpy(last_chunk, x + (size_t)(length_lambda - 1u) * nb, last_bytes);
    }

    uint8_t h0[32], running_s[32], tmp1[32], tmp2[32];
    memcpy(h0, last_chunk, nb);
    memcpy(running_s, s, nb);

    for (unsigned int i = 1u; i < length_lambda; i++) {
        const uint8_t *chunk = x + (size_t)(length_lambda - 1u - i) * nb;
        gf_mul(tmp1, running_s, chunk, lambda);
        for (unsigned int k = 0; k < nb; k++)
            h0[k] ^= tmp1[k];
        gf_mul(tmp2, running_s, s, lambda);
        memcpy(running_s, tmp2, nb);
    }

    /* ------------------------------------------------------------------
     * h1: Horner eval in GF(2^64) of 64-bit words in reverse order.
     *
     * Process the last lambda-bit chunk (in last_chunk) from its high
     * 8-byte word to its low 8-byte word, then continue backwards through
     * the remaining chunks in x.
     * ------------------------------------------------------------------ */
    voleith_gf64_t h1 = 0;
    voleith_gf64_t running_t = 1;
    voleith_gf64_t b_t;
    memcpy(&b_t, t, 8);

    unsigned int i = 0;
    /* First: process last chunk (nb bytes) from highest to lowest 8-byte word */
    for (; i < nb; i += 8) {
        voleith_gf64_t word;
        memcpy(&word, last_chunk + (nb - i - 8), 8);
        h1 ^= voleith_gf64_mul(running_t, word);
        running_t = voleith_gf64_mul(running_t, b_t);
    }
    /* Then: continue backwards through the remaining words in x */
    for (; i < length_lambda * nb; i += 8) {
        voleith_gf64_t word;
        memcpy(&word, x + ((size_t)length_lambda * nb - i - 8), 8);
        h1 ^= voleith_gf64_mul(running_t, word);
        running_t = voleith_gf64_mul(running_t, b_t);
    }

    /* ------------------------------------------------------------------
     * h2 = r0*h0 + r1*(h1 zero-extended to lambda bits)
     * h3 = r2*h0 + r3*(h1 zero-extended to lambda bits)
     * ------------------------------------------------------------------ */
    uint8_t h2[32], h3[32];

    gf_mul(tmp1, r0, h0, lambda);
    gf_mul_64(tmp2, r1, h1, lambda);
    for (unsigned int k = 0; k < nb; k++)
        h2[k] = tmp1[k] ^ tmp2[k];

    gf_mul(tmp1, r2, h0, lambda);
    gf_mul_64(tmp2, r3, h1, lambda);
    for (unsigned int k = 0; k < nb; k++)
        h3[k] = tmp1[k] ^ tmp2[k];

    /* ------------------------------------------------------------------
     * Output = (h2 || h3[0..VOLEITH_VOLE_HASH_B-1]) XOR x1
     * ------------------------------------------------------------------ */
    for (unsigned int k = 0; k < nb; k++)
        h_out[k] = h2[k] ^ x1[k];
    for (unsigned int k = 0; k < VOLEITH_VOLE_HASH_B; k++)
        h_out[nb + k] = h3[k] ^ x1[nb + k];

    /*
     * P-13: zero every local that carried intermediate values of a
     * hash over secret data (`x` is either the prover's `u` or a
     * V-matrix row).  Especially: last_chunk holds the tail bits of
     * x; h0 / h1 / h2 / h3 are the Horner accumulators; running_s /
     * running_t are the Horner-key powers; tmp1/2 are field-mul
     * intermediates; b_t is the GF(2^64) Horner key.
     */
    voleith_secure_zero(last_chunk, sizeof(last_chunk));
    voleith_secure_zero(h0, sizeof(h0));
    voleith_secure_zero(running_s, sizeof(running_s));
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(h2, sizeof(h2));
    voleith_secure_zero(h3, sizeof(h3));
    voleith_secure_zero(&h1, sizeof(h1));
    voleith_secure_zero(&running_t, sizeof(running_t));
    voleith_secure_zero(&b_t, sizeof(b_t));
}
