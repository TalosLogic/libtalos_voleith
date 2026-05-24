/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * verifier.c - QuickSilver verifier (FAEST spec Section 6)
 *
 * Reconstructs a0_tilde from the verifier's VOLE Q matrix, the VOLE
 * correction d, the challenge delta, and the prover's a1_tilde, a2_tilde.
 *
 * Key[w] computation:
 *   For wire w with VOLE slot s:
 *     key[w] = col_s_of_Q + delta * d[s]
 *   For XOR gate (a, b → out):
 *     key[out] = key[a] + key[b]
 *   For NOT gate (a → out):
 *     key[out] = key[a] + delta   (since const-1 has key = delta)
 *   For INSTANCE wire with bit v:
 *     key[w] = delta * v
 *   For CONST wire with bit v:
 *     key[w] = delta * v
 *
 * Final check (verifier reconstructs a0_tilde):
 *   a0_tilde_out = q_tilde + delta*a1_tilde + delta^2*a2_tilde
 */

#include "verifier.h"
#include "circuit.h"
#include "../core/field.h"
#include "../core/util.h"

#include <stdlib.h>
#include <string.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal helpers (same as prover.c, duplicated for self-containment)
 * ===================================================================== */

/*
 * Transpose the VOLE matrix from row-major (lambda rows × row_bytes each)
 * to a flat column-major bit format: Q_T[col * nb .. col * nb + nb - 1]
 * holds the nb-byte packed representation of column col, where bit j is
 * stored at bit position j of Q_T (i.e., byte j/8, bit j%8).
 *
 * Only the first n_cols columns are transposed (callers pass ell + 2*lambda).
 * Returns a calloc'd buffer of n_cols * nb bytes, or NULL on OOM.
 */
static uint8_t *
transpose_matrix_v(const uint8_t **V, unsigned int lambda, unsigned int nb,
                   size_t n_cols)
{
    uint8_t *Q_T = calloc(n_cols * nb, 1);
    if (!Q_T)
        return NULL;
    size_t row_bytes = (n_cols + 7) / 8;
    for (unsigned int j = 0; j < lambda; j++) {
        for (size_t byte_idx = 0; byte_idx < row_bytes; byte_idx++) {
            uint8_t byte = V[j][byte_idx];
            for (int b = 0; b < 8; b++) {
                size_t col = byte_idx * 8 + (size_t)b;
                if (col >= n_cols)
                    break;
                if ((byte >> b) & 1u)
                    Q_T[col * nb + j / 8] |= (uint8_t)(1u << (j % 8));
            }
        }
    }
    return Q_T;
}

static inline unsigned int
get_bit_v(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

static void
gf_mul_alpha_v(uint8_t *out, const uint8_t *in, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    uint8_t carry = (in[nb - 1] >> 7) & 1u;
    for (unsigned int i = nb - 1; i > 0; i--)
        out[i] = (uint8_t)((in[i] << 1) | (in[i - 1] >> 7));
    out[0] = (uint8_t)(in[0] << 1);
    if (carry) {
        if (lambda == 128 || lambda == 192) {
            out[0] ^= 0x87u;
        } else {
            out[0] ^= 0x25u;
            out[1] ^= 0x04u;
        }
    }
}

static void
sum_poly_cols_v(uint8_t *out, uint8_t *tmp, const uint8_t *Q_T,
                unsigned int lambda, unsigned int nb, size_t start_col,
                unsigned int count)
{
    memcpy(out, Q_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf_mul_alpha_v(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, Q_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

static void
gf_mul_v(uint8_t *out, const uint8_t *a, const uint8_t *b, unsigned int lambda)
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
 * zk_hash context (verifier side): single Horner accumulator
 * ===================================================================== */

typedef struct {
    uint8_t h0[32]; /* GF(2^lambda) accumulator */
    uint8_t h1[32]; /* GF(2^lambda) accumulator (using t key) */
    uint8_t s[32];  /* GF(2^lambda) Horner key */
    uint8_t t[32];  /* GF(2^64) key, zero-padded to lambda_bytes */
    unsigned int lambda;
} zk_hash_ctx;

static void
zk_hash_init(zk_hash_ctx *ctx, const uint8_t *chall_2, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    memset(ctx->h0, 0, nb);
    memset(ctx->h1, 0, nb);
    memcpy(ctx->s, chall_2 + 2 * nb, nb);
    memset(ctx->t, 0, nb);
    unsigned int t_bytes = (nb < 8) ? nb : 8;
    memcpy(ctx->t, chall_2 + 3 * nb, t_bytes);
}

static void
zk_hash_update(zk_hash_ctx *ctx, const uint8_t *v, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    /* h0 = h0*s + v */
    gf_mul_v(tmp1, ctx->h0, ctx->s, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h0[k] = tmp1[k] ^ v[k];
    /* h1 = h1*t + v */
    gf_mul_v(tmp2, ctx->h1, ctx->t, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h1[k] = tmp2[k] ^ v[k];
}

static void
zk_hash_finalize(uint8_t *q_tilde, const zk_hash_ctx *ctx,
                 const uint8_t *q_star, const uint8_t *chall_2, uint8_t *tmp1,
                 uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    gf_mul_v(tmp1, r0, ctx->h0, ctx->lambda);
    gf_mul_v(tmp2, r1, ctx->h1, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        q_tilde[k] = tmp1[k] ^ tmp2[k] ^ q_star[k];
}

/* =====================================================================
 * Main verifier
 * ===================================================================== */

int
voleith_qs_verify(const voleith_circuit_t *circuit, const uint8_t *instance,
                  unsigned int lambda, const uint8_t **Q, const uint8_t *d,
                  const uint8_t *delta, const uint8_t *chall_2,
                  const uint8_t *a1_tilde, const uint8_t *a2_tilde,
                  uint8_t *a0_tilde_out)
{
    if (!circuit || !instance || !Q || !d || !delta || !chall_2 || !a1_tilde ||
        !a2_tilde || !a0_tilde_out)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    unsigned int nb = lambda / 8;
    size_t n_wires = voleith_circuit_wire_count(circuit);
    size_t n_witness = voleith_circuit_witness_count(circuit);
    size_t n_and = voleith_circuit_and_gate_count(circuit);
    size_t ell = n_witness + n_and;

    const wire_entry_t *wires = voleith_circuit_wires(circuit);
    const constraint_entry_t *constraints =
        voleith_circuit_constraints(circuit);
    size_t n_constraints = voleith_circuit_constraint_count(circuit);

    /* Allocate per-wire keys */
    uint8_t *keys = NULL;
    uint8_t *Q_T = NULL;

    keys = calloc(n_wires * nb, 1);
    if (!keys)
        goto oom;

    /* Transpose Q to column-major so each column is a contiguous nb-byte block */
    size_t qt_cols = ell + 2 * (size_t)lambda;
    Q_T = transpose_matrix_v(Q, lambda, nb, qt_cols);
    if (!Q_T)
        goto oom;

    /* Working buffers - fixed max size (lambda/8 ≤ 32 bytes for all parameter sets) */
    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};

    /* ------------------------------------------------------------------
     * Step 1: Compute key[w] for each wire.
     * Process in topological order.
     * ------------------------------------------------------------------ */
    {
        size_t witness_idx = 0;
        size_t instance_idx = 0;
        size_t and_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            uint8_t *key_w = keys + w * nb;
            const wire_entry_t *e = &wires[w];

            switch (e->kind) {
            case WIRE_KIND_WITNESS: {
                /* key[w] = col_{witness_idx}_of_Q + delta * d[witness_idx] */
                memcpy(key_w, Q_T + witness_idx * nb, nb);
                if (get_bit_v(d, witness_idx)) {
                    /* XOR delta into key[w] */
                    for (unsigned int k = 0; k < nb; k++)
                        key_w[k] ^= delta[k];
                }
                witness_idx++;
                break;
            }
            case WIRE_KIND_INSTANCE: {
                /* key[w] = delta * v  (v is the public instance bit) */
                unsigned int v = get_bit_v(instance, instance_idx++);
                if (v)
                    memcpy(key_w, delta, nb);
                else
                    memset(key_w, 0, nb);
                break;
            }
            case WIRE_KIND_CONST: {
                /* key[w] = delta * v */
                if (e->const_bit)
                    memcpy(key_w, delta, nb);
                else
                    memset(key_w, 0, nb);
                break;
            }
            case WIRE_KIND_XOR: {
                /* key[out] = key[a] + key[b] */
                const uint8_t *ka = keys + e->a * nb;
                const uint8_t *kb = keys + e->b * nb;
                for (unsigned int k = 0; k < nb; k++)
                    key_w[k] = ka[k] ^ kb[k];
                break;
            }
            case WIRE_KIND_AND: {
                /* key[out] = col_{n_witness+and_idx}_of_Q + delta * d[...] */
                size_t slot = n_witness + and_idx;
                memcpy(key_w, Q_T + slot * nb, nb);
                if (get_bit_v(d, slot)) {
                    for (unsigned int k = 0; k < nb; k++)
                        key_w[k] ^= delta[k];
                }
                and_idx++;
                break;
            }
            case WIRE_KIND_NOT: {
                /* key[out] = key[a] + delta */
                const uint8_t *ka = keys + e->a * nb;
                for (unsigned int k = 0; k < nb; k++)
                    key_w[k] = ka[k] ^ delta[k];
                break;
            }
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 2: Accumulate AND gate checks into zk_hash.
     *
     * For AND gate (a AND b = c):
     *   contribute key[a]*key[b] + key[c]
     * ------------------------------------------------------------------ */
    zk_hash_ctx bctx;
    zk_hash_init(&bctx, chall_2, lambda);

    {
        uint8_t prod[32], contrib[32];

        for (size_t w = 0; w < n_wires; w++) {
            const wire_entry_t *e = &wires[w];
            if (e->kind != WIRE_KIND_AND)
                continue;

            const uint8_t *ka = keys + e->a * nb;
            const uint8_t *kb = keys + e->b * nb;
            const uint8_t *kc = keys + w * nb;

            /* contrib = key[a]*key[b] + key[c] */
            gf_mul_v(prod, ka, kb, lambda);
            for (unsigned int k = 0; k < nb; k++)
                contrib[k] = prod[k] ^ kc[k];

            zk_hash_update(&bctx, contrib, tmp1, tmp2);
        }
    }

    /* ------------------------------------------------------------------
     * Step 3: Accumulate assert_zero constraints.
     * ------------------------------------------------------------------ */
    for (size_t ci = 0; ci < n_constraints; ci++) {
        const constraint_entry_t *c = &constraints[ci];
        if (c->kind == CONSTRAINT_ZERO) {
            zk_hash_update(&bctx, keys + c->a * nb, tmp1, tmp2);
        }
    }

    /* ------------------------------------------------------------------
     * Step 4: Compute q_star correction from Q bits beyond ell.
     *
     * q_star_0 = sum_poly(Q cols ell..ell+lambda-1)
     * q_star_1 = sum_poly(Q cols ell+lambda..ell+2*lambda-1)
     * q_star = q_star_0 + delta * q_star_1
     * ------------------------------------------------------------------ */
    uint8_t q_star[32];
    {
        uint8_t q_star_0[32], q_star_1[32], delta_q_star_1[32];

        sum_poly_cols_v(q_star_0, tmp1, Q_T, lambda, nb, ell, lambda);
        sum_poly_cols_v(q_star_1, tmp1, Q_T, lambda, nb, ell + lambda, lambda);

        /* delta * q_star_1 */
        gf_mul_v(delta_q_star_1, delta, q_star_1, lambda);

        for (unsigned int k = 0; k < nb; k++)
            q_star[k] = q_star_0[k] ^ delta_q_star_1[k];
    }

    /* ------------------------------------------------------------------
     * Step 5: Finalize zk_hash to get q_tilde.
     * ------------------------------------------------------------------ */
    uint8_t q_tilde[32];
    zk_hash_finalize(q_tilde, &bctx, q_star, chall_2, tmp1, tmp2);
    voleith_secure_zero(&bctx, sizeof(bctx));

    /* ------------------------------------------------------------------
     * Step 6: a0_tilde_out = q_tilde + delta*a1_tilde + delta^2*a2_tilde
     * ------------------------------------------------------------------ */
    {
        uint8_t delta_sq[32], term1[32], term2[32];

        /* delta^2 */
        gf_mul_v(delta_sq, delta, delta, lambda);

        /* delta * a1_tilde */
        gf_mul_v(term1, delta, a1_tilde, lambda);

        /* delta^2 * a2_tilde */
        gf_mul_v(term2, delta_sq, a2_tilde, lambda);

        for (unsigned int k = 0; k < nb; k++)
            a0_tilde_out[k] = q_tilde[k] ^ term1[k] ^ term2[k];
    }

    free(Q_T);
    free(keys);
    return 0;

oom:
    free(Q_T);
    free(keys);
    return -1;
}
