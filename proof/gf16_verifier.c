/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_verifier.c - Element-level (GF(2^16)) QuickSilver verifier
 *
 * The GF(2^16) counterpart to gf8_verifier.c.  Uses per-wire 16-bit-key
 * arrays, propagates keys through GF(2)-linear gates, and accumulates the
 * verifier's contribution per MUL gate / constraint via a single Horner hash.
 *
 * Verifier key per wire (16 GF(2^lambda) bit-keys):
 *   WITNESS slot s:  bit_keys[w][i] = Q_T[(s*16+i)] + Delta * ((d[s]>>i)&1)
 *   MUL slot s:      same
 *   INSTANCE elem v: bit_keys[w][i] = ((v>>i)&1) * Delta
 *   CONST elem v:    same
 *   XOR(a,b):        bit_keys[out][i] = bit_keys[a][i] XOR bit_keys[b][i]
 *   XOR_CONST(a,k):  bit_keys[out][i] = bit_keys[a][i] XOR ((k>>i)&1)*Delta
 *   LINEAR_MAP/SQUARE: propagated as a 16x16 GF(2) map on the bit-keys
 *
 * The GF(2^lambda) ZKHash / correction machinery matches gf8_verifier.c
 * verbatim; only the small-field width (16 vs 8) and the combine generator
 * differ.
 */

#include "gf16_verifier.h"
#include "gf16_circuit.h"
#include "../core/field.h"
#include "../core/field16.h"
#include "../core/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u
#define GF16_ELEM_BITS 16u

/* =====================================================================
 * Internal helpers (field-agnostic; mirror gf8_verifier.c)
 * ===================================================================== */

static uint8_t *
gf16v_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                       size_t n_cols)
{
    uint8_t *Q_T = calloc(n_cols, nb);
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

static void
gf16v_gf_mul_alpha(uint8_t *out, const uint8_t *in, unsigned int lambda)
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
gf16v_sum_poly_cols(uint8_t *out, uint8_t *tmp, const uint8_t *Q_T,
                    unsigned int lambda, unsigned int nb, size_t start_col,
                    unsigned int count)
{
    memcpy(out, Q_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf16v_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, Q_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

static void
gf16v_gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b,
             unsigned int lambda)
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

/* Read a 16-bit element at slot s of a little-endian byte buffer. */
static inline uint16_t
gf16v_read_elem(const uint8_t *buf, size_t slot)
{
    return (uint16_t)(buf[2 * slot] | ((uint16_t)buf[2 * slot + 1] << 8));
}

/* Compute out = Sum_i tabs[i] * beta^i in GF(2^lambda) via Horner. */
static void
gf16v_word_combine(uint8_t *out, const uint8_t *tabs, unsigned int nb,
                   unsigned int lambda, const uint8_t *beta)
{
    uint8_t tmp[32];
    memcpy(out, tabs + 15 * nb, nb);
    for (int i = 14; i >= 0; i--) {
        gf16v_gf_mul(tmp, out, beta, lambda);
        for (unsigned int k = 0; k < nb; k++)
            out[k] = tmp[k] ^ tabs[(size_t)i * nb + k];
    }
}

/* Apply a 16x16 GF(2) matrix M to 16 GF(2^lambda) bit-key elements. */
static void
gf16v_apply_linear_map(uint8_t *out_keys, const uint8_t *in_keys,
                       const uint16_t M[16], unsigned int nb)
{
    memset(out_keys, 0, GF16_ELEM_BITS * nb);
    for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
        uint16_t row = M[i];
        for (unsigned int j = 0; j < GF16_ELEM_BITS; j++) {
            if ((row >> j) & 1u) {
                for (unsigned int k = 0; k < nb; k++)
                    out_keys[i * nb + k] ^= in_keys[j * nb + k];
            }
        }
    }
}

/* =====================================================================
 * zk_hash context (single Horner accumulator; field-agnostic)
 * ===================================================================== */

typedef struct {
    uint8_t h0[32];
    uint8_t h1[32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
} gf16v_zk_hash_ctx;

static void
gf16v_zk_hash_init(gf16v_zk_hash_ctx *ctx, const uint8_t *chall_2,
                   unsigned int lambda)
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
gf16v_zk_hash_update(gf16v_zk_hash_ctx *ctx, const uint8_t *v, uint8_t *tmp1,
                     uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    gf16v_gf_mul(tmp1, ctx->h0, ctx->s, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h0[k] = tmp1[k] ^ v[k];
    gf16v_gf_mul(tmp2, ctx->h1, ctx->t, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h1[k] = tmp2[k] ^ v[k];
}

static void
gf16v_zk_hash_finalize(uint8_t *q_tilde, const gf16v_zk_hash_ctx *ctx,
                       const uint8_t *q_star, const uint8_t *chall_2,
                       uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    gf16v_gf_mul(tmp1, r0, ctx->h0, ctx->lambda);
    gf16v_gf_mul(tmp2, r1, ctx->h1, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        q_tilde[k] = tmp1[k] ^ tmp2[k] ^ q_star[k];
}

/* =====================================================================
 * Main verifier
 * ===================================================================== */

int
voleith_gf16_qs_verify(const voleith_gf16_circuit_t *circuit,
                       const voleith_gf16_t *instance, unsigned int lambda,
                       const uint8_t **Q, const uint8_t *d,
                       const uint8_t *delta, const uint8_t *chall_2,
                       const uint8_t *a1_tilde, const uint8_t *a2_tilde,
                       uint8_t *a0_tilde_out)
{
    if (!circuit || !Q || !d || !delta || !chall_2 || !a1_tilde || !a2_tilde ||
        !a0_tilde_out)
        return -1;
    if (voleith_gf16_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    unsigned int nb = lambda / 8;
    size_t n_wires = voleith_gf16_circuit_wire_count(circuit);
    size_t n_witness = voleith_gf16_circuit_witness_count(circuit);
    size_t n_mul = voleith_gf16_circuit_mul_count(circuit);
    size_t ell = n_witness + n_mul;
    size_t n_constraints = voleith_gf16_circuit_constraint_count(circuit);

    const gf16_wire_entry_t *wires = voleith_gf16_circuit_wires(circuit);
    const gf16_constraint_entry_t *constraints =
        voleith_gf16_circuit_constraints(circuit);

    uint8_t *bit_keys = NULL; /* n_wires * 16 * nb bytes */
    uint8_t *Q_T = NULL;

    uint16_t sq_matrix[16];
    voleith_gf16_square_matrix(sq_matrix);

    /*
     * Validate wire / constraint references and the allocation arithmetic
     * before touching the heap: this primitive must stay memory-safe on its
     * own when handed a malformed circuit directly.
     */
    for (size_t w = 0; w < n_wires; w++) {
        const gf16_wire_entry_t *e = &wires[w];
        switch (e->kind) {
        case GF16_WIRE_XOR:
        case GF16_WIRE_MUL:
            if (e->a >= n_wires || e->b >= n_wires)
                return -1;
            break;
        case GF16_WIRE_XOR_CONST:
        case GF16_WIRE_LINEAR_MAP:
        case GF16_WIRE_SQUARE:
            if (e->a >= n_wires)
                return -1;
            break;
        default:
            break;
        }
    }
    for (size_t ci = 0; ci < n_constraints; ci++) {
        const gf16_constraint_entry_t *c = &constraints[ci];
        switch (c->kind) {
        case GF16_CONSTRAINT_PRODUCT:
            if (c->a >= n_wires || c->b >= n_wires || c->c >= n_wires)
                return -1;
            break;
        case GF16_CONSTRAINT_EQUAL:
            if (c->a >= n_wires || c->b >= n_wires)
                return -1;
            break;
        case GF16_CONSTRAINT_ZERO:
            if (c->a >= n_wires)
                return -1;
            break;
        }
    }

    /* ell * 16 must not wrap before it feeds the Q_T column count. */
    if (ell > (SIZE_MAX - 2u * (size_t)lambda) / GF16_ELEM_BITS)
        return -1;
    size_t n_bit_cols = ell * GF16_ELEM_BITS + 2u * (size_t)lambda;

    bit_keys = calloc(n_wires, (size_t)GF16_ELEM_BITS * nb);
    if (!bit_keys)
        goto oom;

    Q_T = gf16v_transpose_matrix(Q, lambda, nb, n_bit_cols);
    if (!Q_T)
        goto oom;

    uint8_t beta[32] = {0};
    voleith_gf16_embed(beta, 0x0002, (int)lambda);

    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};

    /* Step 1: compute bit_keys[w][i] for each wire w, bit i. */
    {
        size_t witness_idx = 0;
        size_t instance_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf16_wire_entry_t *e = &wires[w];
            uint8_t *bk_w = bit_keys + w * GF16_ELEM_BITS * nb;

            switch (e->kind) {
            case GF16_WIRE_WITNESS: {
                size_t slot = witness_idx++;
                uint16_t d_elem = gf16v_read_elem(d, slot);
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
                    memcpy(bk_w + i * nb,
                           Q_T + (slot * GF16_ELEM_BITS + i) * nb, nb);
                    if ((d_elem >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF16_WIRE_MUL: {
                size_t slot = n_witness + mul_idx++;
                uint16_t d_elem = gf16v_read_elem(d, slot);
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
                    memcpy(bk_w + i * nb,
                           Q_T + (slot * GF16_ELEM_BITS + i) * nb, nb);
                    if ((d_elem >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF16_WIRE_INSTANCE: {
                uint16_t v = instance[instance_idx++];
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
                    if ((v >> i) & 1u)
                        memcpy(bk_w + i * nb, delta, nb);
                    else
                        memset(bk_w + i * nb, 0, nb);
                }
                break;
            }
            case GF16_WIRE_CONST: {
                uint16_t v = e->const_val;
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
                    if ((v >> i) & 1u)
                        memcpy(bk_w + i * nb, delta, nb);
                    else
                        memset(bk_w + i * nb, 0, nb);
                }
                break;
            }
            case GF16_WIRE_XOR: {
                const uint8_t *bk_a = bit_keys + e->a * GF16_ELEM_BITS * nb;
                const uint8_t *bk_b = bit_keys + e->b * GF16_ELEM_BITS * nb;
                for (unsigned int i = 0; i < GF16_ELEM_BITS * nb; i++)
                    bk_w[i] = bk_a[i] ^ bk_b[i];
                break;
            }
            case GF16_WIRE_XOR_CONST: {
                uint16_t kval = e->const_val;
                const uint8_t *bk_a = bit_keys + e->a * GF16_ELEM_BITS * nb;
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
                    memcpy(bk_w + i * nb, bk_a + i * nb, nb);
                    if ((kval >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF16_WIRE_LINEAR_MAP:
                gf16v_apply_linear_map(
                    bk_w, bit_keys + e->a * GF16_ELEM_BITS * nb, e->matrix, nb);
                break;

            case GF16_WIRE_SQUARE:
                gf16v_apply_linear_map(
                    bk_w, bit_keys + e->a * GF16_ELEM_BITS * nb, sq_matrix, nb);
                break;
            }
        }
    }

    /* Step 2: accumulate gate checks into zk_hash. */
    gf16v_zk_hash_ctx bctx;
    gf16v_zk_hash_init(&bctx, chall_2, lambda);

    {
        uint8_t key_a[32], key_b[32], key_c[32];
        uint8_t prod[32], contrib[32];

        for (size_t w = 0; w < n_wires; w++) {
            const gf16_wire_entry_t *e = &wires[w];
            if (e->kind != GF16_WIRE_MUL)
                continue;

            gf16v_word_combine(key_a, bit_keys + e->a * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16v_word_combine(key_b, bit_keys + e->b * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16v_word_combine(key_c, bit_keys + w * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);

            gf16v_gf_mul(prod, key_a, key_b, lambda);
            for (unsigned int k = 0; k < nb; k++)
                contrib[k] = prod[k] ^ key_c[k];
            gf16v_zk_hash_update(&bctx, contrib, tmp1, tmp2);
        }

        for (size_t ci = 0; ci < n_constraints; ci++) {
            const gf16_constraint_entry_t *c = &constraints[ci];

            switch (c->kind) {
            case GF16_CONSTRAINT_PRODUCT: {
                gf16v_word_combine(key_a, bit_keys + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16v_word_combine(key_b, bit_keys + c->b * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16v_word_combine(key_c, bit_keys + c->c * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16v_gf_mul(prod, key_a, key_b, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    contrib[k] = prod[k] ^ key_c[k];
                gf16v_zk_hash_update(&bctx, contrib, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_ZERO: {
                gf16v_word_combine(key_a, bit_keys + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16v_zk_hash_update(&bctx, key_a, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_EQUAL: {
                gf16v_word_combine(key_a, bit_keys + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16v_word_combine(key_b, bit_keys + c->b * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                for (unsigned int k = 0; k < nb; k++)
                    key_a[k] ^= key_b[k];
                gf16v_zk_hash_update(&bctx, key_a, tmp1, tmp2);
                break;
            }
            }
        }
    }

    /* Step 3: q_star correction from Q bits beyond ell*16. */
    uint8_t q_star[32];
    {
        uint8_t q_star_0[32], q_star_1[32], delta_q1[32];
        size_t corr_start = ell * GF16_ELEM_BITS;
        gf16v_sum_poly_cols(q_star_0, tmp1, Q_T, lambda, nb, corr_start,
                            lambda);
        gf16v_sum_poly_cols(q_star_1, tmp1, Q_T, lambda, nb,
                            corr_start + lambda, lambda);
        gf16v_gf_mul(delta_q1, delta, q_star_1, lambda);
        for (unsigned int k = 0; k < nb; k++)
            q_star[k] = q_star_0[k] ^ delta_q1[k];
    }

    /* Step 4: finalize zk_hash to get q_tilde. */
    uint8_t q_tilde[32];
    gf16v_zk_hash_finalize(q_tilde, &bctx, q_star, chall_2, tmp1, tmp2);
    voleith_secure_zero(&bctx, sizeof(bctx));

    /* Step 5: a0_tilde_out = q_tilde + Delta*a1_tilde + Delta^2*a2_tilde. */
    {
        uint8_t delta_sq[32], term1[32], term2[32];
        gf16v_gf_mul(delta_sq, delta, delta, lambda);
        gf16v_gf_mul(term1, delta, a1_tilde, lambda);
        gf16v_gf_mul(term2, delta_sq, a2_tilde, lambda);
        for (unsigned int k = 0; k < nb; k++)
            a0_tilde_out[k] = q_tilde[k] ^ term1[k] ^ term2[k];
    }

    free(Q_T);
    free(bit_keys);
    return 0;

oom:
    free(Q_T);
    free(bit_keys);
    return -1;
}
