/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_prover.c - Element-level (GF(2^16)) QuickSilver prover
 *
 * The GF(2^16) counterpart to gf8_prover.c: one VOLE slot per witness
 * element and per MUL gate, with each element spanning 16 VOLE bit-columns.
 *   ell = witness_count + mul_gate_count       (in GF(2^16) elements)
 *   ellhat_bytes = 2*ell + ceil((3*lambda + 16) / 8)
 *
 * Tag tracking (per wire, 16 GF(2^lambda) bit-tags, one per bit of the
 * element value):
 *   WITNESS slot s:    bit_tag[w][i] = V_T column s*16+i
 *   MUL slot s:        bit_tag[w][i] = V_T column s*16+i
 *   XOR:               bit_tag[out][i] = bit_tag[a][i] XOR bit_tag[b][i]
 *   XOR_CONST(k):      bit_tag[out][i] = bit_tag[a][i]   (const has zero tag)
 *   LINEAR_MAP(M):     bit_tag[out][i] = XOR_{j: M[i][j]=1} bit_tag[a][j]
 *   SQUARE:            LINEAR_MAP with the GF(2^16) squaring matrix
 *   INSTANCE/CONST:    bit_tag[w][i] = 0
 *
 * Element tag: tag[w] = Sum_i bit_tag[w][i] * beta^i  in GF(2^lambda), where
 * beta = embed(x) is the alpha16 generator (gf16 analogue of alpha_8).
 *
 * Multiplication check per MUL gate (inputs a, b; output c):
 *   v0 = tag[a]*tag[b] + tag[c]
 *   v1 = tag[a]*embed(val_b) + tag[b]*embed(val_a) + embed(val_c)
 *   v2 = embed(gf16_mul(val_a, val_b))
 * assert_product contributes the same (v0, v1, v2) form on committed values.
 *
 * The GF(2^lambda) ZKHash / correction machinery is field-agnostic and
 * matches gf8_prover.c verbatim; only the small-field width (16 vs 8) and the
 * embed / combine generator differ.
 */

#include "gf16_prover.h"
#include "gf16_prover_internal.h"
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
 * Internal GF(2^lambda) helpers (field-agnostic; mirror gf8_prover.c)
 * ===================================================================== */

static uint8_t *
gf16p_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                       size_t n_cols)
{
    uint8_t *V_T = calloc(n_cols, nb);
    if (!V_T)
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
                    V_T[col * nb + j / 8] |= (uint8_t)(1u << (j % 8));
            }
        }
    }
    return V_T;
}

static inline unsigned int
gf16p_get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

static void
gf16p_gf_mul_alpha(uint8_t *out, const uint8_t *in, unsigned int lambda)
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
gf16p_sum_poly_cols(uint8_t *out, uint8_t *tmp, const uint8_t *V_T,
                    unsigned int lambda, unsigned int nb, size_t start_col,
                    unsigned int count)
{
    memcpy(out, V_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf16p_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, V_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

static void
gf16p_sum_poly_bits_at(uint8_t *out, uint8_t *tmp, const uint8_t *buf,
                       size_t start_bit, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    uint8_t b = (uint8_t)gf16p_get_bit(buf, start_bit + lambda - 1);
    memset(out, 0, nb);
    out[0] = b;
    for (int i = (int)lambda - 2; i >= 0; i--) {
        gf16p_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        b = (uint8_t)gf16p_get_bit(buf, start_bit + (size_t)i);
        out[0] ^= b;
    }
}

static void
gf16p_gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b,
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

/* =====================================================================
 * GF(2^16)-specific helpers
 * ===================================================================== */

/* Read / write a 16-bit element at slot s of a little-endian byte buffer. */
static inline uint16_t
gf16p_read_elem(const uint8_t *buf, size_t slot)
{
    return (uint16_t)(buf[2 * slot] | ((uint16_t)buf[2 * slot + 1] << 8));
}

static inline void
gf16p_write_elem(uint8_t *buf, size_t slot, uint16_t v)
{
    buf[2 * slot] = (uint8_t)(v & 0xff);
    buf[2 * slot + 1] = (uint8_t)(v >> 8);
}

/*
 * Compute tag = Sum_i tabs[i] * beta^i in GF(2^lambda) via Horner's rule.
 * tabs: 16 contiguous GF(2^lambda) elements (16 * nb bytes).  beta: the
 * GF(2^lambda) element beta (the alpha16 generator, precomputed by caller).
 */
static void
gf16p_word_combine(uint8_t *out, const uint8_t *tabs, unsigned int nb,
                   unsigned int lambda, const uint8_t *beta)
{
    uint8_t tmp[32];
    memcpy(out, tabs + 15 * nb, nb);
    for (int i = 14; i >= 0; i--) {
        gf16p_gf_mul(tmp, out, beta, lambda);
        for (unsigned int k = 0; k < nb; k++)
            out[k] = tmp[k] ^ tabs[(size_t)i * nb + k];
    }
}

/* Embed a GF(2^16) element into GF(2^lambda): embed(val) = Sum_i val_i*beta^i. */
static void
gf16p_embed(uint8_t *out, uint16_t val, unsigned int lambda)
{
    voleith_gf16_embed(out, val, (int)lambda);
}

/*
 * Apply a 16x16 GF(2) matrix M to 16 GF(2^lambda) bit-tag elements.
 * Output bit i = XOR of input bit j for each j where (M[i]>>j)&1.
 */
static void
gf16p_apply_linear_map(uint8_t *out_tabs, const uint8_t *in_tabs,
                       const uint16_t M[16], unsigned int nb)
{
    memset(out_tabs, 0, GF16_ELEM_BITS * nb);
    for (unsigned int i = 0; i < GF16_ELEM_BITS; i++) {
        uint16_t row = M[i];
        for (unsigned int j = 0; j < GF16_ELEM_BITS; j++) {
            if ((row >> j) & 1u) {
                for (unsigned int k = 0; k < nb; k++)
                    out_tabs[i * nb + k] ^= in_tabs[j * nb + k];
            }
        }
    }
}

/* =====================================================================
 * zk_hash_3 context (three accumulators; field-agnostic, mirror gf8)
 * ===================================================================== */

typedef struct {
    uint8_t h0[3][32];
    uint8_t h1[3][32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
} gf16p_zk_hash_3_ctx;

static void
gf16p_zk_hash_3_init(gf16p_zk_hash_3_ctx *ctx, const uint8_t *chall_2,
                     unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    memset(ctx->h0, 0, sizeof(ctx->h0));
    memset(ctx->h1, 0, sizeof(ctx->h1));
    memcpy(ctx->s, chall_2 + 2 * nb, nb);
    memset(ctx->t, 0, nb);
    unsigned int t_bytes = (nb < 8) ? nb : 8;
    memcpy(ctx->t, chall_2 + 3 * nb, t_bytes);
}

static void
gf16p_zk_hash_3_update(gf16p_zk_hash_3_ctx *ctx, const uint8_t *v0,
                       const uint8_t *v1, const uint8_t *v2, uint8_t *tmp1,
                       uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *vs[3] = {v0, v1, v2};
    for (int i = 0; i < 3; i++) {
        gf16p_gf_mul(tmp1, ctx->h0[i], ctx->s, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h0[i][k] = tmp1[k] ^ vs[i][k];
        gf16p_gf_mul(tmp2, ctx->h1[i], ctx->t, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h1[i][k] = tmp2[k] ^ vs[i][k];
    }
}

static void
gf16p_zk_hash_3_finalize(uint8_t *a0_tilde, uint8_t *a1_tilde,
                         uint8_t *a2_tilde, const gf16p_zk_hash_3_ctx *ctx,
                         const uint8_t *x1_0, const uint8_t *x1_1,
                         const uint8_t *x1_2, const uint8_t *chall_2,
                         uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    uint8_t *outputs[3] = {a0_tilde, a1_tilde, a2_tilde};
    const uint8_t *x1s[3] = {x1_0, x1_1, x1_2};
    for (int i = 0; i < 3; i++) {
        gf16p_gf_mul(tmp1, r0, ctx->h0[i], ctx->lambda);
        gf16p_gf_mul(tmp2, r1, ctx->h1[i], ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            outputs[i][k] = tmp1[k] ^ tmp2[k] ^ x1s[i][k];
    }
}

/* =====================================================================
 * Main prover
 * ===================================================================== */

size_t
voleith_gf16_qs_ellhat(const voleith_gf16_circuit_t *circuit,
                       unsigned int lambda)
{
    size_t ell = voleith_gf16_qs_ell(circuit);
    return 2u * ell + (3u * lambda + UNIVERSAL_HASH_B_BITS + 7u) / 8u;
}

static int
gf16_qs_prove_impl(const voleith_gf16_circuit_t *circuit,
                   const voleith_gf16_t *witness,
                   const voleith_gf16_t *instance, unsigned int lambda,
                   const uint8_t *u, const uint8_t **V, const uint8_t *chall_2,
                   uint8_t *d_out, uint8_t *a0_tilde, uint8_t *a1_tilde,
                   uint8_t *a2_tilde, int reject_invalid)
{
    if (!circuit || !witness || !u || !V || !chall_2 || !d_out || !a0_tilde ||
        !a1_tilde || !a2_tilde)
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

    voleith_gf16_t *wire_vals = NULL;
    uint8_t *bit_tags = NULL; /* n_wires * 16 * nb bytes */
    uint8_t *V_T = NULL;
    size_t n_bit_cols = ell * GF16_ELEM_BITS + 2 * (size_t)lambda;

    /* The squaring matrix used for SQUARE-gate tag propagation. */
    uint16_t sq_matrix[16];
    voleith_gf16_square_matrix(sq_matrix);

    wire_vals = calloc(n_wires, sizeof(voleith_gf16_t));
    if (!wire_vals)
        goto oom;

    bit_tags = calloc(n_wires, (size_t)GF16_ELEM_BITS * nb);
    if (!bit_tags)
        goto oom;

    V_T = gf16p_transpose_matrix(V, lambda, nb, n_bit_cols);
    if (!V_T)
        goto oom;

    /* Precompute beta as a GF(2^lambda) element: embed(0x0002) = beta^1. */
    uint8_t beta[32] = {0};
    voleith_gf16_embed(beta, 0x0002, (int)lambda);

    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};

    /* Step 1: evaluate the circuit. */
    {
        int ev =
            voleith_gf16_circuit_eval(circuit, witness, instance, wire_vals);
        if (ev < 0 || (reject_invalid && ev != 1))
            goto err;
    }

    /* Step 2: propagate bit-tags in topological order. */
    {
        size_t witness_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf16_wire_entry_t *e = &wires[w];
            uint8_t *bt_w = bit_tags + w * GF16_ELEM_BITS * nb;

            switch (e->kind) {
            case GF16_WIRE_WITNESS: {
                size_t slot = witness_idx++;
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++)
                    memcpy(bt_w + i * nb,
                           V_T + (slot * GF16_ELEM_BITS + i) * nb, nb);
                break;
            }
            case GF16_WIRE_INSTANCE:
            case GF16_WIRE_CONST:
                memset(bt_w, 0, GF16_ELEM_BITS * nb);
                break;

            case GF16_WIRE_XOR: {
                const uint8_t *bt_a = bit_tags + e->a * GF16_ELEM_BITS * nb;
                const uint8_t *bt_b = bit_tags + e->b * GF16_ELEM_BITS * nb;
                for (unsigned int i = 0; i < GF16_ELEM_BITS * nb; i++)
                    bt_w[i] = bt_a[i] ^ bt_b[i];
                break;
            }
            case GF16_WIRE_XOR_CONST:
                memcpy(bt_w, bit_tags + e->a * GF16_ELEM_BITS * nb,
                       GF16_ELEM_BITS * nb);
                break;

            case GF16_WIRE_LINEAR_MAP:
                gf16p_apply_linear_map(
                    bt_w, bit_tags + e->a * GF16_ELEM_BITS * nb, e->matrix, nb);
                break;

            case GF16_WIRE_SQUARE:
                gf16p_apply_linear_map(
                    bt_w, bit_tags + e->a * GF16_ELEM_BITS * nb, sq_matrix, nb);
                break;

            case GF16_WIRE_MUL: {
                size_t slot = n_witness + mul_idx++;
                for (unsigned int i = 0; i < GF16_ELEM_BITS; i++)
                    memcpy(bt_w + i * nb,
                           V_T + (slot * GF16_ELEM_BITS + i) * nb, nb);
                break;
            }
            }
        }
    }

    /* Step 3: d[s] = wire_vals[w] XOR u[s] (16-bit LE per slot). */
    {
        size_t witness_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf16_wire_entry_t *e = &wires[w];
            if (e->kind == GF16_WIRE_WITNESS) {
                size_t slot = witness_idx++;
                gf16p_write_elem(d_out, slot,
                                 wire_vals[w] ^ gf16p_read_elem(u, slot));
            } else if (e->kind == GF16_WIRE_MUL) {
                size_t slot = n_witness + mul_idx++;
                gf16p_write_elem(d_out, slot,
                                 wire_vals[w] ^ gf16p_read_elem(u, slot));
            }
        }
    }

    /* Step 4 + 5: accumulate MUL gate checks and constraints. */
    gf16p_zk_hash_3_ctx hasher;
    gf16p_zk_hash_3_init(&hasher, chall_2, lambda);

    {
        uint8_t tag_a[32], tag_b[32], tag_c[32];
        uint8_t emb_a[32], emb_b[32], emb_c[32];
        uint8_t v0[32], v1[32], v2[32];
        uint8_t prod[32], zero[32];
        memset(zero, 0, nb);

        for (size_t w = 0; w < n_wires; w++) {
            const gf16_wire_entry_t *e = &wires[w];
            if (e->kind != GF16_WIRE_MUL)
                continue;

            gf16_wire_id wa = e->a, wb = e->b;
            uint16_t val_a = wire_vals[wa];
            uint16_t val_b = wire_vals[wb];
            uint16_t val_c = wire_vals[w];

            gf16p_word_combine(tag_a, bit_tags + wa * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16p_word_combine(tag_b, bit_tags + wb * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16p_word_combine(tag_c, bit_tags + w * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16p_embed(emb_a, val_a, lambda);
            gf16p_embed(emb_b, val_b, lambda);
            gf16p_embed(emb_c, val_c, lambda);

            /* v0 = tag_a*tag_b + tag_c */
            gf16p_gf_mul(prod, tag_a, tag_b, lambda);
            for (unsigned int k = 0; k < nb; k++)
                v0[k] = prod[k] ^ tag_c[k];

            /* v1 = tag_a*emb_b + tag_b*emb_a + emb_c */
            gf16p_gf_mul(v1, tag_a, emb_b, lambda);
            gf16p_gf_mul(prod, tag_b, emb_a, lambda);
            for (unsigned int k = 0; k < nb; k++)
                v1[k] ^= prod[k] ^ emb_c[k];

            /* v2 = embed(gf16_mul(val_a, val_b)) */
            gf16p_embed(v2, voleith_gf16_mul(val_a, val_b), lambda);

            gf16p_zk_hash_3_update(&hasher, v0, v1, v2, tmp1, tmp2);
        }

        for (size_t ci = 0; ci < n_constraints; ci++) {
            const gf16_constraint_entry_t *c = &constraints[ci];

            switch (c->kind) {
            case GF16_CONSTRAINT_PRODUCT: {
                uint16_t val_a = wire_vals[c->a];
                uint16_t val_b = wire_vals[c->b];
                uint16_t val_c = wire_vals[c->c];

                gf16p_word_combine(tag_a, bit_tags + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_word_combine(tag_b, bit_tags + c->b * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_word_combine(tag_c, bit_tags + c->c * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_embed(emb_a, val_a, lambda);
                gf16p_embed(emb_b, val_b, lambda);
                gf16p_embed(emb_c, val_c, lambda);

                gf16p_gf_mul(prod, tag_a, tag_b, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    v0[k] = prod[k] ^ tag_c[k];

                gf16p_gf_mul(v1, tag_a, emb_b, lambda);
                gf16p_gf_mul(prod, tag_b, emb_a, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    v1[k] ^= prod[k] ^ emb_c[k];

                /* v2 = embed(val_c): the CLAIMED product value, not
                 * embed(val_a*val_b).  For a correct constraint val_c =
                 * val_a*val_b so the verifier's delta^2 term matches; for a
                 * wrong one they differ and verification fails (soundness). */
                gf16p_embed(v2, val_c, lambda);

                gf16p_zk_hash_3_update(&hasher, v0, v1, v2, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_ZERO: {
                gf16p_word_combine(tag_a, bit_tags + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_zk_hash_3_update(&hasher, tag_a, zero, zero, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_EQUAL: {
                gf16p_word_combine(tag_a, bit_tags + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_word_combine(tag_b, bit_tags + c->b * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                for (unsigned int k = 0; k < nb; k++)
                    tag_a[k] ^= tag_b[k];
                gf16p_zk_hash_3_update(&hasher, tag_a, zero, zero, tmp1, tmp2);
                break;
            }
            }
        }

        /* Zero per-gate stack buffers (witness-derived material). */
        voleith_secure_zero(tag_a, sizeof(tag_a));
        voleith_secure_zero(tag_b, sizeof(tag_b));
        voleith_secure_zero(tag_c, sizeof(tag_c));
        voleith_secure_zero(emb_a, sizeof(emb_a));
        voleith_secure_zero(emb_b, sizeof(emb_b));
        voleith_secure_zero(emb_c, sizeof(emb_c));
        voleith_secure_zero(v0, sizeof(v0));
        voleith_secure_zero(v1, sizeof(v1));
        voleith_secure_zero(v2, sizeof(v2));
        voleith_secure_zero(prod, sizeof(prod));
        voleith_secure_zero(zero, sizeof(zero));
    }

    /* Step 6: x1 corrections from VOLE bits beyond ell*16. */
    uint8_t x1_0[32], x1_1[32], x1_2[32], tmp3[32];
    {
        size_t corr_start = ell * GF16_ELEM_BITS;
        gf16p_sum_poly_cols(x1_0, tmp1, V_T, lambda, nb, corr_start, lambda);
        gf16p_sum_poly_bits_at(tmp3, tmp1, u, corr_start, lambda);
        gf16p_sum_poly_cols(x1_1, tmp1, V_T, lambda, nb, corr_start + lambda,
                            lambda);
        for (unsigned int k = 0; k < nb; k++)
            x1_1[k] ^= tmp3[k];
        gf16p_sum_poly_bits_at(x1_2, tmp1, u, corr_start + lambda, lambda);
    }

    /* Step 7: finalize. */
    gf16p_zk_hash_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, x1_0, x1_1,
                             x1_2, chall_2, tmp1, tmp2);

    if (wire_vals)
        voleith_secure_zero(wire_vals, n_wires * sizeof(voleith_gf16_t));
    if (bit_tags)
        voleith_secure_zero(bit_tags, n_wires * GF16_ELEM_BITS * nb);
    if (V_T)
        voleith_secure_zero(V_T, n_bit_cols * nb);
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(tmp3, sizeof(tmp3));
    voleith_secure_zero(x1_0, sizeof(x1_0));
    voleith_secure_zero(x1_1, sizeof(x1_1));
    voleith_secure_zero(x1_2, sizeof(x1_2));
    voleith_secure_zero(beta, sizeof(beta));
    voleith_secure_zero(&hasher, sizeof(hasher));
    voleith_secure_zero(sq_matrix, sizeof(sq_matrix));
    free(wire_vals);
    free(bit_tags);
    free(V_T);
    return 0;

oom:
err:
    if (wire_vals)
        voleith_secure_zero(wire_vals, n_wires * sizeof(voleith_gf16_t));
    if (bit_tags)
        voleith_secure_zero(bit_tags, n_wires * GF16_ELEM_BITS * nb);
    if (V_T)
        voleith_secure_zero(V_T, n_bit_cols * nb);
    voleith_secure_zero(sq_matrix, sizeof(sq_matrix));
    free(wire_vals);
    free(bit_tags);
    free(V_T);
    return -1;
}

int
voleith_gf16_qs_prove(const voleith_gf16_circuit_t *circuit,
                      const voleith_gf16_t *witness,
                      const voleith_gf16_t *instance, unsigned int lambda,
                      const uint8_t *u, const uint8_t **V,
                      const uint8_t *chall_2, uint8_t *d_out, uint8_t *a0_tilde,
                      uint8_t *a1_tilde, uint8_t *a2_tilde)
{
    return gf16_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                              d_out, a0_tilde, a1_tilde, a2_tilde, 1);
}

int
voleith_gf16_qs_prove_unchecked(const voleith_gf16_circuit_t *circuit,
                                const voleith_gf16_t *witness,
                                const voleith_gf16_t *instance,
                                unsigned int lambda, const uint8_t *u,
                                const uint8_t **V, const uint8_t *chall_2,
                                uint8_t *d_out, uint8_t *a0_tilde,
                                uint8_t *a1_tilde, uint8_t *a2_tilde)
{
    return gf16_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                              d_out, a0_tilde, a1_tilde, a2_tilde, 0);
}

static int
gf16_qs_compute_d_impl(const voleith_gf16_circuit_t *circuit,
                       const voleith_gf16_t *witness,
                       const voleith_gf16_t *instance, const uint8_t *u,
                       uint8_t *d_out, int reject_invalid)
{
    if (!circuit || !witness || !u || !d_out)
        return -1;
    if (voleith_gf16_circuit_instance_count(circuit) > 0 && !instance)
        return -1;

    size_t n_wires = voleith_gf16_circuit_wire_count(circuit);
    size_t n_witness = voleith_gf16_circuit_witness_count(circuit);
    size_t n_mul = voleith_gf16_circuit_mul_count(circuit);
    size_t ell = n_witness + n_mul;

    const gf16_wire_entry_t *wires = voleith_gf16_circuit_wires(circuit);

    voleith_gf16_t *wire_vals = calloc(n_wires, sizeof(voleith_gf16_t));
    if (!wire_vals)
        return -1;

    {
        int ev =
            voleith_gf16_circuit_eval(circuit, witness, instance, wire_vals);
        if (ev < 0 || (reject_invalid && ev != 1)) {
            voleith_secure_zero(wire_vals, n_wires * sizeof(voleith_gf16_t));
            free(wire_vals);
            return -1;
        }
    }

    memset(d_out, 0, 2 * ell);

    size_t witness_idx = 0;
    size_t mul_idx = 0;
    for (size_t w = 0; w < n_wires; w++) {
        const gf16_wire_entry_t *e = &wires[w];
        if (e->kind == GF16_WIRE_WITNESS) {
            size_t slot = witness_idx++;
            gf16p_write_elem(d_out, slot,
                             wire_vals[w] ^ gf16p_read_elem(u, slot));
        } else if (e->kind == GF16_WIRE_MUL) {
            size_t slot = n_witness + mul_idx++;
            gf16p_write_elem(d_out, slot,
                             wire_vals[w] ^ gf16p_read_elem(u, slot));
        }
    }

    voleith_secure_zero(wire_vals, n_wires * sizeof(voleith_gf16_t));
    free(wire_vals);
    return 0;
}

int
voleith_gf16_qs_compute_d(const voleith_gf16_circuit_t *circuit,
                          const voleith_gf16_t *witness,
                          const voleith_gf16_t *instance, const uint8_t *u,
                          uint8_t *d_out)
{
    return gf16_qs_compute_d_impl(circuit, witness, instance, u, d_out, 1);
}

int
voleith_gf16_qs_compute_d_unchecked(const voleith_gf16_circuit_t *circuit,
                                    const voleith_gf16_t *witness,
                                    const voleith_gf16_t *instance,
                                    const uint8_t *u, uint8_t *d_out)
{
    return gf16_qs_compute_d_impl(circuit, witness, instance, u, d_out, 0);
}
