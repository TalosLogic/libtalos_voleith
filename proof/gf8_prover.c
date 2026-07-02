/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_prover.c - Element-level (GF(2⁸)) QuickSilver prover
 *
 * Element-level QuickSilver: one VOLE slot per witness byte and per MUL gate.
 *   ell = witness_count + mul_gate_count   (in GF(2⁸) elements)
 *   ellhat_bytes = ell + ceil((3*lambda + 16) / 8)
 *
 * Each wire carries a GF(2⁸) element. Free gates (XOR, XOR_CONST, LINEAR_MAP,
 * SQUARE) have VOLE tags derived by GF(2)-linearity. MUL gates and WITNESS
 * wires each consume one VOLE slot.
 *
 * Tag tracking:
 *   For each wire w we store 8 GF(2^λ) "bit-tags" (one per bit of the byte
 *   value): bit_tag[w][i] is the GF(2^λ) VOLE tag for bit i of wire w.
 *
 *   For WITNESS slot s: bit_tag[w][i] = V_T column s*8+i
 *   For MUL slot s:     bit_tag[w][i] = V_T column s*8+i
 *   For XOR:            bit_tag[out][i] = bit_tag[a][i] XOR bit_tag[b][i]
 *   For XOR_CONST(k):   bit_tag[out][i] = bit_tag[a][i]  (const has zero tag)
 *   For LINEAR_MAP(M):  bit_tag[out][i] = XOR_{j: M[i][j]=1} bit_tag[a][j]
 *   For SQUARE:         same as LINEAR_MAP with the squaring matrix
 *   For INSTANCE/CONST: bit_tag[w][i] = 0  (public values have zero tag)
 *
 * Element-level tag: tag[w] = ByteCombine(bit_tag[w][0..7])
 *                           = Σᵢ bit_tag[w][i] * α_8^i  ∈ GF(2^λ)
 *
 * Multiplication check per MUL gate (inputs a, b; output c):
 *   v0 = tag[a]*tag[b] + tag[c]                              (degree-0 in Δ)
 *   v1 = tag[a]*embed(val_b) + tag[b]*embed(val_a) + embed(val_c)  (degree-1)
 *   v2 = embed(gf8_mul(val_a, val_b))                         (degree-2)
 *
 * assert_product(a, b, c_expected) contributes the same (v0, v1, v2) form
 * using the existing committed wire values - no new VOLE slot consumed.
 *
 * x1 corrections at finalization: identical to bit-level but with bit offset
 * ell*8 into V_T and u (since each element slot spans 8 bit-columns).
 */

#include "gf8_prover.h"
#include "gf8_prover_internal.h"
#include "gf8_circuit.h"
#include "../core/field.h"
#include "../core/util.h"
#include "circuit.h" /* for VOLEITH_STACK_BUF_MAX */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal GF(2^λ) helpers (mirrored from prover.c)
 * ===================================================================== */

static uint8_t *
gf8p_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                      size_t n_cols)
{
    uint8_t *V_T = calloc(n_cols * nb, 1);
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
gf8p_get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

static void
gf8p_gf_mul_alpha(uint8_t *out, const uint8_t *in, unsigned int lambda)
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
gf8p_sum_poly_cols(uint8_t *out, uint8_t *tmp, const uint8_t *V_T,
                   unsigned int lambda, unsigned int nb, size_t start_col,
                   unsigned int count)
{
    memcpy(out, V_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf8p_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, V_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

static void
gf8p_sum_poly_bits_at(uint8_t *out, uint8_t *tmp, const uint8_t *buf,
                      size_t start_bit, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    uint8_t b = (uint8_t)gf8p_get_bit(buf, start_bit + lambda - 1);
    memset(out, 0, nb);
    out[0] = b;
    for (int i = (int)lambda - 2; i >= 0; i--) {
        gf8p_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        b = (uint8_t)gf8p_get_bit(buf, start_bit + (size_t)i);
        out[0] ^= b;
    }
}

static void
gf8p_gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b,
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
 * GF(2⁸)-specific helpers
 * ===================================================================== */

/*
 * Compute tag = Σᵢ tabs[i] * α_8^i in GF(2^λ) using Horner's rule.
 * tabs: 8 contiguous GF(2^λ) elements (8 * nb bytes).
 * alpha8: the GF(2^λ) element α_8 (precomputed by caller).
 */
static void
gf8p_byte_combine(uint8_t *out, const uint8_t *tabs, unsigned int nb,
                  unsigned int lambda, const uint8_t *alpha8)
{
    uint8_t tmp[32];
    memcpy(out, tabs + 7 * nb, nb);
    for (int i = 6; i >= 0; i--) {
        gf8p_gf_mul(tmp, out, alpha8, lambda);
        for (unsigned int k = 0; k < nb; k++)
            out[k] = tmp[k] ^ tabs[(size_t)i * nb + k];
    }
}

/*
 * Embed a GF(2⁸) byte into GF(2^λ): embed(val) = Σᵢ val_i * α_8^i.
 * Uses voleith_byte_combine with val's 8 bits as scalars.
 */
static void
gf8p_embed(uint8_t *out, uint8_t val, unsigned int lambda)
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++)
        bits[i] = (val >> i) & 1u;
    voleith_byte_combine(out, bits, lambda);
}

/*
 * Apply an 8×8 GF(2) matrix M to 8 GF(2^λ) bit-tag elements.
 * in_tabs:  8 * nb bytes (8 input GF(2^λ) elements)
 * out_tabs: 8 * nb bytes (8 output GF(2^λ) elements)
 *
 * Output bit i = XOR of input bit j for each j where M[i][j] = 1.
 * (Row-major convention: M[i] is row i, bit j is (M[i] >> j) & 1.)
 */
static void
gf8p_apply_linear_map(uint8_t *out_tabs, const uint8_t *in_tabs,
                      const uint8_t M[8], unsigned int nb)
{
    memset(out_tabs, 0, 8 * nb);
    for (unsigned int i = 0; i < 8; i++) {
        uint8_t row = M[i];
        for (unsigned int j = 0; j < 8; j++) {
            if ((row >> j) & 1u) {
                for (unsigned int k = 0; k < nb; k++)
                    out_tabs[i * nb + k] ^= in_tabs[j * nb + k];
            }
        }
    }
}

/* =====================================================================
 * zk_hash_3 context (identical to prover.c - three accumulators)
 * ===================================================================== */

typedef struct {
    uint8_t h0[3][32];
    uint8_t h1[3][32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
} gf8p_zk_hash_3_ctx;

static void
gf8p_zk_hash_3_init(gf8p_zk_hash_3_ctx *ctx, const uint8_t *chall_2,
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
gf8p_zk_hash_3_update(gf8p_zk_hash_3_ctx *ctx, const uint8_t *v0,
                      const uint8_t *v1, const uint8_t *v2, uint8_t *tmp1,
                      uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *vs[3] = {v0, v1, v2};
    for (int i = 0; i < 3; i++) {
        gf8p_gf_mul(tmp1, ctx->h0[i], ctx->s, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h0[i][k] = tmp1[k] ^ vs[i][k];
        gf8p_gf_mul(tmp2, ctx->h1[i], ctx->t, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h1[i][k] = tmp2[k] ^ vs[i][k];
    }
}

static void
gf8p_zk_hash_3_finalize(uint8_t *a0_tilde, uint8_t *a1_tilde, uint8_t *a2_tilde,
                        const gf8p_zk_hash_3_ctx *ctx, const uint8_t *x1_0,
                        const uint8_t *x1_1, const uint8_t *x1_2,
                        const uint8_t *chall_2, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    uint8_t *outputs[3] = {a0_tilde, a1_tilde, a2_tilde};
    const uint8_t *x1s[3] = {x1_0, x1_1, x1_2};
    for (int i = 0; i < 3; i++) {
        gf8p_gf_mul(tmp1, r0, ctx->h0[i], ctx->lambda);
        gf8p_gf_mul(tmp2, r1, ctx->h1[i], ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            outputs[i][k] = tmp1[k] ^ tmp2[k] ^ x1s[i][k];
    }
}

/* =====================================================================
 * Main prover
 * ===================================================================== */

size_t
voleith_gf8_qs_ellhat(const voleith_gf8_circuit_t *circuit, unsigned int lambda)
{
    size_t ell = voleith_gf8_qs_ell(circuit);
    return ell + (3u * lambda + UNIVERSAL_HASH_B_BITS + 7u) / 8u;
}

static int
gf8_qs_prove_impl(const voleith_gf8_circuit_t *circuit, const uint8_t *witness,
                  const uint8_t *instance, unsigned int lambda,
                  const uint8_t *u, const uint8_t **V, const uint8_t *chall_2,
                  uint8_t *d_out, uint8_t *a0_tilde, uint8_t *a1_tilde,
                  uint8_t *a2_tilde, int reject_invalid)
{
    if (!circuit || !witness || !u || !V || !chall_2 || !d_out || !a0_tilde ||
        !a1_tilde || !a2_tilde)
        return -1;
    if (voleith_gf8_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    unsigned int nb = lambda / 8;
    size_t n_wires = voleith_gf8_circuit_wire_count(circuit);
    size_t n_witness = voleith_gf8_circuit_witness_count(circuit);
    size_t n_mul = voleith_gf8_circuit_mul_count(circuit);
    size_t ell = n_witness + n_mul;
    size_t n_constraints = voleith_gf8_circuit_constraint_count(circuit);

    const gf8_wire_entry_t *wires = voleith_gf8_circuit_wires(circuit);
    const gf8_constraint_entry_t *constraints =
        voleith_gf8_circuit_constraints(circuit);

    /* Heap allocations and their sizes - declared before any goto so
     * the oom:/err: cleanup tail can reference them without crossing
     * an uninitialized declaration. */
    uint8_t *wire_vals = NULL;
    uint8_t *bit_tags = NULL; /* n_wires * 8 * nb bytes */
    uint8_t *V_T = NULL;
    size_t n_bit_cols = ell * 8 + 2 * (size_t)lambda;

    /* wire_vals: one byte per wire */
    wire_vals = calloc(n_wires, 1);
    if (!wire_vals)
        goto oom;

    /* bit_tags: 8 GF(2^λ) elements per wire (two-arg calloc: overflow-checked) */
    bit_tags = calloc(n_wires, (size_t)8 * nb);
    if (!bit_tags)
        goto oom;

    /* Transpose V at bit level */
    V_T = gf8p_transpose_matrix(V, lambda, nb, n_bit_cols);
    if (!V_T)
        goto oom;

    /* Precompute α_8 as a GF(2^λ) element: embed(0x02) = ByteCombine({0,1,0,...}) */
    uint8_t alpha8[32] = {0};
    {
        uint8_t x[8] = {0, 1, 0, 0, 0, 0, 0, 0};
        voleith_byte_combine(alpha8, x, (int)lambda);
    }

    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};

    /* ------------------------------------------------------------------
     * Step 1: Evaluate the circuit to get wire_vals[w] for all wires.
     * ------------------------------------------------------------------ */
    {
        int ev =
            voleith_gf8_circuit_eval(circuit, witness, instance, wire_vals);
        if (ev < 0 || (reject_invalid && ev != 1))
            goto err;
    }

    /* ------------------------------------------------------------------
     * Step 2: Propagate bit-tags through the circuit in topological order.
     *
     * bit_tags + (w*8 + i)*nb = GF(2^λ) tag for bit i of wire w.
     * ------------------------------------------------------------------ */
    {
        size_t witness_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf8_wire_entry_t *e = &wires[w];
            uint8_t *bt_w = bit_tags + w * 8 * nb;

            switch (e->kind) {
            case GF8_WIRE_WITNESS: {
                size_t slot = witness_idx++;
                /* bit_tag[w][i] = V_T column (slot*8+i) */
                for (unsigned int i = 0; i < 8; i++)
                    memcpy(bt_w + i * nb, V_T + (slot * 8 + i) * nb, nb);
                break;
            }
            case GF8_WIRE_INSTANCE:
            case GF8_WIRE_CONST:
                /* Public values: zero tag */
                memset(bt_w, 0, 8 * nb);
                break;

            case GF8_WIRE_XOR: {
                /* bit_tag[out][i] = bit_tag[a][i] XOR bit_tag[b][i] */
                const uint8_t *bt_a = bit_tags + e->a * 8 * nb;
                const uint8_t *bt_b = bit_tags + e->b * 8 * nb;
                for (unsigned int i = 0; i < 8; i++)
                    for (unsigned int k = 0; k < nb; k++)
                        bt_w[i * nb + k] = bt_a[i * nb + k] ^ bt_b[i * nb + k];
                break;
            }
            case GF8_WIRE_XOR_CONST:
                /* constant has zero tag, so bit_tag[out] = bit_tag[a] */
                memcpy(bt_w, bit_tags + e->a * 8 * nb, 8 * nb);
                break;

            case GF8_WIRE_LINEAR_MAP:
                gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb, e->matrix,
                                      nb);
                break;

            case GF8_WIRE_SQUARE: {
                /* Frobenius squaring: same as LINEAR_MAP with GF8_SQUARE_MATRIX */
                static const uint8_t SQ[8] = {0x51, 0xD0, 0x22, 0xF0,
                                              0x94, 0x60, 0x28, 0xC0};
                gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb, SQ, nb);
                break;
            }
            case GF8_WIRE_MUL: {
                size_t slot = n_witness + mul_idx++;
                for (unsigned int i = 0; i < 8; i++)
                    memcpy(bt_w + i * nb, V_T + (slot * 8 + i) * nb, nb);
                break;
            }
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 3: Compute d[s] = wire_vals[w] XOR u[s] for each slot.
     * d is ell bytes (one byte per element slot).
     * ------------------------------------------------------------------ */
    {
        size_t witness_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf8_wire_entry_t *e = &wires[w];
            if (e->kind == GF8_WIRE_WITNESS) {
                size_t slot = witness_idx++;
                d_out[slot] = wire_vals[w] ^ u[slot];
            } else if (e->kind == GF8_WIRE_MUL) {
                size_t slot = n_witness + mul_idx++;
                d_out[slot] = wire_vals[w] ^ u[slot];
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 4: Accumulate MUL gate checks into zk_hash_3.
     *
     * For MUL gate with inputs (a, b) and output c:
     *   tag_a = ByteCombine(bit_tags[a])
     *   tag_b = ByteCombine(bit_tags[b])
     *   tag_c = ByteCombine(bit_tags[c])
     *   val_a = wire_vals[a], val_b = wire_vals[b]
     *   v0 = tag_a*tag_b + tag_c              (degree-0)
     *   v1 = tag_a*embed(val_b) + tag_b*embed(val_a) + embed(val_c)  (degree-1)
     *   v2 = embed(gf8_mul(val_a, val_b))     (degree-2)
     * ------------------------------------------------------------------ */
    gf8p_zk_hash_3_ctx hasher;
    gf8p_zk_hash_3_init(&hasher, chall_2, lambda);

    {
        uint8_t tag_a[32], tag_b[32], tag_c[32];
        uint8_t emb_a[32], emb_b[32], emb_c[32];
        uint8_t v0[32], v1[32], v2[32];
        uint8_t prod[32], zero[32];
        memset(zero, 0, nb);

        for (size_t w = 0; w < n_wires; w++) {
            const gf8_wire_entry_t *e = &wires[w];
            if (e->kind != GF8_WIRE_MUL)
                continue;

            gf8_wire_id wa = e->a, wb = e->b;
            uint8_t val_a = wire_vals[wa];
            uint8_t val_b = wire_vals[wb];
            uint8_t val_c = wire_vals[w];

            gf8p_byte_combine(tag_a, bit_tags + wa * 8 * nb, nb, lambda,
                              alpha8);
            gf8p_byte_combine(tag_b, bit_tags + wb * 8 * nb, nb, lambda,
                              alpha8);
            gf8p_byte_combine(tag_c, bit_tags + w * 8 * nb, nb, lambda, alpha8);
            gf8p_embed(emb_a, val_a, lambda);
            gf8p_embed(emb_b, val_b, lambda);
            gf8p_embed(emb_c, val_c, lambda);

            /* v0 = tag_a*tag_b + tag_c */
            gf8p_gf_mul(prod, tag_a, tag_b, lambda);
            for (unsigned int k = 0; k < nb; k++)
                v0[k] = prod[k] ^ tag_c[k];

            /* v1 = tag_a*emb_b + tag_b*emb_a + emb_c */
            gf8p_gf_mul(v1, tag_a, emb_b, lambda);
            gf8p_gf_mul(prod, tag_b, emb_a, lambda);
            for (unsigned int k = 0; k < nb; k++)
                v1[k] ^= prod[k] ^ emb_c[k];

            /* v2 = embed(gf8_mul(val_a, val_b)) */
            gf8p_embed(v2, voleith_gf8_mul(val_a, val_b), lambda);

            gf8p_zk_hash_3_update(&hasher, v0, v1, v2, tmp1, tmp2);
        }

        /* ------------------------------------------------------------------
         * Step 5: Accumulate constraints.
         *
         * PRODUCT constraint (a*b = c_expected): same (v0, v1, v2) form.
         * ZERO constraint: (tag[w], 0, 0).
         * EQUAL constraint: (tag[a] XOR tag[b], 0, 0).
         * ------------------------------------------------------------------ */
        for (size_t ci = 0; ci < n_constraints; ci++) {
            const gf8_constraint_entry_t *c = &constraints[ci];

            switch (c->kind) {
            case GF8_CONSTRAINT_PRODUCT: {
                uint8_t val_a = wire_vals[c->a];
                uint8_t val_b = wire_vals[c->b];
                uint8_t val_c = wire_vals[c->c];

                gf8p_byte_combine(tag_a, bit_tags + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_byte_combine(tag_b, bit_tags + c->b * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_byte_combine(tag_c, bit_tags + c->c * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_embed(emb_a, val_a, lambda);
                gf8p_embed(emb_b, val_b, lambda);
                gf8p_embed(emb_c, val_c, lambda);

                gf8p_gf_mul(prod, tag_a, tag_b, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    v0[k] = prod[k] ^ tag_c[k];

                gf8p_gf_mul(v1, tag_a, emb_b, lambda);
                gf8p_gf_mul(prod, tag_b, emb_a, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    v1[k] ^= prod[k] ^ emb_c[k];

                /* v2 = embed(val_c): the claimed product value.
                 * For a correct constraint val_c = val_a*val_b, so
                 * embed(val_c) = embed(val_a)*embed(val_b) and the verifier's
                 * delta^2 term matches.  For a wrong constraint they differ,
                 * causing verification to fail (soundness). */
                gf8p_embed(v2, val_c, lambda);

                gf8p_zk_hash_3_update(&hasher, v0, v1, v2, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_ZERO: {
                gf8p_byte_combine(tag_a, bit_tags + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_zk_hash_3_update(&hasher, tag_a, zero, zero, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_EQUAL: {
                gf8p_byte_combine(tag_a, bit_tags + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_byte_combine(tag_b, bit_tags + c->b * 8 * nb, nb, lambda,
                                  alpha8);
                for (unsigned int k = 0; k < nb; k++)
                    tag_a[k] ^= tag_b[k];
                gf8p_zk_hash_3_update(&hasher, tag_a, zero, zero, tmp1, tmp2);
                break;
            }
            }
        }

        /* G-4 (mirrors P-3): zero per-gate / per-constraint stack
         * buffers at end of scope.  tag_a/b/c carry per-wire VOLE
         * tags; emb_a/b/c are embed(witness) elements; v0/v1/v2 are
         * the QuickSilver coefficients; prod is the running field
         * product. */
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

    /* ------------------------------------------------------------------
     * Step 6: Compute x1 corrections from VOLE bits beyond ell*8.
     *
     * Same as bit-level but start_col = ell*8 (not ell).
     *
     * x1_0 = sum_poly(V cols ell*8 .. ell*8+lambda-1)
     * x1_1 = sum_poly(V cols ell*8+lambda .. ell*8+2*lambda-1) + u_star_0
     * x1_2 = u_star_1
     * ------------------------------------------------------------------ */
    uint8_t x1_0[32], x1_1[32], x1_2[32], tmp3[32];
    {
        size_t corr_start = ell * 8;
        gf8p_sum_poly_cols(x1_0, tmp1, V_T, lambda, nb, corr_start, lambda);
        gf8p_sum_poly_bits_at(tmp3, tmp1, u, corr_start, lambda);
        gf8p_sum_poly_cols(x1_1, tmp1, V_T, lambda, nb, corr_start + lambda,
                           lambda);
        for (unsigned int k = 0; k < nb; k++)
            x1_1[k] ^= tmp3[k];
        gf8p_sum_poly_bits_at(x1_2, tmp1, u, corr_start + lambda, lambda);
    }

    /* ------------------------------------------------------------------
     * Step 7: Finalize zk_hash_3 to get a0_tilde, a1_tilde, a2_tilde.
     * ------------------------------------------------------------------ */
    gf8p_zk_hash_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, x1_0, x1_1,
                            x1_2, chall_2, tmp1, tmp2);

    /*
     * G-3 (mirrors P-2 for the GF(2^8) prover): zero every heap
     * buffer that carried witness-derived material before freeing.
     *   - wire_vals: every wire byte = direct function of witness.
     *   - bit_tags: per-wire VOLE bit-tags (forging material).
     *   - V_T: transposed VOLE mask matrix (hides witness via u).
     *
     * G-4 (mirrors P-3, P-4): zero function-scoped stack buffers
     * that hold secret-derived material - tmp1/2/3, x1_0/1/2,
     * hasher.  alpha8 is the precomputed α_8 embedding, a public
     * constant per λ, but zeroed for hygiene-bar consistency.
     */
    if (wire_vals)
        voleith_secure_zero(wire_vals, n_wires);
    if (bit_tags)
        voleith_secure_zero(bit_tags, n_wires * 8 * nb);
    if (V_T)
        voleith_secure_zero(V_T, n_bit_cols * nb);
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(tmp3, sizeof(tmp3));
    voleith_secure_zero(x1_0, sizeof(x1_0));
    voleith_secure_zero(x1_1, sizeof(x1_1));
    voleith_secure_zero(x1_2, sizeof(x1_2));
    voleith_secure_zero(alpha8, sizeof(alpha8));
    voleith_secure_zero(&hasher, sizeof(hasher));
    free(wire_vals);
    free(bit_tags);
    free(V_T);
    return 0;

oom:
err:
    /* Same cleanup as the success path.  Each goto site has already
     * populated at least one of these (the OOM in gf8p_transpose_matrix
     * happens after wire_vals/bit_tags are allocated; the err: from
     * gf8_circuit_eval failure has wire_vals populated).  As in
     * proof/prover.c, unconditionally zero function-scoped stack
     * buffers; some are guaranteed-uninitialized on early gotos but
     * writing zeros is harmless. */
    if (wire_vals)
        voleith_secure_zero(wire_vals, n_wires);
    if (bit_tags)
        voleith_secure_zero(bit_tags, n_wires * 8 * nb);
    if (V_T)
        voleith_secure_zero(V_T, n_bit_cols * nb);
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(tmp3, sizeof(tmp3));
    voleith_secure_zero(x1_0, sizeof(x1_0));
    voleith_secure_zero(x1_1, sizeof(x1_1));
    voleith_secure_zero(x1_2, sizeof(x1_2));
    voleith_secure_zero(alpha8, sizeof(alpha8));
    voleith_secure_zero(&hasher, sizeof(hasher));
    free(wire_vals);
    free(bit_tags);
    free(V_T);
    return -1;
}

int
voleith_gf8_qs_prove(const voleith_gf8_circuit_t *circuit,
                     const uint8_t *witness, const uint8_t *instance,
                     unsigned int lambda, const uint8_t *u, const uint8_t **V,
                     const uint8_t *chall_2, uint8_t *d_out, uint8_t *a0_tilde,
                     uint8_t *a1_tilde, uint8_t *a2_tilde)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a0_tilde, a1_tilde, a2_tilde, 1);
}

int
voleith_gf8_qs_prove_unchecked(const voleith_gf8_circuit_t *circuit,
                               const uint8_t *witness, const uint8_t *instance,
                               unsigned int lambda, const uint8_t *u,
                               const uint8_t **V, const uint8_t *chall_2,
                               uint8_t *d_out, uint8_t *a0_tilde,
                               uint8_t *a1_tilde, uint8_t *a2_tilde)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a0_tilde, a1_tilde, a2_tilde, 0);
}

static int
gf8_qs_compute_d_impl(const voleith_gf8_circuit_t *circuit,
                      const uint8_t *witness, const uint8_t *instance,
                      const uint8_t *u, uint8_t *d_out, int reject_invalid)
{
    if (!circuit || !witness || !u || !d_out)
        return -1;
    if (voleith_gf8_circuit_instance_count(circuit) > 0 && !instance)
        return -1;

    size_t n_wires = voleith_gf8_circuit_wire_count(circuit);
    size_t n_witness = voleith_gf8_circuit_witness_count(circuit);
    size_t n_mul = voleith_gf8_circuit_mul_count(circuit);
    size_t ell = n_witness + n_mul;

    const gf8_wire_entry_t *wires = voleith_gf8_circuit_wires(circuit);

    uint8_t *wire_vals = calloc(n_wires, 1);
    if (!wire_vals)
        return -1;

    /* Reject invalid witnesses: circuit_eval returns 1 = all constraints
     * satisfied, 0 = some constraint violated, -1 = error.  The unchecked
     * test seam (reject_invalid == 0) proceeds on 0 so a forged witness
     * can be carried through to the verifier; structural errors (< 0)
     * still fail. */
    {
        int ev =
            voleith_gf8_circuit_eval(circuit, witness, instance, wire_vals);
        if (ev < 0 || (reject_invalid && ev != 1)) {
            /* G-3: wire_vals may already hold partial values from
             * voleith_gf8_circuit_eval before it returned non-1. */
            voleith_secure_zero(wire_vals, n_wires);
            free(wire_vals);
            return -1;
        }
    }

    memset(d_out, 0, ell);

    size_t witness_idx = 0;
    size_t mul_idx = 0;
    for (size_t w = 0; w < n_wires; w++) {
        const gf8_wire_entry_t *e = &wires[w];
        if (e->kind == GF8_WIRE_WITNESS) {
            size_t slot = witness_idx++;
            d_out[slot] = wire_vals[w] ^ u[slot];
        } else if (e->kind == GF8_WIRE_MUL) {
            size_t slot = n_witness + mul_idx++;
            d_out[slot] = wire_vals[w] ^ u[slot];
        }
    }

    /* G-3: wire_vals holds every wire value (direct function of the
     * witness).  Zero before free. */
    voleith_secure_zero(wire_vals, n_wires);
    free(wire_vals);
    return 0;
}

int
voleith_gf8_qs_compute_d(const voleith_gf8_circuit_t *circuit,
                         const uint8_t *witness, const uint8_t *instance,
                         const uint8_t *u, uint8_t *d_out)
{
    return gf8_qs_compute_d_impl(circuit, witness, instance, u, d_out, 1);
}

int
voleith_gf8_qs_compute_d_unchecked(const voleith_gf8_circuit_t *circuit,
                                   const uint8_t *witness,
                                   const uint8_t *instance, const uint8_t *u,
                                   uint8_t *d_out)
{
    return gf8_qs_compute_d_impl(circuit, witness, instance, u, d_out, 0);
}
