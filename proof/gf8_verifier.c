/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_verifier.c - Element-level (GF(2⁸)) QuickSilver verifier
 *
 * Mirrors gf8_prover.c in structure: uses per-wire 8-bit-key arrays,
 * propagates keys through GF(2)-linear gates, and accumulates the
 * verifier's contribution per MUL gate / constraint via a single
 * Horner hash (zk_hash, not zk_hash_3).
 *
 * Verifier key for each wire, tracked as 8 GF(2^λ) bit-keys:
 *   WITNESS slot s:     bit_keys[w][i] = Q_T[(s*8+i)*nb] + Δ * ((d[s]>>i)&1)
 *   MUL slot s:         same
 *   INSTANCE byte v:    bit_keys[w][i] = ((v>>i)&1) * Δ
 *   CONST byte v:       same
 *   XOR(a,b):           bit_keys[out][i] = bit_keys[a][i] XOR bit_keys[b][i]
 *   XOR_CONST(a,k):     bit_keys[out][i] = bit_keys[a][i] XOR ((k>>i)&1)*Δ
 *   LINEAR_MAP(M,a):    bit_keys[out][i] = XOR_{j:M[i][j]=1} bit_keys[a][j]
 *   SQUARE(a):          same as LINEAR_MAP with squaring matrix
 *
 * Per-gate verifier contribution:
 *   element_key[w] = ByteCombine(bit_keys[w][0..7])
 *   MUL gate (a*b=c):    contrib = key[a]*key[b] + key[c]
 *   PRODUCT constraint:  same using constraint wires
 *   ZERO constraint:     contrib = key[a]
 *   EQUAL constraint:    contrib = key[a] + key[b]
 *
 * q_star correction uses Q_T columns at bit offset ell*8 (same structure
 * as bit-level verifier, but indexed from ell*8 instead of ell).
 */

#include "gf8_verifier.h"
#include "gf8_circuit.h"
#include "../core/field.h"
#include "../core/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal helpers (same structure as gf8_prover.c)
 * ===================================================================== */

static uint8_t *
gf8v_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                      size_t n_cols)
{
    uint8_t *Q_T = calloc(n_cols, nb); /* two-arg form: overflow-checked */
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
gf8v_gf_mul_alpha(uint8_t *out, const uint8_t *in, unsigned int lambda)
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
gf8v_sum_poly_cols(uint8_t *out, uint8_t *tmp, const uint8_t *Q_T,
                   unsigned int lambda, unsigned int nb, size_t start_col,
                   unsigned int count)
{
    memcpy(out, Q_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf8v_gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, Q_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

static void
gf8v_gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b,
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

/* Compute out = Σᵢ tabs[i] * α_8^i in GF(2^λ) via Horner */
static void
gf8v_byte_combine(uint8_t *out, const uint8_t *tabs, unsigned int nb,
                  unsigned int lambda, const uint8_t *alpha8)
{
    uint8_t tmp[32];
    memcpy(out, tabs + 7 * nb, nb);
    for (int i = 6; i >= 0; i--) {
        gf8v_gf_mul(tmp, out, alpha8, lambda);
        for (unsigned int k = 0; k < nb; k++)
            out[k] = tmp[k] ^ tabs[(size_t)i * nb + k];
    }
}

/* Apply 8×8 GF(2) matrix M to 8 GF(2^λ) bit-key elements */
static void
gf8v_apply_linear_map(uint8_t *out_keys, const uint8_t *in_keys,
                      const uint8_t M[8], unsigned int nb)
{
    memset(out_keys, 0, 8 * nb);
    for (unsigned int i = 0; i < 8; i++) {
        uint8_t row = M[i];
        for (unsigned int j = 0; j < 8; j++) {
            if ((row >> j) & 1u) {
                for (unsigned int k = 0; k < nb; k++)
                    out_keys[i * nb + k] ^= in_keys[j * nb + k];
            }
        }
    }
}

/* =====================================================================
 * zk_hash context (verifier side: single Horner accumulator)
 * ===================================================================== */

typedef struct {
    uint8_t h0[32];
    uint8_t h1[32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
} gf8v_zk_hash_ctx;

static void
gf8v_zk_hash_init(gf8v_zk_hash_ctx *ctx, const uint8_t *chall_2,
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
gf8v_zk_hash_update(gf8v_zk_hash_ctx *ctx, const uint8_t *v, uint8_t *tmp1,
                    uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    gf8v_gf_mul(tmp1, ctx->h0, ctx->s, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h0[k] = tmp1[k] ^ v[k];
    gf8v_gf_mul(tmp2, ctx->h1, ctx->t, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        ctx->h1[k] = tmp2[k] ^ v[k];
}

static void
gf8v_zk_hash_finalize(uint8_t *q_tilde, const gf8v_zk_hash_ctx *ctx,
                      const uint8_t *q_star, const uint8_t *chall_2,
                      uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    gf8v_gf_mul(tmp1, r0, ctx->h0, ctx->lambda);
    gf8v_gf_mul(tmp2, r1, ctx->h1, ctx->lambda);
    for (unsigned int k = 0; k < nb; k++)
        q_tilde[k] = tmp1[k] ^ tmp2[k] ^ q_star[k];
}

/* =====================================================================
 * Main verifier
 * ===================================================================== */

int
voleith_gf8_qs_verify(const voleith_gf8_circuit_t *circuit,
                      const uint8_t *instance, unsigned int lambda,
                      const uint8_t **Q, const uint8_t *d, const uint8_t *delta,
                      const uint8_t *chall_2, const uint8_t *a1_tilde,
                      const uint8_t *a2_tilde, uint8_t *a0_tilde_out)
{
    if (!circuit || !Q || !d || !delta || !chall_2 || !a1_tilde || !a2_tilde ||
        !a0_tilde_out)
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

    uint8_t *bit_keys = NULL; /* n_wires * 8 * nb bytes */
    uint8_t *Q_T = NULL;

    /*
     * H-3: validate every wire / constraint reference and guard the
     * allocation-size arithmetic before touching the heap.  The proof
     * layer runs voleith_gf8_circuit_validate upstream, but this
     * primitive must stay memory-safe on its own - no OOB read of
     * bit_keys, no size_t wrap on a 32-bit target - when handed a
     * malformed circuit directly.  calloc(nmemb, size) is required to
     * detect the product overflow and return NULL, so the per-wire
     * 8*nb byte stride is passed as the element size.
     */
    for (size_t w = 0; w < n_wires; w++) {
        const gf8_wire_entry_t *e = &wires[w];
        switch (e->kind) {
        case GF8_WIRE_XOR:
        case GF8_WIRE_MUL:
            if (e->a >= n_wires || e->b >= n_wires)
                return -1;
            break;
        case GF8_WIRE_XOR_CONST:
        case GF8_WIRE_LINEAR_MAP:
        case GF8_WIRE_SQUARE:
            if (e->a >= n_wires)
                return -1;
            break;
        default:
            break;
        }
    }
    for (size_t ci = 0; ci < n_constraints; ci++) {
        const gf8_constraint_entry_t *c = &constraints[ci];
        switch (c->kind) {
        case GF8_CONSTRAINT_PRODUCT:
            if (c->a >= n_wires || c->b >= n_wires || c->c >= n_wires)
                return -1;
            break;
        case GF8_CONSTRAINT_EQUAL:
            if (c->a >= n_wires || c->b >= n_wires)
                return -1;
            break;
        case GF8_CONSTRAINT_ZERO:
            if (c->a >= n_wires)
                return -1;
            break;
        }
    }

    /* ell * 8 must not wrap before it feeds the Q_T column count. */
    if (ell > (SIZE_MAX - 2u * (size_t)lambda) / 8u)
        return -1;
    size_t n_bit_cols = ell * 8u + 2u * (size_t)lambda;

    bit_keys = calloc(n_wires, (size_t)8 * nb);
    if (!bit_keys)
        goto oom;

    Q_T = gf8v_transpose_matrix(Q, lambda, nb, n_bit_cols);
    if (!Q_T)
        goto oom;

    /* Precompute α_8 in GF(2^λ) */
    uint8_t alpha8[32] = {0};
    {
        uint8_t x[8] = {0, 1, 0, 0, 0, 0, 0, 0};
        voleith_byte_combine(alpha8, x, (int)lambda);
    }

    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};

    /* ------------------------------------------------------------------
     * Step 1: Compute bit_keys[w][i] for each wire w, bit i.
     *
     * WITNESS slot s: bit_keys[w][i] = Q_T[(s*8+i)*nb] XOR d_bit_i * Δ
     *   where d_bit_i = (d[s] >> i) & 1
     * MUL slot s: same
     * INSTANCE/CONST: bit_keys[w][i] = ((public_val >> i) & 1) * Δ
     * XOR, XOR_CONST, LINEAR_MAP, SQUARE: derived by linearity
     * ------------------------------------------------------------------ */
    {
        size_t witness_idx = 0;
        size_t instance_idx = 0;
        size_t mul_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const gf8_wire_entry_t *e = &wires[w];
            uint8_t *bk_w = bit_keys + w * 8 * nb;

            switch (e->kind) {
            case GF8_WIRE_WITNESS: {
                size_t slot = witness_idx++;
                uint8_t d_byte = d[slot];
                for (unsigned int i = 0; i < 8; i++) {
                    memcpy(bk_w + i * nb, Q_T + (slot * 8 + i) * nb, nb);
                    if ((d_byte >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF8_WIRE_MUL: {
                size_t slot = n_witness + mul_idx++;
                uint8_t d_byte = d[slot];
                for (unsigned int i = 0; i < 8; i++) {
                    memcpy(bk_w + i * nb, Q_T + (slot * 8 + i) * nb, nb);
                    if ((d_byte >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF8_WIRE_INSTANCE: {
                uint8_t v = instance[instance_idx++];
                for (unsigned int i = 0; i < 8; i++) {
                    if ((v >> i) & 1u)
                        memcpy(bk_w + i * nb, delta, nb);
                    else
                        memset(bk_w + i * nb, 0, nb);
                }
                break;
            }
            case GF8_WIRE_CONST: {
                uint8_t v = e->const_val;
                for (unsigned int i = 0; i < 8; i++) {
                    if ((v >> i) & 1u)
                        memcpy(bk_w + i * nb, delta, nb);
                    else
                        memset(bk_w + i * nb, 0, nb);
                }
                break;
            }
            case GF8_WIRE_XOR: {
                const uint8_t *bk_a = bit_keys + e->a * 8 * nb;
                const uint8_t *bk_b = bit_keys + e->b * 8 * nb;
                for (unsigned int i = 0; i < 8; i++)
                    for (unsigned int k = 0; k < nb; k++)
                        bk_w[i * nb + k] = bk_a[i * nb + k] ^ bk_b[i * nb + k];
                break;
            }
            case GF8_WIRE_XOR_CONST: {
                uint8_t kval = e->const_val;
                const uint8_t *bk_a = bit_keys + e->a * 8 * nb;
                for (unsigned int i = 0; i < 8; i++) {
                    memcpy(bk_w + i * nb, bk_a + i * nb, nb);
                    if ((kval >> i) & 1u) {
                        for (unsigned int k = 0; k < nb; k++)
                            bk_w[i * nb + k] ^= delta[k];
                    }
                }
                break;
            }
            case GF8_WIRE_LINEAR_MAP:
                gf8v_apply_linear_map(bk_w, bit_keys + e->a * 8 * nb, e->matrix,
                                      nb);
                break;

            case GF8_WIRE_SQUARE: {
                static const uint8_t SQ[8] = {0x51, 0xD0, 0x22, 0xF0,
                                              0x94, 0x60, 0x28, 0xC0};
                gf8v_apply_linear_map(bk_w, bit_keys + e->a * 8 * nb, SQ, nb);
                break;
            }
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 2: Accumulate gate checks into zk_hash.
     *
     * For each MUL gate / PRODUCT constraint:
     *   key[w] = ByteCombine(bit_keys[w])
     *   contrib = key[a] * key[b] + key[c]
     * ------------------------------------------------------------------ */
    gf8v_zk_hash_ctx bctx;
    gf8v_zk_hash_init(&bctx, chall_2, lambda);

    {
        uint8_t key_a[32], key_b[32], key_c[32];
        uint8_t prod[32], contrib[32];

        /* MUL gates */
        for (size_t w = 0; w < n_wires; w++) {
            const gf8_wire_entry_t *e = &wires[w];
            if (e->kind != GF8_WIRE_MUL)
                continue;

            gf8v_byte_combine(key_a, bit_keys + e->a * 8 * nb, nb, lambda,
                              alpha8);
            gf8v_byte_combine(key_b, bit_keys + e->b * 8 * nb, nb, lambda,
                              alpha8);
            gf8v_byte_combine(key_c, bit_keys + w * 8 * nb, nb, lambda, alpha8);

            gf8v_gf_mul(prod, key_a, key_b, lambda);
            for (unsigned int k = 0; k < nb; k++)
                contrib[k] = prod[k] ^ key_c[k];
            gf8v_zk_hash_update(&bctx, contrib, tmp1, tmp2);
        }

        /* Constraints */
        for (size_t ci = 0; ci < n_constraints; ci++) {
            const gf8_constraint_entry_t *c = &constraints[ci];

            switch (c->kind) {
            case GF8_CONSTRAINT_PRODUCT: {
                gf8v_byte_combine(key_a, bit_keys + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8v_byte_combine(key_b, bit_keys + c->b * 8 * nb, nb, lambda,
                                  alpha8);
                gf8v_byte_combine(key_c, bit_keys + c->c * 8 * nb, nb, lambda,
                                  alpha8);
                gf8v_gf_mul(prod, key_a, key_b, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    contrib[k] = prod[k] ^ key_c[k];
                gf8v_zk_hash_update(&bctx, contrib, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_ZERO: {
                gf8v_byte_combine(key_a, bit_keys + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8v_zk_hash_update(&bctx, key_a, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_EQUAL: {
                gf8v_byte_combine(key_a, bit_keys + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8v_byte_combine(key_b, bit_keys + c->b * 8 * nb, nb, lambda,
                                  alpha8);
                for (unsigned int k = 0; k < nb; k++)
                    key_a[k] ^= key_b[k];
                gf8v_zk_hash_update(&bctx, key_a, tmp1, tmp2);
                break;
            }
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 3: Compute q_star correction from Q bits beyond ell*8.
     *
     * q_star_0 = sum_poly(Q cols ell*8 .. ell*8+lambda-1)
     * q_star_1 = sum_poly(Q cols ell*8+lambda .. ell*8+2*lambda-1)
     * q_star = q_star_0 + Δ * q_star_1
     * ------------------------------------------------------------------ */
    uint8_t q_star[32];
    {
        uint8_t q_star_0[32], q_star_1[32], delta_q1[32];
        size_t corr_start = ell * 8;
        gf8v_sum_poly_cols(q_star_0, tmp1, Q_T, lambda, nb, corr_start, lambda);
        gf8v_sum_poly_cols(q_star_1, tmp1, Q_T, lambda, nb, corr_start + lambda,
                           lambda);
        gf8v_gf_mul(delta_q1, delta, q_star_1, lambda);
        for (unsigned int k = 0; k < nb; k++)
            q_star[k] = q_star_0[k] ^ delta_q1[k];
    }

    /* ------------------------------------------------------------------
     * Step 4: Finalize zk_hash to get q_tilde.
     * ------------------------------------------------------------------ */
    uint8_t q_tilde[32];
    gf8v_zk_hash_finalize(q_tilde, &bctx, q_star, chall_2, tmp1, tmp2);
    voleith_secure_zero(&bctx, sizeof(bctx));

    /* ------------------------------------------------------------------
     * Step 5: a0_tilde_out = q_tilde + Δ*a1_tilde + Δ²*a2_tilde
     * ------------------------------------------------------------------ */
    {
        uint8_t delta_sq[32], term1[32], term2[32];
        gf8v_gf_mul(delta_sq, delta, delta, lambda);
        gf8v_gf_mul(term1, delta, a1_tilde, lambda);
        gf8v_gf_mul(term2, delta_sq, a2_tilde, lambda);
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
