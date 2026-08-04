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
#include "qs_degree.h"
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
 * Less-than (NLT) constraint: evaluate rho_NLT(delta) over keys and push one
 * value (GF(2^16) mirror of gf8v_accumulate_lt, §18.1).
 *   eq_i(delta) = key_a ^ key_b ^ delta
 *   gt_i(delta) = key_a * (key_b ^ delta)
 *   G = sum_i delta^(w-1-i) * gt_i * prefix_i + delta * prod_all eq
 * ===================================================================== */
static void
gf16v_accumulate_lt(gf16v_zk_hash_ctx *bctx, const gf16_lt_entry_t *lt,
                    const gf16_wire_id *bits, const uint8_t *bit_keys,
                    const uint8_t *delta, unsigned int lambda, unsigned int nb,
                    const uint8_t *beta, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = lt->width;
    uint8_t dpow[VOLEITH_QS_COEFFS_MAX][32];
    memset(dpow[0], 0, nb);
    dpow[0][0] = 0x01; /* GF(2^lambda) one */
    for (unsigned int i = 1; i <= w; i++)
        gf16v_gf_mul(dpow[i], dpow[i - 1], delta, lambda);

    uint8_t prefix[32], G[32], key_a[32], key_b[32], nbv[32], gt[32], t[32];
    memset(G, 0, nb);
    memset(prefix, 0, nb);
    prefix[0] = 0x01;

    for (unsigned int i = 0; i < w; i++) {
        gf16v_word_combine(key_a,
                           bit_keys + (size_t)bits[i] * GF16_ELEM_BITS * nb, nb,
                           lambda, beta);
        gf16v_word_combine(key_b,
                           bit_keys + (size_t)bits[w + i] * GF16_ELEM_BITS * nb,
                           nb, lambda, beta);
        for (unsigned int k = 0; k < nb; k++)
            nbv[k] = key_b[k] ^ delta[k];
        gf16v_gf_mul(gt, key_a, nbv, lambda);
        gf16v_gf_mul(t, gt, prefix, lambda);
        gf16v_gf_mul(tmp1, t, dpow[w - 1 - i], lambda);
        for (unsigned int k = 0; k < nb; k++)
            G[k] ^= tmp1[k];
        for (unsigned int k = 0; k < nb; k++)
            tmp2[k] = key_a[k] ^ key_b[k] ^ delta[k];
        gf16v_gf_mul(tmp1, prefix, tmp2, lambda);
        memcpy(prefix, tmp1, nb);
    }
    gf16v_gf_mul(t, prefix, dpow[1], lambda);
    for (unsigned int k = 0; k < nb; k++)
        G[k] ^= t[k];

    gf16v_zk_hash_update(bctx, G, tmp1, tmp2);
}

/* Lever 1 demux tree, GF(2^16) verifier (twin of gf8v_demux_fold). */
static void
gf16v_demux_fold(unsigned int depth, unsigned int w, uint32_t prefix,
                 const uint8_t *facbuf, const uint8_t *node, const uint8_t *R,
                 uint32_t n, unsigned int lambda, unsigned int nb, uint8_t *G,
                 uint8_t *tmp)
{
    if (depth == w) {
        if (prefix < n) {
            gf16v_gf_mul(tmp, R + (size_t)prefix * nb, node, lambda);
            for (unsigned int m = 0; m < nb; m++)
                G[m] ^= tmp[m];
        }
        return;
    }
    uint8_t child[32];
    for (unsigned int bit = 0; bit < 2; bit++) {
        const uint8_t *fac = facbuf + ((size_t)(depth * 2u + bit)) * 32u;
        gf16v_gf_mul(child, node, fac, lambda);
        gf16v_demux_fold(depth + 1u, w, (prefix << 1) | bit, facbuf, child, R,
                         n, lambda, nb, G, tmp);
    }
}

/* =====================================================================
 * Syndrome constraint (GF(2^16) twin of gf8v_accumulate_syndrome):
 * Horner/circulant COLLAPSED verifier.  Push one scalar
 *   G = sum_k sum_i R_i * E_i^{(k)}(delta) + delta^(w-1) * sum_j s^j * key_{s_j}
 * with R_i = sum_{j:M[j,i]=1} s^j (s = bctx->s) and E_i^{(k)}(delta) =
 * prod_b factor_b, factor_b = bit? key_b : key_b ^ delta.  Returns 0, -1 on OOM.
 * ===================================================================== */
static int
gf16v_accumulate_syndrome(gf16v_zk_hash_ctx *bctx,
                          const gf16_syndrome_entry_t *sy,
                          const gf16_wire_id *sbits, const uint8_t *bit_keys,
                          const uint8_t *delta, unsigned int lambda,
                          unsigned int nb, const uint8_t *beta, uint8_t *tmp1,
                          uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf16_wire_id *idx = sbits + sy->idx_off;
    const gf16_wire_id *swires = sbits + sy->s_off;

    uint8_t dpow_w1[32]; /* delta^(w-1) */
    memset(dpow_w1, 0, nb);
    dpow_w1[0] = 0x01;
    for (unsigned int i = 1; i < w; i++) {
        gf16v_gf_mul(tmp1, dpow_w1, delta, lambda);
        memcpy(dpow_w1, tmp1, nb);
    }

    uint8_t *pow_s = calloc((size_t)p, nb);
    uint8_t *R = calloc((size_t)n, nb);
    uint8_t *facbuf = calloc((size_t)w * 2u, 32); /* [b][line][32] */
    if (!pow_s || !R || !facbuf) {
        free(pow_s);
        free(R);
        free(facbuf);
        return -1;
    }

    pow_s[0] = 0x01;
    for (uint32_t u = 1; u < p; u++)
        gf16v_gf_mul(pow_s + (size_t)u * nb, pow_s + (size_t)(u - 1) * nb,
                     bctx->s, lambda);

    {
        uint8_t *Rid = R + (size_t)(sy->n0 - 1u) * p * nb;
        for (uint32_t l = 0; l < p; l++)
            memcpy(Rid + (size_t)l * nb, pow_s + (size_t)l * nb, nb);
        for (uint32_t b = 0; b + 1u < sy->n0; b++) {
            const uint8_t *mb = sy->M + (size_t)b * block_bytes;
            uint8_t *Rb = R + (size_t)b * p * nb;
            for (uint32_t a = 0; a < p; a++) {
                if (!((mb[a >> 3] >> (a & 7u)) & 1u))
                    continue;
                for (uint32_t l = 0; l < p; l++) {
                    uint32_t u = (l + a) % p;
                    uint8_t *rl = Rb + (size_t)l * nb;
                    const uint8_t *pu = pow_s + (size_t)u * nb;
                    for (unsigned int m = 0; m < nb; m++)
                        rl[m] ^= pu[m];
                }
            }
        }
    }

    uint8_t G[32];
    memset(G, 0, nb);
    uint8_t node1[32];
    memset(node1, 0, nb);
    node1[0] = 0x01;
    for (uint32_t k = 0; k < sy->t; k++) {
        for (unsigned int b = 0; b < w; b++) {
            uint8_t *l1 = facbuf + ((size_t)(b * 2u + 1u)) * 32u;
            uint8_t *l0 = facbuf + ((size_t)(b * 2u + 0u)) * 32u;
            gf16v_word_combine(l1,
                               bit_keys + (size_t)idx[(size_t)k * w + b] *
                                              GF16_ELEM_BITS * nb,
                               nb, lambda, beta);
            for (unsigned int m = 0; m < nb; m++)
                l0[m] = (uint8_t)(l1[m] ^ delta[m]);
        }
        gf16v_demux_fold(0, w, 0, facbuf, node1, R, n, lambda, nb, G, tmp1);
    }

    {
        uint8_t Sig[32], key_s[32];
        memset(Sig, 0, nb);
        for (uint32_t j = 0; j < p; j++) {
            gf16v_word_combine(
                key_s, bit_keys + (size_t)swires[j] * GF16_ELEM_BITS * nb, nb,
                lambda, beta);
            gf16v_gf_mul(tmp1, pow_s + (size_t)j * nb, key_s, lambda);
            for (unsigned int m = 0; m < nb; m++)
                Sig[m] ^= tmp1[m];
        }
        gf16v_gf_mul(tmp2, dpow_w1, Sig, lambda);
        for (unsigned int m = 0; m < nb; m++)
            G[m] ^= tmp2[m];
    }

    gf16v_zk_hash_update(bctx, G, tmp1, tmp2);

    free(pow_s);
    free(R);
    free(facbuf);
    return 0;
}

/* Test-only mode flag: defined in gf16_prover.c (shared prover+verifier). */
extern int voleith_gf16_syndrome_ref_mode;

/*
 * Reference syndrome verifier (pre-collapse): push p scalars, one per syndrome
 * bit.  The collapsed verifier is cross-checked against it.  Returns 0, -1 OOM.
 */
static int
gf16v_accumulate_syndrome_ref(gf16v_zk_hash_ctx *bctx,
                              const gf16_syndrome_entry_t *sy,
                              const gf16_wire_id *sbits,
                              const uint8_t *bit_keys, const uint8_t *delta,
                              unsigned int lambda, unsigned int nb,
                              const uint8_t *beta, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf16_wire_id *idx = sbits + sy->idx_off;
    const gf16_wire_id *swires = sbits + sy->s_off;

    uint8_t dpow_w1[32];
    memset(dpow_w1, 0, nb);
    dpow_w1[0] = 0x01;
    for (unsigned int i = 1; i < w; i++) {
        gf16v_gf_mul(tmp1, dpow_w1, delta, lambda);
        memcpy(dpow_w1, tmp1, nb);
    }

    uint8_t *G = calloc((size_t)p, nb);
    uint8_t *keys = calloc((size_t)w, 32);
    if (!G || !keys) {
        free(G);
        free(keys);
        return -1;
    }

    uint8_t E[32], fac[32];
    for (uint32_t k = 0; k < sy->t; k++) {
        for (unsigned int b = 0; b < w; b++)
            gf16v_word_combine(keys + (size_t)b * 32,
                               bit_keys + (size_t)idx[(size_t)k * w + b] *
                                              GF16_ELEM_BITS * nb,
                               nb, lambda, beta);

        for (uint32_t i = 0; i < n; i++) {
            unsigned int bit0 = (i >> (w - 1u)) & 1u;
            const uint8_t *k0 = keys + 0;
            if (bit0)
                memcpy(E, k0, nb);
            else
                for (unsigned int m = 0; m < nb; m++)
                    E[m] = k0[m] ^ delta[m];
            for (unsigned int b = 1; b < w; b++) {
                unsigned int bitb = (i >> (w - 1u - b)) & 1u;
                const uint8_t *kb = keys + (size_t)b * 32;
                if (bitb) {
                    memcpy(fac, kb, nb);
                } else {
                    for (unsigned int m = 0; m < nb; m++)
                        fac[m] = kb[m] ^ delta[m];
                }
                gf16v_gf_mul(tmp1, E, fac, lambda);
                memcpy(E, tmp1, nb);
            }
            uint32_t b_col = i / p;
            uint32_t l = i % p;
            if (b_col == sy->n0 - 1u) {
                uint8_t *gj = G + (size_t)l * nb;
                for (unsigned int m = 0; m < nb; m++)
                    gj[m] ^= E[m];
            } else {
                const uint8_t *mb = sy->M + (size_t)b_col * block_bytes;
                for (uint32_t a = 0; a < p; a++) {
                    if (!((mb[a >> 3] >> (a & 7u)) & 1u))
                        continue;
                    uint8_t *gj = G + (size_t)((l + a) % p) * nb;
                    for (unsigned int m = 0; m < nb; m++)
                        gj[m] ^= E[m];
                }
            }
        }
    }

    for (uint32_t j = 0; j < p; j++) {
        uint8_t key_s[32];
        uint8_t *gj = G + (size_t)j * nb;
        gf16v_word_combine(key_s,
                           bit_keys + (size_t)swires[j] * GF16_ELEM_BITS * nb,
                           nb, lambda, beta);
        gf16v_gf_mul(tmp2, key_s, dpow_w1, lambda);
        for (unsigned int m = 0; m < nb; m++)
            gj[m] ^= tmp2[m];
        gf16v_zk_hash_update(bctx, gj, tmp1, tmp2);
    }

    free(G);
    free(keys);
    return 0;
}

/* =====================================================================
 * Main verifier
 * ===================================================================== */

int
voleith_gf16_qs_verify(const voleith_gf16_circuit_t *circuit,
                       const voleith_gf16_t *instance, unsigned int lambda,
                       const uint8_t **Q, const uint8_t *d,
                       const uint8_t *delta, const uint8_t *chall_2,
                       const uint8_t *const *a_in, uint8_t *a0_tilde_out)
{
    if (!circuit || !Q || !d || !delta || !chall_2 || !a_in || !a0_tilde_out)
        return -1;
    if (voleith_gf16_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    /* Opening count d = max constraint degree (2 today; opener raises it).
     * a_in[i] = coefficient a_i for i = 1..deg (a_in[0] unused).  Validate
     * before any allocation so a null buffer returns directly. */
    unsigned int deg = voleith_gf16_circuit_qs_degree(circuit);
    if (deg > VOLEITH_QS_D_MAX)
        return -1;
    for (unsigned int i = 1; i <= deg; i++)
        if (!a_in[i])
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

    /* ell * 16 must not wrap; correction region is deg mask blocks (was
     * 2*lambda, d=2 only). */
    if (ell > (SIZE_MAX - (size_t)deg * lambda) / GF16_ELEM_BITS)
        return -1;
    size_t n_bit_cols = ell * GF16_ELEM_BITS + (size_t)deg * lambda;

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

    /* Less-than (NLT) constraints: evaluate rho_NLT(delta) and push.  Bounds-
     * check the bit pool here for primitive-level memory safety. */
    {
        size_t n_lt = voleith_gf16_circuit_lt_count(circuit);
        const gf16_lt_entry_t *lts =
            voleith_gf16_circuit_lt_constraints(circuit);
        const gf16_wire_id *lt_bits = voleith_gf16_circuit_lt_bits(circuit);
        for (size_t li = 0; li < n_lt; li++) {
            unsigned int w = lts[li].width;
            const gf16_wire_id *bits = lt_bits + lts[li].bits_off;
            /* INFO-3 defense in depth: reject a zero or over-wide LT here, at
             * the untrusted-input boundary, before gf16v_accumulate_lt indexes
             * its fixed [VOLEITH_QS_COEFFS_MAX] dpow scratch to delta^w. */
            if (w == 0 || w > VOLEITH_QS_D_MAX - 1u) {
                free(Q_T);
                free(bit_keys);
                return -1;
            }
            for (unsigned int j = 0; j < 2u * w; j++)
                if (bits[j] >= n_wires) {
                    free(Q_T);
                    free(bit_keys);
                    return -1;
                }
            gf16v_accumulate_lt(&bctx, &lts[li], bits, bit_keys, delta, lambda,
                                nb, beta, tmp1, tmp2);
        }
    }

    /* Syndrome constraints (s = M*e^T): degree-idx_bits family, evaluated over
     * the keys and pushed into the same zk_hash.  Bounds-check the pool. */
    {
        size_t n_syn = voleith_gf16_circuit_syndrome_count(circuit);
        const gf16_syndrome_entry_t *syn =
            voleith_gf16_circuit_syndrome_constraints(circuit);
        const gf16_wire_id *syn_bits =
            voleith_gf16_circuit_syndrome_bits(circuit);
        for (size_t si = 0; si < n_syn; si++) {
            const gf16_syndrome_entry_t *sy = &syn[si];
            size_t cnt = (size_t)sy->t * sy->idx_bits + (size_t)sy->p;
            /* INFO-3 defense in depth: over-wide idx_bits would overrun the
             * accumulator's fixed [VOLEITH_QS_COEFFS_MAX] scratch; reject here. */
            int bad = (sy->t == 0 || sy->idx_bits == 0 || sy->p == 0 ||
                       sy->n0 == 0 || sy->idx_bits > VOLEITH_QS_D_MAX - 1u);
            for (size_t j = 0; !bad && j < cnt; j++)
                if (syn_bits[sy->idx_off + j] >= n_wires)
                    bad = 1;
            int vrc = bad ? -1
                      : voleith_gf16_syndrome_ref_mode
                          ? gf16v_accumulate_syndrome_ref(
                                &bctx, sy, syn_bits, bit_keys, delta, lambda,
                                nb, beta, tmp1, tmp2)
                          : gf16v_accumulate_syndrome(&bctx, sy, syn_bits,
                                                      bit_keys, delta, lambda,
                                                      nb, beta, tmp1, tmp2);
            if (vrc != 0) {
                free(Q_T);
                free(bit_keys);
                return -1;
            }
        }
    }

    /* Step 3: q_star correction over d mask blocks (QS_DEGREE_D_DESIGN section
     * 11): q_star = sum_{j=0..d-1} delta^j * q_star_j.  At d=2: q_star_0 +
     * delta * q_star_1. */
    /* deg (opening count) was derived from qs_degree at entry. */
    uint8_t q_star[32];
    {
        uint8_t q_star_j[32], delta_pow[32], term[32];
        size_t corr_start = ell * GF16_ELEM_BITS;

        gf16v_sum_poly_cols(q_star, tmp1, Q_T, lambda, nb, corr_start, lambda);
        if (deg > 1)
            memcpy(delta_pow, delta, nb); /* delta^1 */
        for (unsigned int j = 1; j < deg; j++) {
            gf16v_sum_poly_cols(q_star_j, tmp1, Q_T, lambda, nb,
                                corr_start + (size_t)j * lambda, lambda);
            gf16v_gf_mul(term, delta_pow, q_star_j, lambda);
            for (unsigned int k = 0; k < nb; k++)
                q_star[k] ^= term[k];
            if (j + 1 < deg)
                gf16v_gf_mul(delta_pow, delta_pow, delta, lambda);
        }
    }

    /* Step 4: finalize zk_hash to get q_tilde. */
    uint8_t q_tilde[32];
    gf16v_zk_hash_finalize(q_tilde, &bctx, q_star, chall_2, tmp1, tmp2);
    voleith_secure_zero(&bctx, sizeof(bctx));

    /* Step 5: a0_tilde_out = q_tilde + sum_{i=1..d} delta^i * a_i_tilde
     * (at d=2: + delta*a1 + delta^2*a2; a_i for i>2 arrive via serialization). */
    {
        uint8_t delta_pow[32], term[32];

        memcpy(a0_tilde_out, q_tilde, nb);
        memcpy(delta_pow, delta, nb); /* delta^1 */
        for (unsigned int i = 1; i <= deg; i++) {
            gf16v_gf_mul(term, delta_pow, a_in[i], lambda);
            for (unsigned int k = 0; k < nb; k++)
                a0_tilde_out[k] ^= term[k];
            if (i < deg)
                gf16v_gf_mul(delta_pow, delta_pow, delta, lambda);
        }
    }

    free(Q_T);
    free(bit_keys);
    return 0;

oom:
    free(Q_T);
    free(bit_keys);
    return -1;
}
