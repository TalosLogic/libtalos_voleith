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
 * zk_hash context: d+1 accumulators, one per opened coefficient of a degree-d
 * constraint (ctx->d; QS_DEGREE_D_DESIGN section 11).  Field-agnostic, mirrors
 * gf8/base; "_3" is historical (the d=2 case has 3 streams).
 * ===================================================================== */

typedef struct {
    uint8_t h0[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t h1[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
    unsigned int d; /* constraint degree; streams 0..d are live */
} gf16p_zk_hash_3_ctx;

static void
gf16p_zk_hash_3_init(gf16p_zk_hash_3_ctx *ctx, const uint8_t *chall_2,
                     unsigned int lambda, unsigned int d)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    ctx->d = d;
    memset(ctx->h0, 0, sizeof(ctx->h0));
    memset(ctx->h1, 0, sizeof(ctx->h1));
    memcpy(ctx->s, chall_2 + 2 * nb, nb);
    memset(ctx->t, 0, nb);
    unsigned int t_bytes = (nb < 8) ? nb : 8;
    memcpy(ctx->t, chall_2 + 3 * nb, t_bytes);
}

/*
 * v[i] is the coefficient of delta^i (v[0] = degree-0); streams i in 0..d are
 * all folded, with v_i = 0 for i >= nv so a lower-degree constraint zero-pads
 * its high-power coefficients (Horner s/t powers must advance on every stream).
 */
static void
gf16p_zk_hash_3_update(gf16p_zk_hash_3_ctx *ctx, const uint8_t *const *v,
                       unsigned int nv, uint8_t *tmp1, uint8_t *tmp2)
{
    static const uint8_t zero[32] = {0};
    unsigned int nb = ctx->lambda / 8;
    for (unsigned int i = 0; i <= ctx->d; i++) {
        const uint8_t *vi = (i < nv) ? v[i] : zero;
        gf16p_gf_mul(tmp1, ctx->h0[i], ctx->s, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h0[i][k] = tmp1[k] ^ vi[k];
        gf16p_gf_mul(tmp2, ctx->h1[i], ctx->t, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h1[i][k] = tmp2[k] ^ vi[k];
    }
}

static void
gf16p_zk_hash_3_finalize(uint8_t *const *a_tilde,
                         const gf16p_zk_hash_3_ctx *ctx,
                         const uint8_t *const *x1, const uint8_t *chall_2,
                         uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    for (unsigned int i = 0; i <= ctx->d; i++) {
        gf16p_gf_mul(tmp1, r0, ctx->h0[i], ctx->lambda);
        gf16p_gf_mul(tmp2, r1, ctx->h1[i], ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            a_tilde[i][k] = tmp1[k] ^ tmp2[k] ^ x1[i][k];
    }
}

/* =====================================================================
 * Less-than (NLT) degree-(w+1) constraint (GF(2^16) mirror of the gf8
 * gadget; see gf8_prover.c / QS_DEGREE_D_DESIGN §18.1).  Asserts A<B by
 * committing NLT = [A>=B] = 0.  Each wire is a line L(X)=tag+emb(val)*X; the
 * public constant 1 is [0, one] with one=embed(1).  Terms are top-aligned to
 * X^(w+1); rho[0..w] pushed, rho[w+1] (value) omitted.
 * ===================================================================== */
static void
gf16p_poly_mul(uint8_t out[][32], const uint8_t a[][32], unsigned int da,
               const uint8_t b[][32], unsigned int db, unsigned int lambda,
               unsigned int nb, uint8_t *tmp)
{
    for (unsigned int i = 0; i <= da + db; i++)
        memset(out[i], 0, nb);
    for (unsigned int i = 0; i <= da; i++)
        for (unsigned int j = 0; j <= db; j++) {
            gf16p_gf_mul(tmp, a[i], b[j], lambda);
            for (unsigned int k = 0; k < nb; k++)
                out[i + j][k] ^= tmp[k];
        }
}

static int
gf16p_accumulate_lt(gf16p_zk_hash_3_ctx *hasher, const gf16_lt_entry_t *lt,
                    const gf16_wire_id *bits, const uint8_t *bit_tags,
                    const voleith_gf16_t *wire_vals, unsigned int lambda,
                    unsigned int nb, const uint8_t *beta, uint8_t *tmp1,
                    uint8_t *tmp2)
{
    unsigned int w = lt->width;

    /* INFO-3 defense in depth: the fixed [VOLEITH_QS_COEFFS_MAX] coefficient
     * scratch below is indexed by the per-entry width w (up to w+1); bound w
     * locally so a degree-array overrun is impossible even if the aggregate
     * qs_degree guard in qs_prove_impl were ever bypassed.  Unreachable on
     * shipped circuits (w = idx_bits <= 17).  Real check (survives -DNDEBUG),
     * not an assert. */
    if (w > VOLEITH_QS_D_MAX - 1u)
        return -1;

    uint8_t one[32];
    gf16p_embed(one, 1, lambda);

    uint8_t rho[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t prefix[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t prefix_next[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t gt[3][32];
    uint8_t term[VOLEITH_QS_COEFFS_MAX][32];
    for (unsigned int k = 0; k <= w + 1; k++)
        memset(rho[k], 0, nb);

    memcpy(prefix[0], one, nb);
    unsigned int prefix_deg = 0;

    for (unsigned int i = 0; i < w; i++) {
        const uint8_t *bt_a = bit_tags + (size_t)bits[i] * GF16_ELEM_BITS * nb;
        const uint8_t *bt_b =
            bit_tags + (size_t)bits[w + i] * GF16_ELEM_BITS * nb;
        uint8_t ta[32], ea[32], tb[32], eb[32], nb_c1[32];
        gf16p_word_combine(ta, bt_a, nb, lambda, beta);
        gf16p_word_combine(tb, bt_b, nb, lambda, beta);
        gf16p_embed(ea, wire_vals[bits[i]], lambda);
        gf16p_embed(eb, wire_vals[bits[w + i]], lambda);
        for (unsigned int k = 0; k < nb; k++)
            nb_c1[k] = one[k] ^ eb[k];

        gf16p_gf_mul(gt[0], ta, tb, lambda);
        gf16p_gf_mul(gt[1], ta, nb_c1, lambda);
        gf16p_gf_mul(tmp1, ea, tb, lambda);
        for (unsigned int k = 0; k < nb; k++)
            gt[1][k] ^= tmp1[k];
        gf16p_gf_mul(gt[2], ea, nb_c1, lambda);

        gf16p_poly_mul(term, gt, 2, prefix, prefix_deg, lambda, nb, tmp2);
        unsigned int tdeg = prefix_deg + 2;
        unsigned int shift = (w + 1) - tdeg;
        for (unsigned int k = 0; k <= tdeg; k++)
            for (unsigned int m = 0; m < nb; m++)
                rho[shift + k][m] ^= term[k][m];

        uint8_t eq[2][32];
        for (unsigned int k = 0; k < nb; k++) {
            eq[0][k] = ta[k] ^ tb[k];
            eq[1][k] = one[k] ^ ea[k] ^ eb[k];
        }
        gf16p_poly_mul(prefix_next, prefix, prefix_deg, eq, 1, lambda, nb,
                       tmp1);
        prefix_deg += 1;
        for (unsigned int k = 0; k <= prefix_deg; k++)
            memcpy(prefix[k], prefix_next[k], nb);
    }

    for (unsigned int k = 0; k <= w; k++)
        for (unsigned int m = 0; m < nb; m++)
            rho[1 + k][m] ^= prefix[k][m];

    const uint8_t *vv[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int k = 0; k <= w; k++)
        vv[k] = rho[k];
    gf16p_zk_hash_3_update(hasher, vv, w + 1, tmp1, tmp2);

    voleith_secure_zero(rho, sizeof(rho));
    voleith_secure_zero(prefix, sizeof(prefix));
    voleith_secure_zero(prefix_next, sizeof(prefix_next));
    voleith_secure_zero(term, sizeof(term));
    voleith_secure_zero(gt, sizeof(gt));
    return 0;
}

/* Lever 1 demux tree, GF(2^16) prover (twin of gf8p_demux_fold). */
static void
gf16p_demux_fold(unsigned int depth, unsigned int w, uint32_t prefix,
                 const uint8_t *facbuf, const uint8_t node[][32],
                 unsigned int nodedeg, const uint8_t *R, uint32_t n,
                 unsigned int lambda, unsigned int nb, uint8_t G[][32],
                 uint8_t *tmp)
{
    if (depth == w) {
        if (prefix < n) {
            const uint8_t *Ri = R + (size_t)prefix * nb;
            for (unsigned int c = 0; c <= w; c++) {
                gf16p_gf_mul(tmp, Ri, node[c], lambda);
                for (unsigned int m = 0; m < nb; m++)
                    G[c][m] ^= tmp[m];
            }
        }
        return;
    }
    uint8_t child[VOLEITH_QS_COEFFS_MAX][32];
    for (unsigned int bit = 0; bit < 2; bit++) {
        const uint8_t(*line)[32] = (const uint8_t(*)[32])(
            facbuf + ((size_t)(depth * 2u + bit)) * 2u * 32u);
        gf16p_poly_mul(child, node, nodedeg, line, 1, lambda, nb, tmp);
        gf16p_demux_fold(depth + 1u, w, (prefix << 1) | bit, facbuf, child,
                         nodedeg + 1u, R, n, lambda, nb, G, tmp);
    }
}

/* =====================================================================
 * Syndrome constraint (GF(2^16) twin of gf8p_accumulate_syndrome):
 * Horner/circulant COLLAPSED prover (QS_DEGREE_D section 8 lever 2).  Push one
 * degree-w (w = idx_bits) vector G = sum_k sum_i R_i * E_i^{(k)}, with the
 * per-column weight R_i = sum_{j:M[j,i]=1} s^j (identity block s^l; non-identity
 * block the cyclic sum of pow_s[u]=s^u; s = hasher->s), removing the per-column
 * M-row scatter.  Value coeff w omitted; the public s_j folds into it as
 * sum_j s^j s_j, so the assert-zero is sum_j s^j (synd_j ^ s_j) = 0 (sound to
 * (p-1)/2^lambda, the same Schwartz-Zippel bound the reference zk_hash used).
 * Returns 0 on success, -1 on OOM.
 * ===================================================================== */
static int
gf16p_accumulate_syndrome(gf16p_zk_hash_3_ctx *hasher,
                          const gf16_syndrome_entry_t *sy,
                          const gf16_wire_id *sbits, const uint8_t *bit_tags,
                          const voleith_gf16_t *wire_vals, unsigned int lambda,
                          unsigned int nb, const uint8_t *beta, uint8_t *tmp1,
                          uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf16_wire_id *idx = sbits + sy->idx_off;

    uint8_t one[32];
    gf16p_embed(one, 1, lambda);

    /* INFO-3 defense in depth: bound w before it sizes/indexes the fixed
     * [VOLEITH_QS_COEFFS_MAX] scratch (G, demux node/child).  Unreachable on
     * shipped circuits (w = idx_bits <= 17); real check, survives -DNDEBUG. */
    if (w > VOLEITH_QS_D_MAX - 1u)
        return -1;

    uint8_t *pow_s = calloc((size_t)p, nb);
    uint8_t *R = calloc((size_t)n, nb);
    uint8_t *facbuf = calloc((size_t)w * 2u * 2u, 32); /* [b][line][coeff] */
    if (!pow_s || !R || !facbuf) {
        free(pow_s);
        free(R);
        free(facbuf);
        return -1;
    }

    memcpy(pow_s, one, nb);
    for (uint32_t u = 1; u < p; u++)
        gf16p_gf_mul(pow_s + (size_t)u * nb, pow_s + (size_t)(u - 1) * nb,
                     hasher->s, lambda);

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

    uint8_t G[VOLEITH_QS_COEFFS_MAX][32];
    for (unsigned int c = 0; c <= w; c++)
        memset(G[c], 0, nb);

    uint8_t node0[VOLEITH_QS_COEFFS_MAX][32]; /* constant-1 poly (degree 0) */
    memcpy(node0[0], one, nb);

    for (uint32_t k = 0; k < sy->t; k++) {
        for (unsigned int b = 0; b < w; b++) {
            gf16_wire_id wid = idx[(size_t)k * w + b];
            uint8_t tag[32], val[32];
            gf16p_word_combine(tag,
                               bit_tags + (size_t)wid * GF16_ELEM_BITS * nb, nb,
                               lambda, beta);
            gf16p_embed(val, wire_vals[wid], lambda);
            uint8_t *l1 = facbuf + ((size_t)(b * 2u + 1u)) * 2u * 32u;
            uint8_t *l0 = facbuf + ((size_t)(b * 2u + 0u)) * 2u * 32u;
            memcpy(l1, tag, nb);
            memcpy(l1 + 32, val, nb);
            memcpy(l0, tag, nb);
            for (unsigned int m = 0; m < nb; m++)
                l0[32 + m] = (uint8_t)(one[m] ^ val[m]);
        }
        gf16p_demux_fold(0, w, 0, facbuf, node0, 0, R, n, lambda, nb, G, tmp1);
    }

    const uint8_t *vv[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int c = 0; c < w; c++)
        vv[c] = G[c];
    gf16p_zk_hash_3_update(hasher, vv, w, tmp1, tmp2);

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(facbuf, (size_t)w * 2u * 2u * 32u);
    free(pow_s);
    free(R);
    free(facbuf);
    return 0;
}

/* Test-only mode flag (declared in gf16_prover_internal.h): 0 = collapsed,
 * nonzero = reference.  Never set outside tests. */
int voleith_gf16_syndrome_ref_mode = 0;

/*
 * Reference syndrome accumulator (pre-collapse): one degree-w constraint per
 * syndrome bit, pushed p times.  The collapsed prover is cross-checked against
 * it (verdict-level).  Returns 0, -1 on OOM.
 */
static int
gf16p_accumulate_syndrome_ref(gf16p_zk_hash_3_ctx *hasher,
                              const gf16_syndrome_entry_t *sy,
                              const gf16_wire_id *sbits,
                              const uint8_t *bit_tags,
                              const voleith_gf16_t *wire_vals,
                              unsigned int lambda, unsigned int nb,
                              const uint8_t *beta, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf16_wire_id *idx = sbits + sy->idx_off;

    uint8_t one[32];
    gf16p_embed(one, 1, lambda);

    /* INFO-3 defense in depth: bound w before it sizes the rho scratch
     * (p*(w+1)) and indexes the fixed [VOLEITH_QS_COEFFS_MAX] push buffer.
     * Unreachable on shipped circuits (w = idx_bits <= 17); survives -DNDEBUG. */
    if (w > VOLEITH_QS_D_MAX - 1u)
        return -1;

    uint8_t *rho = calloc((size_t)p * (w + 1u), nb);
    uint8_t *tags = calloc((size_t)w, 32);
    uint8_t *vals = calloc((size_t)w, 32);
    if (!rho || !tags || !vals) {
        free(rho);
        free(tags);
        free(vals);
        return -1;
    }

    uint8_t Ecur[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t Enext[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t fac[2][32];

    for (uint32_t k = 0; k < sy->t; k++) {
        for (unsigned int b = 0; b < w; b++) {
            const uint8_t *bt =
                bit_tags + (size_t)idx[(size_t)k * w + b] * GF16_ELEM_BITS * nb;
            gf16p_word_combine(tags + (size_t)b * 32, bt, nb, lambda, beta);
            gf16p_embed(vals + (size_t)b * 32,
                        wire_vals[idx[(size_t)k * w + b]], lambda);
        }

        for (uint32_t i = 0; i < n; i++) {
            unsigned int bit0 = (i >> (w - 1u)) & 1u;
            memcpy(Ecur[0], tags + 0, nb);
            for (unsigned int m = 0; m < nb; m++)
                Ecur[1][m] = bit0 ? vals[m] : (uint8_t)(one[m] ^ vals[m]);
            unsigned int Edeg = 1;
            for (unsigned int b = 1; b < w; b++) {
                unsigned int bitb = (i >> (w - 1u - b)) & 1u;
                memcpy(fac[0], tags + (size_t)b * 32, nb);
                const uint8_t *vb = vals + (size_t)b * 32;
                for (unsigned int m = 0; m < nb; m++)
                    fac[1][m] = bitb ? vb[m] : (uint8_t)(one[m] ^ vb[m]);
                gf16p_poly_mul(Enext, Ecur, Edeg, fac, 1, lambda, nb, tmp1);
                Edeg += 1;
                for (unsigned int c = 0; c <= Edeg; c++)
                    memcpy(Ecur[c], Enext[c], nb);
            }
            uint32_t b_col = i / p;
            uint32_t l = i % p;
            if (b_col == sy->n0 - 1u) {
                uint8_t *rj = rho + (size_t)l * (w + 1u) * nb;
                for (unsigned int c = 0; c <= w; c++)
                    for (unsigned int m = 0; m < nb; m++)
                        rj[(size_t)c * nb + m] ^= Ecur[c][m];
            } else {
                const uint8_t *mb = sy->M + (size_t)b_col * block_bytes;
                for (uint32_t a = 0; a < p; a++) {
                    if (!((mb[a >> 3] >> (a & 7u)) & 1u))
                        continue;
                    uint32_t j = (l + a) % p;
                    uint8_t *rj = rho + (size_t)j * (w + 1u) * nb;
                    for (unsigned int c = 0; c <= w; c++)
                        for (unsigned int m = 0; m < nb; m++)
                            rj[(size_t)c * nb + m] ^= Ecur[c][m];
                }
            }
        }
    }

    const uint8_t *vv[VOLEITH_QS_COEFFS_MAX];
    for (uint32_t j = 0; j < p; j++) {
        const uint8_t *rj = rho + (size_t)j * (w + 1u) * nb;
        for (unsigned int c = 0; c < w; c++)
            vv[c] = rj + (size_t)c * nb;
        gf16p_zk_hash_3_update(hasher, vv, w, tmp1, tmp2);
    }

    voleith_secure_zero(rho, (size_t)p * (w + 1u) * nb);
    voleith_secure_zero(tags, (size_t)w * 32);
    voleith_secure_zero(vals, (size_t)w * 32);
    voleith_secure_zero(Ecur, sizeof(Ecur));
    voleith_secure_zero(Enext, sizeof(Enext));
    free(rho);
    free(tags);
    free(vals);
    return 0;
}

/* =====================================================================
 * Main prover
 * ===================================================================== */

size_t
voleith_gf16_qs_ellhat(const voleith_gf16_circuit_t *circuit,
                       unsigned int lambda)
{
    size_t ell = voleith_gf16_qs_ell(circuit);
    unsigned int d = voleith_gf16_circuit_qs_degree(circuit);
    return 2u * ell + ((d + 1u) * lambda + UNIVERSAL_HASH_B_BITS + 7u) / 8u;
}

static int
gf16_qs_prove_impl(const voleith_gf16_circuit_t *circuit,
                   const voleith_gf16_t *witness,
                   const voleith_gf16_t *instance, unsigned int lambda,
                   const uint8_t *u, const uint8_t **V, const uint8_t *chall_2,
                   uint8_t *d_out, uint8_t *const *a_out, int reject_invalid)
{
    if (!circuit || !witness || !u || !V || !chall_2 || !d_out || !a_out)
        return -1;
    if (voleith_gf16_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    /* Opening count d = max constraint degree in force (2 today; the opener
     * raises it).  a_out[0..d] receive coefficients a_0..a_d.  No allocations
     * yet, so a bad degree / null buffer returns directly. */
    unsigned int d = voleith_gf16_circuit_qs_degree(circuit);
    if (d > VOLEITH_QS_D_MAX)
        return -1;
    for (unsigned int i = 0; i <= d; i++)
        if (!a_out[i])
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
    /* deg mask blocks of lambda columns (x1 staircase); scales with d (was
     * 2*lambda, d=2 only). */
    size_t n_bit_cols = ell * GF16_ELEM_BITS + (size_t)d * lambda;

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
    /* d (opening count) was derived from qs_degree at entry; zk_hash is
     * degree-parameterized. */
    gf16p_zk_hash_3_init(&hasher, chall_2, lambda, d);

    {
        uint8_t tag_a[32], tag_b[32], tag_c[32];
        uint8_t emb_a[32], emb_b[32], emb_c[32];
        uint8_t v0[32], v1[32], v2[32];
        uint8_t prod[32];

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

            const uint8_t *vv[3] = {v0, v1, v2};
            gf16p_zk_hash_3_update(&hasher, vv, 3, tmp1, tmp2);
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

                const uint8_t *vv[3] = {v0, v1, v2};
                gf16p_zk_hash_3_update(&hasher, vv, 3, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_ZERO: {
                gf16p_word_combine(tag_a, bit_tags + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                const uint8_t *vv[1] = {tag_a};
                gf16p_zk_hash_3_update(&hasher, vv, 1, tmp1, tmp2);
                break;
            }
            case GF16_CONSTRAINT_EQUAL: {
                gf16p_word_combine(tag_a, bit_tags + c->a * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                gf16p_word_combine(tag_b, bit_tags + c->b * GF16_ELEM_BITS * nb,
                                   nb, lambda, beta);
                for (unsigned int k = 0; k < nb; k++)
                    tag_a[k] ^= tag_b[k];
                const uint8_t *vv[1] = {tag_a};
                gf16p_zk_hash_3_update(&hasher, vv, 1, tmp1, tmp2);
                break;
            }
            }
        }

        /* Less-than (NLT) constraints: degree-(w+1) family batched into the
         * same zk_hash at natural degree (§18.1). */
        {
            size_t n_lt = voleith_gf16_circuit_lt_count(circuit);
            const gf16_lt_entry_t *lts =
                voleith_gf16_circuit_lt_constraints(circuit);
            const gf16_wire_id *lt_bits = voleith_gf16_circuit_lt_bits(circuit);
            for (size_t li = 0; li < n_lt; li++)
                if (gf16p_accumulate_lt(
                        &hasher, &lts[li], lt_bits + lts[li].bits_off, bit_tags,
                        wire_vals, lambda, nb, beta, tmp1, tmp2) != 0)
                    goto err;
        }

        /* Syndrome constraints (s = M*e^T): degree-idx_bits family, batched
         * into the same zk_hash at natural degree (sections 8-10). */
        {
            size_t n_syn = voleith_gf16_circuit_syndrome_count(circuit);
            const gf16_syndrome_entry_t *syn =
                voleith_gf16_circuit_syndrome_constraints(circuit);
            const gf16_wire_id *syn_bits =
                voleith_gf16_circuit_syndrome_bits(circuit);
            for (size_t si = 0; si < n_syn; si++) {
                int src = voleith_gf16_syndrome_ref_mode
                              ? gf16p_accumulate_syndrome_ref(
                                    &hasher, &syn[si], syn_bits, bit_tags,
                                    wire_vals, lambda, nb, beta, tmp1, tmp2)
                              : gf16p_accumulate_syndrome(
                                    &hasher, &syn[si], syn_bits, bit_tags,
                                    wire_vals, lambda, nb, beta, tmp1, tmp2);
                if (src != 0)
                    goto err;
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
    }

    /* Step 6: d+1 x1 corrections from the VOLE mask blocks beyond ell*16.
     * Staircase (QS_DEGREE_D_DESIGN section 11): x1_i = v*_i + u*_{i-1} over d
     * blocks; at d=2 identical to x1_0=v*_0, x1_1=u*_0+v*_1, x1_2=u*_1. */
    uint8_t x1[VOLEITH_QS_COEFFS_MAX][32], tmp3[32];
    {
        size_t corr_start = ell * GF16_ELEM_BITS;
        for (unsigned int i = 0; i <= d; i++)
            memset(x1[i], 0, nb);
        for (unsigned int j = 0; j < d; j++) {
            size_t off = corr_start + (size_t)j * lambda;

            gf16p_sum_poly_cols(tmp3, tmp1, V_T, lambda, nb, off, lambda);
            for (unsigned int k = 0; k < nb; k++)
                x1[j][k] ^= tmp3[k]; /* v*_j -> x1[j] */
            gf16p_sum_poly_bits_at(tmp3, tmp1, u, off, lambda);
            for (unsigned int k = 0; k < nb; k++)
                x1[j + 1][k] ^= tmp3[k]; /* u*_j -> x1[j+1] */
        }
    }

    /* Step 7: finalize (d+1 outputs a0_tilde..ad_tilde). */
    {
        const uint8_t *x1p[VOLEITH_QS_COEFFS_MAX];

        for (unsigned int i = 0; i <= d; i++)
            x1p[i] = x1[i];
        gf16p_zk_hash_3_finalize(a_out, &hasher, x1p, chall_2, tmp1, tmp2);
    }

    if (wire_vals)
        voleith_secure_zero(wire_vals, n_wires * sizeof(voleith_gf16_t));
    if (bit_tags)
        voleith_secure_zero(bit_tags, n_wires * GF16_ELEM_BITS * nb);
    if (V_T)
        voleith_secure_zero(V_T, n_bit_cols * nb);
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(tmp3, sizeof(tmp3));
    voleith_secure_zero(x1, sizeof(x1));
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
                      const uint8_t *chall_2, uint8_t *d_out,
                      uint8_t *const *a_out)
{
    return gf16_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                              d_out, a_out, 1);
}

int
voleith_gf16_qs_prove_unchecked(const voleith_gf16_circuit_t *circuit,
                                const voleith_gf16_t *witness,
                                const voleith_gf16_t *instance,
                                unsigned int lambda, const uint8_t *u,
                                const uint8_t **V, const uint8_t *chall_2,
                                uint8_t *d_out, uint8_t *const *a_out)
{
    return gf16_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                              d_out, a_out, 0);
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
