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
#include "qs_degree.h"
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
 * zk_hash context (identical structure to prover.c): d+1 accumulators, one
 * per opened coefficient of a degree-d constraint (ctx->d; QS_DEGREE_D_DESIGN
 * section 11).  "_3" is historical (the d=2 case has 3 streams).
 * ===================================================================== */

typedef struct {
    uint8_t h0[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t h1[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t s[32];
    uint8_t t[32];
    unsigned int lambda;
    unsigned int d; /* constraint degree; streams 0..d are live */
} gf8p_zk_hash_3_ctx;

static void
gf8p_zk_hash_3_init(gf8p_zk_hash_3_ctx *ctx, const uint8_t *chall_2,
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
gf8p_zk_hash_3_update(gf8p_zk_hash_3_ctx *ctx, const uint8_t *const *v,
                      unsigned int nv, uint8_t *tmp1, uint8_t *tmp2)
{
    static const uint8_t zero[32] = {0};
    unsigned int nb = ctx->lambda / 8;
    for (unsigned int i = 0; i <= ctx->d; i++) {
        const uint8_t *vi = (i < nv) ? v[i] : zero;
        gf8p_gf_mul(tmp1, ctx->h0[i], ctx->s, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h0[i][k] = tmp1[k] ^ vi[k];
        gf8p_gf_mul(tmp2, ctx->h1[i], ctx->t, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h1[i][k] = tmp2[k] ^ vi[k];
    }
}

static void
gf8p_zk_hash_3_finalize(uint8_t *const *a_tilde, const gf8p_zk_hash_3_ctx *ctx,
                        const uint8_t *const *x1, const uint8_t *chall_2,
                        uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    for (unsigned int i = 0; i <= ctx->d; i++) {
        gf8p_gf_mul(tmp1, r0, ctx->h0[i], ctx->lambda);
        gf8p_gf_mul(tmp2, r1, ctx->h1[i], ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            a_tilde[i][k] = tmp1[k] ^ tmp2[k] ^ x1[i][k];
    }
}

/* =====================================================================
 * Less-than (NLT) degree-(w+1) constraint coefficient production
 *
 * Asserts A < B (A,B MSB-first w-bit indices) by committing that the value of
 * NLT = [A >= B] is zero.  Each wire is a line L(X) = tag + emb(val)*X; the
 * public constant 1 is the line [0, one] (one = embed(1), value at top).
 *
 *   eq_j     = 1 ^ a_j ^ b_j                (line)
 *   gt_i     = a_i * (1 ^ b_i)              (product of two lines: degree 2)
 *   prefix_i = prod_{j<i} eq_j              (degree i)
 *   NLT      = sum_i gt_i*prefix_i + prod_all eq_j
 *
 * Each term is top-aligned to X^(w+1) (FAEST Fig 6.1 Add: multiply by
 * X^(w+1-deg)) so every term's value coefficient lands at X^(w+1) = NLT value.
 * rho[0..w] are pushed (nv = w+1); rho[w+1] (the value) is OMITTED, so the a_0
 * reconstruction forces it to 0 <=> A < B (FAEST Remark 6.2 assert-zero).
 * ===================================================================== */

/* out(deg da+db) = a(deg da) * b(deg db) over GF(2^lambda); out distinct. */
static void
gf8p_poly_mul(uint8_t out[][32], const uint8_t a[][32], unsigned int da,
              const uint8_t b[][32], unsigned int db, unsigned int lambda,
              unsigned int nb, uint8_t *tmp)
{
    for (unsigned int i = 0; i <= da + db; i++)
        memset(out[i], 0, nb);
    for (unsigned int i = 0; i <= da; i++)
        for (unsigned int j = 0; j <= db; j++) {
            gf8p_gf_mul(tmp, a[i], b[j], lambda);
            for (unsigned int k = 0; k < nb; k++)
                out[i + j][k] ^= tmp[k];
        }
}

static int
gf8p_accumulate_lt(gf8p_zk_hash_3_ctx *hasher, const gf8_lt_entry_t *lt,
                   const gf8_wire_id *bits, const uint8_t *bit_tags,
                   const uint8_t *wire_vals, unsigned int lambda,
                   unsigned int nb, const uint8_t *alpha8, uint8_t *tmp1,
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
    gf8p_embed(one, 1, lambda); /* GF(2^lambda) one = embed(1) */

    uint8_t rho[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t prefix[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t prefix_next[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t gt[3][32];
    uint8_t term[VOLEITH_QS_COEFFS_MAX][32];
    for (unsigned int k = 0; k <= w + 1; k++)
        memset(rho[k], 0, nb);

    /* prefix_0 = 1 (constant poly, degree 0). */
    memset(prefix[0], 0, nb);
    prefix[0][0] = one[0];
    for (unsigned int k = 1; k < nb; k++)
        prefix[0][k] = one[k];
    unsigned int prefix_deg = 0;

    for (unsigned int i = 0; i < w; i++) {
        const uint8_t *bt_a = bit_tags + (size_t)bits[i] * 8 * nb;
        const uint8_t *bt_b = bit_tags + (size_t)bits[w + i] * 8 * nb;
        uint8_t ta[32], ea[32], tb[32], eb[32], nb_c1[32];
        gf8p_byte_combine(ta, bt_a, nb, lambda, alpha8);
        gf8p_byte_combine(tb, bt_b, nb, lambda, alpha8);
        gf8p_embed(ea, wire_vals[bits[i]], lambda);
        gf8p_embed(eb, wire_vals[bits[w + i]], lambda);
        /* (1 ^ b_i) line = [tb, one ^ eb] */
        for (unsigned int k = 0; k < nb; k++)
            nb_c1[k] = one[k] ^ eb[k];

        /* gt = a_i * (1 ^ b_i) : gt0=ta*tb, gt1=ta*nb_c1+ea*tb, gt2=ea*nb_c1 */
        gf8p_gf_mul(gt[0], ta, tb, lambda);
        gf8p_gf_mul(gt[1], ta, nb_c1, lambda);
        gf8p_gf_mul(tmp1, ea, tb, lambda);
        for (unsigned int k = 0; k < nb; k++)
            gt[1][k] ^= tmp1[k];
        gf8p_gf_mul(gt[2], ea, nb_c1, lambda);

        /* term = gt(deg2) * prefix(deg prefix_deg) -> deg prefix_deg+2 = i+2 */
        gf8p_poly_mul(term, gt, 2, prefix, prefix_deg, lambda, nb, tmp2);
        unsigned int tdeg = prefix_deg + 2;  /* = i + 2 */
        unsigned int shift = (w + 1) - tdeg; /* top-align to X^(w+1) */
        for (unsigned int k = 0; k <= tdeg; k++)
            for (unsigned int m = 0; m < nb; m++)
                rho[shift + k][m] ^= term[k][m];

        /* prefix *= eq_i, eq_i line = [ta^tb, one ^ ea ^ eb] */
        uint8_t eq[2][32];
        for (unsigned int k = 0; k < nb; k++) {
            eq[0][k] = ta[k] ^ tb[k];
            eq[1][k] = one[k] ^ ea[k] ^ eb[k];
        }
        gf8p_poly_mul(prefix_next, prefix, prefix_deg, eq, 1, lambda, nb, tmp1);
        prefix_deg += 1;
        for (unsigned int k = 0; k <= prefix_deg; k++)
            memcpy(prefix[k], prefix_next[k], nb);
    }

    /* prod_all eq (prefix, degree w) = [A=B]; top-align by X^1. */
    for (unsigned int k = 0; k <= w; k++)
        for (unsigned int m = 0; m < nb; m++)
            rho[1 + k][m] ^= prefix[k][m];

    /* Push rho[0..w] (nv = w+1); rho[w+1] (NLT value) omitted -> asserted 0. */
    const uint8_t *vv[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int k = 0; k <= w; k++)
        vv[k] = rho[k];
    gf8p_zk_hash_3_update(hasher, vv, w + 1, tmp1, tmp2);

    voleith_secure_zero(rho, sizeof(rho));
    voleith_secure_zero(prefix, sizeof(prefix));
    voleith_secure_zero(prefix_next, sizeof(prefix_next));
    voleith_secure_zero(term, sizeof(term));
    voleith_secure_zero(gt, sizeof(gt));
    return 0;
}

/* =====================================================================
 * Lever 1 (QS_DEGREE_D_DESIGN section 8): demux-tree sharing.  For a fixed
 * support element k the n column polys E_i share MSB-first bit-prefix factors,
 * so a depth-w binary product tree computes all leaves in O(2^w * w) coeff-ops
 * (a factor w cheaper than the per-column O(n * w^2) recompute).  DFS keeps only
 * O(w) partial polys live.  facbuf holds the 2 factor lines per bit b as
 * [b][line][coeff][32]; line 1 = {tag, val} (bit set), line 0 = {tag, comp}
 * (bit clear).  At each leaf i < n the value R_i folds into G (prover: poly;
 * value coeff w kept here, omitted at push time).  Same E_i as the reference, so
 * validated by the retained _ref path, not by byte-equality.
 * ===================================================================== */
static void
gf8p_demux_fold(unsigned int depth, unsigned int w, uint32_t prefix,
                const uint8_t *facbuf, const uint8_t node[][32],
                unsigned int nodedeg, const uint8_t *R, uint32_t n,
                unsigned int lambda, unsigned int nb, uint8_t G[][32],
                uint8_t *tmp)
{
    if (depth == w) {
        if (prefix < n) {
            const uint8_t *Ri = R + (size_t)prefix * nb;
            for (unsigned int c = 0; c <= w; c++) {
                gf8p_gf_mul(tmp, Ri, node[c], lambda);
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
        gf8p_poly_mul(child, node, nodedeg, line, 1, lambda, nb, tmp);
        gf8p_demux_fold(depth + 1u, w, (prefix << 1) | bit, facbuf, child,
                        nodedeg + 1u, R, n, lambda, nb, G, tmp);
    }
}

/* =====================================================================
 * Syndrome constraint: assert s = M * e^T in the global-bit
 * equality-polynomial form (QS_DEGREE_D_DESIGN sections 8-10), Horner/circulant
 * COLLAPSED prover (section 8 lever 2).
 *
 * The reference form pushed one degree-w (w = idx_bits) constraint per syndrome
 * bit j, rho_j = sum_{k, i : M[j,i]=1} E_i^{(k)}, and let the zk_hash Horner (key
 * s = chall_2 h0 key) fold them as sum_j s^j rho_j.  Folding directly collapses
 * the public matrix into a per-column weight and removes the per-column M-row
 * scatter and the p-fold constraint count:
 *
 *     sum_j s^j rho_j = sum_i R_i * (sum_k E_i^{(k)}),   R_i = sum_{j:M[j,i]=1} s^j.
 *
 * For a non-identity block b, column (b,l): R_i = sum_{a:m_b[a]=1} s^{(l+a) mod p}
 * (a cyclic sum of the power table pow_s[u]=s^u); identity last block: R_i = s^l
 * (matching the circulant map of voleith_rs_opener_argus_syndrome).  One degree-w
 * vector G is pushed (nv = w; value coeff w omitted).  Its value = sum_k R_{g_k}
 * = sum_j s^j (sum_k M[j,g_k]); the public s_j (zero tag) folds into the same
 * omitted value as sum_j s^j s_j, so the assert-zero is sum_j s^j (synd_j ^ s_j)
 * = 0, i.e. synd_j = s_j for all j except with probability <= (p-1)/2^lambda
 * (Schwartz-Zippel over s: the SAME bound the reference zk_hash relies on to
 * separate those p constraints, so no new assumption).  Columns i in [0, n) only
 * (out-of-range g_k selects no column; guarded by the range check).  Validated
 * by round-trip against the clear-domain oracle, not by byte-equality (the
 * transcript legitimately changes vs the reference).  Returns 0, -1 on OOM.
 * ===================================================================== */
static int
gf8p_accumulate_syndrome(gf8p_zk_hash_3_ctx *hasher,
                         const gf8_syndrome_entry_t *sy,
                         const gf8_wire_id *sbits, const uint8_t *bit_tags,
                         const uint8_t *wire_vals, unsigned int lambda,
                         unsigned int nb, const uint8_t *alpha8, uint8_t *tmp1,
                         uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf8_wire_id *idx = sbits + sy->idx_off;

    uint8_t one[32];
    gf8p_embed(one, 1, lambda);

    /* INFO-3 defense in depth: bound w before it sizes/indexes the fixed
     * [VOLEITH_QS_COEFFS_MAX] scratch (G, demux node/child).  Unreachable on
     * shipped circuits (w = idx_bits <= 17); real check, survives -DNDEBUG. */
    if (w > VOLEITH_QS_D_MAX - 1u)
        return -1;

    uint8_t *pow_s = calloc((size_t)p, nb); /* pow_s[u] = s^u          */
    uint8_t *R = calloc((size_t)n, nb);     /* per-column weight R_i    */
    uint8_t *facbuf = calloc((size_t)w * 2u * 2u, 32); /* [b][line][coeff] */
    if (!pow_s || !R || !facbuf) {
        free(pow_s);
        free(R);
        free(facbuf);
        return -1;
    }

    /* pow_s[0] = 1, pow_s[u] = pow_s[u-1] * s (s = hasher->s, the h0 key). */
    memcpy(pow_s, one, nb);
    for (uint32_t u = 1; u < p; u++)
        gf8p_gf_mul(pow_s + (size_t)u * nb, pow_s + (size_t)(u - 1) * nb,
                    hasher->s, lambda);

    /* R_i: identity last block R = s^l; non-identity block R = cyclic sum. */
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

    /* G = sum_k sum_i R_i * E_i^{(k)} (one degree-w vector), via demux tree. */
    uint8_t G[VOLEITH_QS_COEFFS_MAX][32];
    for (unsigned int c = 0; c <= w; c++)
        memset(G[c], 0, nb);

    uint8_t node0[VOLEITH_QS_COEFFS_MAX][32]; /* constant-1 poly (degree 0) */
    memcpy(node0[0], one, nb);

    for (uint32_t k = 0; k < sy->t; k++) {
        /* Build the 2 factor lines per bit b: line 1 = {tag, val}, line 0 =
         * {tag, one ^ val}.  coeff0 = tag (byte_combine of bit tags), coeff1 =
         * the value factor (MSB-first bit order preserved by depth == b). */
        for (unsigned int b = 0; b < w; b++) {
            gf8_wire_id wid = idx[(size_t)k * w + b];
            uint8_t tag[32], val[32];
            gf8p_byte_combine(tag, bit_tags + (size_t)wid * 8 * nb, nb, lambda,
                              alpha8);
            gf8p_embed(val, wire_vals[wid], lambda);
            uint8_t *l1 = facbuf + ((size_t)(b * 2u + 1u)) * 2u * 32u;
            uint8_t *l0 = facbuf + ((size_t)(b * 2u + 0u)) * 2u * 32u;
            memcpy(l1, tag, nb);
            memcpy(l1 + 32, val, nb);
            memcpy(l0, tag, nb);
            for (unsigned int m = 0; m < nb; m++)
                l0[32 + m] = (uint8_t)(one[m] ^ val[m]);
        }
        gf8p_demux_fold(0, w, 0, facbuf, node0, 0, R, n, lambda, nb, G, tmp1);
    }

    /* Push once: coeffs 0..w-1 (nv = w); value coeff w omitted / asserted 0. */
    const uint8_t *vv[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int c = 0; c < w; c++)
        vv[c] = G[c];
    gf8p_zk_hash_3_update(hasher, vv, w, tmp1, tmp2);

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(facbuf, (size_t)w * 2u * 2u * 32u);
    free(pow_s);
    free(R);
    free(facbuf);
    return 0;
}

/*
 * Test-only mode flag (declared in gf8_prover_internal.h).  0 = the collapsed
 * production accumulator above; nonzero = the reference accumulator below.  The
 * verdict cross-check test (test_syndrome_gf8) runs both and asserts identical
 * accept/reject on honest + forgery cases.  Never set outside tests.
 */
int voleith_gf8_syndrome_ref_mode = 0;

/*
 * Reference syndrome accumulator (pre-collapse): one degree-w constraint per
 * syndrome bit j, rho_j = sum_{k, i : M[j,i]=1} E_i^{(k)}, pushed p times.  Kept
 * as the trusted oracle the collapsed prover is cross-checked against (its own
 * validity rides the clear-domain check_constraints + round-trip, same as the
 * collapsed form).  Returns 0, -1 on OOM.
 */
static int
gf8p_accumulate_syndrome_ref(gf8p_zk_hash_3_ctx *hasher,
                             const gf8_syndrome_entry_t *sy,
                             const gf8_wire_id *sbits, const uint8_t *bit_tags,
                             const uint8_t *wire_vals, unsigned int lambda,
                             unsigned int nb, const uint8_t *alpha8,
                             uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf8_wire_id *idx = sbits + sy->idx_off;

    uint8_t one[32];
    gf8p_embed(one, 1, lambda);

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
                bit_tags + (size_t)idx[(size_t)k * w + b] * 8 * nb;
            gf8p_byte_combine(tags + (size_t)b * 32, bt, nb, lambda, alpha8);
            gf8p_embed(vals + (size_t)b * 32, wire_vals[idx[(size_t)k * w + b]],
                       lambda);
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
                gf8p_poly_mul(Enext, Ecur, Edeg, fac, 1, lambda, nb, tmp1);
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
        gf8p_zk_hash_3_update(hasher, vv, w, tmp1, tmp2);
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
voleith_gf8_qs_ellhat(const voleith_gf8_circuit_t *circuit, unsigned int lambda)
{
    size_t ell = voleith_gf8_qs_ell(circuit);
    unsigned int d = voleith_gf8_circuit_qs_degree(circuit);
    return ell + ((d + 1u) * lambda + UNIVERSAL_HASH_B_BITS + 7u) / 8u;
}

static int
gf8_qs_prove_impl(const voleith_gf8_circuit_t *circuit, const uint8_t *witness,
                  const uint8_t *instance, unsigned int lambda,
                  const uint8_t *u, const uint8_t **V, const uint8_t *chall_2,
                  uint8_t *d_out, uint8_t *const *a_out, int reject_invalid)
{
    if (!circuit || !witness || !u || !V || !chall_2 || !d_out || !a_out)
        return -1;
    if (voleith_gf8_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    /* Opening count d = max constraint degree in force (2 today; the opener
     * raises it).  a_out[0..d] receive coefficients a_0..a_d.  No allocations
     * yet, so a bad degree / null buffer returns directly. */
    unsigned int d = voleith_gf8_circuit_qs_degree(circuit);
    if (d > VOLEITH_QS_D_MAX)
        return -1;
    for (unsigned int i = 0; i <= d; i++)
        if (!a_out[i])
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
    /* Correction region holds d mask blocks of lambda columns each (the x1
     * staircase reads columns [ell*8, ell*8 + d*lambda)).  Was hardcoded to
     * 2*lambda (d=2 only); must scale with d for the degree-d opener. */
    size_t n_bit_cols = ell * 8 + (size_t)d * lambda;

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
            case GF8_WIRE_SCALE_INSTANCE: {
                /* out = b * a with b a public instance byte: a GF(2)-linear map
                 * x -> b*x, so the tag propagates like LINEAR_MAP with the
                 * runtime matrix of that scalar.  No VOLE slot consumed. */
                uint8_t M[8];
                voleith_gf8_mul_matrix(M, wire_vals[e->b]);
                gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb, M, nb);
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
    /* d (opening count) was derived from qs_degree at entry; the zk_hash
     * below is degree-parameterized (QS_DEGREE_D_DESIGN). */
    gf8p_zk_hash_3_ctx hasher;
    gf8p_zk_hash_3_init(&hasher, chall_2, lambda, d);

    {
        uint8_t tag_a[32], tag_b[32], tag_c[32];
        uint8_t emb_a[32], emb_b[32], emb_c[32];
        uint8_t v0[32], v1[32], v2[32];
        uint8_t prod[32];

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

            const uint8_t *vv[3] = {v0, v1, v2};
            gf8p_zk_hash_3_update(&hasher, vv, 3, tmp1, tmp2);
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

                const uint8_t *vv[3] = {v0, v1, v2};
                gf8p_zk_hash_3_update(&hasher, vv, 3, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_ZERO: {
                gf8p_byte_combine(tag_a, bit_tags + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                const uint8_t *vv[1] = {tag_a};
                gf8p_zk_hash_3_update(&hasher, vv, 1, tmp1, tmp2);
                break;
            }
            case GF8_CONSTRAINT_EQUAL: {
                gf8p_byte_combine(tag_a, bit_tags + c->a * 8 * nb, nb, lambda,
                                  alpha8);
                gf8p_byte_combine(tag_b, bit_tags + c->b * 8 * nb, nb, lambda,
                                  alpha8);
                for (unsigned int k = 0; k < nb; k++)
                    tag_a[k] ^= tag_b[k];
                const uint8_t *vv[1] = {tag_a};
                gf8p_zk_hash_3_update(&hasher, vv, 1, tmp1, tmp2);
                break;
            }
            }
        }

        /* Less-than (NLT) constraints: separate degree-(w+1) family, batched
         * into the same zk_hash at natural degree (§18.1). */
        {
            size_t n_lt = voleith_gf8_circuit_lt_count(circuit);
            const gf8_lt_entry_t *lts =
                voleith_gf8_circuit_lt_constraints(circuit);
            const gf8_wire_id *lt_bits = voleith_gf8_circuit_lt_bits(circuit);
            for (size_t li = 0; li < n_lt; li++)
                if (gf8p_accumulate_lt(
                        &hasher, &lts[li], lt_bits + lts[li].bits_off, bit_tags,
                        wire_vals, lambda, nb, alpha8, tmp1, tmp2) != 0)
                    goto err;
        }

        /* Syndrome constraints (s = M*e^T): degree-idx_bits family, batched
         * into the same zk_hash at natural degree (sections 8-10). */
        {
            size_t n_syn = voleith_gf8_circuit_syndrome_count(circuit);
            const gf8_syndrome_entry_t *syn =
                voleith_gf8_circuit_syndrome_constraints(circuit);
            const gf8_wire_id *syn_bits =
                voleith_gf8_circuit_syndrome_bits(circuit);
            for (size_t si = 0; si < n_syn; si++) {
                int src = voleith_gf8_syndrome_ref_mode
                              ? gf8p_accumulate_syndrome_ref(
                                    &hasher, &syn[si], syn_bits, bit_tags,
                                    wire_vals, lambda, nb, alpha8, tmp1, tmp2)
                              : gf8p_accumulate_syndrome(
                                    &hasher, &syn[si], syn_bits, bit_tags,
                                    wire_vals, lambda, nb, alpha8, tmp1, tmp2);
                if (src != 0)
                    goto err;
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
    }

    /* ------------------------------------------------------------------
     * Step 6: Compute x1 corrections from VOLE bits beyond ell*8.
     *
     * Same as bit-level but start_col = ell*8 (not ell).
     *
     * Staircase (QS_DEGREE_D_DESIGN section 11): x1_i = v*_i + u*_{i-1} over d
     * mask blocks starting at corr_start = ell*8; at d=2, x1_0 = v*_0,
     * x1_1 = u*_0 + v*_1, x1_2 = u*_1 (byte-identical to the prior form).
     * ------------------------------------------------------------------ */
    uint8_t x1[VOLEITH_QS_COEFFS_MAX][32], tmp3[32];
    {
        size_t corr_start = ell * 8;
        for (unsigned int i = 0; i <= d; i++)
            memset(x1[i], 0, nb);
        for (unsigned int j = 0; j < d; j++) {
            size_t off = corr_start + (size_t)j * lambda;

            gf8p_sum_poly_cols(tmp3, tmp1, V_T, lambda, nb, off, lambda);
            for (unsigned int k = 0; k < nb; k++)
                x1[j][k] ^= tmp3[k]; /* v*_j -> x1[j] */
            gf8p_sum_poly_bits_at(tmp3, tmp1, u, off, lambda);
            for (unsigned int k = 0; k < nb; k++)
                x1[j + 1][k] ^= tmp3[k]; /* u*_j -> x1[j+1] */
        }
    }

    /* ------------------------------------------------------------------
     * Step 7: Finalize the zk_hash to get a0_tilde..ad_tilde (d+1 outputs).
     * ------------------------------------------------------------------ */
    {
        const uint8_t *x1p[VOLEITH_QS_COEFFS_MAX];

        for (unsigned int i = 0; i <= d; i++)
            x1p[i] = x1[i];
        gf8p_zk_hash_3_finalize(a_out, &hasher, x1p, chall_2, tmp1, tmp2);
    }

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
    voleith_secure_zero(x1, sizeof(x1));
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
    voleith_secure_zero(x1, sizeof(x1));
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
                     const uint8_t *chall_2, uint8_t *d_out,
                     uint8_t *const *a_out)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a_out, 1);
}

int
voleith_gf8_qs_prove_unchecked(const voleith_gf8_circuit_t *circuit,
                               const uint8_t *witness, const uint8_t *instance,
                               unsigned int lambda, const uint8_t *u,
                               const uint8_t **V, const uint8_t *chall_2,
                               uint8_t *d_out, uint8_t *const *a_out)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a_out, 0);
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
