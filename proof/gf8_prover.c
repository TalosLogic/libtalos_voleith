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
#include "gf8_grostl_norm_const.h"
#include "gf8_norm_const.h"
#include "qs_degree.h"
#include "../core/field.h"
#include "../core/util.h"
#include "circuit.h" /* for VOLEITH_STACK_BUF_MAX */

#include <ichor/pool.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal GF(2^λ) helpers (mirrored from prover.c)
 * ===================================================================== */

/*
 * Transpose a contiguous byte range [bz_lo, bz_hi) of every input row into V_T
 * (T3.2).  Each source byte index maps to 8 output columns (col = byte_idx*8 +
 * b), so a byte-aligned range owns a disjoint set of output columns and writes
 * a disjoint region of V_T; the inner loop is identical to the serial transpose,
 * just sliced, and every V_T bit is still set exactly once (bit-identical).
 */
static void
gf8p_transpose_byte_range(const uint8_t **V, uint8_t *V_T, unsigned int lambda,
                          unsigned int nb, size_t n_cols, size_t bz_lo,
                          size_t bz_hi)
{
    for (unsigned int j = 0; j < lambda; j++) {
        for (size_t byte_idx = bz_lo; byte_idx < bz_hi; byte_idx++) {
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
}

/* Read-only descriptor for the parallel transpose; each block owns a disjoint
 * byte range (offs[blk], offs[blk+1]) of the source rows. */
typedef struct {
    const uint8_t **V;
    uint8_t *V_T;
    const size_t *offs;
    unsigned int lambda, nb;
    size_t n_cols;
} gf8p_transpose_shared_t;

static int
gf8p_transpose_job(size_t blk, void *ud)
{
    const gf8p_transpose_shared_t *sh = (const gf8p_transpose_shared_t *)ud;
    gf8p_transpose_byte_range(sh->V, sh->V_T, sh->lambda, sh->nb, sh->n_cols,
                              sh->offs[blk], sh->offs[blk + 1]);
    return 0;
}

/*
 * Build V_T = transpose(V).  Memory-bound, so threading (T3.2) splits the source
 * byte range across the pool into disjoint, byte-aligned column blocks; the
 * result is bit-identical to the serial transpose.  A null / size<=1 pool, or an
 * allocation failure for the partition, runs the serial path.
 */
static uint8_t *
gf8p_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                      size_t n_cols, struct ichor_pool *pool)
{
    uint8_t *V_T = calloc(n_cols * nb, 1);
    if (!V_T)
        return NULL;
    size_t row_bytes = (n_cols + 7) / 8;

    size_t W = 1;
    if (pool != NULL) {
        unsigned ps = ichor_pool_size(pool);
        if (ps > 1u)
            W = (size_t)ps;
    }
    if (W > row_bytes)
        W = (row_bytes > 0) ? row_bytes : 1;

    if (W > 1) {
        size_t *offs = calloc(W + 1, sizeof(*offs));
        if (offs != NULL) {
            for (size_t b = 0; b <= W; b++)
                offs[b] = (row_bytes * b) / W; /* even, byte-aligned split */
            gf8p_transpose_shared_t sh = {V, V_T, offs, lambda, nb, n_cols};
            int rc = ichor_pool_parallel_for(pool, W, gf8p_transpose_job, &sh);
            free(offs);
            if (rc == 0)
                return V_T;
            /* Pool refused the batch: redo serially into a cleared buffer (the
             * job only ORs bits, so re-zero + serial is correct). */
            memset(V_T, 0, n_cols * nb);
        }
    }

    gf8p_transpose_byte_range(V, V_T, lambda, nb, n_cols, 0, row_bytes);
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

/* Frobenius squaring matrix, shared by the serial and wavefront tag paths. */
static const uint8_t GF8P_SQUARE_MATRIX[8] = {0x51, 0xD0, 0x22, 0xF0,
                                              0x94, 0x60, 0x28, 0xC0};

/* =====================================================================
 * Step 2 bit-tag wavefront threading (T3.3).
 *
 * Step 2 propagates a wire's 8 GF(2^λ) bit-tags from its DAG predecessors in
 * topological order.  Source wires (WITNESS / MUL / INSTANCE / CONST) depend on
 * nothing; the free gates (XOR / XOR_CONST / LINEAR_MAP / SQUARE /
 * SCALE_INSTANCE) depend on their input wire(s).  Wires sharing a topological
 * level are therefore mutually independent: each reads only strictly-earlier
 * levels and writes its own disjoint bit_tag region, so tagging a level in any
 * order gives bit-identical output.
 *
 * The threaded path precomputes, per prove, each wire's level and its V_T slot
 * (WITNESS / MUL only), buckets wire ids by level (CSR: offs + order), then
 * dispatches one ichor_pool_parallel_for per level (a barrier between levels).
 * Narrow levels run inline in the calling thread (width < 4*W) so only levels
 * wide enough to amortize the dispatch pay a barrier.  A null / size<=1 pool,
 * an allocation failure, or a pool refusal returns -1 and the caller runs the
 * serial reference walk instead.
 * ===================================================================== */

/* Read-only descriptor for the wavefront; lvl is retargeted at each level. */
typedef struct {
    uint8_t *bit_tags;
    const uint8_t *V_T;
    const gf8_wire_entry_t *wires;
    const uint8_t *wire_vals;
    const size_t *slot;     /* V_T column-group index for WITNESS / MUL wires */
    const gf8_wire_id *lvl; /* current level's wire-id slice */
    size_t width;           /* wires in the current level */
    unsigned int W_eff;     /* contiguous chunks the level is split into */
    unsigned int nb;
} gf8p_tag_shared_t;

/* Compute wire w's 8 bit-tags from its predecessors (slot[] replaces the serial
 * walk's running witness / mul counters). */
static void
gf8p_tag_wire(const gf8p_tag_shared_t *sh, size_t w)
{
    const gf8_wire_entry_t *e = &sh->wires[w];
    unsigned int nb = sh->nb;
    uint8_t *bt_w = sh->bit_tags + w * 8 * nb;

    switch (e->kind) {
    case GF8_WIRE_WITNESS:
    case GF8_WIRE_MUL: {
        size_t slot = sh->slot[w];
        for (unsigned int i = 0; i < 8; i++)
            memcpy(bt_w + i * nb, sh->V_T + (slot * 8 + i) * nb, nb);
        break;
    }
    case GF8_WIRE_INSTANCE:
    case GF8_WIRE_CONST:
        memset(bt_w, 0, 8 * nb);
        break;
    case GF8_WIRE_XOR: {
        const uint8_t *bt_a = sh->bit_tags + e->a * 8 * nb;
        const uint8_t *bt_b = sh->bit_tags + e->b * 8 * nb;
        for (unsigned int i = 0; i < 8 * nb; i++)
            bt_w[i] = bt_a[i] ^ bt_b[i];
        break;
    }
    case GF8_WIRE_XOR_CONST:
        memcpy(bt_w, sh->bit_tags + e->a * 8 * nb, 8 * nb);
        break;
    case GF8_WIRE_LINEAR_MAP:
        gf8p_apply_linear_map(bt_w, sh->bit_tags + e->a * 8 * nb, e->matrix,
                              nb);
        break;
    case GF8_WIRE_SQUARE:
        gf8p_apply_linear_map(bt_w, sh->bit_tags + e->a * 8 * nb,
                              GF8P_SQUARE_MATRIX, nb);
        break;
    case GF8_WIRE_SCALE_INSTANCE: {
        uint8_t M[8];
        voleith_gf8_mul_matrix(M, sh->wire_vals[e->b]);
        gf8p_apply_linear_map(bt_w, sh->bit_tags + e->a * 8 * nb, M, nb);
        break;
    }
    }
}

/* Each job tags one contiguous chunk of the current level (W_eff chunks total),
 * not one wire: one job per wire would drown the tiny per-wire work in dispatch
 * overhead. */
static int
gf8p_tag_job(size_t blk, void *ud)
{
    const gf8p_tag_shared_t *sh = (const gf8p_tag_shared_t *)ud;
    size_t lo = sh->width * blk / sh->W_eff;
    size_t hi = sh->width * (blk + 1) / sh->W_eff;
    for (size_t i = lo; i < hi; i++)
        gf8p_tag_wire(sh, sh->lvl[i]);
    return 0;
}

/*
 * Threaded Step 2.  Returns 0 with bit_tags filled, or -1 (alloc failure or
 * pool refusal) to signal the caller to run the serial reference walk; a -1
 * after partial progress is harmless because the serial walk overwrites every
 * wire from scratch.
 */
static int
gf8p_tag_wavefront(uint8_t *bit_tags, const uint8_t *V_T,
                   const gf8_wire_entry_t *wires, const uint8_t *wire_vals,
                   size_t n_wires, size_t n_witness, unsigned int nb,
                   struct ichor_pool *pool, unsigned int W)
{
    size_t *level = calloc(n_wires, sizeof(*level));
    size_t *slot = calloc(n_wires, sizeof(*slot));
    gf8_wire_id *order = calloc(n_wires, sizeof(*order));
    size_t *offs = NULL;
    size_t *cur = NULL;
    size_t span = 0, witness_idx = 0, mul_idx = 0;
    int rc = -1;

    if (!level || !slot || !order)
        goto done;

    /* Serial pre-pass: per-wire topological level + V_T slot + span. */
    for (size_t w = 0; w < n_wires; w++) {
        const gf8_wire_entry_t *e = &wires[w];
        size_t lv;
        switch (e->kind) {
        case GF8_WIRE_WITNESS:
            slot[w] = witness_idx++;
            lv = 0;
            break;
        case GF8_WIRE_MUL:
            slot[w] = n_witness + mul_idx++;
            lv = 0;
            break;
        case GF8_WIRE_XOR:
            lv = 1 + (level[e->a] > level[e->b] ? level[e->a] : level[e->b]);
            break;
        case GF8_WIRE_XOR_CONST:
        case GF8_WIRE_LINEAR_MAP:
        case GF8_WIRE_SQUARE:
        case GF8_WIRE_SCALE_INSTANCE:
            lv = 1 + level[e->a];
            break;
        case GF8_WIRE_INSTANCE:
        case GF8_WIRE_CONST:
        default:
            lv = 0;
            break;
        }
        level[w] = lv;
        if (lv + 1 > span)
            span = lv + 1;
    }

    /* Counting sort into the CSR level buckets.  Wires are visited in ascending
     * id, so each level's slice is ascending (deterministic). */
    offs = calloc(span + 1, sizeof(*offs));
    cur = calloc(span, sizeof(*cur));
    if (!offs || !cur)
        goto done;
    for (size_t w = 0; w < n_wires; w++)
        offs[level[w] + 1]++;
    for (size_t l = 0; l < span; l++)
        offs[l + 1] += offs[l];
    for (size_t w = 0; w < n_wires; w++) {
        size_t l = level[w];
        order[offs[l] + cur[l]++] = (gf8_wire_id)w;
    }

    /* Dispatch each level as W contiguous chunks; a barrier falls between
     * levels.  Levels narrower than 4*W run inline (dispatch would not pay). */
    gf8p_tag_shared_t sh;
    sh.bit_tags = bit_tags;
    sh.V_T = V_T;
    sh.wires = wires;
    sh.wire_vals = wire_vals;
    sh.slot = slot;
    sh.nb = nb;
    rc = 0;
    for (size_t l = 0; l < span; l++) {
        size_t base = offs[l];
        size_t width = offs[l + 1] - base;
        if (width == 0)
            continue;
        sh.lvl = order + base;
        if (width >= (size_t)4 * W) {
            sh.width = width;
            sh.W_eff = W;
            if (ichor_pool_parallel_for(pool, W, gf8p_tag_job, &sh) != 0) {
                rc = -1; /* pool refused: caller runs the serial walk */
                break;
            }
        } else {
            for (size_t i = 0; i < width; i++)
                gf8p_tag_wire(&sh, sh.lvl[i]);
        }
    }

done:
    free(level);
    free(slot);
    free(order);
    free(offs);
    free(cur);
    return rc;
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
    /*
     * Count of update calls folded into this context.  Each update advances
     * every live stream by one Horner step (multiply by s / t once), so for a
     * context that hashed a contiguous SEGMENT of the canonical update stream
     * starting from zero, n_upd is the exponent L in the segmented-reduction
     * combine H = H*s^L + H_seg (QS accumulate threading, T3.1).  Unused by the
     * serial single-context path, where it simply counts up and is ignored.
     */
    uint64_t n_upd;
} gf8p_zk_hash_3_ctx;

static void
gf8p_zk_hash_3_init(gf8p_zk_hash_3_ctx *ctx, const uint8_t *chall_2,
                    unsigned int lambda, unsigned int d)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    ctx->d = d;
    ctx->n_upd = 0;
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
    ctx->n_upd++;
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

/* =====================================================================
 * AES norm S-box round-pair accumulation (FAEST paired-round norm, d=2).
 *
 * Replays one round-pair's constraint math in the Delta-coefficient (conjugate)
 * domain, mirroring faest-ref aes_SSS_enc_constraints_prover (oracle; never
 * copied).  The even round's S-box output a^-1 = c*a^16 is carried as a
 * degree-2 value through the AES linear layers, then the two folded per-byte
 * relations s_sq*st0 - s and s*st1 - st0 are pushed to the existing d=2
 * zk_hash_3.  The isolated per-byte norm relation c*a^2*a^16 = a is emitted
 * separately by the circuit builder as PRODUCT3.
 *
 * Constants (voleith AES field, reduce 0x1B; derived independently from the
 * AES affine matrix and verified: span closed under Frobenius^4, affine
 * linearized poly reproduces M*z, inverse_affine(affine(z))==z; pinned vs
 * faest-ref bfSSS_c / beta tables in the norm compat gate):
 *   GF8_NORM_SQ        Frobenius x->x^2 bit matrix (same as the prover's SQUARE)
 *   GF8_NORM_AFFINE_C  AES affine linearized-polynomial coeffs C[0..7] + const
 *                      C[8]=0x63 (forward); the dosq/b=1 variant squares them
 *   GF8_NORM_INV_AFFINE inverse AES affine linear part (for s recovery)
 *   GF8_NORM_SHIFTROWS / _INV_SHIFTROWS  forward / inverse ShiftRows byte perm
 * The four norm conjugates y[k]=c^(2^k) are Frobenius squarings of the embedded
 * norm (no beta tables); the b=1 path is uniformly the Frobenius-square of b=0
 * (C^2, MixColumns consts^2, k0^2).  The per-byte math is pair-uniform: the even
 * round always has MixColumns; the final round's missing MixColumns lives in
 * the s_tilde -> s recovery (inverse-ShiftRows + inverse-affine only).
 * ===================================================================== */

#define GF8_NORM_MAX_NST 16u

/* Apply an 8x8 GF(2) bit matrix M to one byte z (output bit i = parity of
 * M[i] & z); squaring/affine on cleartext byte values. */
static uint8_t
gf8p_bytemap(const uint8_t M[8], uint8_t z)
{
    uint8_t o = 0;
    for (unsigned int i = 0; i < 8; i++) {
        uint8_t m = (uint8_t)(M[i] & z);
        unsigned int p = 0;
        for (unsigned int j = 0; j < 8; j++)
            p ^= (m >> j) & 1u;
        o |= (uint8_t)((p & 1u) << i);
    }
    return o;
}

/* acc[0..nb-1] ^= x * y in GF(2^lambda). */
static void
gf8p_fmadd(uint8_t *acc, const uint8_t *x, const uint8_t *y, unsigned int nb,
           unsigned int lambda, uint8_t *t)
{
    gf8p_gf_mul(t, x, y, lambda);
    for (unsigned int k = 0; k < nb; k++)
        acc[k] ^= t[k];
}

static int
gf8p_accumulate_aes_norm(gf8p_zk_hash_3_ctx *hasher, const gf8_norm_entry_t *e,
                         const gf8_wire_id *wires, const uint8_t *bit_tags,
                         const uint8_t *wire_vals, unsigned int lambda,
                         unsigned int nb, const uint8_t *alpha8, uint8_t *tmp1,
                         uint8_t *tmp2)
{
    unsigned int nst = e->nst;
    if (nst == 0 || nst > GF8_NORM_MAX_NST)
        return -1;

    const gf8_wire_id *state_in = wires + e->wires_off + 0 * nst;
    const gf8_wire_id *norm_c = wires + e->wires_off + 1 * nst;
    const gf8_wire_id *s_tilde = wires + e->wires_off + 2 * nst;
    const gf8_wire_id *k0 = wires + e->wires_off + 3 * nst;

    /* Precompute embedded field constants. */
    uint8_t embC[9][32], embCsq[9][32];
    uint8_t emb2[32], emb3[32], emb2s[32], emb3s[32];
    for (unsigned int k = 0; k < 9; k++) {
        gf8p_embed(embC[k], GF8_NORM_AFFINE_C[k], lambda);
        gf8p_embed(embCsq[k], gf8p_bytemap(GF8_NORM_SQ, GF8_NORM_AFFINE_C[k]),
                   lambda);
    }
    gf8p_embed(emb2, 0x02, lambda);
    gf8p_embed(emb3, 0x03, lambda);
    gf8p_embed(emb2s, gf8p_bytemap(GF8_NORM_SQ, 0x02), lambda);
    gf8p_embed(emb3s, gf8p_bytemap(GF8_NORM_SQ, 0x03), lambda);

    /* st_b[b][byte][deg] (degree-2 per byte). */
    uint8_t stb[2][GF8_NORM_MAX_NST][3][32];
    uint8_t srb[2][GF8_NORM_MAX_NST][3][32];
    memset(stb, 0, sizeof(stb));

    /* --- Stage A: per-byte S-box inverse (conjugate domain) + affine. --- */
    for (unsigned int i = 0; i < nst; i++) {
        /* 8 conjugates of state_in[i] as lines (deg0 = tag, deg1 = emb(val)). */
        uint8_t conj_t[8][32], conj_e[8][32];
        uint8_t bt[8 * 32], bt2[8 * 32], val;
        memcpy(bt, bit_tags + (size_t)state_in[i] * 8 * nb, (size_t)8 * nb);
        val = wire_vals[state_in[i]];
        for (unsigned int j = 0; j < 8; j++) {
            gf8p_byte_combine(conj_t[j], bt, nb, lambda, alpha8);
            gf8p_embed(conj_e[j], val, lambda);
            if (j != 7) {
                gf8p_apply_linear_map(bt2, bt, GF8_NORM_SQ, nb);
                memcpy(bt, bt2, (size_t)8 * nb);
                val = gf8p_bytemap(GF8_NORM_SQ, val);
            }
        }
        /* 4 conjugates y[k] = c^(2^k) of the embedded norm as lines. */
        uint8_t y_t[4][32], y_e[4][32];
        memcpy(bt, bit_tags + (size_t)norm_c[i] * 8 * nb, (size_t)8 * nb);
        val = wire_vals[norm_c[i]];
        for (unsigned int k = 0; k < 4; k++) {
            gf8p_byte_combine(y_t[k], bt, nb, lambda, alpha8);
            gf8p_embed(y_e[k], val, lambda);
            if (k != 3) {
                gf8p_apply_linear_map(bt2, bt, GF8_NORM_SQ, nb);
                memcpy(bt, bt2, (size_t)8 * nb);
                val = gf8p_bytemap(GF8_NORM_SQ, val);
            }
        }
        /* Conjugate-domain affine: out = sum_Cidx C[Cidx] * st_dash[(Cidx+t)%8],
         * where st_dash[comp] (degree-2) = conj[(comp+4)%8] * y[comp%4].  b=0
         * uses C with t=0; b=1 uses C^2 with t=1.  Constant C[8] adds to deg2. */
        for (unsigned int b = 0; b < 2; b++) {
            unsigned int t = b;
            const uint8_t(*Cb)[32] = b ? embCsq : embC;
            for (unsigned int cidx = 0; cidx < 8; cidx++) {
                unsigned int comp = (cidx + t) % 8u;
                unsigned int cj = (comp + 4u) % 8u;
                unsigned int yj = comp % 4u;
                uint8_t sd0[32], sd1[32], sd2[32];
                gf8p_gf_mul(sd0, conj_t[cj], y_t[yj], lambda); /* deg0 */
                gf8p_gf_mul(sd2, conj_e[cj], y_e[yj], lambda); /* deg2 */
                gf8p_gf_mul(sd1, conj_t[cj], y_e[yj], lambda);
                gf8p_gf_mul(tmp1, conj_e[cj], y_t[yj], lambda);
                for (unsigned int m = 0; m < nb; m++)
                    sd1[m] ^= tmp1[m]; /* deg1 */
                gf8p_fmadd(stb[b][i][0], Cb[cidx], sd0, nb, lambda, tmp2);
                gf8p_fmadd(stb[b][i][1], Cb[cidx], sd1, nb, lambda, tmp2);
                gf8p_fmadd(stb[b][i][2], Cb[cidx], sd2, nb, lambda, tmp2);
            }
            for (unsigned int m = 0; m < nb; m++)
                stb[b][i][2][m] ^= Cb[8][m];
        }
    }

    /* --- Stage B: ShiftRows (byte permutation on degree-2 values). --- */
    for (unsigned int b = 0; b < 2; b++)
        for (unsigned int i = 0; i < nst; i++)
            memcpy(srb[b][i], stb[b][GF8_NORM_SHIFTROWS[i]], 3 * 32);

    /* --- Stage C: MixColumns (per column; b=1 uses squared 02/03). --- */
    for (unsigned int b = 0; b < 2; b++) {
        const uint8_t *v2 = b ? emb2s : emb2;
        const uint8_t *v3 = b ? emb3s : emb3;
        for (unsigned int col = 0; col * 4u < nst; col++) {
            unsigned int i0 = 4 * col, i1 = i0 + 1, i2 = i0 + 2, i3 = i0 + 3;
            for (unsigned int d = 0; d < 3; d++) {
                uint8_t *o0 = stb[b][i0][d], *o1 = stb[b][i1][d];
                uint8_t *o2 = stb[b][i2][d], *o3 = stb[b][i3][d];
                const uint8_t *a0 = srb[b][i0][d], *a1 = srb[b][i1][d];
                const uint8_t *a2 = srb[b][i2][d], *a3 = srb[b][i3][d];
                memset(o0, 0, nb);
                memset(o1, 0, nb);
                memset(o2, 0, nb);
                memset(o3, 0, nb);
                /* [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] */
                gf8p_fmadd(o0, v2, a0, nb, lambda, tmp1);
                gf8p_fmadd(o0, v3, a1, nb, lambda, tmp1);
                for (unsigned int m = 0; m < nb; m++)
                    o0[m] ^= a2[m] ^ a3[m];
                gf8p_fmadd(o1, v2, a1, nb, lambda, tmp1);
                gf8p_fmadd(o1, v3, a2, nb, lambda, tmp1);
                for (unsigned int m = 0; m < nb; m++)
                    o1[m] ^= a0[m] ^ a3[m];
                gf8p_fmadd(o2, v2, a2, nb, lambda, tmp1);
                gf8p_fmadd(o2, v3, a3, nb, lambda, tmp1);
                for (unsigned int m = 0; m < nb; m++)
                    o2[m] ^= a0[m] ^ a1[m];
                gf8p_fmadd(o3, v2, a3, nb, lambda, tmp1);
                gf8p_fmadd(o3, v3, a0, nb, lambda, tmp1);
                for (unsigned int m = 0; m < nb; m++)
                    o3[m] ^= a1[m] ^ a2[m];
            }
        }
    }

    /* --- Stage D: AddRoundKey.  b=0 adds the k0 line (deg0=tag, deg1=emb);
     * b=1 adds k0^2 = (tag^2 at deg0, emb^2 at deg2). --- */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t tk[32], ek[32];
        gf8p_byte_combine(tk, bit_tags + (size_t)k0[i] * 8 * nb, nb, lambda,
                          alpha8);
        gf8p_embed(ek, wire_vals[k0[i]], lambda);
        /* b=0 (degree_1): add the k0 line shifted up by one degree (k0 * delta),
         * so its tag lands at deg1 and its value at deg2 (faest shift_tag). */
        for (unsigned int m = 0; m < nb; m++) {
            stb[0][i][1][m] ^= tk[m];
            stb[0][i][2][m] ^= ek[m];
        }
        /* b=1 (degree_2): add k1 = k0^2 directly (tag^2 at deg0, emb^2 at deg2). */
        gf8p_fmadd(stb[1][i][0], tk, tk, nb, lambda, tmp1);
        gf8p_fmadd(stb[1][i][2], ek, ek, nb, lambda, tmp1);
    }

    /* --- Stages E + F: recover s from the committed reset state and push the
     * two folded per-byte constraints.  s = inverse_affine(inverse_shiftrows(
     * s_tilde)); s_sq = Frobenius(s).  All linear, so s stays degree-1. --- */
    for (unsigned int i = 0; i < nst; i++) {
        gf8_wire_id sw = s_tilde[GF8_NORM_INV_SHIFTROWS[i]];
        uint8_t sdd_bt[8 * 32], s_bt[8 * 32], ssq_bt[8 * 32];
        gf8p_apply_linear_map(s_bt, bit_tags + (size_t)sw * 8 * nb,
                              GF8_NORM_INV_AFFINE, nb);
        gf8p_apply_linear_map(ssq_bt, s_bt, GF8_NORM_SQ, nb);
        uint8_t sdd_val = (uint8_t)(wire_vals[sw] ^ 0x63);
        uint8_t s_val = gf8p_bytemap(GF8_NORM_INV_AFFINE, sdd_val);
        uint8_t ssq_val = gf8p_bytemap(GF8_NORM_SQ, s_val);
        (void)sdd_bt;

        uint8_t s0[32], s1[32], q0[32], q1[32];
        gf8p_byte_combine(s0, s_bt, nb, lambda, alpha8);   /* s deg0 (tag) */
        gf8p_embed(s1, s_val, lambda);                     /* s deg1 (emb)  */
        gf8p_byte_combine(q0, ssq_bt, nb, lambda, alpha8); /* s_sq deg0 */
        gf8p_embed(q1, ssq_val, lambda);                   /* s_sq deg1 */

        const uint8_t *p0 = stb[0][i][0], *p1 = stb[0][i][1],
                      *p2 = stb[0][i][2];
        const uint8_t *r0 = stb[1][i][0], *r1 = stb[1][i][1],
                      *r2 = stb[1][i][2];
        uint8_t v0[32], v1[32], v2[32];
        const uint8_t *vv[3] = {v0, v1, v2};

        /* ::36  s_sq * st_b0 - s  (target s top-aligned; deg3 parked). */
        memset(v0, 0, nb);
        memset(v1, 0, nb);
        memset(v2, 0, nb);
        gf8p_fmadd(v0, q0, p0, nb, lambda, tmp1);
        gf8p_fmadd(v1, q0, p1, nb, lambda, tmp1);
        gf8p_fmadd(v1, q1, p0, nb, lambda, tmp1);
        gf8p_fmadd(v2, q0, p2, nb, lambda, tmp1);
        gf8p_fmadd(v2, q1, p1, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v2[m] ^= s0[m];
        gf8p_zk_hash_3_update(hasher, vv, 3, tmp1, tmp2);

        /* ::37  s * st_b1 - st_b0. */
        memset(v0, 0, nb);
        memset(v1, 0, nb);
        memset(v2, 0, nb);
        gf8p_fmadd(v0, s0, r0, nb, lambda, tmp1);
        gf8p_fmadd(v1, s0, r1, nb, lambda, tmp1);
        gf8p_fmadd(v1, s1, r0, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v1[m] ^= p0[m];
        gf8p_fmadd(v2, s0, r2, nb, lambda, tmp1);
        gf8p_fmadd(v2, s1, r1, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v2[m] ^= p1[m];
        gf8p_zk_hash_3_update(hasher, vv, 3, tmp1, tmp2);
    }

    voleith_secure_zero(stb, sizeof(stb));
    voleith_secure_zero(srb, sizeof(srb));
    return 0;
}

/* =====================================================================
 * Grostl norm round-pair gadget (prover): sibling of
 * gf8p_accumulate_aes_norm for Grostl's linear layer.  Stages A (inverse +
 * conjugate-domain affine) and E/F (s recovery + the two folded d=2 triples)
 * are identical (same S-box); Stage B is Grostl ShiftBytes, Stage C is the
 * 8-byte MixBytes MDS, and Stage D adds the public odd-round AddRoundConstant
 * at the degree-2 coefficient instead of a secret round key.  State is up to
 * 128 bytes, so the degree-coefficient scratch (stb/srb) is allocated once by
 * the caller (before the entry loop) and passed in, rather than sitting on the
 * stack or being allocated per entry: stb holds >= 2*nst [3][32] elements and
 * srb >= nst [32] elements (sized for GROSTL_NORM_MAX_STATE by the caller).
 * stb is zeroed here since Stage A accumulates into it.
 * ===================================================================== */
static int
gf8p_accumulate_grostl_norm(gf8p_zk_hash_3_ctx *hasher,
                            const gf8_grostl_norm_entry_t *e,
                            const gf8_wire_id *wires, const uint8_t *bit_tags,
                            const uint8_t *wire_vals, unsigned int lambda,
                            unsigned int nb, const uint8_t *alpha8,
                            uint8_t *tmp1, uint8_t *tmp2, uint8_t (*stb)[3][32],
                            uint8_t (*srb)[32])
{
    unsigned int nst = e->nst, cols = e->cols;
    if (nst == 0 || nst > GROSTL_NORM_MAX_STATE || cols == 0 ||
        (unsigned int)(GROSTL_NORM_ROWS * cols) != nst)
        return -1;

    const gf8_wire_id *state_in = wires + e->wires_off + 0 * nst;
    const gf8_wire_id *norm_c = wires + e->wires_off + 1 * nst;
    const gf8_wire_id *s_tilde = wires + e->wires_off + 2 * nst;

    /* ShiftBytes flat permutation (+ inverse for s recovery) and the public
     * odd-round AddRoundConstant. */
    uint8_t fwd[GROSTL_NORM_MAX_STATE], inv[GROSTL_NORM_MAX_STATE];
    uint8_t rc_odd[GROSTL_NORM_MAX_STATE];
    grostl_norm_build_shift(cols, e->shift, fwd, inv);
    grostl_norm_round_const(e->is_q, cols, e->odd_round, rc_odd);

    /* Embedded field constants. */
    uint8_t embC[9][32], embCsq[9][32];
    uint8_t embMul[8][32], embMulSq[8][32];
    for (unsigned int k = 0; k < 9; k++) {
        gf8p_embed(embC[k], GF8_NORM_AFFINE_C[k], lambda);
        gf8p_embed(embCsq[k], gf8p_bytemap(GF8_NORM_SQ, GF8_NORM_AFFINE_C[k]),
                   lambda);
    }
    for (unsigned int m = 0; m < 8; m++) {
        gf8p_embed(embMul[m], (uint8_t)m, lambda);
        gf8p_embed(embMulSq[m], gf8p_bytemap(GF8_NORM_SQ, (uint8_t)m), lambda);
    }

    /* stb[b*nst + i][deg] (degree-2 per byte); srb = one shifted coefficient.
     * Caller-owned scratch; zero stb since Stage A accumulates into it. */
    memset(stb, 0, (size_t)2 * nst * sizeof(*stb));

    /* --- Stage A: per-byte S-box inverse (conjugate domain) + affine. --- */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t conj_t[8][32], conj_e[8][32];
        uint8_t bt[8 * 32], bt2[8 * 32], val;
        memcpy(bt, bit_tags + (size_t)state_in[i] * 8 * nb, (size_t)8 * nb);
        val = wire_vals[state_in[i]];
        for (unsigned int j = 0; j < 8; j++) {
            gf8p_byte_combine(conj_t[j], bt, nb, lambda, alpha8);
            gf8p_embed(conj_e[j], val, lambda);
            if (j != 7) {
                gf8p_apply_linear_map(bt2, bt, GF8_NORM_SQ, nb);
                memcpy(bt, bt2, (size_t)8 * nb);
                val = gf8p_bytemap(GF8_NORM_SQ, val);
            }
        }
        uint8_t y_t[4][32], y_e[4][32];
        memcpy(bt, bit_tags + (size_t)norm_c[i] * 8 * nb, (size_t)8 * nb);
        val = wire_vals[norm_c[i]];
        for (unsigned int k = 0; k < 4; k++) {
            gf8p_byte_combine(y_t[k], bt, nb, lambda, alpha8);
            gf8p_embed(y_e[k], val, lambda);
            if (k != 3) {
                gf8p_apply_linear_map(bt2, bt, GF8_NORM_SQ, nb);
                memcpy(bt, bt2, (size_t)8 * nb);
                val = gf8p_bytemap(GF8_NORM_SQ, val);
            }
        }
        for (unsigned int b = 0; b < 2; b++) {
            unsigned int t = b;
            const uint8_t(*Cb)[32] = b ? embCsq : embC;
            uint8_t *o0 = stb[b * nst + i][0], *o1 = stb[b * nst + i][1];
            uint8_t *o2 = stb[b * nst + i][2];
            for (unsigned int cidx = 0; cidx < 8; cidx++) {
                unsigned int comp = (cidx + t) % 8u;
                unsigned int cj = (comp + 4u) % 8u;
                unsigned int yj = comp % 4u;
                uint8_t sd0[32], sd1[32], sd2[32];
                gf8p_gf_mul(sd0, conj_t[cj], y_t[yj], lambda);
                gf8p_gf_mul(sd2, conj_e[cj], y_e[yj], lambda);
                gf8p_gf_mul(sd1, conj_t[cj], y_e[yj], lambda);
                gf8p_gf_mul(tmp1, conj_e[cj], y_t[yj], lambda);
                for (unsigned int m = 0; m < nb; m++)
                    sd1[m] ^= tmp1[m];
                gf8p_fmadd(o0, Cb[cidx], sd0, nb, lambda, tmp2);
                gf8p_fmadd(o1, Cb[cidx], sd1, nb, lambda, tmp2);
                gf8p_fmadd(o2, Cb[cidx], sd2, nb, lambda, tmp2);
            }
            for (unsigned int m = 0; m < nb; m++)
                o2[m] ^= Cb[8][m];
        }
    }

    /* --- Stages B + C: ShiftBytes then MixBytes, per degree coefficient.
     * Snapshot the shifted coefficient into srb, then multiply each 8-byte
     * column by the circulant (b=1 uses the squared multipliers). --- */
    for (unsigned int b = 0; b < 2; b++) {
        const uint8_t(*eM)[32] = b ? embMulSq : embMul;
        for (unsigned int d = 0; d < 3; d++) {
            for (unsigned int i = 0; i < nst; i++)
                memcpy(srb[i], stb[b * nst + fwd[i]][d], nb);
            for (unsigned int col = 0; col < cols; col++) {
                for (unsigned int r = 0; r < GROSTL_NORM_ROWS; r++) {
                    uint8_t *o = stb[b * nst + r + GROSTL_NORM_ROWS * col][d];
                    memset(o, 0, nb);
                    for (unsigned int j = 0; j < GROSTL_NORM_ROWS; j++)
                        gf8p_fmadd(o, eM[GROSTL_NORM_MIX[r][j]],
                                   srb[j + GROSTL_NORM_ROWS * col], nb, lambda,
                                   tmp1);
                }
            }
        }
    }

    /* --- Stage D: odd-round public AddRoundConstant at the degree-2
     * coefficient (b=0 adds emb(rc), b=1 adds emb(rc^2)). --- */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t er[32];
        gf8p_embed(er, rc_odd[i], lambda);
        for (unsigned int m = 0; m < nb; m++)
            stb[0 * nst + i][2][m] ^= er[m];
        gf8p_embed(er, gf8p_bytemap(GF8_NORM_SQ, rc_odd[i]), lambda);
        for (unsigned int m = 0; m < nb; m++)
            stb[1 * nst + i][2][m] ^= er[m];
    }

    /* --- Stages E + F: recover s (= inverse_affine(inverse_ShiftBytes(
     * s_tilde))) and push the two folded per-byte constraints. --- */
    for (unsigned int i = 0; i < nst; i++) {
        gf8_wire_id sw = s_tilde[inv[i]];
        uint8_t s_bt[8 * 32], ssq_bt[8 * 32];
        gf8p_apply_linear_map(s_bt, bit_tags + (size_t)sw * 8 * nb,
                              GF8_NORM_INV_AFFINE, nb);
        gf8p_apply_linear_map(ssq_bt, s_bt, GF8_NORM_SQ, nb);
        uint8_t sdd_val = (uint8_t)(wire_vals[sw] ^ 0x63);
        uint8_t s_val = gf8p_bytemap(GF8_NORM_INV_AFFINE, sdd_val);
        uint8_t ssq_val = gf8p_bytemap(GF8_NORM_SQ, s_val);

        uint8_t s0[32], s1[32], q0[32], q1[32];
        gf8p_byte_combine(s0, s_bt, nb, lambda, alpha8);
        gf8p_embed(s1, s_val, lambda);
        gf8p_byte_combine(q0, ssq_bt, nb, lambda, alpha8);
        gf8p_embed(q1, ssq_val, lambda);

        const uint8_t *p0 = stb[0 * nst + i][0], *p1 = stb[0 * nst + i][1],
                      *p2 = stb[0 * nst + i][2];
        const uint8_t *r0 = stb[1 * nst + i][0], *r1 = stb[1 * nst + i][1],
                      *r2 = stb[1 * nst + i][2];
        uint8_t v0[32], v1[32], v2[32];
        const uint8_t *vv[3] = {v0, v1, v2};

        /* ::36  s_sq * st_b0 - s. */
        memset(v0, 0, nb);
        memset(v1, 0, nb);
        memset(v2, 0, nb);
        gf8p_fmadd(v0, q0, p0, nb, lambda, tmp1);
        gf8p_fmadd(v1, q0, p1, nb, lambda, tmp1);
        gf8p_fmadd(v1, q1, p0, nb, lambda, tmp1);
        gf8p_fmadd(v2, q0, p2, nb, lambda, tmp1);
        gf8p_fmadd(v2, q1, p1, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v2[m] ^= s0[m];
        gf8p_zk_hash_3_update(hasher, vv, 3, tmp1, tmp2);

        /* ::37  s * st_b1 - st_b0. */
        memset(v0, 0, nb);
        memset(v1, 0, nb);
        memset(v2, 0, nb);
        gf8p_fmadd(v0, s0, r0, nb, lambda, tmp1);
        gf8p_fmadd(v1, s0, r1, nb, lambda, tmp1);
        gf8p_fmadd(v1, s1, r0, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v1[m] ^= p0[m];
        gf8p_fmadd(v2, s0, r2, nb, lambda, tmp1);
        gf8p_fmadd(v2, s1, r1, nb, lambda, tmp1);
        for (unsigned int m = 0; m < nb; m++)
            v2[m] ^= p1[m];
        gf8p_zk_hash_3_update(hasher, vv, 3, tmp1, tmp2);
    }

    return 0;
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
 * QuickSilver accumulate threading (T3.1)
 *
 * Steps 4-5 feed a strictly ordered stream of zk_hash_3 updates into one
 * context.  The recurrence is Horner (per stream h = h*s + v), order dependent
 * but ASSOCIATIVE, so the ordered stream can be cut into contiguous segments,
 * each hashed independently from zero into its own local context, then folded
 * back in order:  H = H*s^{L_b} + H_b  (and the t-stream with t^{L_b}), where
 * L_b = block b's update count (gf8p_zk_hash_3_ctx.n_upd).  The result is
 * bit-identical to the serial fold, so proof bytes are unchanged.
 *
 * The canonical order is: MUL gates (ascending wire id), then PRODUCT /
 * PRODUCT3 / ZERO / EQUAL constraints, then LT, syndrome, AES-norm and
 * Grostl-norm entries, each in index order.  gf8p_qs_accum_range dispatches a
 * contiguous [g_start, g_end) sub-range of that global item stream.
 * ===================================================================== */

/* Per-block transient scratch: hoisted out of the per-item helpers (as the
 * serial loop hoisted them) so no per-item allocation happens, and disjoint per
 * block so the threaded path needs no locking.  Secret per-wire tags pass
 * through here; secure-zeroed once when the block finishes. */
typedef struct {
    uint8_t tag_a[32], tag_b[32], tag_c[32], tag_d[32];
    uint8_t emb_a[32], emb_b[32], emb_c[32];
    uint8_t v0[32], v1[32], v2[32];
    uint8_t prod[32], pp[32], acc[32];
    uint8_t tmp1[32], tmp2[32];
} gf8p_accum_scratch_t;

/* One MUL gate check (output wire w, inputs e->a, e->b).  Byte-identical to the
 * inline Step-4 body. */
static void
gf8p_accumulate_mul(gf8p_zk_hash_3_ctx *hasher, const gf8_wire_entry_t *e,
                    gf8_wire_id w, const uint8_t *bit_tags,
                    const uint8_t *wire_vals, unsigned int lambda,
                    unsigned int nb, const uint8_t *alpha8,
                    gf8p_accum_scratch_t *sc)
{
    gf8_wire_id wa = e->a, wb = e->b;
    uint8_t val_a = wire_vals[wa];
    uint8_t val_b = wire_vals[wb];
    uint8_t val_c = wire_vals[w];

    gf8p_byte_combine(sc->tag_a, bit_tags + (size_t)wa * 8 * nb, nb, lambda,
                      alpha8);
    gf8p_byte_combine(sc->tag_b, bit_tags + (size_t)wb * 8 * nb, nb, lambda,
                      alpha8);
    gf8p_byte_combine(sc->tag_c, bit_tags + (size_t)w * 8 * nb, nb, lambda,
                      alpha8);
    gf8p_embed(sc->emb_a, val_a, lambda);
    gf8p_embed(sc->emb_b, val_b, lambda);
    gf8p_embed(sc->emb_c, val_c, lambda);

    /* v0 = tag_a*tag_b + tag_c */
    gf8p_gf_mul(sc->prod, sc->tag_a, sc->tag_b, lambda);
    for (unsigned int k = 0; k < nb; k++)
        sc->v0[k] = sc->prod[k] ^ sc->tag_c[k];

    /* v1 = tag_a*emb_b + tag_b*emb_a + emb_c */
    gf8p_gf_mul(sc->v1, sc->tag_a, sc->emb_b, lambda);
    gf8p_gf_mul(sc->prod, sc->tag_b, sc->emb_a, lambda);
    for (unsigned int k = 0; k < nb; k++)
        sc->v1[k] ^= sc->prod[k] ^ sc->emb_c[k];

    /* v2 = embed(gf8_mul(val_a, val_b)) */
    gf8p_embed(sc->v2, voleith_gf8_mul(val_a, val_b), lambda);

    const uint8_t *vv[3] = {sc->v0, sc->v1, sc->v2};
    gf8p_zk_hash_3_update(hasher, vv, 3, sc->tmp1, sc->tmp2);
}

/* One PRODUCT / PRODUCT3 / ZERO / EQUAL constraint.  Byte-identical to the
 * inline Step-5 switch. */
static void
gf8p_accumulate_constraint(gf8p_zk_hash_3_ctx *hasher,
                           const gf8_constraint_entry_t *c,
                           const uint8_t *bit_tags, const uint8_t *wire_vals,
                           unsigned int lambda, unsigned int nb,
                           const uint8_t *alpha8, gf8p_accum_scratch_t *sc)
{
    switch (c->kind) {
    case GF8_CONSTRAINT_PRODUCT: {
        uint8_t val_a = wire_vals[c->a];
        uint8_t val_b = wire_vals[c->b];
        uint8_t val_c = wire_vals[c->c];

        gf8p_byte_combine(sc->tag_a, bit_tags + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_b, bit_tags + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_c, bit_tags + (size_t)c->c * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_embed(sc->emb_a, val_a, lambda);
        gf8p_embed(sc->emb_b, val_b, lambda);
        gf8p_embed(sc->emb_c, val_c, lambda);

        gf8p_gf_mul(sc->prod, sc->tag_a, sc->tag_b, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v0[k] = sc->prod[k] ^ sc->tag_c[k];

        gf8p_gf_mul(sc->v1, sc->tag_a, sc->emb_b, lambda);
        gf8p_gf_mul(sc->prod, sc->tag_b, sc->emb_a, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v1[k] ^= sc->prod[k] ^ sc->emb_c[k];

        /* v2 = embed(val_c): the claimed product value (soundness: differs from
         * embed(val_a)*embed(val_b) for a wrong constraint). */
        gf8p_embed(sc->v2, val_c, lambda);

        const uint8_t *vv[3] = {sc->v0, sc->v1, sc->v2};
        gf8p_zk_hash_3_update(hasher, vv, 3, sc->tmp1, sc->tmp2);
        break;
    }
    case GF8_CONSTRAINT_PRODUCT3: {
        /* Three-way product a*b*c == d (FAEST norm S-box, Fig 6.19); r0..r2
         * pushed, degree-3 top parked (see the serial comment this mirrors). */
        gf8p_byte_combine(sc->tag_a, bit_tags + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_b, bit_tags + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_c, bit_tags + (size_t)c->c * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_d, bit_tags + (size_t)c->d * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_embed(sc->emb_a, wire_vals[c->a], lambda);
        gf8p_embed(sc->emb_b, wire_vals[c->b], lambda);
        gf8p_embed(sc->emb_c, wire_vals[c->c], lambda);

        /* r0 = t_a*t_b*t_c */
        gf8p_gf_mul(sc->pp, sc->tag_a, sc->tag_b, lambda);
        gf8p_gf_mul(sc->v0, sc->pp, sc->tag_c, lambda);

        /* r1 = e_a*(t_b*t_c) + e_b*(t_a*t_c) + e_c*(t_a*t_b) */
        gf8p_gf_mul(sc->pp, sc->tag_b, sc->tag_c, lambda);
        gf8p_gf_mul(sc->v1, sc->emb_a, sc->pp, lambda);
        gf8p_gf_mul(sc->pp, sc->tag_a, sc->tag_c, lambda);
        gf8p_gf_mul(sc->acc, sc->emb_b, sc->pp, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v1[k] ^= sc->acc[k];
        gf8p_gf_mul(sc->pp, sc->tag_a, sc->tag_b, lambda);
        gf8p_gf_mul(sc->acc, sc->emb_c, sc->pp, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v1[k] ^= sc->acc[k];

        /* r2 = t_a*(e_b*e_c) + t_b*(e_a*e_c) + t_c*(e_a*e_b) + t_d */
        gf8p_gf_mul(sc->pp, sc->emb_b, sc->emb_c, lambda);
        gf8p_gf_mul(sc->v2, sc->tag_a, sc->pp, lambda);
        gf8p_gf_mul(sc->pp, sc->emb_a, sc->emb_c, lambda);
        gf8p_gf_mul(sc->acc, sc->tag_b, sc->pp, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v2[k] ^= sc->acc[k];
        gf8p_gf_mul(sc->pp, sc->emb_a, sc->emb_b, lambda);
        gf8p_gf_mul(sc->acc, sc->tag_c, sc->pp, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->v2[k] ^= sc->acc[k];
        for (unsigned int k = 0; k < nb; k++)
            sc->v2[k] ^= sc->tag_d[k];

        const uint8_t *vv[3] = {sc->v0, sc->v1, sc->v2};
        gf8p_zk_hash_3_update(hasher, vv, 3, sc->tmp1, sc->tmp2);
        break;
    }
    case GF8_CONSTRAINT_ZERO: {
        gf8p_byte_combine(sc->tag_a, bit_tags + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        const uint8_t *vv[1] = {sc->tag_a};
        gf8p_zk_hash_3_update(hasher, vv, 1, sc->tmp1, sc->tmp2);
        break;
    }
    case GF8_CONSTRAINT_EQUAL: {
        gf8p_byte_combine(sc->tag_a, bit_tags + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8p_byte_combine(sc->tag_b, bit_tags + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        for (unsigned int k = 0; k < nb; k++)
            sc->tag_a[k] ^= sc->tag_b[k];
        const uint8_t *vv[1] = {sc->tag_a};
        gf8p_zk_hash_3_update(hasher, vv, 1, sc->tmp1, sc->tmp2);
        break;
    }
    }
}

/* out = base^e in GF(2^lambda), square-and-multiply; e may be 0 (-> field 1).
 * Used only in the serial combine, so its cost is O(W * log L), negligible. */
static void
gf8p_gf_pow(uint8_t *out, const uint8_t *base, uint64_t e, unsigned int lambda,
            unsigned int nb)
{
    uint8_t result[32], b[32], tmp[32];
    gf8p_embed(result, 1, lambda); /* GF(2^lambda) one */
    memcpy(b, base, nb);
    while (e != 0) {
        if (e & 1u) {
            gf8p_gf_mul(tmp, result, b, lambda);
            memcpy(result, tmp, nb);
        }
        e >>= 1;
        if (e != 0) {
            gf8p_gf_mul(tmp, b, b, lambda);
            memcpy(b, tmp, nb);
        }
    }
    memcpy(out, result, nb);
}

/*
 * Read-only descriptor of the accumulate work, shared by every block job.  The
 * circuit arrays and VOLE buffers are read concurrently; the per-block outputs
 * (hashers[b], scr[b], and the Grostl-norm scratch strided by block) are
 * written only by block b, so no two jobs touch the same memory.
 */
typedef struct {
    const gf8_wire_entry_t *wires;
    const gf8_constraint_entry_t *constraints;
    const gf8_wire_id *mul_ids; /* ascending-wire-id MUL list, c0 long */
    const uint8_t *bit_tags;
    const uint8_t *wire_vals;
    const uint8_t *alpha8;
    const gf8_lt_entry_t *lts;
    const gf8_wire_id *lt_bits;
    const gf8_syndrome_entry_t *syn;
    const gf8_wire_id *syn_bits;
    const gf8_norm_entry_t *norms;
    const gf8_wire_id *norm_wires;
    const gf8_grostl_norm_entry_t *gnorms;
    const gf8_wire_id *gn_wires;
    const size_t *offs;          /* W+1 partition offsets into [0, n_items) */
    gf8p_zk_hash_3_ctx *hashers; /* W per-block local contexts              */
    gf8p_accum_scratch_t *scr;   /* W per-block scratch                     */
    uint8_t (*gstb)[3][32];      /* W * gstb_stride, or NULL if no Grostl   */
    uint8_t (*gsrb)[32];         /* W * gsrb_stride, or NULL if no Grostl   */
    size_t gstb_stride;          /* 2 * GROSTL_NORM_MAX_STATE               */
    size_t gsrb_stride;          /* GROSTL_NORM_MAX_STATE                   */
    size_t c0, c1, c2, c3, c4;   /* cumulative segment bounds               */
    unsigned int lambda, nb;
    int syn_ref_mode;
} gf8p_accum_shared_t;

/* Hash one contiguous [g0, g1) sub-range of the canonical item stream into the
 * block's local context.  Returns 0, or -1 if a helper fails. */
static int
gf8p_qs_accum_range(const gf8p_accum_shared_t *sh, size_t blk, size_t g0,
                    size_t g1)
{
    gf8p_zk_hash_3_ctx *h = &sh->hashers[blk];
    gf8p_accum_scratch_t *sc = &sh->scr[blk];
    uint8_t *t1 = sc->tmp1, *t2 = sc->tmp2;
    unsigned int lambda = sh->lambda, nb = sh->nb;

    for (size_t g = g0; g < g1; g++) {
        if (g < sh->c0) {
            gf8_wire_id w = sh->mul_ids[g];
            gf8p_accumulate_mul(h, &sh->wires[w], w, sh->bit_tags,
                                sh->wire_vals, lambda, nb, sh->alpha8, sc);
        } else if (g < sh->c1) {
            gf8p_accumulate_constraint(h, &sh->constraints[g - sh->c0],
                                       sh->bit_tags, sh->wire_vals, lambda, nb,
                                       sh->alpha8, sc);
        } else if (g < sh->c2) {
            const gf8_lt_entry_t *lt = &sh->lts[g - sh->c1];
            if (gf8p_accumulate_lt(h, lt, sh->lt_bits + lt->bits_off,
                                   sh->bit_tags, sh->wire_vals, lambda, nb,
                                   sh->alpha8, t1, t2) != 0)
                return -1;
        } else if (g < sh->c3) {
            const gf8_syndrome_entry_t *sy = &sh->syn[g - sh->c2];
            int rc = sh->syn_ref_mode
                         ? gf8p_accumulate_syndrome_ref(
                               h, sy, sh->syn_bits, sh->bit_tags, sh->wire_vals,
                               lambda, nb, sh->alpha8, t1, t2)
                         : gf8p_accumulate_syndrome(
                               h, sy, sh->syn_bits, sh->bit_tags, sh->wire_vals,
                               lambda, nb, sh->alpha8, t1, t2);
            if (rc != 0)
                return -1;
        } else if (g < sh->c4) {
            if (gf8p_accumulate_aes_norm(
                    h, &sh->norms[g - sh->c3], sh->norm_wires, sh->bit_tags,
                    sh->wire_vals, lambda, nb, sh->alpha8, t1, t2) != 0)
                return -1;
        } else {
            uint8_t(*gstb)[3][32] = sh->gstb + blk * sh->gstb_stride;
            uint8_t(*gsrb)[32] = sh->gsrb + blk * sh->gsrb_stride;
            if (gf8p_accumulate_grostl_norm(
                    h, &sh->gnorms[g - sh->c4], sh->gn_wires, sh->bit_tags,
                    sh->wire_vals, lambda, nb, sh->alpha8, t1, t2, gstb,
                    gsrb) != 0)
                return -1;
        }
    }
    return 0;
}

/* ichor indexed-job trampoline: block index -> its partition range. */
static int
gf8p_qs_accum_job(size_t blk, void *ud)
{
    const gf8p_accum_shared_t *sh = (const gf8p_accum_shared_t *)ud;
    return gf8p_qs_accum_range(sh, blk, sh->offs[blk], sh->offs[blk + 1]);
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
                  uint8_t *d_out, uint8_t *const *a_out, int reject_invalid,
                  struct ichor_pool *pool)
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
    V_T = gf8p_transpose_matrix(V, lambda, nb, n_bit_cols, pool);
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
        unsigned int W = 1;
        if (pool != NULL) {
            unsigned ps = ichor_pool_size(pool);
            if (ps > 1u)
                W = ps;
        }
        int threaded = -1;
        if (W > 1)
            threaded = gf8p_tag_wavefront(bit_tags, V_T, wires, wire_vals,
                                          n_wires, n_witness, nb, pool, W);

        /* Serial reference walk: W<=1, no pool, alloc failure, or pool refusal.
         * Topological (ascending wire id) order; the threaded path above is
         * bit-identical to this. */
        if (threaded != 0) {
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
                            bt_w[i * nb + k] =
                                bt_a[i * nb + k] ^ bt_b[i * nb + k];
                    break;
                }
                case GF8_WIRE_XOR_CONST:
                    /* constant has zero tag, so bit_tag[out] = bit_tag[a] */
                    memcpy(bt_w, bit_tags + e->a * 8 * nb, 8 * nb);
                    break;

                case GF8_WIRE_LINEAR_MAP:
                    gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb,
                                          e->matrix, nb);
                    break;

                case GF8_WIRE_SQUARE: {
                    /* Frobenius squaring: same as LINEAR_MAP with GF8_SQUARE_MATRIX */
                    static const uint8_t SQ[8] = {0x51, 0xD0, 0x22, 0xF0,
                                                  0x94, 0x60, 0x28, 0xC0};
                    gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb, SQ,
                                          nb);
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
                    gf8p_apply_linear_map(bt_w, bit_tags + e->a * 8 * nb, M,
                                          nb);
                    break;
                }
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
        /*
         * Steps 4-5 as a threaded segmented reduction (T3.1).  The canonical
         * update stream is [MUL gates | PRODUCT/PRODUCT3/ZERO/EQUAL | LT |
         * syndrome | AES-norm | Grostl-norm], each segment in index order.  It
         * is cut into W contiguous blocks, each hashed from zero into its own
         * local context, then folded back in order; the result is bit-identical
         * to the serial fold (see the T3.1 banner).
         */
        size_t n_lt = voleith_gf8_circuit_lt_count(circuit);
        const gf8_lt_entry_t *lts = voleith_gf8_circuit_lt_constraints(circuit);
        const gf8_wire_id *lt_bits = voleith_gf8_circuit_lt_bits(circuit);
        size_t n_syn = voleith_gf8_circuit_syndrome_count(circuit);
        const gf8_syndrome_entry_t *syn =
            voleith_gf8_circuit_syndrome_constraints(circuit);
        const gf8_wire_id *syn_bits =
            voleith_gf8_circuit_syndrome_bits(circuit);
        size_t n_norm = voleith_gf8_circuit_norm_count(circuit);
        const gf8_norm_entry_t *norms =
            voleith_gf8_circuit_norm_constraints(circuit);
        const gf8_wire_id *norm_wires = voleith_gf8_circuit_norm_wires(circuit);
        size_t n_gn = voleith_gf8_circuit_grostl_norm_count(circuit);
        const gf8_grostl_norm_entry_t *gnorms =
            n_gn ? voleith_gf8_circuit_grostl_norm_constraints(circuit) : NULL;
        const gf8_wire_id *gn_wires =
            n_gn ? voleith_gf8_circuit_grostl_norm_wires(circuit) : NULL;

        /* MUL item list in ascending wire id (the serial MUL order). */
        gf8_wire_id *mul_ids = NULL;
        if (n_mul > 0) {
            mul_ids = calloc(n_mul, sizeof(*mul_ids));
            if (!mul_ids)
                goto err;
            size_t mi = 0;
            for (size_t w = 0; w < n_wires; w++)
                if (wires[w].kind == GF8_WIRE_MUL)
                    mul_ids[mi++] = (gf8_wire_id)w;
        }

        size_t c0 = n_mul;
        size_t c1 = c0 + n_constraints;
        size_t c2 = c1 + n_lt;
        size_t c3 = c2 + n_syn;
        size_t c4 = c3 + n_norm;
        size_t n_items = c4 + n_gn;

        /* One block per worker, capped at the item count; a null or size<=1
         * pool runs a single serial block (bit-identical reference). */
        size_t W = 1;
        if (pool != NULL) {
            unsigned ps = ichor_pool_size(pool);
            if (ps > 1u)
                W = (size_t)ps;
        }
        if (W > n_items)
            W = (n_items > 0) ? n_items : 1;

        size_t *offs = calloc(W + 1, sizeof(*offs));
        gf8p_zk_hash_3_ctx *hashers = calloc(W, sizeof(*hashers));
        gf8p_accum_scratch_t *scr = calloc(W, sizeof(*scr));
        size_t gstb_stride = (size_t)2 * GROSTL_NORM_MAX_STATE;
        size_t gsrb_stride = GROSTL_NORM_MAX_STATE;
        uint8_t(*gstb)[3][32] = NULL;
        uint8_t(*gsrb)[32] = NULL;
        if (n_gn > 0) {
            gstb = calloc(W * gstb_stride, sizeof(*gstb));
            gsrb = calloc(W * gsrb_stride, sizeof(*gsrb));
        }
        if (!offs || !hashers || !scr || (n_gn > 0 && (!gstb || !gsrb))) {
            free(mul_ids);
            free(offs);
            free(hashers);
            free(scr);
            free(gstb);
            free(gsrb);
            goto err;
        }

        /*
         * Weighted contiguous partition: syndrome and norm items cost much more
         * than a single gate, so split by cumulative weight to balance blocks.
         * Boundaries stay on item (canonical-order) edges, which the segmented
         * combine requires; empty blocks (weight all at one end) are harmless.
         */
        offs[0] = 0;
        offs[W] = n_items;
        if (W > 1) {
            uint64_t total_w = (uint64_t)c2 + (uint64_t)n_syn * 8u +
                               (uint64_t)(n_norm + n_gn) * 16u;
            uint64_t cw = 0;
            size_t b = 1;
            for (size_t g = 0; g < n_items && b < W; g++) {
                unsigned int wt = (g < c2) ? 1u : (g < c3) ? 8u : 16u;
                cw += wt;
                while (b < W && cw * (uint64_t)W >= (uint64_t)b * total_w) {
                    offs[b] = g + 1;
                    b++;
                }
            }
            while (b < W) {
                offs[b] = n_items;
                b++;
            }
        }

        for (size_t b = 0; b < W; b++)
            gf8p_zk_hash_3_init(&hashers[b], chall_2, lambda, d);

        gf8p_accum_shared_t sh;
        memset(&sh, 0, sizeof(sh));
        sh.wires = wires;
        sh.constraints = constraints;
        sh.mul_ids = mul_ids;
        sh.bit_tags = bit_tags;
        sh.wire_vals = wire_vals;
        sh.alpha8 = alpha8;
        sh.lts = lts;
        sh.lt_bits = lt_bits;
        sh.syn = syn;
        sh.syn_bits = syn_bits;
        sh.norms = norms;
        sh.norm_wires = norm_wires;
        sh.gnorms = gnorms;
        sh.gn_wires = gn_wires;
        sh.offs = offs;
        sh.hashers = hashers;
        sh.scr = scr;
        sh.gstb = gstb;
        sh.gsrb = gsrb;
        sh.gstb_stride = gstb_stride;
        sh.gsrb_stride = gsrb_stride;
        sh.c0 = c0;
        sh.c1 = c1;
        sh.c2 = c2;
        sh.c3 = c3;
        sh.c4 = c4;
        sh.lambda = lambda;
        sh.nb = nb;
        sh.syn_ref_mode = voleith_gf8_syndrome_ref_mode;

        int perr;
        if (W <= 1)
            perr = gf8p_qs_accum_range(&sh, 0, 0, n_items);
        else
            perr = ichor_pool_parallel_for(pool, W, gf8p_qs_accum_job, &sh);

        if (perr == 0) {
            /* Fold the blocks into the zeroed master context, in order:
             * H = H*s^{L_b} + H_b  (and the t-stream with t^{L_b}). */
            uint8_t spow[32], tpow[32];
            for (size_t b = 0; b < W; b++) {
                gf8p_zk_hash_3_ctx *hb = &hashers[b];
                gf8p_gf_pow(spow, hasher.s, hb->n_upd, lambda, nb);
                gf8p_gf_pow(tpow, hasher.t, hb->n_upd, lambda, nb);
                for (unsigned int i = 0; i <= d; i++) {
                    gf8p_gf_mul(tmp1, hasher.h0[i], spow, lambda);
                    for (unsigned int k = 0; k < nb; k++)
                        hasher.h0[i][k] = tmp1[k] ^ hb->h0[i][k];
                    gf8p_gf_mul(tmp2, hasher.h1[i], tpow, lambda);
                    for (unsigned int k = 0; k < nb; k++)
                        hasher.h1[i][k] = tmp2[k] ^ hb->h1[i][k];
                }
            }
            voleith_secure_zero(spow, sizeof(spow));
            voleith_secure_zero(tpow, sizeof(tpow));
        }

        /* Per-block secret material (local tags in the contexts, the embed /
         * tag scratch, and the Grostl-norm degree buffers) scrubbed before
         * free, mirroring the serial G-4 end-of-scope zeroing. */
        if (gstb)
            voleith_secure_zero(gstb, W * gstb_stride * sizeof(*gstb));
        voleith_secure_zero(hashers, W * sizeof(*hashers));
        voleith_secure_zero(scr, W * sizeof(*scr));
        free(mul_ids);
        free(offs);
        free(hashers);
        free(scr);
        free(gstb);
        free(gsrb);
        if (perr != 0)
            goto err;
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
                             d_out, a_out, 1, NULL);
}

int
voleith_gf8_qs_prove_ex(const voleith_gf8_circuit_t *circuit,
                        const uint8_t *witness, const uint8_t *instance,
                        unsigned int lambda, const uint8_t *u,
                        const uint8_t **V, const uint8_t *chall_2,
                        uint8_t *d_out, uint8_t *const *a_out,
                        struct ichor_pool *pool)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a_out, 1, pool);
}

int
voleith_gf8_qs_prove_unchecked(const voleith_gf8_circuit_t *circuit,
                               const uint8_t *witness, const uint8_t *instance,
                               unsigned int lambda, const uint8_t *u,
                               const uint8_t **V, const uint8_t *chall_2,
                               uint8_t *d_out, uint8_t *const *a_out)
{
    return gf8_qs_prove_impl(circuit, witness, instance, lambda, u, V, chall_2,
                             d_out, a_out, 0, NULL);
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
