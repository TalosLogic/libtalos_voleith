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
#include "gf8_grostl_norm_const.h"
#include "gf8_norm_const.h"
#include "qs_degree.h"
#include "../core/field.h"
#include "../core/util.h"

#include <ichor/pool.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal helpers (same structure as gf8_prover.c)
 * ===================================================================== */

/*
 * Transpose a contiguous byte range [bz_lo, bz_hi) of every input row into Q_T
 * (T3.4b, mirror of the prover's gf8p_transpose_byte_range / T3.2).  Each source
 * byte index maps to 8 output columns (col = byte_idx*8 + b), so a byte-aligned
 * range owns a disjoint set of output columns and writes a disjoint region of
 * Q_T; the inner loop is identical to the serial transpose, just sliced, and
 * every Q_T bit is still set exactly once (bit-identical).
 */
static void
gf8v_transpose_byte_range(const uint8_t **V, uint8_t *Q_T, unsigned int lambda,
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
                    Q_T[col * nb + j / 8] |= (uint8_t)(1u << (j % 8));
            }
        }
    }
}

/* Read-only descriptor for the parallel transpose; each block owns a disjoint,
 * byte-aligned source byte range (hence a disjoint column region of Q_T). */
typedef struct {
    const uint8_t **V;
    uint8_t *Q_T;
    const size_t *offs;
    unsigned int lambda, nb;
    size_t n_cols;
} gf8v_transpose_shared_t;

static int
gf8v_transpose_job(size_t blk, void *ud)
{
    const gf8v_transpose_shared_t *sh = (const gf8v_transpose_shared_t *)ud;
    gf8v_transpose_byte_range(sh->V, sh->Q_T, sh->lambda, sh->nb, sh->n_cols,
                              sh->offs[blk], sh->offs[blk + 1]);
    return 0;
}

/*
 * Build Q_T = transpose(Q).  Memory-bound, so threading (T3.4b, the verifier
 * twin of the prover's T3.2 gf8p_transpose_matrix) splits the source byte range
 * across the pool into disjoint, byte-aligned column blocks; the result is
 * bit-identical to the serial transpose.  A null / size<=1 pool, an allocation
 * failure for the partition, or a pool refusal runs the serial path.
 */
static uint8_t *
gf8v_transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                      size_t n_cols, struct ichor_pool *pool)
{
    uint8_t *Q_T = calloc(n_cols, nb); /* two-arg form: overflow-checked */
    if (!Q_T)
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
            gf8v_transpose_shared_t sh = {V, Q_T, offs, lambda, nb, n_cols};
            int rc = ichor_pool_parallel_for(pool, W, gf8v_transpose_job, &sh);
            free(offs);
            if (rc == 0)
                return Q_T;
            /* Pool refused the batch: redo serially into a cleared buffer (the
             * job only ORs bits, so re-zero + serial is correct). */
            memset(Q_T, 0, n_cols * nb);
        }
    }

    gf8v_transpose_byte_range(V, Q_T, lambda, nb, n_cols, 0, row_bytes);
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
    uint64_t n_upd; /* number of updates folded in (T3.4b segmented combine) */
} gf8v_zk_hash_ctx;

static void
gf8v_zk_hash_init(gf8v_zk_hash_ctx *ctx, const uint8_t *chall_2,
                  unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    ctx->n_upd = 0;
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
    ctx->n_upd++;
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

/* out = base^e in GF(2^lambda), square-and-multiply; e may be 0 (-> field 1).
 * Used only in the T3.4b segmented combine, O(W * log L), negligible.  Mirror
 * of the prover's gf8p_gf_pow (the GF(2^lambda) one is byte {01, 00, ...}). */
static void
gf8v_gf_pow(uint8_t *out, const uint8_t *base, uint64_t e, unsigned int lambda,
            unsigned int nb)
{
    uint8_t result[32] = {0}, b[32], tmp[32];
    result[0] = 1; /* GF(2^lambda) one */
    memcpy(b, base, nb);
    while (e != 0) {
        if (e & 1u) {
            gf8v_gf_mul(tmp, result, b, lambda);
            memcpy(result, tmp, nb);
        }
        e >>= 1;
        if (e != 0) {
            gf8v_gf_mul(tmp, b, b, lambda);
            memcpy(b, tmp, nb);
        }
    }
    memcpy(out, result, nb);
}

/* =====================================================================
 * Less-than (NLT) constraint: evaluate rho_NLT(delta) over the verifier keys
 * and push the single value.  Mirror of gf8p_accumulate_lt (§18.1): each wire
 * key is L(delta); the constant 1 contributes one*delta = delta.
 *   eq_i(delta) = key_a ^ key_b ^ delta
 *   gt_i(delta) = key_a * (key_b ^ delta)
 *   G = sum_i delta^(w-1-i) * gt_i * prefix_i + delta * prod_all eq
 * with prefix_i = prod_{j<i} eq_j.  Top-align shifts match the prover exactly.
 * ===================================================================== */
static void
gf8v_accumulate_lt(gf8v_zk_hash_ctx *bctx, const gf8_lt_entry_t *lt,
                   const gf8_wire_id *bits, const uint8_t *bit_keys,
                   const uint8_t *delta, unsigned int lambda, unsigned int nb,
                   const uint8_t *alpha8, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = lt->width;
    uint8_t dpow[VOLEITH_QS_COEFFS_MAX][32]; /* delta^0..delta^w */
    memset(dpow[0], 0, nb);
    dpow[0][0] = 0x01; /* GF(2^lambda) one */
    for (unsigned int i = 1; i <= w; i++)
        gf8v_gf_mul(dpow[i], dpow[i - 1], delta, lambda);

    uint8_t prefix[32], G[32], key_a[32], key_b[32], nbv[32], gt[32], t[32];
    memset(G, 0, nb);
    memset(prefix, 0, nb);
    prefix[0] = 0x01; /* prefix_0 = 1 */

    for (unsigned int i = 0; i < w; i++) {
        gf8v_byte_combine(key_a, bit_keys + (size_t)bits[i] * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(key_b, bit_keys + (size_t)bits[w + i] * 8 * nb, nb,
                          lambda, alpha8);
        /* gt_i(delta) = key_a * (key_b ^ delta) */
        for (unsigned int k = 0; k < nb; k++)
            nbv[k] = key_b[k] ^ delta[k];
        gf8v_gf_mul(gt, key_a, nbv, lambda);
        /* term = delta^(w-1-i) * gt * prefix */
        gf8v_gf_mul(t, gt, prefix, lambda);
        gf8v_gf_mul(tmp1, t, dpow[w - 1 - i], lambda);
        for (unsigned int k = 0; k < nb; k++)
            G[k] ^= tmp1[k];
        /* prefix *= eq_i(delta) = key_a ^ key_b ^ delta */
        for (unsigned int k = 0; k < nb; k++)
            tmp2[k] = key_a[k] ^ key_b[k] ^ delta[k];
        gf8v_gf_mul(tmp1, prefix, tmp2, lambda);
        memcpy(prefix, tmp1, nb);
    }
    /* + delta * prod_all eq (= [A=B]) */
    gf8v_gf_mul(t, prefix, dpow[1], lambda);
    for (unsigned int k = 0; k < nb; k++)
        G[k] ^= t[k];

    gf8v_zk_hash_update(bctx, G, tmp1, tmp2);
}

/* =====================================================================
 * AES norm S-box round-pair, verifier (scalar) dual of
 * gf8p_accumulate_aes_norm.  Each wire collapses to its key K = L(delta); the
 * degree-2 S-box output st_dash = K_conj * K_y, carried through the same
 * conjugate-domain affine / ShiftRows / MixColumns / AddRoundKey as the prover.
 * The two folded relations are evaluated at delta with the target top-aligned
 * (same parking rule as PRODUCT3: scale the target by delta^(R - topdeg)):
 *   ::36  K_ssq * st0 + K_s  * delta^2
 *   ::37  K_s   * st1 + st0 * delta
 * Value-exact to the prover's pushed (v0,v1,v2); an honest prover's parked
 * delta^3 term is zero, a cheat leaves one no degree-2 opening can match.
 * ===================================================================== */
#define GF8V_NORM_MAX_NST 16u

static uint8_t
gf8v_norm_bytemap(const uint8_t M[8], uint8_t z)
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

static void
gf8v_norm_embed(uint8_t *out, uint8_t val, unsigned int lambda)
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++)
        bits[i] = (val >> i) & 1u;
    voleith_byte_combine(out, bits, lambda);
}

static int
gf8v_accumulate_aes_norm(gf8v_zk_hash_ctx *bctx, const gf8_norm_entry_t *e,
                         const gf8_wire_id *wires, const uint8_t *bit_keys,
                         const uint8_t *delta, unsigned int lambda,
                         unsigned int nb, const uint8_t *alpha8, uint8_t *tmp1,
                         uint8_t *tmp2)
{
    unsigned int nst = e->nst;
    if (nst == 0 || nst > GF8V_NORM_MAX_NST)
        return -1;

    const gf8_wire_id *state_in = wires + e->wires_off + 0 * nst;
    const gf8_wire_id *norm_c = wires + e->wires_off + 1 * nst;
    const gf8_wire_id *s_tilde = wires + e->wires_off + 2 * nst;
    const gf8_wire_id *k0 = wires + e->wires_off + 3 * nst;

    uint8_t embC[9][32], embCsq[9][32];
    uint8_t emb2[32], emb3[32], emb2s[32], emb3s[32];
    uint8_t dsq[32], kd2[32], kd1[32];
    for (unsigned int k = 0; k < 9; k++) {
        gf8v_norm_embed(embC[k], GF8_NORM_AFFINE_C[k], lambda);
        gf8v_norm_embed(embCsq[k],
                        gf8v_norm_bytemap(GF8_NORM_SQ, GF8_NORM_AFFINE_C[k]),
                        lambda);
    }
    gf8v_norm_embed(emb2, 0x02, lambda);
    gf8v_norm_embed(emb3, 0x03, lambda);
    gf8v_norm_embed(emb2s, gf8v_norm_bytemap(GF8_NORM_SQ, 0x02), lambda);
    gf8v_norm_embed(emb3s, gf8v_norm_bytemap(GF8_NORM_SQ, 0x03), lambda);
    gf8v_gf_mul(dsq, delta, delta, lambda);
    /* inverse-affine constant key contributions: K63 = M^-1 * 0x63 and its
     * Frobenius square, each a public constant with key emb(.)*delta. */
    uint8_t k63 = gf8v_norm_bytemap(GF8_NORM_INV_AFFINE, 0x63);
    gf8v_norm_embed(tmp1, k63, lambda);
    gf8v_gf_mul(kd1, tmp1, delta, lambda);
    gf8v_norm_embed(tmp1, gf8v_norm_bytemap(GF8_NORM_SQ, k63), lambda);
    gf8v_gf_mul(kd2, tmp1, delta, lambda);

    uint8_t stb[2][GF8V_NORM_MAX_NST][32]; /* st_b key per byte */
    uint8_t srb[2][GF8V_NORM_MAX_NST][32];

    /* Stage A: per byte, S-box inverse + conjugate-domain affine (key domain). */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t Kc[8][32], Ky[4][32];
        uint8_t bk[8 * 32], bk2[8 * 32];
        memcpy(bk, bit_keys + (size_t)state_in[i] * 8 * nb, (size_t)8 * nb);
        for (unsigned int j = 0; j < 8; j++) {
            gf8v_byte_combine(Kc[j], bk, nb, lambda, alpha8);
            if (j != 7) {
                gf8v_apply_linear_map(bk2, bk, GF8_NORM_SQ, nb);
                memcpy(bk, bk2, (size_t)8 * nb);
            }
        }
        memcpy(bk, bit_keys + (size_t)norm_c[i] * 8 * nb, (size_t)8 * nb);
        for (unsigned int k = 0; k < 4; k++) {
            gf8v_byte_combine(Ky[k], bk, nb, lambda, alpha8);
            if (k != 3) {
                gf8v_apply_linear_map(bk2, bk, GF8_NORM_SQ, nb);
                memcpy(bk, bk2, (size_t)8 * nb);
            }
        }
        for (unsigned int b = 0; b < 2; b++) {
            unsigned int t = b;
            const uint8_t(*Cb)[32] = b ? embCsq : embC;
            uint8_t acc[32];
            memset(acc, 0, nb);
            for (unsigned int cidx = 0; cidx < 8; cidx++) {
                unsigned int comp = (cidx + t) % 8u;
                unsigned int cj = (comp + 4u) % 8u;
                unsigned int yj = comp % 4u;
                uint8_t sd[32];
                gf8v_gf_mul(sd, Kc[cj], Ky[yj], lambda); /* st_dash key */
                gf8v_gf_mul(tmp1, Cb[cidx], sd, lambda);
                for (unsigned int m = 0; m < nb; m++)
                    acc[m] ^= tmp1[m];
            }
            /* constant C[8] sits at the degree-2 coefficient. */
            gf8v_gf_mul(tmp1, Cb[8], dsq, lambda);
            for (unsigned int m = 0; m < nb; m++)
                stb[b][i][m] = acc[m] ^ tmp1[m];
        }
    }

    /* Stage B: ShiftRows. */
    for (unsigned int b = 0; b < 2; b++)
        for (unsigned int i = 0; i < nst; i++)
            memcpy(srb[b][i], stb[b][GF8_NORM_SHIFTROWS[i]], nb);

    /* Stage C: MixColumns (single key value per byte). */
    for (unsigned int b = 0; b < 2; b++) {
        const uint8_t *v2 = b ? emb2s : emb2;
        const uint8_t *v3 = b ? emb3s : emb3;
        for (unsigned int col = 0; col * 4u < nst; col++) {
            unsigned int i0 = 4 * col, i1 = i0 + 1, i2 = i0 + 2, i3 = i0 + 3;
            uint8_t *o0 = stb[b][i0], *o1 = stb[b][i1];
            uint8_t *o2 = stb[b][i2], *o3 = stb[b][i3];
            const uint8_t *a0 = srb[b][i0], *a1 = srb[b][i1];
            const uint8_t *a2 = srb[b][i2], *a3 = srb[b][i3];
            uint8_t p[32];
            memset(o0, 0, nb);
            memset(o1, 0, nb);
            memset(o2, 0, nb);
            memset(o3, 0, nb);
            gf8v_gf_mul(p, v2, a0, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o0[m] ^= p[m];
            gf8v_gf_mul(p, v3, a1, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o0[m] ^= p[m] ^ a2[m] ^ a3[m];
            gf8v_gf_mul(p, v2, a1, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o1[m] ^= p[m];
            gf8v_gf_mul(p, v3, a2, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o1[m] ^= p[m] ^ a0[m] ^ a3[m];
            gf8v_gf_mul(p, v2, a2, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o2[m] ^= p[m];
            gf8v_gf_mul(p, v3, a3, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o2[m] ^= p[m] ^ a0[m] ^ a1[m];
            gf8v_gf_mul(p, v2, a3, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o3[m] ^= p[m];
            gf8v_gf_mul(p, v3, a0, lambda);
            for (unsigned int m = 0; m < nb; m++)
                o3[m] ^= p[m] ^ a1[m] ^ a2[m];
        }
    }

    /* Stage D: AddRoundKey.  b=0 (degree_1) adds K_k0 * delta (shift_tag); b=1
     * (degree_2) adds K_k0^2 directly. */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t kk[32], kksh[32], kksq[32];
        gf8v_byte_combine(kk, bit_keys + (size_t)k0[i] * 8 * nb, nb, lambda,
                          alpha8);
        gf8v_gf_mul(kksh, kk, delta, lambda); /* K_k0 * delta */
        gf8v_gf_mul(kksq, kk, kk, lambda);    /* K_k0^2        */
        for (unsigned int m = 0; m < nb; m++) {
            stb[0][i][m] ^= kksh[m];
            stb[1][i][m] ^= kksq[m];
        }
    }

    /* Stages E + F: recover K_s / K_ssq and push the two folded contribs. */
    for (unsigned int i = 0; i < nst; i++) {
        gf8_wire_id sw = s_tilde[GF8_NORM_INV_SHIFTROWS[i]];
        uint8_t s_bk[8 * 32], ssq_bk[8 * 32], Ks[32], Kssq[32];
        gf8v_apply_linear_map(s_bk, bit_keys + (size_t)sw * 8 * nb,
                              GF8_NORM_INV_AFFINE, nb);
        gf8v_apply_linear_map(ssq_bk, s_bk, GF8_NORM_SQ, nb);
        gf8v_byte_combine(Ks, s_bk, nb, lambda, alpha8);
        gf8v_byte_combine(Kssq, ssq_bk, nb, lambda, alpha8);
        for (unsigned int m = 0; m < nb; m++) {
            Ks[m] ^= kd1[m];   /* + emb(K63)*delta   */
            Kssq[m] ^= kd2[m]; /* + emb(K63^2)*delta */
        }
        uint8_t g[32], prod[32];
        /* ::36  K_ssq * st0 + K_s * delta^2 */
        gf8v_gf_mul(g, Kssq, stb[0][i], lambda);
        gf8v_gf_mul(prod, Ks, dsq, lambda);
        for (unsigned int m = 0; m < nb; m++)
            g[m] ^= prod[m];
        gf8v_zk_hash_update(bctx, g, tmp1, tmp2);
        /* ::37  K_s * st1 + st0 * delta */
        gf8v_gf_mul(g, Ks, stb[1][i], lambda);
        gf8v_gf_mul(prod, stb[0][i], delta, lambda);
        for (unsigned int m = 0; m < nb; m++)
            g[m] ^= prod[m];
        gf8v_zk_hash_update(bctx, g, tmp1, tmp2);
    }
    return 0;
}

/* =====================================================================
 * Grostl norm round-pair gadget (verifier): scalar dual of
 * gf8p_accumulate_grostl_norm and the exact Grostl analogue of
 * gf8v_accumulate_aes_norm.  Stage A / E / F are identical; Stage B is Grostl
 * ShiftBytes, Stage C the 8-byte MixBytes, Stage D adds the public odd-round
 * AddRoundConstant at the degree-2 coefficient (emb(rc)*delta^2).  State is up
 * to 128 bytes, so stb/srb are caller-owned scratch allocated once before the
 * entry loop (stb >= 2*nst [32], srb >= nst [32]); Stage A fully assigns stb so
 * no pre-zeroing is needed.
 * ===================================================================== */
static int
gf8v_accumulate_grostl_norm(gf8v_zk_hash_ctx *bctx,
                            const gf8_grostl_norm_entry_t *e,
                            const gf8_wire_id *wires, const uint8_t *bit_keys,
                            const uint8_t *delta, unsigned int lambda,
                            unsigned int nb, const uint8_t *alpha8,
                            uint8_t *tmp1, uint8_t *tmp2, uint8_t (*stb)[32],
                            uint8_t (*srb)[32])
{
    unsigned int nst = e->nst, cols = e->cols;
    if (nst == 0 || nst > GROSTL_NORM_MAX_STATE || cols == 0 ||
        (unsigned int)(GROSTL_NORM_ROWS * cols) != nst)
        return -1;

    const gf8_wire_id *state_in = wires + e->wires_off + 0 * nst;
    const gf8_wire_id *norm_c = wires + e->wires_off + 1 * nst;
    const gf8_wire_id *s_tilde = wires + e->wires_off + 2 * nst;

    uint8_t fwd[GROSTL_NORM_MAX_STATE], inv[GROSTL_NORM_MAX_STATE];
    uint8_t rc_odd[GROSTL_NORM_MAX_STATE];
    grostl_norm_build_shift(cols, e->shift, fwd, inv);
    grostl_norm_round_const(e->is_q, cols, e->odd_round, rc_odd);

    uint8_t embC[9][32], embCsq[9][32];
    uint8_t embMul[8][32], embMulSq[8][32];
    uint8_t dsq[32], kd1[32], kd2[32];
    for (unsigned int k = 0; k < 9; k++) {
        gf8v_norm_embed(embC[k], GF8_NORM_AFFINE_C[k], lambda);
        gf8v_norm_embed(embCsq[k],
                        gf8v_norm_bytemap(GF8_NORM_SQ, GF8_NORM_AFFINE_C[k]),
                        lambda);
    }
    for (unsigned int m = 0; m < 8; m++) {
        gf8v_norm_embed(embMul[m], (uint8_t)m, lambda);
        gf8v_norm_embed(embMulSq[m], gf8v_norm_bytemap(GF8_NORM_SQ, (uint8_t)m),
                        lambda);
    }
    gf8v_gf_mul(dsq, delta, delta, lambda);
    uint8_t k63 = gf8v_norm_bytemap(GF8_NORM_INV_AFFINE, 0x63);
    gf8v_norm_embed(tmp1, k63, lambda);
    gf8v_gf_mul(kd1, tmp1, delta, lambda);
    gf8v_norm_embed(tmp1, gf8v_norm_bytemap(GF8_NORM_SQ, k63), lambda);
    gf8v_gf_mul(kd2, tmp1, delta, lambda);

    /* stb[b*nst + i] / srb: caller-owned scratch (Stage A fully assigns stb). */

    /* Stage A: S-box inverse + conjugate-domain affine (key domain). */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t Kc[8][32], Ky[4][32];
        uint8_t bk[8 * 32], bk2[8 * 32];
        memcpy(bk, bit_keys + (size_t)state_in[i] * 8 * nb, (size_t)8 * nb);
        for (unsigned int j = 0; j < 8; j++) {
            gf8v_byte_combine(Kc[j], bk, nb, lambda, alpha8);
            if (j != 7) {
                gf8v_apply_linear_map(bk2, bk, GF8_NORM_SQ, nb);
                memcpy(bk, bk2, (size_t)8 * nb);
            }
        }
        memcpy(bk, bit_keys + (size_t)norm_c[i] * 8 * nb, (size_t)8 * nb);
        for (unsigned int k = 0; k < 4; k++) {
            gf8v_byte_combine(Ky[k], bk, nb, lambda, alpha8);
            if (k != 3) {
                gf8v_apply_linear_map(bk2, bk, GF8_NORM_SQ, nb);
                memcpy(bk, bk2, (size_t)8 * nb);
            }
        }
        for (unsigned int b = 0; b < 2; b++) {
            unsigned int t = b;
            const uint8_t(*Cb)[32] = b ? embCsq : embC;
            uint8_t acc[32];
            memset(acc, 0, nb);
            for (unsigned int cidx = 0; cidx < 8; cidx++) {
                unsigned int comp = (cidx + t) % 8u;
                unsigned int cj = (comp + 4u) % 8u;
                unsigned int yj = comp % 4u;
                uint8_t sd[32];
                gf8v_gf_mul(sd, Kc[cj], Ky[yj], lambda);
                gf8v_gf_mul(tmp1, Cb[cidx], sd, lambda);
                for (unsigned int m = 0; m < nb; m++)
                    acc[m] ^= tmp1[m];
            }
            gf8v_gf_mul(tmp1, Cb[8], dsq, lambda);
            for (unsigned int m = 0; m < nb; m++)
                stb[b * nst + i][m] = acc[m] ^ tmp1[m];
        }
    }

    /* Stages B + C: ShiftBytes then MixBytes (single key per byte). */
    for (unsigned int b = 0; b < 2; b++) {
        const uint8_t(*eM)[32] = b ? embMulSq : embMul;
        for (unsigned int i = 0; i < nst; i++)
            memcpy(srb[i], stb[b * nst + fwd[i]], nb);
        for (unsigned int col = 0; col < cols; col++) {
            for (unsigned int r = 0; r < GROSTL_NORM_ROWS; r++) {
                uint8_t *o = stb[b * nst + r + GROSTL_NORM_ROWS * col];
                memset(o, 0, nb);
                for (unsigned int j = 0; j < GROSTL_NORM_ROWS; j++) {
                    gf8v_gf_mul(tmp1, eM[GROSTL_NORM_MIX[r][j]],
                                srb[j + GROSTL_NORM_ROWS * col], lambda);
                    for (unsigned int m = 0; m < nb; m++)
                        o[m] ^= tmp1[m];
                }
            }
        }
    }

    /* Stage D: odd-round public AddRoundConstant at the degree-2 coefficient
     * (emb(rc)*delta^2; b=1 squares rc). */
    for (unsigned int i = 0; i < nst; i++) {
        uint8_t er[32];
        gf8v_norm_embed(er, rc_odd[i], lambda);
        gf8v_gf_mul(tmp1, er, dsq, lambda);
        for (unsigned int m = 0; m < nb; m++)
            stb[0 * nst + i][m] ^= tmp1[m];
        gf8v_norm_embed(er, gf8v_norm_bytemap(GF8_NORM_SQ, rc_odd[i]), lambda);
        gf8v_gf_mul(tmp1, er, dsq, lambda);
        for (unsigned int m = 0; m < nb; m++)
            stb[1 * nst + i][m] ^= tmp1[m];
    }

    /* Stages E + F: recover K_s / K_ssq and push the two folded contribs. */
    for (unsigned int i = 0; i < nst; i++) {
        gf8_wire_id sw = s_tilde[inv[i]];
        uint8_t s_bk[8 * 32], ssq_bk[8 * 32], Ks[32], Kssq[32];
        gf8v_apply_linear_map(s_bk, bit_keys + (size_t)sw * 8 * nb,
                              GF8_NORM_INV_AFFINE, nb);
        gf8v_apply_linear_map(ssq_bk, s_bk, GF8_NORM_SQ, nb);
        gf8v_byte_combine(Ks, s_bk, nb, lambda, alpha8);
        gf8v_byte_combine(Kssq, ssq_bk, nb, lambda, alpha8);
        for (unsigned int m = 0; m < nb; m++) {
            Ks[m] ^= kd1[m];
            Kssq[m] ^= kd2[m];
        }
        uint8_t g[32], prod[32];
        /* ::36  K_ssq * st0 + K_s * delta^2 */
        gf8v_gf_mul(g, Kssq, stb[0 * nst + i], lambda);
        gf8v_gf_mul(prod, Ks, dsq, lambda);
        for (unsigned int m = 0; m < nb; m++)
            g[m] ^= prod[m];
        gf8v_zk_hash_update(bctx, g, tmp1, tmp2);
        /* ::37  K_s * st1 + st0 * delta */
        gf8v_gf_mul(g, Ks, stb[1 * nst + i], lambda);
        gf8v_gf_mul(prod, stb[0 * nst + i], delta, lambda);
        for (unsigned int m = 0; m < nb; m++)
            g[m] ^= prod[m];
        gf8v_zk_hash_update(bctx, g, tmp1, tmp2);
    }

    return 0;
}

/* =====================================================================
 * Lever 1 demux tree, verifier (scalar) dual of gf8p_demux_fold.  Leaves are
 * E_i(delta); facbuf holds the 2 scalar factors per bit b as [b][line][32],
 * line 1 = key_b, line 0 = key_b ^ delta.  Folds R_i * E_i(delta) into G.
 * ===================================================================== */
static void
gf8v_demux_fold(unsigned int depth, unsigned int w, uint32_t prefix,
                const uint8_t *facbuf, const uint8_t *node, const uint8_t *R,
                uint32_t n, unsigned int lambda, unsigned int nb, uint8_t *G,
                uint8_t *tmp)
{
    if (depth == w) {
        if (prefix < n) {
            gf8v_gf_mul(tmp, R + (size_t)prefix * nb, node, lambda);
            for (unsigned int m = 0; m < nb; m++)
                G[m] ^= tmp[m];
        }
        return;
    }
    uint8_t child[32];
    for (unsigned int bit = 0; bit < 2; bit++) {
        const uint8_t *fac = facbuf + ((size_t)(depth * 2u + bit)) * 32u;
        gf8v_gf_mul(child, node, fac, lambda);
        gf8v_demux_fold(depth + 1u, w, (prefix << 1) | bit, facbuf, child, R, n,
                        lambda, nb, G, tmp);
    }
}

/* =====================================================================
 * Syndrome constraint: Horner/circulant COLLAPSED verifier (dual of
 * gf8p_accumulate_syndrome).  Evaluate the single folded constraint at delta
 * over the keys and push one scalar:
 *   G = sum_k sum_i R_i * E_i^{(k)}(delta) + delta^(w-1) * sum_j s^j * key_{s_j}
 * with R_i = sum_{j:M[j,i]=1} s^j (identity block s^l; non-identity block the
 * cyclic sum), s = bctx->s (the h0 key), and E_i^{(k)}(delta) = prod_b factor_b,
 * factor_b = bit? key_b : key_b ^ delta.  The public s_j enters via its instance
 * key (emb(s_j)*delta) at the value position delta^w = key_{s_j} * delta^(w-1).
 * Returns 0 on success, -1 on allocation failure.
 * ===================================================================== */
static int
gf8v_accumulate_syndrome(gf8v_zk_hash_ctx *bctx, const gf8_syndrome_entry_t *sy,
                         const gf8_wire_id *sbits, const uint8_t *bit_keys,
                         const uint8_t *delta, unsigned int lambda,
                         unsigned int nb, const uint8_t *alpha8, uint8_t *tmp1,
                         uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf8_wire_id *idx = sbits + sy->idx_off;
    const gf8_wire_id *swires = sbits + sy->s_off;

    uint8_t dpow_w1[32]; /* delta^(w-1) */
    memset(dpow_w1, 0, nb);
    dpow_w1[0] = 0x01;
    for (unsigned int i = 1; i < w; i++) {
        gf8v_gf_mul(tmp1, dpow_w1, delta, lambda);
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

    /* pow_s[u] = s^u (s = bctx->s). */
    pow_s[0] = 0x01;
    for (uint32_t u = 1; u < p; u++)
        gf8v_gf_mul(pow_s + (size_t)u * nb, pow_s + (size_t)(u - 1) * nb,
                    bctx->s, lambda);

    /* R_i: identity last block s^l; non-identity block cyclic sum. */
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
        /* factor line 1 = key_b, line 0 = key_b ^ delta (MSB-first by depth). */
        for (unsigned int b = 0; b < w; b++) {
            uint8_t *l1 = facbuf + ((size_t)(b * 2u + 1u)) * 32u;
            uint8_t *l0 = facbuf + ((size_t)(b * 2u + 0u)) * 32u;
            gf8v_byte_combine(
                l1, bit_keys + (size_t)idx[(size_t)k * w + b] * 8 * nb, nb,
                lambda, alpha8);
            for (unsigned int m = 0; m < nb; m++)
                l0[m] = (uint8_t)(l1[m] ^ delta[m]);
        }
        gf8v_demux_fold(0, w, 0, facbuf, node1, R, n, lambda, nb, G, tmp1);
    }

    /* Public term: G += delta^(w-1) * sum_j s^j * key_{s_j}. */
    {
        uint8_t Sig[32], key_s[32];
        memset(Sig, 0, nb);
        for (uint32_t j = 0; j < p; j++) {
            gf8v_byte_combine(key_s, bit_keys + (size_t)swires[j] * 8 * nb, nb,
                              lambda, alpha8);
            gf8v_gf_mul(tmp1, pow_s + (size_t)j * nb, key_s, lambda);
            for (unsigned int m = 0; m < nb; m++)
                Sig[m] ^= tmp1[m];
        }
        gf8v_gf_mul(tmp2, dpow_w1, Sig, lambda);
        for (unsigned int m = 0; m < nb; m++)
            G[m] ^= tmp2[m];
    }

    gf8v_zk_hash_update(bctx, G, tmp1, tmp2);

    free(pow_s);
    free(R);
    free(facbuf);
    return 0;
}

/* Test-only mode flag: defined in gf8_prover.c (shared prover+verifier). */
extern int voleith_gf8_syndrome_ref_mode;

/*
 * Reference syndrome verifier (pre-collapse): evaluate rho_j(delta) over keys
 * per syndrome bit j and push p scalars.  Dual of gf8p_accumulate_syndrome_ref;
 * the collapsed verifier is cross-checked against it (verdict-level).
 * Returns 0, -1 on OOM.
 */
static int
gf8v_accumulate_syndrome_ref(gf8v_zk_hash_ctx *bctx,
                             const gf8_syndrome_entry_t *sy,
                             const gf8_wire_id *sbits, const uint8_t *bit_keys,
                             const uint8_t *delta, unsigned int lambda,
                             unsigned int nb, const uint8_t *alpha8,
                             uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int w = sy->idx_bits;
    uint32_t p = sy->p;
    uint32_t n = sy->n0 * p;
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    const gf8_wire_id *idx = sbits + sy->idx_off;
    const gf8_wire_id *swires = sbits + sy->s_off;

    uint8_t dpow_w1[32];
    memset(dpow_w1, 0, nb);
    dpow_w1[0] = 0x01;
    for (unsigned int i = 1; i < w; i++) {
        gf8v_gf_mul(tmp1, dpow_w1, delta, lambda);
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
            gf8v_byte_combine(keys + (size_t)b * 32,
                              bit_keys +
                                  (size_t)idx[(size_t)k * w + b] * 8 * nb,
                              nb, lambda, alpha8);

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
                gf8v_gf_mul(tmp1, E, fac, lambda);
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
        gf8v_byte_combine(key_s, bit_keys + (size_t)swires[j] * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_gf_mul(tmp2, key_s, dpow_w1, lambda);
        for (unsigned int m = 0; m < nb; m++)
            gj[m] ^= tmp2[m];
        gf8v_zk_hash_update(bctx, gj, tmp1, tmp2);
    }

    free(G);
    free(keys);
    return 0;
}

/* =====================================================================
 * Threaded Step-1 key propagation (T3.4c): compute each wire's 8 bit-keys as a
 * level-synchronous wavefront, the verifier twin of the prover's T3.3
 * gf8p_tag_wavefront.  Wires form a DAG (a gate depends only on lower-id wires);
 * a serial pre-pass assigns each wire a topological level and, for WITNESS/MUL,
 * its Q_T column slot, and precomputes wire_pub for every INSTANCE/CONST wire
 * (so the parallel phase never writes wire_pub and SCALE_INSTANCE reads it
 * race-free).  Each level's wires are mutually independent and are tagged in W
 * contiguous chunks with a barrier between levels; the result is bit-identical
 * to the serial walk.  Unlike the prover, input keys fold in d + delta and
 * XOR_CONST adds const*delta (the verifier constant key is delta*const, not 0).
 * ===================================================================== */

static const uint8_t GF8V_SQUARE_MATRIX[8] = {0x51, 0xD0, 0x22, 0xF0,
                                              0x94, 0x60, 0x28, 0xC0};

typedef struct {
    uint8_t *bit_keys;
    const uint8_t *Q_T;
    const gf8_wire_entry_t *wires;
    const uint8_t *d;
    const uint8_t *delta;
    const uint8_t *wire_pub; /* public byte per wire, precomputed */
    const size_t *slot;      /* Q_T column-group for WITNESS / MUL wires */
    const gf8_wire_id *lvl;  /* current level's wire-id slice */
    size_t width;            /* wires in the current level */
    unsigned int W_eff;      /* contiguous chunks the level is split into */
    unsigned int nb;
} gf8v_key_shared_t;

/* Compute wire w's 8 bit-keys from its predecessors (slot[] / wire_pub[] replace
 * the serial walk's running counters).  Byte-identical to the Step-1 switch. */
static void
gf8v_key_wire(const gf8v_key_shared_t *sh, size_t w)
{
    const gf8_wire_entry_t *e = &sh->wires[w];
    unsigned int nb = sh->nb;
    const uint8_t *delta = sh->delta;
    uint8_t *bk_w = sh->bit_keys + w * 8 * nb;

    switch (e->kind) {
    case GF8_WIRE_WITNESS:
    case GF8_WIRE_MUL: {
        size_t slot = sh->slot[w];
        uint8_t d_byte = sh->d[slot];
        for (unsigned int i = 0; i < 8; i++) {
            memcpy(bk_w + i * nb, sh->Q_T + (slot * 8 + i) * nb, nb);
            if ((d_byte >> i) & 1u)
                for (unsigned int k = 0; k < nb; k++)
                    bk_w[i * nb + k] ^= delta[k];
        }
        break;
    }
    case GF8_WIRE_INSTANCE:
    case GF8_WIRE_CONST: {
        uint8_t v = sh->wire_pub[w];
        for (unsigned int i = 0; i < 8; i++) {
            if ((v >> i) & 1u)
                memcpy(bk_w + i * nb, delta, nb);
            else
                memset(bk_w + i * nb, 0, nb);
        }
        break;
    }
    case GF8_WIRE_XOR: {
        const uint8_t *bk_a = sh->bit_keys + (size_t)e->a * 8 * nb;
        const uint8_t *bk_b = sh->bit_keys + (size_t)e->b * 8 * nb;
        for (unsigned int i = 0; i < 8 * nb; i++)
            bk_w[i] = bk_a[i] ^ bk_b[i];
        break;
    }
    case GF8_WIRE_XOR_CONST: {
        uint8_t kval = e->const_val;
        const uint8_t *bk_a = sh->bit_keys + (size_t)e->a * 8 * nb;
        for (unsigned int i = 0; i < 8; i++) {
            memcpy(bk_w + i * nb, bk_a + i * nb, nb);
            if ((kval >> i) & 1u)
                for (unsigned int k = 0; k < nb; k++)
                    bk_w[i * nb + k] ^= delta[k];
        }
        break;
    }
    case GF8_WIRE_LINEAR_MAP:
        gf8v_apply_linear_map(bk_w, sh->bit_keys + (size_t)e->a * 8 * nb,
                              e->matrix, nb);
        break;
    case GF8_WIRE_SQUARE:
        gf8v_apply_linear_map(bk_w, sh->bit_keys + (size_t)e->a * 8 * nb,
                              GF8V_SQUARE_MATRIX, nb);
        break;
    case GF8_WIRE_SCALE_INSTANCE: {
        uint8_t M[8];
        voleith_gf8_mul_matrix(M, sh->wire_pub[e->b]);
        gf8v_apply_linear_map(bk_w, sh->bit_keys + (size_t)e->a * 8 * nb, M,
                              nb);
        break;
    }
    }
}

/* Each job tags one contiguous chunk of the current level (W_eff chunks), not
 * one wire: per-wire dispatch would drown the tiny per-wire work. */
static int
gf8v_key_job(size_t blk, void *ud)
{
    const gf8v_key_shared_t *sh = (const gf8v_key_shared_t *)ud;
    size_t lo = sh->width * blk / sh->W_eff;
    size_t hi = sh->width * (blk + 1) / sh->W_eff;
    for (size_t i = lo; i < hi; i++)
        gf8v_key_wire(sh, sh->lvl[i]);
    return 0;
}

/* Threaded Step 1.  Fills bit_keys and wire_pub.  Returns 0 on success, or -1
 * (alloc failure or pool refusal) to signal the caller to run the serial walk;
 * a -1 after partial progress is harmless because the serial walk overwrites
 * every wire from scratch (and re-fills wire_pub). */
static int
gf8v_key_wavefront(uint8_t *bit_keys, const uint8_t *Q_T,
                   const gf8_wire_entry_t *wires, const uint8_t *d,
                   const uint8_t *delta, const uint8_t *instance,
                   uint8_t *wire_pub, size_t n_wires, size_t n_witness,
                   unsigned int nb, struct ichor_pool *pool, unsigned int W)
{
    size_t *level = calloc(n_wires, sizeof(*level));
    size_t *slot = calloc(n_wires, sizeof(*slot));
    gf8_wire_id *order = calloc(n_wires, sizeof(*order));
    size_t *offs = NULL;
    size_t *cur = NULL;
    size_t span = 0, witness_idx = 0, mul_idx = 0, instance_idx = 0;
    int rc = -1;

    if (!level || !slot || !order)
        goto done;

    /* Serial pre-pass: per-wire topological level, Q_T slot (WITNESS/MUL),
     * wire_pub (INSTANCE/CONST), and span. */
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
        case GF8_WIRE_INSTANCE:
            wire_pub[w] = instance[instance_idx++];
            lv = 0;
            break;
        case GF8_WIRE_CONST:
            wire_pub[w] = e->const_val;
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
        default:
            lv = 0;
            break;
        }
        level[w] = lv;
        if (lv + 1 > span)
            span = lv + 1;
    }

    /* Counting sort into CSR level buckets (ascending id within each level). */
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
    gf8v_key_shared_t sh;
    sh.bit_keys = bit_keys;
    sh.Q_T = Q_T;
    sh.wires = wires;
    sh.d = d;
    sh.delta = delta;
    sh.wire_pub = wire_pub;
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
            if (ichor_pool_parallel_for(pool, W, gf8v_key_job, &sh) != 0) {
                rc = -1; /* pool refused: caller runs the serial walk */
                break;
            }
        } else {
            for (size_t i = 0; i < width; i++)
                gf8v_key_wire(&sh, sh.lvl[i]);
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
 * Threaded QuickSilver accumulate (T3.4b): the Step-2 zk_hash over gates and
 * constraints as a segmented reduction.  The canonical update stream is
 * [MUL gates | PRODUCT/PRODUCT3/ZERO/EQUAL | LT | syndrome | AES-norm |
 * Grostl-norm], each segment in index order (identical to the serial walk).  It
 * is cut into W contiguous blocks, each hashed from zero into its own local
 * context, then folded back in order (H = H*s^{n_upd_b} + H_b, t-stream with
 * t^{n_upd_b}); the result is bit-identical to the serial fold.  Mirror of the
 * prover's gf8p_qs_accum_* (T3.1).  The verifier works purely over keys + delta
 * (no wire_vals), so the descriptor is the prover's minus the witness fields
 * plus delta.
 * ===================================================================== */

typedef struct {
    uint8_t key_a[32], key_b[32], key_c[32], key_d[32];
    uint8_t prod[32], contrib[32], dsq[32];
    uint8_t tmp1[32], tmp2[32];
} gf8v_accum_scratch_t;

/* One MUL gate check (output wire w, inputs e->a, e->b): byte-identical to the
 * inline Step-2 MUL body. */
static void
gf8v_accumulate_mul(gf8v_zk_hash_ctx *bctx, const gf8_wire_entry_t *e,
                    gf8_wire_id w, const uint8_t *bit_keys, unsigned int lambda,
                    unsigned int nb, const uint8_t *alpha8,
                    gf8v_accum_scratch_t *sc)
{
    gf8v_byte_combine(sc->key_a, bit_keys + (size_t)e->a * 8 * nb, nb, lambda,
                      alpha8);
    gf8v_byte_combine(sc->key_b, bit_keys + (size_t)e->b * 8 * nb, nb, lambda,
                      alpha8);
    gf8v_byte_combine(sc->key_c, bit_keys + (size_t)w * 8 * nb, nb, lambda,
                      alpha8);
    gf8v_gf_mul(sc->prod, sc->key_a, sc->key_b, lambda);
    for (unsigned int k = 0; k < nb; k++)
        sc->contrib[k] = sc->prod[k] ^ sc->key_c[k];
    gf8v_zk_hash_update(bctx, sc->contrib, sc->tmp1, sc->tmp2);
}

/* One PRODUCT / PRODUCT3 / ZERO / EQUAL constraint: byte-identical to the
 * inline Step-2 constraint switch. */
static void
gf8v_accumulate_constraint(gf8v_zk_hash_ctx *bctx,
                           const gf8_constraint_entry_t *c,
                           const uint8_t *bit_keys, const uint8_t *delta,
                           unsigned int lambda, unsigned int nb,
                           const uint8_t *alpha8, gf8v_accum_scratch_t *sc)
{
    switch (c->kind) {
    case GF8_CONSTRAINT_PRODUCT:
        gf8v_byte_combine(sc->key_a, bit_keys + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_b, bit_keys + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_c, bit_keys + (size_t)c->c * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_gf_mul(sc->prod, sc->key_a, sc->key_b, lambda);
        for (unsigned int k = 0; k < nb; k++)
            sc->contrib[k] = sc->prod[k] ^ sc->key_c[k];
        gf8v_zk_hash_update(bctx, sc->contrib, sc->tmp1, sc->tmp2);
        break;
    case GF8_CONSTRAINT_PRODUCT3:
        gf8v_byte_combine(sc->key_a, bit_keys + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_b, bit_keys + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_c, bit_keys + (size_t)c->c * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_d, bit_keys + (size_t)c->d * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_gf_mul(sc->prod, sc->key_a, sc->key_b, lambda);
        gf8v_gf_mul(sc->contrib, sc->prod, sc->key_c, lambda); /* K_a*K_b*K_c */
        gf8v_gf_mul(sc->dsq, delta, delta, lambda);            /* delta^2 */
        gf8v_gf_mul(sc->prod, sc->key_d, sc->dsq, lambda);     /* K_d*delta^2 */
        for (unsigned int k = 0; k < nb; k++)
            sc->contrib[k] ^= sc->prod[k];
        gf8v_zk_hash_update(bctx, sc->contrib, sc->tmp1, sc->tmp2);
        break;
    case GF8_CONSTRAINT_ZERO:
        gf8v_byte_combine(sc->key_a, bit_keys + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_zk_hash_update(bctx, sc->key_a, sc->tmp1, sc->tmp2);
        break;
    case GF8_CONSTRAINT_EQUAL:
        gf8v_byte_combine(sc->key_a, bit_keys + (size_t)c->a * 8 * nb, nb,
                          lambda, alpha8);
        gf8v_byte_combine(sc->key_b, bit_keys + (size_t)c->b * 8 * nb, nb,
                          lambda, alpha8);
        for (unsigned int k = 0; k < nb; k++)
            sc->key_a[k] ^= sc->key_b[k];
        gf8v_zk_hash_update(bctx, sc->key_a, sc->tmp1, sc->tmp2);
        break;
    }
}

/* Read-only descriptor of the accumulate work, shared by every block job. */
typedef struct {
    const gf8_wire_entry_t *wires;
    const gf8_constraint_entry_t *constraints;
    const gf8_wire_id *mul_ids; /* ascending-wire-id MUL list, c0 long */
    const uint8_t *bit_keys;
    const uint8_t *alpha8;
    const uint8_t *delta;
    const gf8_lt_entry_t *lts;
    const gf8_wire_id *lt_bits;
    const gf8_syndrome_entry_t *syn;
    const gf8_wire_id *syn_bits;
    const gf8_norm_entry_t *norms;
    const gf8_wire_id *norm_wires;
    const gf8_grostl_norm_entry_t *gnorms;
    const gf8_wire_id *gn_wires;
    const size_t *offs;        /* W+1 partition offsets into [0, n_items)  */
    gf8v_zk_hash_ctx *hashers; /* W per-block local contexts               */
    gf8v_accum_scratch_t *scr; /* W per-block scratch                      */
    uint8_t (*gstb)[32];       /* W * gstb_stride, or NULL if no Grostl    */
    uint8_t (*gsrb)[32];       /* W * gsrb_stride, or NULL if no Grostl    */
    size_t gstb_stride;        /* 2 * GROSTL_NORM_MAX_STATE                */
    size_t gsrb_stride;        /* GROSTL_NORM_MAX_STATE                    */
    size_t c0, c1, c2, c3, c4; /* cumulative segment bounds                */
    unsigned int lambda, nb;
    int syn_ref_mode;
} gf8v_accum_shared_t;

/* Hash one contiguous [g0, g1) sub-range of the canonical item stream into the
 * block's local context.  Returns 0, or -1 if a helper fails. */
static int
gf8v_qs_accum_range(const gf8v_accum_shared_t *sh, size_t blk, size_t g0,
                    size_t g1)
{
    gf8v_zk_hash_ctx *h = &sh->hashers[blk];
    gf8v_accum_scratch_t *sc = &sh->scr[blk];
    uint8_t *t1 = sc->tmp1, *t2 = sc->tmp2;
    unsigned int lambda = sh->lambda, nb = sh->nb;

    for (size_t g = g0; g < g1; g++) {
        if (g < sh->c0) {
            gf8_wire_id w = sh->mul_ids[g];
            gf8v_accumulate_mul(h, &sh->wires[w], w, sh->bit_keys, lambda, nb,
                                sh->alpha8, sc);
        } else if (g < sh->c1) {
            gf8v_accumulate_constraint(h, &sh->constraints[g - sh->c0],
                                       sh->bit_keys, sh->delta, lambda, nb,
                                       sh->alpha8, sc);
        } else if (g < sh->c2) {
            const gf8_lt_entry_t *lt = &sh->lts[g - sh->c1];
            gf8v_accumulate_lt(h, lt, sh->lt_bits + lt->bits_off, sh->bit_keys,
                               sh->delta, lambda, nb, sh->alpha8, t1, t2);
        } else if (g < sh->c3) {
            const gf8_syndrome_entry_t *sy = &sh->syn[g - sh->c2];
            int rc = sh->syn_ref_mode
                         ? gf8v_accumulate_syndrome_ref(
                               h, sy, sh->syn_bits, sh->bit_keys, sh->delta,
                               lambda, nb, sh->alpha8, t1, t2)
                         : gf8v_accumulate_syndrome(
                               h, sy, sh->syn_bits, sh->bit_keys, sh->delta,
                               lambda, nb, sh->alpha8, t1, t2);
            if (rc != 0)
                return -1;
        } else if (g < sh->c4) {
            if (gf8v_accumulate_aes_norm(
                    h, &sh->norms[g - sh->c3], sh->norm_wires, sh->bit_keys,
                    sh->delta, lambda, nb, sh->alpha8, t1, t2) != 0)
                return -1;
        } else {
            uint8_t(*gstb)[32] = sh->gstb + blk * sh->gstb_stride;
            uint8_t(*gsrb)[32] = sh->gsrb + blk * sh->gsrb_stride;
            if (gf8v_accumulate_grostl_norm(
                    h, &sh->gnorms[g - sh->c4], sh->gn_wires, sh->bit_keys,
                    sh->delta, lambda, nb, sh->alpha8, t1, t2, gstb, gsrb) != 0)
                return -1;
        }
    }
    return 0;
}

/* ichor indexed-job trampoline: block index -> its partition range. */
static int
gf8v_qs_accum_job(size_t blk, void *ud)
{
    const gf8v_accum_shared_t *sh = (const gf8v_accum_shared_t *)ud;
    return gf8v_qs_accum_range(sh, blk, sh->offs[blk], sh->offs[blk + 1]);
}

/* =====================================================================
 * Main verifier
 * ===================================================================== */

int
voleith_gf8_qs_verify_ex(const voleith_gf8_circuit_t *circuit,
                         const uint8_t *instance, unsigned int lambda,
                         const uint8_t **Q, const uint8_t *d,
                         const uint8_t *delta, const uint8_t *chall_2,
                         const uint8_t *const *a_in, uint8_t *a0_tilde_out,
                         struct ichor_pool *pool)
{
    if (!circuit || !Q || !d || !delta || !chall_2 || !a_in || !a0_tilde_out)
        return -1;
    if (voleith_gf8_circuit_instance_count(circuit) > 0 && !instance)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    /* Opening count d = max constraint degree (2 today; opener raises it).
     * a_in[i] = coefficient a_i for i = 1..deg (a_in[0] unused).  Validate
     * before any allocation so a null buffer returns directly. */
    unsigned int deg = voleith_gf8_circuit_qs_degree(circuit);
    if (deg > VOLEITH_QS_D_MAX)
        return -1;
    for (unsigned int i = 1; i <= deg; i++)
        if (!a_in[i])
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
    uint8_t *wire_pub = NULL; /* public byte per INSTANCE/CONST wire, by id */

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
        case GF8_WIRE_SCALE_INSTANCE:
            /* b must be an in-range instance wire (mirrors circuit_validate):
             * keep the primitive memory-safe and public-only even if handed a
             * forged circuit directly. */
            if (e->a >= n_wires || e->b >= n_wires ||
                wires[e->b].kind != GF8_WIRE_INSTANCE)
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
        case GF8_CONSTRAINT_PRODUCT3:
            if (c->a >= n_wires || c->b >= n_wires || c->c >= n_wires ||
                c->d >= n_wires)
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

    /* ell * 8 must not wrap before it feeds the Q_T column count.  The
     * correction region is deg mask blocks (q_star reads columns up to
     * ell*8 + deg*lambda); scales with the opening degree (was d=2 only). */
    if (ell > (SIZE_MAX - (size_t)deg * lambda) / 8u)
        return -1;
    size_t n_bit_cols = ell * 8u + (size_t)deg * lambda;

    bit_keys = calloc(n_wires, (size_t)8 * nb);
    if (!bit_keys)
        goto oom;

    /* Public scalar per wire, needed to rebuild the x -> b*x matrix for
     * SCALE_INSTANCE gates (b is always an earlier INSTANCE wire). */
    wire_pub = calloc(n_wires ? n_wires : 1, 1);
    if (!wire_pub)
        goto oom;

    Q_T = gf8v_transpose_matrix(Q, lambda, nb, n_bit_cols, pool);
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
    int keys_threaded = -1;
    {
        unsigned int W = 1;
        if (pool != NULL) {
            unsigned ps = ichor_pool_size(pool);
            if (ps > 1u)
                W = ps;
        }
        if (W > 1)
            keys_threaded =
                gf8v_key_wavefront(bit_keys, Q_T, wires, d, delta, instance,
                                   wire_pub, n_wires, n_witness, nb, pool, W);
    }

    /* Serial reference walk: W<=1, no pool, alloc failure, or pool refusal.
     * Bit-identical to the wavefront above. */
    if (keys_threaded != 0) {
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
                wire_pub[w] = v;
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
                wire_pub[w] = v;
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
            case GF8_WIRE_SCALE_INSTANCE: {
                /* Mirror the prover: rebuild the x -> b*x matrix from the
                 * public scalar on the instance operand and propagate the key
                 * by linearity.  Free: no d byte, no slot. */
                uint8_t M[8];
                voleith_gf8_mul_matrix(M, wire_pub[e->b]);
                gf8v_apply_linear_map(bk_w, bit_keys + e->a * 8 * nb, M, nb);
                break;
            }
            }
        }
    }

    gf8v_zk_hash_ctx bctx;
    gf8v_zk_hash_init(&bctx, chall_2, lambda);

    /*
     * Step 2: accumulate every gate / constraint into zk_hash as a segmented
     * reduction (T3.4b, the verifier twin of the prover's T3.1).  Gather the
     * auxiliary constraint arrays, bounds-check the LT / syndrome pools once up
     * front (defense in depth, as the serial path did inline), build the
     * canonical item stream [MUL | PRODUCT/.. | LT | syndrome | AES-norm |
     * Grostl-norm], cut it into W weight-balanced contiguous blocks hashed in
     * parallel, then fold the W local contexts back into bctx (h0/h1 start
     * zero) in canonical order: H = H*s^{n_upd_b} + H_b, t-stream with
     * t^{n_upd_b}.  Bit-identical to the serial Horner fold.
     */
    {
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

        /* INFO-3 defense in depth: reject a zero / over-wide LT or syndrome and
         * out-of-range bit references at the untrusted-input boundary, before
         * any accumulate indexes its fixed [VOLEITH_QS_COEFFS_MAX] dpow scratch
         * to delta^w.  Done once here (the serial path checked inline), so the
         * threaded per-item work runs only on validated entries. */
        for (size_t li = 0; li < n_lt; li++) {
            unsigned int w = lts[li].width;
            const gf8_wire_id *bits = lt_bits + lts[li].bits_off;
            if (w == 0 || w > VOLEITH_QS_D_MAX - 1u)
                goto oom;
            for (unsigned int j = 0; j < 2u * w; j++)
                if (bits[j] >= n_wires)
                    goto oom;
        }
        for (size_t si = 0; si < n_syn; si++) {
            const gf8_syndrome_entry_t *sy = &syn[si];
            size_t cnt = (size_t)sy->t * sy->idx_bits + (size_t)sy->p;
            if (sy->t == 0 || sy->idx_bits == 0 || sy->p == 0 || sy->n0 == 0 ||
                sy->idx_bits > VOLEITH_QS_D_MAX - 1u)
                goto oom;
            for (size_t j = 0; j < cnt; j++)
                if (syn_bits[sy->idx_off + j] >= n_wires)
                    goto oom;
        }

        /* MUL item list in ascending wire id (the serial MUL order). */
        gf8_wire_id *mul_ids = NULL;
        if (n_mul > 0) {
            mul_ids = calloc(n_mul, sizeof(*mul_ids));
            if (!mul_ids)
                goto oom;
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

        /* One block per worker, capped at the item count; a null / size<=1 pool
         * runs a single serial block (the bit-identical reference). */
        size_t W = 1;
        if (pool != NULL) {
            unsigned ps = ichor_pool_size(pool);
            if (ps > 1u)
                W = (size_t)ps;
        }
        if (W > n_items)
            W = (n_items > 0) ? n_items : 1;

        size_t *offs = calloc(W + 1, sizeof(*offs));
        gf8v_zk_hash_ctx *hashers = calloc(W, sizeof(*hashers));
        gf8v_accum_scratch_t *scr = calloc(W, sizeof(*scr));
        size_t gstb_stride = (size_t)2 * GROSTL_NORM_MAX_STATE;
        size_t gsrb_stride = GROSTL_NORM_MAX_STATE;
        uint8_t(*gstb)[32] = NULL;
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
            goto oom;
        }

        /* Weighted contiguous partition: syndrome and norm items cost much more
         * than a single gate, so split by cumulative weight to balance blocks.
         * Boundaries stay on item (canonical-order) edges, which the segmented
         * combine requires; empty blocks are harmless.  Identical to the
         * prover's T3.1 scheme. */
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
            gf8v_zk_hash_init(&hashers[b], chall_2, lambda);

        gf8v_accum_shared_t sh;
        memset(&sh, 0, sizeof(sh));
        sh.wires = wires;
        sh.constraints = constraints;
        sh.mul_ids = mul_ids;
        sh.bit_keys = bit_keys;
        sh.alpha8 = alpha8;
        sh.delta = delta;
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
            perr = gf8v_qs_accum_range(&sh, 0, 0, n_items);
        else
            perr = ichor_pool_parallel_for(pool, W, gf8v_qs_accum_job, &sh);

        if (perr == 0) {
            /* Fold the blocks into bctx (its h0/h1 start zero) in canonical
             * order: H = H*s^{n_upd_b} + H_b (t-stream with t^{n_upd_b}). */
            uint8_t spow[32], tpow[32];
            for (size_t b = 0; b < W; b++) {
                gf8v_zk_hash_ctx *hb = &hashers[b];
                gf8v_gf_pow(spow, bctx.s, hb->n_upd, lambda, nb);
                gf8v_gf_pow(tpow, bctx.t, hb->n_upd, lambda, nb);
                gf8v_gf_mul(tmp1, bctx.h0, spow, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    bctx.h0[k] = tmp1[k] ^ hb->h0[k];
                gf8v_gf_mul(tmp2, bctx.h1, tpow, lambda);
                for (unsigned int k = 0; k < nb; k++)
                    bctx.h1[k] = tmp2[k] ^ hb->h1[k];
            }
        }

        /* The verifier keys are public (not witness), but mirror the serial
         * hygiene: scrub the per-block scratch and the Grostl degree buffers
         * before free. */
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
            goto oom;
    }

    /* ------------------------------------------------------------------
     * Step 3: q_star correction over d mask blocks (QS_DEGREE_D_DESIGN section
     * 11, verifier side): q_star = sum_{j=0..d-1} delta^j * q_star_j, block j
     * at corr_start + j*lambda.  At d=2: q_star_0 + delta * q_star_1.
     * ------------------------------------------------------------------ */
    /* deg (opening count) was derived from qs_degree at entry. */
    uint8_t q_star[32];
    {
        uint8_t q_star_j[32], delta_pow[32], term[32];
        size_t corr_start = ell * 8;

        gf8v_sum_poly_cols(q_star, tmp1, Q_T, lambda, nb, corr_start, lambda);
        if (deg > 1)
            memcpy(delta_pow, delta, nb); /* delta^1 */
        for (unsigned int j = 1; j < deg; j++) {
            gf8v_sum_poly_cols(q_star_j, tmp1, Q_T, lambda, nb,
                               corr_start + (size_t)j * lambda, lambda);
            gf8v_gf_mul(term, delta_pow, q_star_j, lambda);
            for (unsigned int k = 0; k < nb; k++)
                q_star[k] ^= term[k];
            if (j + 1 < deg)
                gf8v_gf_mul(delta_pow, delta_pow, delta, lambda);
        }
    }

    /* ------------------------------------------------------------------
     * Step 4: Finalize zk_hash to get q_tilde.
     * ------------------------------------------------------------------ */
    uint8_t q_tilde[32];
    gf8v_zk_hash_finalize(q_tilde, &bctx, q_star, chall_2, tmp1, tmp2);
    voleith_secure_zero(&bctx, sizeof(bctx));

    /* ------------------------------------------------------------------
     * Step 5: a0_tilde_out = q_tilde + sum_{i=1..d} delta^i * a_i_tilde
     * (at d=2: + delta*a1 + delta^2*a2; a_i for i>2 arrive via serialization).
     * ------------------------------------------------------------------ */
    {
        uint8_t delta_pow[32], term[32];

        memcpy(a0_tilde_out, q_tilde, nb);
        memcpy(delta_pow, delta, nb); /* delta^1 */
        for (unsigned int i = 1; i <= deg; i++) {
            gf8v_gf_mul(term, delta_pow, a_in[i], lambda);
            for (unsigned int k = 0; k < nb; k++)
                a0_tilde_out[k] ^= term[k];
            if (i < deg)
                gf8v_gf_mul(delta_pow, delta_pow, delta, lambda);
        }
    }

    free(Q_T);
    free(bit_keys);
    free(wire_pub);
    return 0;

oom:
    free(Q_T);
    free(bit_keys);
    free(wire_pub);
    return -1;
}

/* Serial wrapper: the historical signature, pool == NULL (no threading). */
int
voleith_gf8_qs_verify(const voleith_gf8_circuit_t *circuit,
                      const uint8_t *instance, unsigned int lambda,
                      const uint8_t **Q, const uint8_t *d, const uint8_t *delta,
                      const uint8_t *chall_2, const uint8_t *const *a_in,
                      uint8_t *a0_tilde_out)
{
    return voleith_gf8_qs_verify_ex(circuit, instance, lambda, Q, d, delta,
                                    chall_2, a_in, a0_tilde_out, NULL);
}
