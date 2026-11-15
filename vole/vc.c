/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * vc.c - Vector commitment via GGM tree (FAEST spec Section 5)
 *
 * Implements GGM tree expansion and the PosInTree mapping from the
 * FAEST v2.0 specification.
 */

#include "vc.h"
#include "prg.h"
#include "hash.h"
#include "util.h"
#include <assert.h>
#include <ichor/pool.h>
#include <stdlib.h>
#include <string.h>

/* ---- Parameter initialization ---- */

int
voleith_vc_params_init(voleith_vc_params_t *params, int lambda, int tau,
                       int w_grind, int n_leafcom, int T_open)
{
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;
    if (tau <= 0)
        return -1;
    if (n_leafcom != 2 && n_leafcom != 3)
        return -1;
    if (T_open <= 0)
        return -1;
    /*
     * S-3: bound w_grind and the derived per-vector depth k before any
     * shift uses them.  These mirror the guards in
     * proof.c:voleith_params_validate so a direct caller of this
     * exported initializer cannot trigger UB:
     *   - w_grind < 0 or w_grind >= lambda makes effective = lambda -
     *     w_grind non-positive (or exceeds lambda), driving k to a
     *     non-positive value and `1 << (k - 1)` into a negative shift.
     *   - k > VOLEITH_MAX_K overruns the v_ptrs[VOLEITH_MAX_K] stack
     *     array in vole/convert.c and risks `1 << k` past size_t width.
     */
    if (w_grind < 0 || w_grind >= lambda)
        return -1;

    /*
     * FAEST spec Table 5.1:
     *   k    = floor((lambda - w_grind) / tau) + 1
     *   tau1 = (lambda - w_grind) mod tau
     *   tau0 = tau - tau1
     *   L    = tau1 * 2^k + tau0 * 2^{k-1}
     */
    int effective = lambda - w_grind;
    int k = effective / tau + 1;
    if (k > VOLEITH_MAX_K)
        return -1;

    params->lambda = lambda;
    params->tau = tau;
    params->n_leafcom = n_leafcom;
    params->w_grind = w_grind;
    params->T_open = T_open;
    params->k = k;
    params->tau1 = effective % tau;
    params->tau0 = tau - params->tau1;

    size_t two_k = (size_t)1 << params->k;
    size_t two_km1 = (size_t)1 << (params->k - 1);
    params->L = (size_t)params->tau1 * two_k + (size_t)params->tau0 * two_km1;

    return 0;
}

size_t
voleith_vc_N(const voleith_vc_params_t *params, int i)
{
    if (i < params->tau1)
        return (size_t)1 << params->k;
    else
        return (size_t)1 << (params->k - 1);
}

/*
 * PosInTree(i, j) - FAEST spec Figure 5.2
 *
 * Maps (vector index i, position j) to leaf index α ∈ [L-1..2L-2].
 *
 * if j < 2^{k-1}:
 *     return L - 1 + τ*j + i
 * else:
 *     return L - 1 + τ*2^{k-1} + τ_1*(j mod 2^{k-1}) + i
 */
size_t
voleith_pos_in_tree(const voleith_vc_params_t *params, int i, size_t j)
{
    size_t two_km1 = (size_t)1 << (params->k - 1);

    if (j < two_km1) {
        return params->L - 1 + (size_t)params->tau * j + (size_t)i;
    } else {
        return params->L - 1 + (size_t)params->tau * two_km1 +
               (size_t)params->tau1 * (j % two_km1) + (size_t)i;
    }
}

/* ---- GGM tree allocation ---- */

int
voleith_ggm_tree_alloc(voleith_ggm_tree_t *tree, size_t L, int lambda)
{
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;
    if (L == 0)
        return -1;

    size_t seed_bytes = (size_t)lambda / 8;
    size_t total_nodes = 2 * L - 1;

    tree->nodes = calloc(total_nodes, seed_bytes);
    if (!tree->nodes)
        return -1;

    tree->L = L;
    tree->lambda = lambda;
    tree->seed_bytes = seed_bytes;
    return 0;
}

void
voleith_ggm_tree_free(voleith_ggm_tree_t *tree)
{
    if (tree->nodes) {
        size_t total_nodes = 2 * tree->L - 1;
        voleith_secure_zero(tree->nodes, total_nodes * tree->seed_bytes);
        free(tree->nodes);
        tree->nodes = NULL;
    }
    tree->L = 0;
}

/* ---- GGM tree expansion ---- */

/*
 * Expand the GGM tree from a root seed.
 *
 * For each internal node α ∈ [0..L-2]:
 *   PRG(k_α, iv, α; 2λ) → (k_{2α+1}, k_{2α+2})
 *
 * The PRG output is 2λ bits = 2 * seed_bytes bytes.
 * The first seed_bytes go to the left child (2α+1),
 * the next seed_bytes go to the right child (2α+2).
 */
void
voleith_ggm_tree_expand(voleith_ggm_tree_t *tree, const uint8_t *root_seed,
                        const uint8_t iv[16])
{
    size_t sb = tree->seed_bytes;
    size_t L = tree->L;

    /* Set root node */
    memcpy(tree->nodes, root_seed, sb);

    /* Buffer for PRG output: 2λ bits = 2 * sb bytes */
    uint8_t prg_out[64]; /* max 2*32 = 64 bytes for lambda=256 */

    /* Expand each internal node */
    for (size_t alpha = 0; alpha < L - 1; alpha++) {
        const uint8_t *parent_seed = tree->nodes + alpha * sb;

        /* Initialize PRG with this node's seed */
        voleith_prg_ctx_t prg;
        voleith_prg_init(&prg, parent_seed, tree->lambda);

        /* PRG(k_α, iv, α; 2λ) - tweak = α */
        voleith_prg_gen(&prg, prg_out, iv, (uint32_t)alpha,
                        2 * (size_t)tree->lambda);
        voleith_prg_clear(&prg);

        /* Left child: 2α+1 */
        memcpy(tree->nodes + (2 * alpha + 1) * sb, prg_out, sb);

        /* Right child: 2α+2 */
        memcpy(tree->nodes + (2 * alpha + 2) * sb, prg_out + sb, sb);
    }

    voleith_secure_zero(prg_out, sizeof(prg_out));
}

/* ---- Domain-separated hash functions (FAEST spec Section 3.3) ---- */

/*
 * H_1(m) = SHAKE(m || 0x01; 2λ)
 *
 * SHAKE128 if lambda=128, SHAKE256 otherwise.
 * Output: 2λ bits = 2*lambda/8 bytes.
 */
static void
hash_h1(int lambda, const uint8_t *msg, size_t msg_len, uint8_t *out)
{
    size_t out_bytes = 2 * (size_t)lambda / 8;
    uint8_t domain = 0x01;

    voleith_hash_ctx_t ctx;
    /*
     * Fresh context, absorbed then squeezed once, so the absorb cannot return
     * the finalized error; asserted for debug-build documentation.  hash_h1 is
     * void and internal but its callers are the VOLE commit / reconstruct
     * paths, so it is asserted rather than made int to avoid cascading the
     * return up through them.
     *
     * TODO(v1.11.0 / next minor bump): make hash_h1 return int and thread the
     * transcript error through the VOLE commit / reconstruct callers instead of
     * asserting.
     */
    int rc;
    if (lambda == 128) {
        voleith_shake128_init(&ctx);
        rc = voleith_shake128_absorb(&ctx, msg, msg_len);
        assert(rc == 0);
        rc = voleith_shake128_absorb(&ctx, &domain, 1);
        assert(rc == 0);
        voleith_shake128_squeeze(&ctx, out, out_bytes);
    } else {
        voleith_shake256_init(&ctx);
        rc = voleith_shake256_absorb(&ctx, msg, msg_len);
        assert(rc == 0);
        rc = voleith_shake256_absorb(&ctx, &domain, 1);
        assert(rc == 0);
        voleith_shake256_squeeze(&ctx, out, out_bytes);
    }
    (void)rc;
    voleith_hash_ctx_clear(&ctx);
}

/* ---- FAEST-EM LeafCommit (FAEST spec Figure 5.3, right column) ---- */

/*
 * FAEST-EM.LeafCommit(r, iv, twk):
 *   com ← PRG(r, iv, twk; 2λ)
 *   sd  ← r
 *   return (sd, com)
 *
 * For FAEST-EM, n_leafcom = 2, so com is 2λ bits.
 * sd is simply the input seed r (copied separately by the caller).
 */
static void
leaf_commit_em(int lambda, const uint8_t *seed, const uint8_t iv[16],
               uint32_t twk, uint8_t *com_out)
{
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, lambda);
    voleith_prg_gen(&prg, com_out, iv, twk, 2 * (size_t)lambda);
    voleith_prg_clear(&prg);
}

/* ---- Prover threading-context scratch (T1.5) ---- */

int
voleith_threadctx_scratch_init(voleith_threadctx_t *tctx,
                               const voleith_vc_params_t *params,
                               size_t ellhat_bytes)
{
    if (!tctx || !params)
        return -1;

    size_t tau = (size_t)params->tau;
    size_t sb = (size_t)params->lambda / 8;
    size_t com_bytes = (size_t)params->n_leafcom * sb;
    size_t hash_bytes = 2 * sb;
    size_t max_N = (size_t)1 << params->k;

    /* Transient scratch is per-worker (nworkers slots); the pool count is the
     * source of truth (nthreads == 0 already resolved to physical cores).  No
     * pool means a single inline worker (T2.3). */
    size_t nworkers = tctx->pool ? (size_t)ichor_pool_size(tctx->pool) : 1u;

    tctx->jobs = calloc(tau, sizeof(struct ichor_job_info));
    tctx->bavc_concat = calloc(nworkers * max_N, com_bytes);
    tctx->bavc_h_all = calloc(tau, hash_bytes);
    tctx->vole_sd_buf = calloc(nworkers * max_N, sb);
    tctx->vole_r = calloc(nworkers * 2 * max_N, ellhat_bytes);
    tctx->vole_ui = calloc(tau, ellhat_bytes);
    tctx->vole_v_off = calloc(tau + 1, sizeof(int));
    if (!tctx->jobs || !tctx->bavc_concat || !tctx->bavc_h_all ||
        !tctx->vole_sd_buf || !tctx->vole_r || !tctx->vole_ui ||
        !tctx->vole_v_off) {
        voleith_threadctx_scratch_free(tctx);
        return -1;
    }

    tctx->vole_sd_buf_bytes = nworkers * max_N * sb;
    tctx->vole_r_bytes = nworkers * 2 * max_N * ellhat_bytes;
    tctx->vole_ui_bytes = tau * ellhat_bytes;

    /* v_off is public and fixed by params, so fill it once here (T1.2). */
    tctx->vole_v_off[0] = 0;
    for (int i = 0; i < params->tau; i++) {
        int ki = (i < params->tau1) ? params->k : (params->k - 1);
        tctx->vole_v_off[i + 1] = tctx->vole_v_off[i] + ki;
    }

    tctx->scratch_tau = params->tau;
    tctx->scratch_nworkers = (int)nworkers;
    tctx->scratch_ellhat_bytes = ellhat_bytes;
    return 0;
}

void
voleith_threadctx_scratch_free(voleith_threadctx_t *tctx)
{
    if (!tctx)
        return;

    /* Secret buffers: zero before free (the per-call zeroing in
     * voleith_vole_commit / voleith_convert_to_vole already clears the used
     * portions; this is the defense-in-depth backstop other free sites in this
     * file also apply, and it also scrubs any slot tail a short vector left
     * untouched). */
    if (tctx->vole_sd_buf)
        voleith_secure_zero(tctx->vole_sd_buf, tctx->vole_sd_buf_bytes);
    if (tctx->vole_r)
        voleith_secure_zero(tctx->vole_r, tctx->vole_r_bytes);
    if (tctx->vole_ui)
        voleith_secure_zero(tctx->vole_ui, tctx->vole_ui_bytes);

    free(tctx->jobs);
    free(tctx->bavc_concat);
    free(tctx->bavc_h_all);
    free(tctx->vole_sd_buf);
    free(tctx->vole_r);
    free(tctx->vole_ui);
    free(tctx->vole_v_off);

    tctx->jobs = NULL;
    tctx->bavc_concat = NULL;
    tctx->bavc_h_all = NULL;
    tctx->vole_sd_buf = NULL;
    tctx->vole_r = NULL;
    tctx->vole_ui = NULL;
    tctx->vole_v_off = NULL;
    tctx->scratch_tau = 0;
    tctx->scratch_nworkers = 0;
    tctx->scratch_ellhat_bytes = 0;
    tctx->vole_sd_buf_bytes = 0;
    tctx->vole_r_bytes = 0;
    tctx->vole_ui_bytes = 0;
}

/* ---- BAVC Commit (FAEST spec Figure 5.4) ---- */

/*
 * Shared, read-only arguments for the per-vector commit job (T1.3).  One
 * instance is built on the stack of voleith_bavc_commit and pointed at by
 * every job descriptor; the job's own vector index arrives as the descriptor
 * index i.  The GGM tree (in result->tree) is expanded once before any job
 * runs and only read here; each job writes only its vector's disjoint RETAINED
 * slices of result->leaf_seeds / result->leaf_coms and its h_all[i] slot
 * (tau-indexed), and uses a PER-WORKER concat slot (concat_base + worker *
 * concat_slot_bytes, worker = ichor_job_worker_index) as transient scratch, so
 * the running jobs never touch the same bytes (T2.3).
 */
typedef struct {
    voleith_bavc_t *result;
    const voleith_vc_params_t *params;
    const uint8_t *iv;
    uint8_t *concat_base; /* per-worker: slot = concat_base + w*slot_bytes */
    uint8_t *h_all;       /* per-tau (retained) */
    size_t L;
    size_t sb;
    size_t com_bytes;
    size_t concat_slot_bytes;
    size_t hash_bytes;
    int lambda;
} bavc_commit_job_t;

/*
 * Commit one tau vector i: gather its leaf seeds, compute its leaf
 * commitments, and fold them into h_all[i] = H_1(com_{i,0} || ... ||
 * com_{i,N_i-1}).  Behavior-identical to the former two serial loops fused per
 * vector: vector i reads only the leaf commitments it just wrote (its own
 * PosInTree leaves), so fusing the compute and hash steps changes no output.
 * Returns 0 (no failure path today; leaf_commit_em is infallible).
 */
static int
bavc_commit_vector_job(size_t i, void *ud, ichor_job_ctx_t *jctx)
{
    const bavc_commit_job_t *a = ud;
    const voleith_vc_params_t *params = a->params;
    voleith_bavc_t *result = a->result;
    size_t L = a->L;
    size_t sb = a->sb;
    size_t com_bytes = a->com_bytes;
    int lambda = a->lambda;

    uint32_t twk = (uint32_t)(i + L - 1);
    size_t Ni = voleith_vc_N(params, (int)i);
    uint8_t *concat = a->concat_base + (size_t)ichor_job_worker_index(jctx) *
                                           a->concat_slot_bytes;

    for (size_t j = 0; j < Ni; j++) {
        size_t alpha = voleith_pos_in_tree(params, (int)i, j);
        size_t leaf_idx = alpha - (L - 1);
        const uint8_t *k_alpha = voleith_ggm_tree_node(&result->tree, alpha);

        /* Leaf seed: for EM, sd = k_alpha. */
        memcpy(result->leaf_seeds + leaf_idx * sb, k_alpha, sb);

        /* Leaf commitment. */
        if (params->n_leafcom == 2) {
            /* FAEST-EM variant. */
            leaf_commit_em(lambda, k_alpha, a->iv, twk,
                           result->leaf_coms + leaf_idx * com_bytes);
        }
        /* TODO: FAEST variant (n_leafcom == 3) with LeafHash */

        /* Build concat of com_{i,0} || ... || com_{i,N_i-1} in (i,j) order. */
        memcpy(concat + j * com_bytes, result->leaf_coms + leaf_idx * com_bytes,
               com_bytes);
    }

    /* h_i = H_1(concat). */
    hash_h1(lambda, concat, Ni * com_bytes, a->h_all + i * a->hash_bytes);
    return 0;
}

int
voleith_bavc_commit(voleith_bavc_t *result, const voleith_vc_params_t *params,
                    const uint8_t *root_seed, const uint8_t iv[16],
                    const voleith_threadctx_t *tctx)
{
    int lambda = params->lambda;
    size_t sb = (size_t)lambda / 8;
    size_t L = params->L;
    int tau = params->tau;
    size_t com_bytes = (size_t)params->n_leafcom * sb;

    result->com_bytes = com_bytes;
    result->seed_bytes = sb;
    result->leaf_coms = NULL;
    result->leaf_seeds = NULL;

    /* Step 1: Expand GGM tree (lines 5-7 of Figure 5.4) */
    if (voleith_ggm_tree_alloc(&result->tree, L, lambda) != 0)
        return -1;

    voleith_ggm_tree_expand(&result->tree, root_seed, iv);

    /* Allocate per-leaf commitments and seeds */
    result->leaf_coms = calloc(L, com_bytes);
    result->leaf_seeds = calloc(L, sb);
    if (!result->leaf_coms || !result->leaf_seeds) {
        voleith_bavc_free(result);
        return -1;
    }

    /*
     * Steps 8-13: for each tau vector, compute its leaf commitments (FAEST-EM:
     * sd_{i,j} = k_alpha, com_{i,j} = PRG(k_alpha, iv, i+L-1; 2lambda), same
     * tweak across a vector, distinct seeds) and fold them into the per-vector
     * hash h_i = H_1(com_{i,0} || ... || com_{i,N_i-1}).  Each vector's leaves
     * (its PosInTree positions) are disjoint from every other vector's, so the
     * vectors are independent and the tau-rep loop runs either serially or as
     * one pool batch, bit-identically.  The final com = H_1(h_0 || ... ||
     * h_{tau-1}) stays serial after the join (ordered absorb).
     *
     * Scratch (T2.3): h_all is per-tau (retained); concat is PER-WORKER
     * transient scratch (nworkers slots, keyed in the job by worker index), so a
     * worker reuses its one slot across the vectors it runs.  Prefer the
     * prover's preallocated scratch on tctx; fall back to a local allocation
     * when there is none (tctx == NULL, or a bare tctx as in a vole-layer test),
     * sized to nworkers slots (1 when there is no pool).  hash_bytes = 2*sb is
     * the H_1 output (2lambda bits).
     */
    size_t hash_bytes = 2 * sb;
    size_t max_N = (size_t)1 << params->k;
    size_t concat_slot_bytes = max_N * com_bytes;
    size_t nworkers =
        (tctx && tctx->pool) ? (size_t)ichor_pool_size(tctx->pool) : 1u;

    int have_scratch = (tctx && tctx->scratch_tau == tau);
    uint8_t *h_all =
        have_scratch ? tctx->bavc_h_all : calloc((size_t)tau, hash_bytes);
    uint8_t *concat_all =
        have_scratch ? tctx->bavc_concat : calloc(nworkers * max_N, com_bytes);
    if (!h_all || !concat_all) {
        if (!have_scratch) {
            free(h_all);
            free(concat_all);
        }
        voleith_bavc_free(result);
        return -1;
    }

    bavc_commit_job_t jarg = {
        .result = result,
        .params = params,
        .iv = iv,
        .concat_base = concat_all,
        .h_all = h_all,
        .L = L,
        .sb = sb,
        .com_bytes = com_bytes,
        .concat_slot_bytes = concat_slot_bytes,
        .hash_bytes = hash_bytes,
        .lambda = lambda,
    };

    int rc = 0;
    if (tctx && tctx->pool) {
        /*
         * Threaded path: submit the tau vectors as one caller-owned batch and
         * block until all finish.  Reuse the preallocated descriptor array when
         * present, else a local one.  jarg and jobs stay alive on this stack /
         * on tctx until the wait returns, as the submit contract requires.
         */
        ichor_job_info_t *jobs =
            have_scratch ? tctx->jobs : calloc((size_t)tau, sizeof(*jobs));
        if (!jobs) {
            rc = -1;
        } else {
            for (int i = 0; i < tau; i++) {
                jobs[i].fn = bavc_commit_vector_job;
                jobs[i].ud = &jarg;
            }
            uint64_t label = ichor_pool_new_label(tctx->pool);
            int done = 0;
            int err = 0;
            rc = ichor_pool_submit_jobs(tctx->pool, jobs, (size_t)tau, label);
            if (rc == 0)
                rc = ichor_pool_wait(tctx->pool, label, -1, &done, &err);
            if (rc == 0 && err != 0)
                rc = err;
            if (!have_scratch)
                free(jobs);
        }
    } else {
        /* Serial path (no pool, e.g. tctx == NULL): same job, run inline. */
        for (int i = 0; i < tau; i++)
            (void)bavc_commit_vector_job((size_t)i, &jarg, NULL);
    }

    if (rc != 0) {
        if (!have_scratch) {
            free(h_all);
            free(concat_all);
        }
        voleith_bavc_free(result);
        return -1;
    }

    /* com = H_1(h_0 || ... || h_{tau-1}). */
    hash_h1(lambda, h_all, (size_t)tau * hash_bytes, result->com);

    if (!have_scratch) {
        free(concat_all);
        free(h_all);
    }
    return 0;
}

void
voleith_bavc_free(voleith_bavc_t *result)
{
    if (result->leaf_seeds) {
        voleith_secure_zero(result->leaf_seeds,
                            result->tree.L * result->seed_bytes);
        free(result->leaf_seeds);
        result->leaf_seeds = NULL;
    }
    if (result->leaf_coms) {
        free(result->leaf_coms);
        result->leaf_coms = NULL;
    }
    voleith_ggm_tree_free(&result->tree);
    voleith_secure_zero(result->com, sizeof(result->com));
}

const uint8_t *
voleith_bavc_leaf_seed(const voleith_bavc_t *result,
                       const voleith_vc_params_t *params, int i, size_t j)
{
    size_t alpha = voleith_pos_in_tree(params, i, j);
    size_t leaf_idx = alpha - (params->L - 1);
    return result->leaf_seeds + leaf_idx * result->seed_bytes;
}

const uint8_t *
voleith_bavc_leaf_com(const voleith_bavc_t *result,
                      const voleith_vc_params_t *params, int i, size_t j)
{
    size_t alpha = voleith_pos_in_tree(params, i, j);
    size_t leaf_idx = alpha - (params->L - 1);
    return result->leaf_coms + leaf_idx * result->com_bytes;
}

/* ---- Bitmap helpers ---- */

static inline void
bit_set(uint8_t *bitmap, size_t idx)
{
    bitmap[idx / 8] |= (uint8_t)(1 << (idx % 8));
}

static inline int
bit_get(const uint8_t *bitmap, size_t idx)
{
    return (bitmap[idx / 8] >> (idx % 8)) & 1;
}

/* ---- BAVC Open (FAEST spec Figure 5.4, Open) ---- */

size_t
voleith_bavc_opening_size(const voleith_vc_params_t *params)
{
    size_t sb = (size_t)params->lambda / 8;
    size_t com_bytes = (size_t)params->n_leafcom * sb;
    return com_bytes * (size_t)params->tau + (size_t)params->T_open * sb;
}

int
voleith_bavc_open(voleith_bavc_opening_t *opening, const voleith_bavc_t *bavc,
                  const voleith_vc_params_t *params, const size_t *i_delta)
{
    size_t L = params->L;
    size_t sb = (size_t)params->lambda / 8;
    int tau = params->tau;
    size_t com_bytes = (size_t)params->n_leafcom * sb;

    opening->data = NULL;
    opening->data_len = 0;
    opening->n_revealed = 0;

    /*
     * V-12: Validate i_delta[i] < N_i for every vector.  Without this,
     * voleith_pos_in_tree() can return alpha outside [L-1, 2L-2],
     * which becomes an out-of-bounds bit_set on the bitmap below.
     * An honest caller (the prover) will pass valid values, but this
     * is a defense-in-depth check against stale/corrupt i_delta from
     * the grinding loop or proof-state plumbing.
     */
    for (int i = 0; i < tau; i++) {
        if (i_delta[i] >= voleith_vc_N(params, i))
            return -1;
    }

    /* Allocate bitmap S for 2L-1 nodes */
    size_t bitmap_bytes = (2 * L - 1 + 7) / 8;
    uint8_t *S = calloc(bitmap_bytes, 1);
    if (!S)
        return -1;

    /*
     * Step 5-15: Mark hidden leaves and propagate upward.
     * For each i, mark leaf α = PosInTree(i, Δ_i) and all ancestors.
     * Count total marked nodes n_h.
     */
    size_t n_h = 0;
    for (int i = 0; i < tau; i++) {
        size_t alpha = voleith_pos_in_tree(params, i, i_delta[i]);
        bit_set(S, alpha);
        n_h++;

        while (alpha > 0 && !bit_get(S, (alpha - 1) / 2)) {
            alpha = (alpha - 1) / 2;
            bit_set(S, alpha);
            n_h++;
        }
    }

    /* Step 16-17: Check that the number of revealed seeds fits in T_open */
    if (n_h < 2 * (size_t)tau) {
        /* This shouldn't happen with valid inputs, but guard against underflow */
        free(S);
        return -1;
    }
    size_t n_revealed = n_h - 2 * (size_t)tau + 1;
    if (n_revealed > (size_t)params->T_open) {
        free(S);
        return -1;
    }

    /* Allocate the output buffer */
    size_t total_len = voleith_bavc_opening_size(params);
    opening->data = calloc(total_len, 1);
    if (!opening->data) {
        free(S);
        return -1;
    }
    opening->data_len = total_len;

    /*
     * Step 3: Write hidden leaf commitments com_{i,Δ_i} for each i.
     */
    uint8_t *ptr = opening->data;
    for (int i = 0; i < tau; i++) {
        size_t alpha = voleith_pos_in_tree(params, i, i_delta[i]);
        size_t leaf_idx = alpha - (L - 1);
        memcpy(ptr, bavc->leaf_coms + leaf_idx * com_bytes, com_bytes);
        ptr += com_bytes;
    }

    /*
     * Steps 19-25: Walk the tree bottom-up. For each internal node i
     * where exactly one child is marked, reveal the unmarked child's seed.
     *
     * First propagate S upward via OR (an internal node is marked if
     * either child is marked).
     */
    for (int i = (int)L - 2; i >= 0; i--) {
        int left_marked = bit_get(S, 2 * (size_t)i + 1);
        int right_marked = bit_get(S, 2 * (size_t)i + 2);

        /* Update parent: marked if either child is marked */
        if (left_marked || right_marked)
            bit_set(S, (size_t)i);

        /* If exactly one child is marked, reveal the other */
        if (left_marked ^ right_marked) {
            /* α = the unmarked child (reveal its seed) */
            size_t alpha = 2 * (size_t)i + 1 + (size_t)left_marked;
            const uint8_t *seed = voleith_ggm_tree_node(&bavc->tree, alpha);
            memcpy(ptr, seed, sb);
            ptr += sb;
        }
    }

    opening->n_revealed = n_revealed;

    /* Remaining bytes are already zero from calloc (padding to fixed size) */

    free(S);
    return 0;
}

void
voleith_bavc_opening_free(voleith_bavc_opening_t *opening)
{
    if (opening->data) {
        free(opening->data);
        opening->data = NULL;
    }
    opening->data_len = 0;
    opening->n_revealed = 0;
}

/* ---- BAVC Reconstruct (FAEST spec Figure 5.4, Reconstruct) ---- */

/*
 * Per-vector reconstruct job (T3.4a).  Mirrors bavc_commit_vector_job: computes
 * vector i's leaf seeds / commitments (hidden leaf from the opening, the rest
 * via LeafCommit on the reconstructed key) and folds them into h_i = H_1(concat
 * of its com_{i,j}).  Each vector's leaves (its PosInTree positions) are
 * disjoint, so the tau vectors are independent and run serially or as one pool
 * batch, bit-identically.  concat is PER-WORKER transient scratch (nworkers
 * slots, keyed by worker index); keys / rec / h_all are read or written at
 * per-tau-disjoint offsets.
 */
typedef struct {
    voleith_bavc_reconstruct_t *rec;
    const voleith_bavc_opening_t *opening;
    const voleith_vc_params_t *params;
    const size_t *i_delta;
    const uint8_t *keys;
    const uint8_t *iv;
    uint8_t *h_all;
    uint8_t *concat_base;
    size_t concat_slot_bytes;
    size_t hash_bytes;
    size_t com_bytes;
    size_t sb;
    size_t L;
    int lambda;
} bavc_reconstruct_job_t;

static int
bavc_reconstruct_vector_job(size_t i, void *ud, ichor_job_ctx_t *jctx)
{
    const bavc_reconstruct_job_t *a = ud;
    const voleith_vc_params_t *params = a->params;
    size_t L = a->L;
    size_t sb = a->sb;
    size_t com_bytes = a->com_bytes;
    int lambda = a->lambda;

    uint32_t twk = (uint32_t)(i + L - 1);
    size_t Ni = voleith_vc_N(params, (int)i);
    size_t delta_i = a->i_delta[i];
    uint8_t *concat = a->concat_base + (size_t)ichor_job_worker_index(jctx) *
                                           a->concat_slot_bytes;

    for (size_t j = 0; j < Ni; j++) {
        size_t alpha = voleith_pos_in_tree(params, (int)i, j);
        size_t leaf_idx = alpha - (L - 1);

        if (j == delta_i) {
            /* Hidden leaf: commitment from opening, seed stays zero. */
            const uint8_t *hidden_com = a->opening->data + i * com_bytes;
            memcpy(a->rec->leaf_coms + leaf_idx * com_bytes, hidden_com,
                   com_bytes);
            memcpy(concat + j * com_bytes, hidden_com, com_bytes);
        } else {
            /* Non-hidden leaf: LeafCommit from the reconstructed key. */
            const uint8_t *k_alpha = a->keys + alpha * sb;
            memcpy(a->rec->leaf_seeds + leaf_idx * sb, k_alpha, sb);

            if (params->n_leafcom == 2)
                leaf_commit_em(lambda, k_alpha, a->iv, twk,
                               a->rec->leaf_coms + leaf_idx * com_bytes);
            /* TODO: FAEST variant (n_leafcom == 3) */

            memcpy(concat + j * com_bytes,
                   a->rec->leaf_coms + leaf_idx * com_bytes, com_bytes);
        }
    }

    /* h_i = H_1(concat). */
    hash_h1(lambda, concat, Ni * com_bytes, a->h_all + i * a->hash_bytes);
    return 0;
}

int
voleith_bavc_reconstruct_ex(voleith_bavc_reconstruct_t *rec,
                            const voleith_bavc_opening_t *opening,
                            const voleith_vc_params_t *params,
                            const size_t *i_delta, const uint8_t iv[16],
                            const voleith_threadctx_t *tctx)
{
    int lambda = params->lambda;
    size_t sb = (size_t)lambda / 8;
    size_t L = params->L;
    int tau = params->tau;
    size_t com_bytes = (size_t)params->n_leafcom * sb;

    rec->leaf_seeds = NULL;
    rec->leaf_coms = NULL;
    rec->seed_bytes = sb;
    rec->com_bytes = com_bytes;
    rec->L = L;
    memset(rec->com, 0, sizeof(rec->com));

    /*
     * V-1: Validate the opening buffer length against the expected
     * fixed size for these parameters.  Without this, a truncated
     * opening makes seed_ptr = opening->data + tau*com_bytes overrun
     * the buffer, and subsequent pointer arithmetic on the trailing-
     * zero scan becomes undefined behavior even when the per-read
     * `seed_ptr + sb > seed_end` guard kicks in.  The verifier in
     * proof/{proof,gf8_proof}.c already validates proof->len against
     * voleith_proof_byte_size before slicing decom_i, but this check
     * makes voleith_bavc_reconstruct safe to call on any caller-
     * supplied opening (defense-in-depth).
     */
    if (opening->data == NULL ||
        opening->data_len != voleith_bavc_opening_size(params))
        return -1;

    /*
     * V-2: Validate i_delta[i] < N_i for every vector.  Without this,
     * voleith_pos_in_tree() can return alpha outside [L-1, 2L-2],
     * which becomes an out-of-bounds bit_set on the bitmap S.  In
     * normal FAEST parameters voleith_decode_challenge already keeps
     * i_delta in range (each vector reads exactly k or k-1 bits, and
     * N_i = 2^k or 2^{k-1}), but a malicious proof or a future
     * parameter-set change could break that invariant silently.
     */
    for (int i = 0; i < tau; i++) {
        if (i_delta[i] >= voleith_vc_N(params, i))
            return -1;
    }

    /* Allocate node keys array for the full tree (2L-1 nodes) */
    size_t total_nodes = 2 * L - 1;
    uint8_t *keys = calloc(total_nodes, sb);
    if (!keys)
        return -1;

    /* Allocate bitmap S for marking hidden nodes */
    size_t bitmap_bytes = (total_nodes + 7) / 8;
    uint8_t *S = calloc(bitmap_bytes, 1);
    if (!S) {
        free(keys);
        return -1;
    }

    /*
     * Step 7-10: Mark hidden leaves.
     */
    for (int i = 0; i < tau; i++) {
        size_t alpha = voleith_pos_in_tree(params, i, i_delta[i]);
        bit_set(S, alpha);
    }

    /*
     * Step 12: Walk tree bottom-up. Propagate marks upward and place
     * revealed seeds from the opening into the keys array.
     *
     * The opening's seed data starts after the τ hidden commitments.
     */
    const uint8_t *seed_ptr = opening->data + (size_t)tau * com_bytes;
    const uint8_t *seed_end = opening->data + opening->data_len;

    for (int i = (int)L - 2; i >= 0; i--) {
        int left_marked = bit_get(S, 2 * (size_t)i + 1);
        int right_marked = bit_get(S, 2 * (size_t)i + 2);

        /* Propagate: parent is marked if either child is */
        if (left_marked || right_marked)
            bit_set(S, (size_t)i);

        /* If exactly one child is marked, read the unmarked sibling's seed */
        if (left_marked ^ right_marked) {
            if (seed_ptr + sb > seed_end) {
                free(S);
                free(keys);
                return -1;
            }
            /* α = unmarked child = 2i+1+left_marked */
            size_t alpha = 2 * (size_t)i + 1 + (size_t)left_marked;
            memcpy(keys + alpha * sb, seed_ptr, sb);
            seed_ptr += sb;
        }
    }

    /* Verify padding bytes are all zero */
    for (const uint8_t *p = seed_ptr; p < seed_end; p++) {
        if (*p != 0) {
            free(S);
            free(keys);
            return -1;
        }
    }

    /*
     * Expand unmarked internal nodes via PRG to fill in their children.
     * Walk top-down: for each unmarked internal node, run PRG to produce
     * both children.
     */
    uint8_t prg_out[64]; /* max 2*32 = 64 bytes for lambda=256 */

    for (size_t alpha = 0; alpha < L - 1; alpha++) {
        if (!bit_get(S, alpha)) {
            voleith_prg_ctx_t prg;
            voleith_prg_init(&prg, keys + alpha * sb, lambda);
            voleith_prg_gen(&prg, prg_out, iv, (uint32_t)alpha,
                            2 * (size_t)lambda);
            voleith_prg_clear(&prg);

            memcpy(keys + (2 * alpha + 1) * sb, prg_out, sb);
            memcpy(keys + (2 * alpha + 2) * sb, prg_out + sb, sb);
        }
    }

    voleith_secure_zero(prg_out, sizeof(prg_out));

    /*
     * For each (i, j): compute leaf seed and commitment, and build per-vector
     * hashes for the global commitment.  The tau vectors are independent (T3.4a)
     * and run either serially or as one pool batch, bit-identically.  h_all is
     * per-tau (retained); concat is PER-WORKER transient scratch (nworkers
     * slots, keyed in the job by worker index).  The reconstruct is one-shot
     * (not a repeated prover chain), so the scratch is allocated locally here
     * rather than carried on the threadctx.
     */
    size_t hash_bytes = 2 * sb;
    size_t max_N = (size_t)1 << params->k;
    size_t concat_slot_bytes = max_N * com_bytes;
    size_t nworkers =
        (tctx && tctx->pool) ? (size_t)ichor_pool_size(tctx->pool) : 1u;

    rec->leaf_seeds = calloc(L, sb);
    rec->leaf_coms = calloc(L, com_bytes);
    uint8_t *h_all = calloc((size_t)tau, hash_bytes);
    uint8_t *concat_all = calloc(nworkers * max_N, com_bytes);
    if (!rec->leaf_seeds || !rec->leaf_coms || !h_all || !concat_all) {
        free(concat_all);
        free(h_all);
        voleith_bavc_reconstruct_free(rec);
        free(S);
        free(keys);
        return -1;
    }

    bavc_reconstruct_job_t jarg = {
        .rec = rec,
        .opening = opening,
        .params = params,
        .i_delta = i_delta,
        .keys = keys,
        .iv = iv,
        .h_all = h_all,
        .concat_base = concat_all,
        .concat_slot_bytes = concat_slot_bytes,
        .hash_bytes = hash_bytes,
        .com_bytes = com_bytes,
        .sb = sb,
        .L = L,
        .lambda = lambda,
    };

    int rc = 0;
    if (tctx && tctx->pool) {
        ichor_job_info_t *jobs = calloc((size_t)tau, sizeof(*jobs));
        if (!jobs) {
            rc = -1;
        } else {
            for (int i = 0; i < tau; i++) {
                jobs[i].fn = bavc_reconstruct_vector_job;
                jobs[i].ud = &jarg;
            }
            uint64_t label = ichor_pool_new_label(tctx->pool);
            int done = 0;
            int err = 0;
            rc = ichor_pool_submit_jobs(tctx->pool, jobs, (size_t)tau, label);
            if (rc == 0)
                rc = ichor_pool_wait(tctx->pool, label, -1, &done, &err);
            if (rc == 0 && err != 0)
                rc = err;
            free(jobs);
        }
    } else {
        /* Serial path (no pool, e.g. tctx == NULL): same job, run inline. */
        for (int i = 0; i < tau; i++)
            (void)bavc_reconstruct_vector_job((size_t)i, &jarg, NULL);
    }

    if (rc != 0) {
        free(concat_all);
        free(h_all);
        voleith_bavc_reconstruct_free(rec);
        free(S);
        free(keys);
        return -1;
    }

    /* com = H_1(h_0 || ... || h_{τ-1}) */
    hash_h1(lambda, h_all, (size_t)tau * hash_bytes, rec->com);

    free(concat_all);
    free(h_all);
    voleith_secure_zero(keys, total_nodes * sb);
    free(keys);
    free(S);
    return 0;
}

/* Serial reconstruct: the historical entry point, now a thin wrapper over the
 * threaded _ex with no pool (bit-identical to the pre-T3.4a code). */
int
voleith_bavc_reconstruct(voleith_bavc_reconstruct_t *rec,
                         const voleith_bavc_opening_t *opening,
                         const voleith_vc_params_t *params,
                         const size_t *i_delta, const uint8_t iv[16])
{
    return voleith_bavc_reconstruct_ex(rec, opening, params, i_delta, iv, NULL);
}

void
voleith_bavc_reconstruct_free(voleith_bavc_reconstruct_t *rec)
{
    if (rec->leaf_seeds) {
        voleith_secure_zero(rec->leaf_seeds, rec->L * rec->seed_bytes);
        free(rec->leaf_seeds);
        rec->leaf_seeds = NULL;
    }
    if (rec->leaf_coms) {
        free(rec->leaf_coms);
        rec->leaf_coms = NULL;
    }
    voleith_secure_zero(rec->com, sizeof(rec->com));
}

const uint8_t *
voleith_bavc_reconstruct_leaf_seed(const voleith_bavc_reconstruct_t *rec,
                                   const voleith_vc_params_t *params, int i,
                                   size_t j, const size_t *i_delta)
{
    if (j == i_delta[i])
        return NULL;

    size_t alpha = voleith_pos_in_tree(params, i, j);
    size_t leaf_idx = alpha - (params->L - 1);
    return rec->leaf_seeds + leaf_idx * rec->seed_bytes;
}
