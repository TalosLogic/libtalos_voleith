/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * convert.c - ConvertToVOLE (FAEST spec Section 5.2, Figure 5.2)
 *
 * Implements the butterfly XOR reduction that converts per-leaf seeds
 * from a vector commitment into VOLE correlation vectors.
 */

#include "convert.h"
#include "prg.h"
#include "util.h"
#include <ichor/pool.h>
#include <stdlib.h>
#include <string.h>

/* Tweak offset for ConvertToVOLE PRG calls: 2^31 */
#define CONVERT_TWEAK_OFFSET UINT32_C(0x80000000)

static void
xor_bytes(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = a[i] ^ b[i];
}

/* out[i] = a[i] ^ (b[i] & mask), where mask = -mask_bit */
static void
masked_xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b,
                 uint8_t mask_bit, size_t len)
{
    uint8_t mask = -(mask_bit & 1);
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ (b[i] & mask);
}

int
voleith_convert_to_vole(const uint8_t *iv, const uint8_t *sd, bool sd0_bot,
                        int vec_index, size_t outlen, uint8_t *u, uint8_t **v,
                        const voleith_vc_params_t *params, uint8_t *r)
{
    const size_t N_i = voleith_vc_N(params, vec_index);
    const int depth = (vec_index < params->tau1) ? params->k : (params->k - 1);
    const size_t lambda_bytes = (size_t)params->lambda / 8;

    /*
     * Rolling butterfly buffer, caller-owned (T2.3): `r` must hold at least
     * 2 * N_i * outlen bytes (the caller sizes it for the largest vector,
     * 2 * max_N * outlen, so it fits every N_i).  r[row % 2][column] holds the
     * PRG output / intermediate XOR results.  The caller owns the allocation
     * and its lifetime; this function neither allocates nor frees it, but does
     * scrub the portion it used before returning (V-4).
     */

#define R(row, col) (r + (((row) % 2) * N_i + (col)) * outlen)

    uint32_t tweak = (uint32_t)vec_index ^ CONVERT_TWEAK_OFFSET;

    /* Step 2: PRG(sd_0, iv, tweak).
     *
     * On the prover path every cell of row 0 is written by the PRG calls below
     * and every later butterfly row is fully computed before it is read, so the
     * caller need not zero `r` (T2.2).  The one exception is the verifier side
     * (sd0_bot): there R(0, 0) is not PRG-filled (the hidden seed contributes 0)
     * yet the first butterfly level reads it, so zero exactly that one cell.
     *
     * V-3: clear the PRG context (expanded AES round keys derived from
     * the secret leaf seed) on every exit from this scope. */
    if (!sd0_bot) {
        voleith_prg_ctx_t prg;
        voleith_prg_init(&prg, sd, params->lambda);
        voleith_prg_gen(&prg, R(0, 0), iv, tweak, outlen * 8);
        voleith_prg_clear(&prg);
    } else {
        memset(R(0, 0), 0, outlen);
    }

    /* Steps 3-4: PRG(sd_j, iv, tweak) for j = 1..N_i-1.  V-3: same
     * PRG-context cleanup as above. */
    for (size_t j = 1; j < N_i; j++) {
        voleith_prg_ctx_t prg;
        voleith_prg_init(&prg, sd + lambda_bytes * j, params->lambda);
        voleith_prg_gen(&prg, R(0, j), iv, tweak, outlen * 8);
        voleith_prg_clear(&prg);
    }

    /* Steps 5-9: Butterfly XOR reduction */
    for (int j = 0; j < depth; j++) {
        size_t depthloop = N_i >> (j + 1);
        memset(v[j], 0, outlen);
        for (size_t idx = 0; idx < depthloop; idx++) {
            xor_bytes(v[j], v[j], R(j, 2 * idx + 1), outlen);
            xor_bytes(R(j + 1, idx), R(j, 2 * idx), R(j, 2 * idx + 1), outlen);
        }
    }

    /* Step 10: u = R(depth, 0) */
    if (!sd0_bot && u != NULL) {
        memcpy(u, R(depth, 0), outlen);
    }

    /*
     * V-4: `r` holds the raw PRG outputs of every leaf seed (row 0) and
     * the butterfly XOR reductions for each depth (subsequent rows).
     * Together these are the per-leaf v-vectors before final
     * combination, which directly encode the VOLE keys and (via the
     * butterfly) the witness mask u.  Recovering them would let an
     * attacker who later sees the proof recover the witness.  Scrub the used
     * portion (the caller owns and later frees / reuses the buffer).
     */
    voleith_secure_zero(r, 2 * N_i * outlen);
    return depth;

#undef R
}

/*
 * Shared, read-only arguments for the per-vector ConvertToVOLE job (T1.4).  One
 * instance is built on the stack of voleith_vole_commit and pointed at by every
 * job descriptor; the job's own vector index arrives as the descriptor index i.
 * Each job writes its vector's disjoint RETAINED slices: its ui slot
 * (ui + i*ellhat_bytes) and its v-row range (v[v_off[i] .. v_off[i+1]), T1.2),
 * and uses PER-WORKER transient scratch for the seed gather (sd) and the
 * butterfly buffer (r), keyed by ichor_job_worker_index (T2.3).  The BAVC
 * result (bavc) is produced before any job runs and only read.
 */
typedef struct {
    const voleith_vc_params_t *params;
    const voleith_bavc_t *bavc;
    const uint8_t *iv;
    uint8_t *sd_base; /* per-worker: slot = sd_base + w*sd_slot_bytes */
    uint8_t *r_base;  /* per-worker: slot = r_base + w*r_slot_bytes */
    uint8_t *ui;      /* per-tau (retained) */
    uint8_t **v;
    const int *v_off;
    size_t lambda_bytes;
    size_t ellhat_bytes;
    size_t sd_slot_bytes;
    size_t r_slot_bytes;
} vole_commit_job_t;

/*
 * ConvertToVOLE for one tau vector i: gather its interleaved leaf seeds into its
 * worker's sd slot, then run the butterfly reduction (in its worker's r slot)
 * into ui[i] and the disjoint v-row range at v + v_off[i].  Behavior-identical
 * to the former serial loop body.  Returns the convert error (negative) on
 * failure, else 0; the convert depth is not needed here because v_off already
 * fixes each vector's v range.
 */
static int
vole_commit_vector_job(size_t i, void *ud, ichor_job_ctx_t *jctx)
{
    const vole_commit_job_t *a = ud;
    size_t w = (size_t)ichor_job_worker_index(jctx);
    uint8_t *sd_i = a->sd_base + w * a->sd_slot_bytes;
    uint8_t *r = a->r_base + w * a->r_slot_bytes;
    size_t N_i = voleith_vc_N(a->params, (int)i);

    for (size_t j = 0; j < N_i; j++) {
        const uint8_t *seed =
            voleith_bavc_leaf_seed(a->bavc, a->params, (int)i, j);
        memcpy(sd_i + j * a->lambda_bytes, seed, a->lambda_bytes);
    }

    int ki = voleith_convert_to_vole(
        a->iv, sd_i, false, (int)i, a->ellhat_bytes,
        a->ui + i * a->ellhat_bytes, a->v + a->v_off[i], a->params, r);
    return ki < 0 ? ki : 0;
}

int
voleith_vole_commit(const voleith_vc_params_t *params, const uint8_t *root_seed,
                    const uint8_t iv[16], unsigned int ellhat,
                    voleith_bavc_t *bavc, uint8_t *c, uint8_t *u, uint8_t **v,
                    const voleith_threadctx_t *tctx)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    /* Step 1: BAVC.Commit */
    int ret = voleith_bavc_commit(bavc, params, root_seed, iv, tctx);
    if (ret != 0)
        return ret;

    /*
     * Working buffers.  RETAINED per-tau: ui gathers each vector's u-vector;
     * v_off holds the precomputed per-vector v-row offsets (prefix sum of the
     * public depths k_j, T1.2).  TRANSIENT per-worker (T2.3): sd (seed gather)
     * and r (the ConvertToVOLE butterfly buffer), nworkers slots each, keyed in
     * the job by worker index.  Prefer the prover's preallocated scratch on
     * tctx; fall back to a local allocation when there is none (tctx == NULL, or
     * a bare tctx as in a vole-layer test), sized to nworkers slots (1 with no
     * pool).  The secret buffers (sd, ui) are secure-zeroed after use regardless
     * of ownership; r's used portion is scrubbed inside voleith_convert_to_vole
     * per call, so no secret lingers between proofs when the scratch is reused.
     *
     * V-5 note: at the allocation-failure path below the local buffers are
     * either NULL or just-allocated, so a bare free() is correct and no
     * secure-zero is needed; the later free / reuse sites DO secure-zero.
     */
    size_t max_N = (size_t)1 << params->k;
    size_t ui_size = (size_t)params->tau * ellhat_bytes;
    size_t sd_slot_bytes = max_N * lambda_bytes;
    size_t r_slot_bytes = (size_t)2 * max_N * ellhat_bytes;
    size_t nworkers =
        (tctx && tctx->pool) ? (size_t)ichor_pool_size(tctx->pool) : 1u;
    size_t sd_region = nworkers * sd_slot_bytes;

    int have_scratch = (tctx && tctx->scratch_tau == params->tau &&
                        tctx->scratch_ellhat_bytes == ellhat_bytes);
    uint8_t *ui = have_scratch ? tctx->vole_ui
                               : calloc((size_t)params->tau, ellhat_bytes);
    uint8_t *sd_base = have_scratch ? tctx->vole_sd_buf
                                    : calloc(nworkers * max_N, lambda_bytes);
    uint8_t *r_base =
        have_scratch ? tctx->vole_r : malloc(nworkers * r_slot_bytes);
    int *v_off = have_scratch ? tctx->vole_v_off
                              : calloc((size_t)params->tau + 1, sizeof(int));
    if (!ui || !sd_base || !r_base || !v_off) {
        if (!have_scratch) {
            free(ui);
            free(sd_base);
            free(r_base);
            free(v_off);
        }
        return -1;
    }

    /* The preallocated v_off was filled once by voleith_threadctx_scratch_init;
     * a local one is filled here (T1.2). */
    if (!have_scratch) {
        v_off[0] = 0;
        for (int i = 0; i < params->tau; i++) {
            int ki = (i < params->tau1) ? params->k : (params->k - 1);
            v_off[i + 1] = v_off[i] + ki;
        }
    }

    /*
     * Step 2-6: ConvertToVOLE for each vector.  The tau vectors write disjoint
     * ui / v slices and use per-worker sd / r scratch, so the loop runs either
     * serially or as one pool batch, bit-identically (T1.4 / T2.3).  Each job
     * gathers its vector's interleaved leaf seeds (PosInTree interleaving, via
     * the accessor) and runs the butterfly reduction.  The u / c fold below
     * stays serial after the join.
     */
    vole_commit_job_t jarg = {
        .params = params,
        .bavc = bavc,
        .iv = iv,
        .sd_base = sd_base,
        .r_base = r_base,
        .ui = ui,
        .v = v,
        .v_off = v_off,
        .lambda_bytes = lambda_bytes,
        .ellhat_bytes = ellhat_bytes,
        .sd_slot_bytes = sd_slot_bytes,
        .r_slot_bytes = r_slot_bytes,
    };

    int job_err = 0;
    if (tctx && tctx->pool) {
        /*
         * Threaded path: submit the tau vectors as one caller-owned batch and
         * block until all finish.  Reuse the preallocated descriptor array when
         * present, else a local one.  jarg and jobs stay alive on this stack /
         * on tctx until the wait returns, as the submit contract requires.
         */
        ichor_job_info_t *jobs =
            have_scratch ? tctx->jobs
                         : calloc((size_t)params->tau, sizeof(*jobs));
        if (!jobs) {
            job_err = -1;
        } else {
            for (int i = 0; i < params->tau; i++) {
                jobs[i].fn = vole_commit_vector_job;
                jobs[i].ud = &jarg;
            }
            uint64_t label = ichor_pool_new_label(tctx->pool);
            int done = 0;
            int rc = ichor_pool_submit_jobs(tctx->pool, jobs,
                                            (size_t)params->tau, label);
            if (rc == 0)
                rc = ichor_pool_wait(tctx->pool, label, -1, &done, &job_err);
            if (rc != 0)
                job_err = rc;
            if (!have_scratch)
                free(jobs);
        }
    } else {
        /*
         * Serial path (no pool, e.g. tctx == NULL): same job, run inline, and
         * stop at the first failing vector as the pre-threading loop did.
         */
        for (int i = 0; job_err == 0 && i < params->tau; i++)
            job_err = vole_commit_vector_job((size_t)i, &jarg, NULL);
    }

    if (job_err != 0) {
        /* V-5: sd holds gathered leaf seeds (the most secret material in the
         * protocol); ui holds partially-populated per-vector u-vectors; r's used
         * portions were already scrubbed per call inside convert.  Zero sd and
         * ui before any free / reuse, then free only what is local. */
        voleith_secure_zero(sd_base, sd_region);
        voleith_secure_zero(ui, ui_size);
        if (!have_scratch) {
            free(ui);
            free(sd_base);
            free(r_base);
            free(v_off);
        }
        return -1;
    }

    /* Zero-pad remaining v vectors up to lambda */
    for (int v_idx = v_off[params->tau]; v_idx < params->lambda; v_idx++) {
        memset(v[v_idx], 0, ellhat_bytes);
    }

    /* Step 9: u = ui[0], c[i-1] = u XOR ui[i] for i >= 1 */
    memcpy(u, ui, ellhat_bytes);
    for (int i = 1; i < params->tau; i++) {
        xor_bytes(c + (size_t)(i - 1) * ellhat_bytes, u,
                  ui + (size_t)i * ellhat_bytes, ellhat_bytes);
    }

    /*
     * V-5: success path.  sd holds each worker's last gathered leaf seeds; ui
     * holds the full set of per-vector u-vectors (now folded into the outputs u
     * and c, but the originals remain in the buffer); r's used portions were
     * scrubbed per call inside convert.  Zero sd and ui before any free / reuse;
     * free only what is local to this call.
     */
    voleith_secure_zero(sd_base, sd_region);
    voleith_secure_zero(ui, ui_size);
    if (!have_scratch) {
        free(ui);
        free(sd_base);
        free(r_base);
        free(v_off);
    }
    return 0;
}

/*
 * Per-vector VOLE-reconstruct job (T3.4a).  Mirrors vole_commit_vector_job:
 * rearranges vector i's reconstructed leaf seeds (XOR-permuted by delta_i) and
 * runs ConvertToVOLE into its disjoint q-row range at q[q_off[i]], combining
 * with the correction values.  TRANSIENT per-worker scratch (nworkers slots,
 * keyed by worker index): the seed gather sd, the convert output qtmp, and the
 * butterfly buffer r.  Independent across the tau vectors.
 */
typedef struct {
    const voleith_vc_params_t *params;
    const size_t *i_delta;
    const uint8_t *iv;
    const uint8_t *c;
    uint8_t **q;
    voleith_bavc_reconstruct_t *rec;
    const int *q_off;
    uint8_t *sd_base;
    uint8_t *qtmp_base;
    uint8_t *r_base;
    size_t sd_slot_bytes;
    size_t qtmp_slot_bytes;
    size_t r_slot_bytes;
    size_t lambda_bytes;
    size_t ellhat_bytes;
    int k;
    int tau1;
} vole_reconstruct_job_t;

static int
vole_reconstruct_vector_job(size_t i, void *ud, ichor_job_ctx_t *jctx)
{
    const vole_reconstruct_job_t *a = ud;
    const voleith_vc_params_t *params = a->params;
    size_t w = (size_t)ichor_job_worker_index(jctx);
    const size_t N_i = voleith_vc_N(params, (int)i);
    const size_t delta_i = a->i_delta[i];
    uint8_t *sd = a->sd_base + w * a->sd_slot_bytes;
    uint8_t *qtmp = a->qtmp_base + w * a->qtmp_slot_bytes;
    uint8_t *r_buf = a->r_base + w * a->r_slot_bytes;

    /* Rearrange seeds: sd[j ^ delta_i] = reconstructed leaf seed for (i, j),
     * for j != delta_i (the hidden leaf's slot stays zero). */
    memset(sd, 0, N_i * a->lambda_bytes);
    for (size_t j = 0; j < N_i; j++) {
        if (j != delta_i) {
            const uint8_t *seed = voleith_bavc_reconstruct_leaf_seed(
                a->rec, params, (int)i, j, a->i_delta);
            memcpy(sd + (j ^ delta_i) * a->lambda_bytes, seed, a->lambda_bytes);
        }
    }

    uint8_t *v_ptrs[VOLEITH_MAX_K]; /* one slot per tree level */
    int depth = ((int)i < a->tau1) ? a->k : (a->k - 1);
    for (int d = 0; d < depth; d++)
        v_ptrs[d] = qtmp + (size_t)d * a->ellhat_bytes;

    int ki = voleith_convert_to_vole(a->iv, sd, true, (int)i, a->ellhat_bytes,
                                     NULL, v_ptrs, params, r_buf);
    if (ki < 0)
        return -1;

    /* Combine with the correction values into the disjoint q range. */
    int qbase = a->q_off[i];
    if (i == 0) {
        for (int d = 0; d < ki; d++)
            memcpy(a->q[qbase + d], qtmp + (size_t)d * a->ellhat_bytes,
                   a->ellhat_bytes);
    } else {
        for (int d = 0; d < ki; d++)
            masked_xor_bytes(a->q[qbase + d],
                             qtmp + (size_t)d * a->ellhat_bytes,
                             a->c + (size_t)(i - 1) * a->ellhat_bytes,
                             (uint8_t)((delta_i >> d) & 1), a->ellhat_bytes);
    }
    return 0;
}

int
voleith_vole_reconstruct_ex(const voleith_vc_params_t *params,
                            const voleith_bavc_opening_t *opening,
                            const size_t *i_delta, const uint8_t iv[16],
                            unsigned int ellhat, const uint8_t *c, uint8_t *com,
                            uint8_t **q, const voleith_threadctx_t *tctx)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;
    const size_t ellhat_bytes = (ellhat + 7) / 8;
    const int k = params->k;
    const int tau = params->tau;

    /* Step 1: BAVC.Reconstruct (its tau leaf-commitment loop also threads). */
    voleith_bavc_reconstruct_t rec;
    int ret =
        voleith_bavc_reconstruct_ex(&rec, opening, params, i_delta, iv, tctx);
    if (ret != 0)
        return ret;

    /* Copy reconstructed global commitment */
    memcpy(com, rec.com, 2 * lambda_bytes);

    /*
     * Step 2: for each vector, rearrange seeds and run ConvertToVOLE.  The tau
     * vectors are independent (T3.4a) and run serially or as one pool batch,
     * bit-identically.  TRANSIENT per-worker scratch (nworkers slots): sd (seed
     * gather), qtmp (convert output), r (butterfly buffer); with nworkers == 1
     * this is exactly the single-buffer serial code.  q_off holds the per-vector
     * q-row offsets (prefix sum of the public per-vector depths), so vectors
     * write disjoint q ranges in any order.  One-shot, so scratch is local here.
     */
    const size_t sd_slot_bytes = (size_t)(1 << k) * lambda_bytes;
    const size_t qtmp_slot_bytes = (size_t)k * ellhat_bytes;
    const size_t r_slot_bytes = (size_t)2 * (1 << k) * ellhat_bytes;
    size_t nworkers =
        (tctx && tctx->pool) ? (size_t)ichor_pool_size(tctx->pool) : 1u;

    uint8_t *sd_base = calloc(nworkers, sd_slot_bytes);
    uint8_t *qtmp_base = calloc(nworkers, qtmp_slot_bytes);
    uint8_t *r_base = malloc(nworkers * r_slot_bytes);
    int *q_off = malloc(((size_t)tau + 1) * sizeof(int));
    if (!sd_base || !qtmp_base || !r_base || !q_off) {
        free(sd_base);
        free(qtmp_base);
        free(r_base);
        free(q_off);
        voleith_bavc_reconstruct_free(&rec);
        return -1;
    }
    q_off[0] = 0;
    for (int i = 0; i < tau; i++)
        q_off[i + 1] = q_off[i] + ((i < params->tau1) ? k : (k - 1));

    vole_reconstruct_job_t jarg = {
        .params = params,
        .i_delta = i_delta,
        .iv = iv,
        .c = c,
        .q = q,
        .rec = &rec,
        .q_off = q_off,
        .sd_base = sd_base,
        .qtmp_base = qtmp_base,
        .r_base = r_base,
        .sd_slot_bytes = sd_slot_bytes,
        .qtmp_slot_bytes = qtmp_slot_bytes,
        .r_slot_bytes = r_slot_bytes,
        .lambda_bytes = lambda_bytes,
        .ellhat_bytes = ellhat_bytes,
        .k = k,
        .tau1 = params->tau1,
    };

    int rc = 0;
    if (tctx && tctx->pool) {
        ichor_job_info_t *jobs = calloc((size_t)tau, sizeof(*jobs));
        if (!jobs) {
            rc = -1;
        } else {
            for (int i = 0; i < tau; i++) {
                jobs[i].fn = vole_reconstruct_vector_job;
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
        for (int i = 0; i < tau && rc == 0; i++)
            rc = vole_reconstruct_vector_job((size_t)i, &jarg, NULL);
    }

    if (rc == 0) {
        /* Zero-pad remaining q vectors up to lambda. */
        for (int q_idx = q_off[tau]; q_idx < params->lambda; q_idx++)
            memset(q[q_idx], 0, ellhat_bytes);
    }

    /* No scrub of sd / qtmp / r here, by design: this is the VERIFIER-side
     * reconstruct, where all three buffers hold public material.  sd = leaf
     * seeds recoverable from the opening; qtmp / r = ConvertToVOLE outputs
     * derived from the public q.  The prover-side counterpart (voleith_vole_commit)
     * zeroes its own witness-derived scratch; mirroring that here bought nothing
     * but a serial secure_zero over nworkers * r_slot_bytes (the big
     * 2 * 2^k * ellhat butterfly buffer), which scaled with the worker count and
     * dominated the threaded verify (up to ~49% of wall on a 28-core run).
     * Dropping it is sound (nothing secret) and is what makes T3.4a-c a net win
     * at high core counts. */
    free(qtmp_base);
    free(sd_base);
    free(r_base);
    free(q_off);
    voleith_bavc_reconstruct_free(&rec);
    return rc;
}

/* Serial VOLE reconstruct: the historical entry point, now a thin wrapper over
 * the threaded _ex with no pool (bit-identical to the pre-T3.4a code). */
int
voleith_vole_reconstruct(const voleith_vc_params_t *params,
                         const voleith_bavc_opening_t *opening,
                         const size_t *i_delta, const uint8_t iv[16],
                         unsigned int ellhat, const uint8_t *c, uint8_t *com,
                         uint8_t **q)
{
    return voleith_vole_reconstruct_ex(params, opening, i_delta, iv, ellhat, c,
                                       com, q, NULL);
}
