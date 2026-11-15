/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * threadctx.h - prover threading context for the VOLEitH commit chain
 *
 * A voleith_threadctx_t is allocated once on the prover-commit context in the
 * proof layer and passed as a read-only handle down the commit chain
 * (voleith_commit_ex -> voleith_vole_commit_ex -> voleith_bavc_commit_ex),
 * where the tau VOLE repetitions are parallelized.  A NULL handle, or a handle
 * whose pool is NULL, means run the existing serial code path.
 *
 * Passing the handle down is not a layering violation: the proof layer (4)
 * creates the pool and the vole layer (2-3) consumes the ichor core (0).
 */

#ifndef VOLEITH_THREADCTX_H
#define VOLEITH_THREADCTX_H

#include <stddef.h>
#include <stdint.h>

/* Forward declarations: the ichor pool header and the job-descriptor type are
 * only needed where the pool is actually created or submitted to, not by every
 * includer of this type, so a pointer to each suffices here. */
struct ichor_pool;
struct ichor_job_info;

/*
 * Prover threading context.
 *
 * `pool` / `owns_pool` are the worker pool and its ownership (see the file
 * banner).  The remaining fields (T1.5) are the per-commit scratch, preallocated
 * once at prover init (voleith_threadctx_scratch_init, declared in vc.h) and
 * reused across proofs so the commit chain does no per-proof allocation.  They
 * are sized to the prover's parameters; `scratch_tau` (and, for the ellhat-sized
 * vole buffers, `scratch_ellhat_bytes`) record that size, and a commit uses the
 * scratch only when it matches the call's parameters.  When they are zero / NULL
 * (a bare threadctx, e.g. a vole-layer test that sets only `pool`), the commit
 * functions fall back to allocating locally per call.
 *
 * The jobs descriptor array is reused across the two sequential batches in one
 * voleith_vole_commit call (BAVC commit, then ConvertToVOLE): each batch is
 * submitted and waited to completion before the next, and ichor_pool_submit_jobs
 * re-initializes every descriptor's state, so no clearing is needed between
 * batches.
 *
 * Scratch is split by how it is used (T2.3):
 *   - TRANSIENT scratch (consumed within one job) is PER-WORKER: nworkers slots,
 *     keyed at runtime by ichor_job_worker_index(ctx).  A worker runs one job at
 *     a time, so nworkers slots suffice, and the resident cost scales with the
 *     caller's thread count, not with tau.  These are vole_sd_buf (the seed
 *     gather, SECRET), vole_r (the ConvertToVOLE butterfly, SECRET), and
 *     bavc_concat (the leaf-commitment concatenation, public).
 *   - RETAINED outputs are PER-TAU: vole_ui (the per-vector u vectors, SECRET)
 *     and bavc_h_all (per-vector hashes, public), plus the vole_v_off lookup
 *     table (tau+1 public offsets).  All are indexed by the tau index and kept.
 *
 * scratch_tau / scratch_ellhat_bytes / scratch_nworkers record the sizes the
 * scratch was built for; a commit uses the scratch only when they match the
 * call.  When they are zero / NULL (a bare threadctx, e.g. a vole-layer test
 * that sets only `pool`), the commit functions fall back to allocating locally
 * per call (nworkers slots if there is a pool, else 1).  Secret buffers
 * (vole_sd_buf, vole_r, vole_ui) are secure-zeroed on free.
 */
typedef struct {
    struct ichor_pool
        *pool;     /* worker pool (borrowed or owned); NULL = serial */
    int owns_pool; /* 1: destroy at prover free; 0: borrowed */

    struct ichor_job_info
        *jobs;            /* tau descriptors, reused across batches     */
    uint8_t *bavc_concat; /* nworkers * max_N * com_bytes (public)      */
    uint8_t *bavc_h_all;  /* tau * hash_bytes (public)                  */
    uint8_t *vole_sd_buf; /* nworkers * max_N * lambda_bytes (SECRET)   */
    uint8_t *vole_r;      /* nworkers * 2*max_N * ellhat_bytes (SECRET) */
    uint8_t *vole_ui;     /* tau * ellhat_bytes (SECRET)                */
    int *vole_v_off;      /* tau + 1 public v-row offsets               */
    int scratch_tau;      /* tau the scratch is sized for; 0 = none     */
    int scratch_nworkers; /* worker slots the transient scratch has     */
    size_t
        scratch_ellhat_bytes; /* ellhat_bytes vole_ui / vole_r sized for    */
    size_t vole_sd_buf_bytes; /* byte size of vole_sd_buf (free zeroes)     */
    size_t vole_r_bytes;      /* byte size of vole_r (free zeroes)          */
    size_t vole_ui_bytes;     /* byte size of vole_ui (free zeroes)         */
} voleith_threadctx_t;

#endif /* VOLEITH_THREADCTX_H */
