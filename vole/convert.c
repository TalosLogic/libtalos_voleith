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
                        const voleith_vc_params_t *params)
{
    const size_t N_i = voleith_vc_N(params, vec_index);
    const int depth = (vec_index < params->tau1) ? params->k : (params->k - 1);
    const size_t lambda_bytes = (size_t)params->lambda / 8;

    /*
     * Rolling buffer: only need two rows at a time for the butterfly reduction.
     * r[row % 2][column] holds the PRG output / intermediate XOR results.
     */
    uint8_t *r = calloc(2 * N_i, outlen);
    if (!r)
        return -1;

#define R(row, col) (r + (((row) % 2) * N_i + (col)) * outlen)

    uint32_t tweak = (uint32_t)vec_index ^ CONVERT_TWEAK_OFFSET;

    /* Step 2: PRG(sd_0, iv, tweak) - skip if sd0_bot (verifier side).
     * V-3: clear the PRG context (expanded AES round keys derived from
     * the secret leaf seed) on every exit from this scope. */
    if (!sd0_bot) {
        voleith_prg_ctx_t prg;
        voleith_prg_init(&prg, sd, params->lambda);
        voleith_prg_gen(&prg, R(0, 0), iv, tweak, outlen * 8);
        voleith_prg_clear(&prg);
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
     * attacker who later sees the proof recover the witness.  Zero
     * before free.
     */
    voleith_secure_zero(r, 2 * N_i * outlen);
    free(r);
    return depth;

#undef R
}

int
voleith_vole_commit(const voleith_vc_params_t *params, const uint8_t *root_seed,
                    const uint8_t iv[16], unsigned int ellhat,
                    voleith_bavc_t *bavc, uint8_t *c, uint8_t *u, uint8_t **v)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    /* Step 1: BAVC.Commit */
    int ret = voleith_bavc_commit(bavc, params, root_seed, iv);
    if (ret != 0)
        return ret;

    /* Allocate per-vector u buffers and a temp buffer to gather seeds.
     *
     * V-5 note: at the allocation-failure path immediately below, the
     * buffers are either NULL or just-calloc'd (still all zero), so a
     * bare free() is correct and no secure-zero is needed.  Subsequent
     * free sites that follow code which wrote secret material into
     * these buffers DO require voleith_secure_zero.
     */
    size_t max_N = (size_t)1 << params->k;
    size_t ui_size = (size_t)params->tau * ellhat_bytes;
    size_t sd_buf_size = max_N * lambda_bytes;
    uint8_t *ui = calloc((size_t)params->tau, ellhat_bytes);
    uint8_t *sd_buf = calloc(max_N, lambda_bytes);
    if (!ui || !sd_buf) {
        free(ui);
        free(sd_buf);
        return -1;
    }

    /* Step 2-6: ConvertToVOLE for each vector */
    int v_idx = 0;
    for (int i = 0; i < params->tau; i++) {
        /*
         * Gather leaf seeds for vector i into a contiguous buffer.
         * Leaves are interleaved in bavc->leaf_seeds (PosInTree interleaving),
         * so we must collect them using the accessor.
         */
        size_t N_i = voleith_vc_N(params, i);
        for (size_t j = 0; j < N_i; j++) {
            const uint8_t *seed = voleith_bavc_leaf_seed(bavc, params, i, j);
            memcpy(sd_buf + j * lambda_bytes, seed, lambda_bytes);
        }

        int ki = voleith_convert_to_vole(iv, sd_buf, false, i, ellhat_bytes,
                                         ui + (size_t)i * ellhat_bytes,
                                         v + v_idx, params);
        if (ki < 0) {
            /* V-5: sd_buf holds the leaf seeds for the current vector
             * (the most secret material in the protocol); ui holds
             * partially-populated per-vector u-vectors. */
            voleith_secure_zero(sd_buf, sd_buf_size);
            voleith_secure_zero(ui, ui_size);
            free(ui);
            free(sd_buf);
            return -1;
        }
        v_idx += ki;
    }

    /* Zero-pad remaining v vectors up to lambda */
    for (; v_idx < params->lambda; v_idx++) {
        memset(v[v_idx], 0, ellhat_bytes);
    }

    /* Step 9: u = ui[0], c[i-1] = u XOR ui[i] for i >= 1 */
    memcpy(u, ui, ellhat_bytes);
    for (int i = 1; i < params->tau; i++) {
        xor_bytes(c + (size_t)(i - 1) * ellhat_bytes, u,
                  ui + (size_t)i * ellhat_bytes, ellhat_bytes);
    }

    /*
     * V-5: success path.  sd_buf holds the last vector's leaf seeds;
     * ui holds the full set of per-vector u-vectors (now folded into
     * the outputs u and c, but the originals remain in the buffer).
     * Both must be securely zeroed before free.
     */
    voleith_secure_zero(sd_buf, sd_buf_size);
    voleith_secure_zero(ui, ui_size);
    free(ui);
    free(sd_buf);
    return 0;
}

int
voleith_vole_reconstruct(const voleith_vc_params_t *params,
                         const voleith_bavc_opening_t *opening,
                         const size_t *i_delta, const uint8_t iv[16],
                         unsigned int ellhat, const uint8_t *c, uint8_t *com,
                         uint8_t **q)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;
    const size_t ellhat_bytes = (ellhat + 7) / 8;
    const int k = params->k;

    /* Step 1: BAVC.Reconstruct */
    voleith_bavc_reconstruct_t rec;
    int ret = voleith_bavc_reconstruct(&rec, opening, params, i_delta, iv);
    if (ret != 0)
        return ret;

    /* Copy reconstructed global commitment */
    memcpy(com, rec.com, 2 * lambda_bytes);

    /* Allocate working buffers */
    const size_t sd_size = (size_t)(1 << k) * lambda_bytes;
    int max_depth = k;
    const size_t qtmp_size = (size_t)max_depth * ellhat_bytes;
    uint8_t *sd = calloc((size_t)(1 << k), lambda_bytes);
    uint8_t *qtmp = calloc((size_t)max_depth, ellhat_bytes);
    if (!sd || !qtmp) {
        free(sd);
        free(qtmp);
        voleith_bavc_reconstruct_free(&rec);
        return -1;
    }

    /* Step 2: For each vector, rearrange seeds and run ConvertToVOLE */
    int q_idx = 0;
    for (int i = 0; i < params->tau; i++) {
        const size_t N_i = voleith_vc_N(params, i);
        const size_t delta_i = i_delta[i];

        /*
         * Rearrange seeds: the reconstructed result has leaf seeds
         * indexed by flat tree position (interleaved across vectors).
         * We gather them per-vector and XOR-permute by delta_i.
         *
         * sd[j ^ delta_i] = rec leaf seed for (i, j)
         * for j != delta_i
         */
        memset(sd, 0, N_i * lambda_bytes);
        for (size_t j = 0; j < N_i; j++) {
            if (j != delta_i) {
                const uint8_t *seed = voleith_bavc_reconstruct_leaf_seed(
                    &rec, params, i, j, i_delta);
                memcpy(sd + (j ^ delta_i) * lambda_bytes, seed, lambda_bytes);
            }
        }

        /* Run ConvertToVOLE with sd0_bot = true (hidden seed) */
        /* Use qtmp as a flat buffer for depth vectors */
        uint8_t *v_ptrs[VOLEITH_MAX_K]; /* one slot per tree level */
        int depth = (i < params->tau1) ? k : (k - 1);
        for (int d = 0; d < depth; d++)
            v_ptrs[d] = qtmp + (size_t)d * ellhat_bytes;

        int ki = voleith_convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL,
                                         v_ptrs, params);
        if (ki < 0) {
            voleith_secure_zero(sd, sd_size);
            voleith_secure_zero(qtmp, qtmp_size);
            free(sd);
            free(qtmp);
            voleith_bavc_reconstruct_free(&rec);
            return -1;
        }

        /* Combine with correction values */
        if (i == 0) {
            for (int d = 0; d < ki; d++, q_idx++) {
                memcpy(q[q_idx], qtmp + (size_t)d * ellhat_bytes, ellhat_bytes);
            }
        } else {
            for (int d = 0; d < ki; d++, q_idx++) {
                masked_xor_bytes(q[q_idx], qtmp + (size_t)d * ellhat_bytes,
                                 c + (size_t)(i - 1) * ellhat_bytes,
                                 (uint8_t)((delta_i >> d) & 1), ellhat_bytes);
            }
        }
    }

    /* Zero-pad remaining q vectors up to lambda */
    for (; q_idx < params->lambda; q_idx++) {
        memset(q[q_idx], 0, ellhat_bytes);
    }

    /* L-N3: align discipline with the prover-side V-5 zeroing.  sd
     * holds reconstructed leaf seeds (public, recoverable from the
     * opening) and qtmp holds per-vector convert-to-VOLE outputs
     * already folded into q[].  Neither is secret on the verifier
     * side, but the prover-side counterpart zeroes the same shapes
     * and a consistent rule is cheaper than the per-site judgement
     * call. */
    voleith_secure_zero(sd, sd_size);
    voleith_secure_zero(qtmp, qtmp_size);
    free(qtmp);
    free(sd);
    voleith_bavc_reconstruct_free(&rec);
    return 0;
}
