/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * voleith.c - VOLEitH protocol layer (FAEST spec Section 5.3)
 */

#include "voleith.h"
#include "hash.h"
#include "../core/util.h"
#include <stdlib.h>
#include <string.h>

void
voleith_challenge_from_commitment(const uint8_t iv[16],
                                  const voleith_commitment_t *com,
                                  uint8_t *delta)
{
    const size_t lambda_bytes = (size_t)com->lambda / 8;
    const size_t ellhat_bytes = ((size_t)com->ellhat + 7) / 8;
    const size_t c_len = (size_t)(com->tau - 1) * ellhat_bytes;

    voleith_hash_ctx_t ctx;
    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, iv, 16);
    voleith_shake256_absorb(&ctx, com->hcom, 2 * lambda_bytes);
    voleith_shake256_absorb(&ctx, com->u, ellhat_bytes);
    voleith_shake256_absorb(&ctx, com->c, c_len);
    voleith_shake256_squeeze(&ctx, delta, lambda_bytes);
    voleith_hash_ctx_clear(&ctx);
}

void
voleith_decode_challenge(const uint8_t *delta,
                         const voleith_vc_params_t *params, size_t *i_delta)
{
    int bit_pos = 0;
    for (int i = 0; i < params->tau; i++) {
        int depth = (i < params->tau1) ? params->k : (params->k - 1);
        size_t val = 0;
        for (int b = 0; b < depth; b++, bit_pos++) {
            int bit = (delta[bit_pos / 8] >> (bit_pos % 8)) & 1;
            val |= (size_t)bit << b;
        }
        i_delta[i] = val;
    }
}

int
voleith_commit(voleith_commitment_t *com, voleith_prover_t *state,
               const voleith_vc_params_t *params, const uint8_t *root_seed,
               const uint8_t iv[16], unsigned int ellhat)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    /* Allocate commitment buffers */
    com->hcom = calloc(2, lambda_bytes);
    com->u = calloc(1, ellhat_bytes);
    com->c = calloc((size_t)(params->tau - 1), ellhat_bytes);
    if (!com->hcom || !com->u || !com->c)
        goto fail_com;

    /* Allocate prover v buffers */
    state->v = calloc((size_t)params->lambda, sizeof(uint8_t *));
    state->_v_buf = calloc((size_t)params->lambda, ellhat_bytes);
    if (!state->v || !state->_v_buf)
        goto fail_state;

    for (int i = 0; i < params->lambda; i++)
        state->v[i] = state->_v_buf + (size_t)i * ellhat_bytes;

    /* Run BAVC.Commit + ConvertToVOLE */
    int ret = voleith_vole_commit(params, root_seed, iv, ellhat, &state->bavc,
                                  com->c, com->u, state->v);
    if (ret != 0)
        goto fail_state;

    /* hcom is the BAVC global commitment */
    memcpy(com->hcom, state->bavc.com, 2 * lambda_bytes);

    com->ellhat = ellhat;
    com->lambda = (unsigned int)params->lambda;
    com->tau = (unsigned int)params->tau;

    state->ellhat = ellhat;
    state->lambda = (unsigned int)params->lambda;

    return 0;

fail_state:
    /*
     * V-7 (and P-12 transitively): on a failed voleith_vole_commit the
     * buffers com->u, com->c, and state->_v_buf may hold partially
     * written secret material (per-row v vectors and partial
     * VOLE-correlated outputs of the leaf seeds).  Zero them before
     * free - mirrors the success-path teardown in voleith_prover_free /
     * voleith_commitment_free.  Sized off ellhat_bytes computed above.
     */
    if (state->_v_buf) {
        voleith_secure_zero(state->_v_buf,
                            (size_t)params->lambda * ellhat_bytes);
    }
    free(state->v);
    free(state->_v_buf);
    state->v = NULL;
    state->_v_buf = NULL;
fail_com:
    if (com->u)
        voleith_secure_zero(com->u, ellhat_bytes);
    if (com->c)
        voleith_secure_zero(com->c, (size_t)(params->tau - 1) * ellhat_bytes);
    free(com->hcom);
    free(com->u);
    free(com->c);
    com->hcom = NULL;
    com->u = NULL;
    com->c = NULL;
    return -1;
}

int
voleith_open(voleith_bavc_opening_t *opening, const voleith_prover_t *state,
             const voleith_vc_params_t *params, const size_t *i_delta)
{
    return voleith_bavc_open(opening, &state->bavc, params, i_delta);
}

int
voleith_reconstruct(const voleith_commitment_t *com,
                    const voleith_bavc_opening_t *opening,
                    const voleith_vc_params_t *params, const size_t *i_delta,
                    const uint8_t iv[16], uint8_t **q)
{
    const size_t lambda_bytes = (size_t)params->lambda / 8;

    uint8_t reconstructed_com[64];
    int ret =
        voleith_vole_reconstruct(params, opening, i_delta, iv, com->ellhat,
                                 com->c, reconstructed_com, q);
    if (ret != 0)
        return ret;

    return voleith_const_memcmp(reconstructed_com, com->hcom, 2 * lambda_bytes)
               ? -1
               : 0;
}

void
voleith_commitment_free(voleith_commitment_t *com)
{
    free(com->hcom);
    if (com->u) {
        const size_t ellhat_bytes = ((size_t)com->ellhat + 7) / 8;
        voleith_secure_zero(com->u, ellhat_bytes);
        free(com->u);
    }
    if (com->c) {
        const size_t ellhat_bytes = ((size_t)com->ellhat + 7) / 8;
        voleith_secure_zero(com->c, (size_t)(com->tau - 1) * ellhat_bytes);
        free(com->c);
    }
    com->hcom = NULL;
    com->u = NULL;
    com->c = NULL;
}

void
voleith_prover_free(voleith_prover_t *state)
{
    voleith_bavc_free(&state->bavc);
    if (state->_v_buf) {
        /* Zero v vectors before freeing (contain VOLE tag material) */
        const size_t ellhat_bytes = (state->ellhat + 7) / 8;
        voleith_secure_zero(state->_v_buf,
                            (size_t)state->lambda * ellhat_bytes);
        free(state->_v_buf);
        state->_v_buf = NULL;
    }
    free(state->v);
    state->v = NULL;
}
