/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_proof.c - Full VOLEitH non-interactive proof system (element-level)
 *
 * Direct port of proof.c for the GF(2⁸) element-level QuickSilver variant.
 * All VOLEitH commitment machinery is unchanged.  Substitutions vs proof.c:
 *
 *   voleith_circuit_t      → voleith_gf8_circuit_t
 *   voleith_qs_ell()       → voleith_gf8_qs_ell()
 *   ellhat_bytes           = voleith_gf8_qs_ellhat() [already in bytes]
 *   ell_bytes              = ell  [d is ell bytes, not ceil(ell/8)]
 *   instance_bytes         = n_instance [one byte per wire, not bit-packed]
 *   voleith_qs_compute_d() → voleith_gf8_qs_compute_d()
 *   voleith_qs_prove()     → voleith_gf8_qs_prove()
 *   voleith_qs_verify()    → voleith_gf8_qs_verify()
 */

#include "gf8_proof.h"
#include "fiat_shamir.h"
#include "vole_hash.h"
#include "gf8_prover.h"
#include "gf8_verifier.h"
#include "../vole/voleith.h"
#include "../vole/convert.h"
#include "../vole/vc.h"
#include "circuit.h" /* VOLEITH_STACK_BUF_MAX */

#include "../core/util.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ================================================================
 * Two-phase API: opaque context structs
 * ================================================================ */

struct voleith_gf8_prover_commit_t {
    voleith_params_t params;
    voleith_vc_params_t vcp;
    voleith_commitment_t com;
    voleith_prover_t state;
    size_t ell;
    size_t ellhat_bytes;
    size_t ell_bytes; /* = ell (d is ell bytes for element-level) */
    size_t n_instance;
    size_t utilde_bytes;
    size_t decom_size;
    size_t proof_size;
    uint8_t *pbuf;
};

struct voleith_gf8_verifier_reconstruct_t {
    voleith_params_t params;
    voleith_vc_params_t vcp;
    uint8_t **Q;
    uint8_t *u_tilde_copy;
    uint8_t *d_copy;
    uint8_t *a1_tilde_copy;
    uint8_t *a2_tilde_copy;
    uint8_t chall_3[32];
    uint32_t ctr_val;
    size_t ell;
    size_t ellhat_bytes;
    size_t ell_bytes;
    size_t n_instance;
    size_t utilde_bytes;
};

/* ================================================================
 * Internal helpers
 * ================================================================ */

#define IV_SIZE 16

static inline unsigned int
get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

static int
check_grinding(const uint8_t *chall_3, unsigned int lambda,
               unsigned int w_grind)
{
    for (unsigned int i = lambda - w_grind; i < lambda; i++) {
        if (get_bit(chall_3, i))
            return 0;
    }
    return 1;
}

static int
make_vc_params(voleith_vc_params_t *vcp, const voleith_params_t *p)
{
    return voleith_vc_params_init(vcp, (int)p->lambda, (int)p->tau,
                                  (int)p->w_grind, (int)p->n_leafcom,
                                  (int)p->T_open);
}

/*
 * Compute proof layout offsets from a base pointer.
 * ell_bytes = ell for element-level (d is one byte per slot).
 */
static void
proof_layout(const uint8_t *base, const voleith_params_t *params,
             size_t ellhat_bytes, size_t ell_bytes, size_t decom_size,
             const uint8_t **c_out, const uint8_t **u_tilde_out,
             const uint8_t **d_out, const uint8_t **a1_tilde_out,
             const uint8_t **a2_tilde_out, const uint8_t **decom_i_out,
             const uint8_t **chall_3_out, const uint8_t **iv_out,
             const uint8_t **ctr_out)
{
    unsigned int nb = params->lambda / 8;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    const uint8_t *p = base;

    if (c_out)
        *c_out = p;
    p += (params->tau - 1) * ellhat_bytes;
    if (u_tilde_out)
        *u_tilde_out = p;
    p += utilde_bytes;
    if (d_out)
        *d_out = p;
    p += ell_bytes;
    if (a1_tilde_out)
        *a1_tilde_out = p;
    p += nb;
    if (a2_tilde_out)
        *a2_tilde_out = p;
    p += nb;
    if (decom_i_out)
        *decom_i_out = p;
    p += decom_size;
    if (chall_3_out)
        *chall_3_out = p;
    p += nb;
    if (iv_out)
        *iv_out = p;
    p += IV_SIZE;
    if (ctr_out)
        *ctr_out = p;
}

static void
proof_layout_w(uint8_t *base, const voleith_params_t *params,
               size_t ellhat_bytes, size_t ell_bytes, size_t decom_size,
               uint8_t **c_out, uint8_t **u_tilde_out, uint8_t **d_out,
               uint8_t **a1_tilde_out, uint8_t **a2_tilde_out,
               uint8_t **decom_i_out, uint8_t **chall_3_out, uint8_t **iv_out,
               uint8_t **ctr_out)
{
    proof_layout((const uint8_t *)base, params, ellhat_bytes, ell_bytes,
                 decom_size, (const uint8_t **)c_out,
                 (const uint8_t **)u_tilde_out, (const uint8_t **)d_out,
                 (const uint8_t **)a1_tilde_out, (const uint8_t **)a2_tilde_out,
                 (const uint8_t **)decom_i_out, (const uint8_t **)chall_3_out,
                 (const uint8_t **)iv_out, (const uint8_t **)ctr_out);
}

/* ================================================================
 * Proof size
 * ================================================================ */

size_t
voleith_gf8_proof_byte_size(const voleith_params_t *params, size_t ell)
{
    unsigned int nb = params->lambda / 8;
    /* ellhat_bytes = ell + ceil((3*lambda + 16) / 8) */
    size_t ellhat_bytes = ell + (3u * params->lambda + 16u + 7u) / 8u;
    size_t ell_bytes = ell; /* d is ell bytes, not ceil(ell/8) bytes */
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    size_t decom_size =
        ((size_t)params->n_leafcom * params->tau + (size_t)params->T_open) * nb;

    return (params->tau - 1u) * ellhat_bytes + utilde_bytes + ell_bytes +
           nb                /* a1_tilde */
           + nb              /* a2_tilde */
           + decom_size + nb /* chall_3 */
           + IV_SIZE + 4u;   /* ctr */
}

/* ================================================================
 * Two-phase API: implementation
 * ================================================================ */

size_t
voleith_gf8_commit_blob_size(const voleith_params_t *params,
                             const voleith_gf8_circuit_t *circuit)
{
    unsigned int nb = params->lambda / 8;
    /* voleith_gf8_qs_ellhat already returns bytes */
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(circuit, params->lambda);
    return 2u * nb + (params->tau - 1u) * ellhat_bytes + IV_SIZE;
}

int
voleith_gf8_prove_commit(voleith_gf8_prover_commit_t **ctx_out,
                         const voleith_params_t *params,
                         const voleith_gf8_circuit_t *circuit,
                         const uint8_t *witness, const uint8_t *instance,
                         const uint8_t *fs_seed, size_t fs_seed_len,
                         uint8_t *commitment_out)
{
    if (!ctx_out || !params || !circuit || !witness || !fs_seed ||
        !commitment_out)
        return -1;
    /* X-7: full parameter validation at the public API boundary. */
    if (voleith_params_validate(params) != 0)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    unsigned int tau = params->tau;

    size_t ell = voleith_gf8_qs_ell(circuit);
    size_t ellhat_bytes =
        voleith_gf8_qs_ellhat(circuit, lambda); /* already bytes */
    size_t ell_bytes = ell; /* d is one byte per element slot */
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    size_t n_instance = voleith_gf8_circuit_instance_count(circuit);

    voleith_gf8_prover_commit_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->params = *params;
    ctx->ell = ell;
    ctx->ellhat_bytes = ellhat_bytes;
    ctx->ell_bytes = ell_bytes;
    ctx->n_instance = n_instance;
    ctx->utilde_bytes = utilde_bytes;

    if (make_vc_params(&ctx->vcp, params) != 0) {
        free(ctx);
        return -1;
    }

    ctx->decom_size = voleith_bavc_opening_size(&ctx->vcp);
    ctx->proof_size = voleith_gf8_proof_byte_size(params, ell);

    ctx->pbuf = calloc(ctx->proof_size, 1);
    if (!ctx->pbuf) {
        free(ctx);
        return -1;
    }

    uint8_t *c_ptr, *u_tilde_ptr, *d_ptr, *a1_ptr, *a2_ptr;
    uint8_t *decom_ptr, *chall3_ptr, *iv_ptr, *ctr_ptr;
    proof_layout_w(ctx->pbuf, params, ellhat_bytes, ell_bytes, ctx->decom_size,
                   &c_ptr, &u_tilde_ptr, &d_ptr, &a1_ptr, &a2_ptr, &decom_ptr,
                   &chall3_ptr, &iv_ptr, &ctr_ptr);

    /* Step 1: Derive root_seed || iv via H_3(fs_seed).
     *
     * G-2 (same as P-1 for the GF(2⁸) prover): root_seed is the master
     * secret; zero it and the wrapping buf on every exit. */
    uint8_t root_seed[32];
    {
        uint8_t buf[48];
        voleith_fs_hash(lambda, VOLEITH_FS_H3, fs_seed, fs_seed_len, buf,
                        nb + IV_SIZE);
        memcpy(root_seed, buf, nb);
        memcpy(iv_ptr, buf + nb, IV_SIZE);
        voleith_secure_zero(buf, sizeof(buf));
    }

    /* Step 2: VOLEitH commit
     * The ellhat passed to voleith_commit is the bit count: ellhat_bytes * 8. */
    unsigned int ellhat_bits = (unsigned int)(ellhat_bytes * 8);
    int commit_rc = voleith_commit(&ctx->com, &ctx->state, &ctx->vcp, root_seed,
                                   iv_ptr, ellhat_bits);
    voleith_secure_zero(root_seed, sizeof(root_seed));
    if (commit_rc != 0) {
        voleith_gf8_prover_commit_free(ctx);
        return -1;
    }

    /* Copy c[0..tau-2] into proof buffer */
    memcpy(c_ptr, ctx->com.c, (tau - 1) * ellhat_bytes);

    /* Fill commitment blob: hcom || c || iv */
    memcpy(commitment_out, ctx->com.hcom, 2 * nb);
    memcpy(commitment_out + 2 * nb, c_ptr, (tau - 1) * ellhat_bytes);
    memcpy(commitment_out + 2 * nb + (tau - 1) * ellhat_bytes, iv_ptr, IV_SIZE);

    *ctx_out = ctx;
    return 0;
}

int
voleith_gf8_prove_respond(voleith_proof_t *proof_out,
                          voleith_gf8_prover_commit_t *ctx,
                          const voleith_gf8_circuit_t *circuit,
                          const uint8_t *witness, const uint8_t *instance,
                          const uint8_t *chall_1)
{
    if (!proof_out || !ctx || !ctx->pbuf || !circuit || !witness || !chall_1)
        return -1;

    const voleith_params_t *params = &ctx->params;
    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t ell = ctx->ell;
    size_t ell_bytes = ctx->ell_bytes;
    size_t ellhat_bytes = ctx->ellhat_bytes;
    size_t utilde_bytes = ctx->utilde_bytes;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    uint8_t *c, *u_tilde, *d, *a1_tilde, *a2_tilde, *decom_i, *chall_3, *iv,
        *ctr;
    proof_layout_w(ctx->pbuf, params, ellhat_bytes, ell_bytes, ctx->decom_size,
                   &c, &u_tilde, &d, &a1_tilde, &a2_tilde, &decom_i, &chall_3,
                   &iv, &ctr);

    /* Step 4: u_tilde = VOLEHash(chall_1, u, ell) */
    voleith_vole_hash(u_tilde, chall_1, ctx->com.u, ell, lambda);

    /* Step 5: d = wire_vals XOR u_slots */
    if (voleith_gf8_qs_compute_d(circuit, witness, inst, ctx->com.u, d) != 0)
        return -1;

    /* Step 6: chall_2 = H_2^2(chall_1 || u_tilde || V_tilde[0..λ-1] || d) */
    uint8_t chall_2[3 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_2);
        voleith_transcript_absorb(&t, chall_1, 5 * nb + 8);
        voleith_transcript_absorb(&t, u_tilde, utilde_bytes);

        uint8_t v_tilde[32 + VOLEITH_VOLE_HASH_B];
        for (unsigned int i = 0; i < lambda; i++) {
            voleith_vole_hash(v_tilde, chall_1, ctx->state.v[i], ell, lambda);
            voleith_transcript_absorb(&t, v_tilde, utilde_bytes);
        }

        voleith_transcript_absorb(&t, d, ell_bytes);
        voleith_transcript_squeeze(&t, chall_2, 3 * nb + 8);
        voleith_transcript_clear(&t);
    }

    /* Step 7: QuickSilver prove
     * Use heap for d_tmp since ell_bytes = ell can be large (e.g. 6600 for KVAC). */
    uint8_t a0_tilde[32];
    {
        uint8_t d_tmp_stack[VOLEITH_STACK_BUF_MAX];
        uint8_t *d_tmp_heap = NULL;
        uint8_t *d_dyn;
        if (ell_bytes > sizeof(d_tmp_stack)) {
            d_tmp_heap = calloc(ell_bytes, 1);
            if (!d_tmp_heap)
                return -1;
            d_dyn = d_tmp_heap;
        } else
            d_dyn = d_tmp_stack;

        int ret =
            voleith_gf8_qs_prove(circuit, witness, inst, lambda, ctx->com.u,
                                 (const uint8_t **)ctx->state.v, chall_2, d_dyn,
                                 a0_tilde, a1_tilde, a2_tilde);
        /* X-9: d_dyn carries `witness ⊕ u_slots` (gf8_qs_prove writes
         * d here).  Same defense-in-depth concern as the bit-level
         * variant: zero before free / before the stack buffer goes
         * out of scope. */
        if (d_tmp_heap) {
            voleith_secure_zero(d_tmp_heap, ell_bytes);
            free(d_tmp_heap);
        } else {
            voleith_secure_zero(d_tmp_stack, ell_bytes);
        }
        if (ret != 0)
            return -1;
    }

    /* Steps 8-9: chall_3 grinding loop + BAVC open */
    uint32_t ctr_val = 0;
    for (;; ctr_val++) {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_3);
        voleith_transcript_absorb(&t, chall_2, 3 * nb + 8);
        voleith_transcript_absorb(&t, a0_tilde, nb);
        voleith_transcript_absorb(&t, a1_tilde, nb);
        voleith_transcript_absorb(&t, a2_tilde, nb);
        uint8_t ctr_bytes[4];
        memcpy(ctr_bytes, &ctr_val, 4);
        voleith_transcript_absorb(&t, ctr_bytes, 4);
        voleith_transcript_squeeze(&t, chall_3, nb);
        voleith_transcript_clear(&t);

        if (!check_grinding(chall_3, lambda, params->w_grind))
            continue;

        size_t i_delta[32];
        voleith_decode_challenge(chall_3, &ctx->vcp, i_delta);

        voleith_bavc_opening_t opening;
        memset(&opening, 0, sizeof(opening));
        if (voleith_open(&opening, &ctx->state, &ctx->vcp, i_delta) != 0)
            continue;

        memcpy(decom_i, opening.data, opening.data_len);
        voleith_bavc_opening_free(&opening);
        break;
    }

    memcpy(ctr, &ctr_val, 4);

    proof_out->data = ctx->pbuf;
    proof_out->len = ctx->proof_size;
    ctx->pbuf = NULL;
    return 0;
}

void
voleith_gf8_prover_commit_free(voleith_gf8_prover_commit_t *ctx)
{
    if (!ctx)
        return;
    voleith_commitment_free(&ctx->com);
    voleith_prover_free(&ctx->state);
    if (ctx->pbuf) {
        voleith_secure_zero(ctx->pbuf, ctx->proof_size);
        free(ctx->pbuf);
    }
    free(ctx);
}

int
voleith_gf8_verify_reconstruct(voleith_gf8_verifier_reconstruct_t **ctx_out,
                               const voleith_proof_t *proof,
                               const voleith_params_t *params,
                               const voleith_gf8_circuit_t *circuit,
                               uint8_t *commitment_out)
{
    if (!ctx_out || !proof || !proof->data || !params || !circuit ||
        !commitment_out)
        return -1;
    /* X-7: full parameter validation at the public API boundary. */
    if (voleith_params_validate(params) != 0)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    unsigned int tau = params->tau;

    size_t ell = voleith_gf8_qs_ell(circuit);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(circuit, lambda);
    size_t ell_bytes = ell;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    size_t n_instance = voleith_gf8_circuit_instance_count(circuit);

    voleith_vc_params_t vcp;
    if (make_vc_params(&vcp, params) != 0)
        return -1;

    size_t decom_size = voleith_bavc_opening_size(&vcp);
    size_t expected_size = voleith_gf8_proof_byte_size(params, ell);

    if (proof->len != expected_size)
        return -1;

    const uint8_t *c, *u_tilde, *d, *a1_tilde, *a2_tilde, *decom_i_ptr,
        *chall_3_ptr, *iv, *ctr_ptr;
    proof_layout(proof->data, params, ellhat_bytes, ell_bytes, decom_size, &c,
                 &u_tilde, &d, &a1_tilde, &a2_tilde, &decom_i_ptr, &chall_3_ptr,
                 &iv, &ctr_ptr);

    if (!check_grinding(chall_3_ptr, lambda, params->w_grind))
        return -1;

    size_t i_delta[32];
    voleith_decode_challenge(chall_3_ptr, &vcp, i_delta);

    voleith_gf8_verifier_reconstruct_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->params = *params;
    ctx->vcp = vcp;
    ctx->ell = ell;
    ctx->ellhat_bytes = ellhat_bytes;
    ctx->ell_bytes = ell_bytes;
    ctx->n_instance = n_instance;
    ctx->utilde_bytes = utilde_bytes;
    memcpy(ctx->chall_3, chall_3_ptr, nb);
    memcpy(&ctx->ctr_val, ctr_ptr, 4);

    ctx->u_tilde_copy = malloc(utilde_bytes);
    ctx->d_copy = malloc(ell_bytes);
    ctx->a1_tilde_copy = malloc(nb);
    ctx->a2_tilde_copy = malloc(nb);
    if (!ctx->u_tilde_copy || !ctx->d_copy || !ctx->a1_tilde_copy ||
        !ctx->a2_tilde_copy) {
        voleith_gf8_verifier_reconstruct_free(ctx);
        return -1;
    }
    memcpy(ctx->u_tilde_copy, u_tilde, utilde_bytes);
    memcpy(ctx->d_copy, d, ell_bytes);
    memcpy(ctx->a1_tilde_copy, a1_tilde, nb);
    memcpy(ctx->a2_tilde_copy, a2_tilde, nb);

    ctx->Q = calloc(lambda, sizeof(uint8_t *));
    if (!ctx->Q) {
        voleith_gf8_verifier_reconstruct_free(ctx);
        return -1;
    }
    ctx->Q[0] = calloc(lambda, ellhat_bytes);
    if (!ctx->Q[0]) {
        voleith_gf8_verifier_reconstruct_free(ctx);
        return -1;
    }
    for (unsigned int i = 1; i < lambda; i++)
        ctx->Q[i] = ctx->Q[0] + (size_t)i * ellhat_bytes;

    voleith_bavc_opening_t opening;
    opening.data = (uint8_t *)decom_i_ptr;
    opening.data_len = decom_size;
    opening.n_revealed = 0;

    uint8_t hcom_rec[64];
    if (voleith_vole_reconstruct(&ctx->vcp, &opening, i_delta, iv,
                                 (unsigned int)(ellhat_bytes * 8), c, hcom_rec,
                                 ctx->Q) != 0) {
        voleith_gf8_verifier_reconstruct_free(ctx);
        return -1;
    }

    memcpy(commitment_out, hcom_rec, 2 * nb);
    memcpy(commitment_out + 2 * nb, c, (tau - 1) * ellhat_bytes);
    memcpy(commitment_out + 2 * nb + (tau - 1) * ellhat_bytes, iv, IV_SIZE);

    *ctx_out = ctx;
    return 0;
}

int
voleith_gf8_verify_respond(voleith_gf8_verifier_reconstruct_t *ctx,
                           const voleith_gf8_circuit_t *circuit,
                           const uint8_t *instance, const uint8_t *chall_1)
{
    if (!ctx || !circuit || !chall_1)
        return -1;

    const voleith_params_t *params = &ctx->params;
    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t ell = ctx->ell;
    size_t ell_bytes = ctx->ell_bytes;
    size_t utilde_bytes = ctx->utilde_bytes;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    /* Steps 5-6: chall_2 */
    uint8_t chall_2[3 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_2);
        voleith_transcript_absorb(&t, chall_1, 5 * nb + 8);
        voleith_transcript_absorb(&t, ctx->u_tilde_copy, utilde_bytes);

        uint8_t q_tilde[32 + VOLEITH_VOLE_HASH_B];
        for (unsigned int i = 0; i < lambda; i++) {
            voleith_vole_hash(q_tilde, chall_1, ctx->Q[i], ell, lambda);
            if (get_bit(ctx->chall_3, i)) {
                for (unsigned int k = 0; k < utilde_bytes; k++)
                    q_tilde[k] ^= ctx->u_tilde_copy[k];
            }
            voleith_transcript_absorb(&t, q_tilde, utilde_bytes);
        }

        voleith_transcript_absorb(&t, ctx->d_copy, ell_bytes);
        voleith_transcript_squeeze(&t, chall_2, 3 * nb + 8);
        voleith_transcript_clear(&t);
    }

    /* Step 7: QuickSilver verify */
    uint8_t a0_tilde_out[32];
    if (voleith_gf8_qs_verify(circuit, inst, lambda, (const uint8_t **)ctx->Q,
                              ctx->d_copy, ctx->chall_3, chall_2,
                              ctx->a1_tilde_copy, ctx->a2_tilde_copy,
                              a0_tilde_out) != 0)
        return -1;

    /* Step 8: Recompute chall_3' and compare */
    uint8_t chall_3_check[32];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_3);
        voleith_transcript_absorb(&t, chall_2, 3 * nb + 8);
        voleith_transcript_absorb(&t, a0_tilde_out, nb);
        voleith_transcript_absorb(&t, ctx->a1_tilde_copy, nb);
        voleith_transcript_absorb(&t, ctx->a2_tilde_copy, nb);
        uint8_t ctr_bytes[4];
        memcpy(ctr_bytes, &ctx->ctr_val, 4);
        voleith_transcript_absorb(&t, ctr_bytes, 4);
        voleith_transcript_squeeze(&t, chall_3_check, nb);
        voleith_transcript_clear(&t);
    }

    return voleith_const_memcmp(chall_3_check, ctx->chall_3, nb) ? -1 : 0;
}

void
voleith_gf8_verifier_reconstruct_free(voleith_gf8_verifier_reconstruct_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->Q) {
        if (ctx->Q[0]) {
            voleith_secure_zero(ctx->Q[0],
                                (size_t)ctx->params.lambda * ctx->ellhat_bytes);
            free(ctx->Q[0]);
        }
        free(ctx->Q);
    }
    if (ctx->u_tilde_copy) {
        voleith_secure_zero(ctx->u_tilde_copy, ctx->utilde_bytes);
        free(ctx->u_tilde_copy);
    }
    if (ctx->d_copy) {
        voleith_secure_zero(ctx->d_copy, ctx->ell_bytes);
        free(ctx->d_copy);
    }
    if (ctx->a1_tilde_copy) {
        voleith_secure_zero(ctx->a1_tilde_copy, ctx->params.lambda / 8);
        free(ctx->a1_tilde_copy);
    }
    if (ctx->a2_tilde_copy) {
        voleith_secure_zero(ctx->a2_tilde_copy, ctx->params.lambda / 8);
        free(ctx->a2_tilde_copy);
    }
    free(ctx);
}

/* ================================================================
 * Prove
 * ================================================================ */

int
voleith_gf8_prove(voleith_proof_t *proof, const voleith_params_t *params,
                  const voleith_gf8_circuit_t *circuit, const uint8_t *witness,
                  const uint8_t *instance, const uint8_t *fs_seed,
                  size_t fs_seed_len)
{
    if (!proof || !params || !circuit || !witness || !fs_seed)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t n_instance = voleith_gf8_circuit_instance_count(circuit);
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    size_t blob_size = voleith_gf8_commit_blob_size(params, circuit);
    uint8_t *blob = malloc(blob_size);
    if (!blob)
        return -1;

    voleith_gf8_prover_commit_t *ctx = NULL;
    if (voleith_gf8_prove_commit(&ctx, params, circuit, witness, instance,
                                 fs_seed, fs_seed_len, blob) != 0) {
        free(blob);
        return -1;
    }

    uint8_t chall_1[5 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_1);
        voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
        if (n_instance > 0)
            voleith_transcript_absorb(&t, inst, n_instance);
        voleith_transcript_absorb(&t, blob, blob_size);
        voleith_transcript_squeeze(&t, chall_1, 5 * nb + 8);
        voleith_transcript_clear(&t);
    }
    free(blob);

    int ret = voleith_gf8_prove_respond(proof, ctx, circuit, witness, instance,
                                        chall_1);
    voleith_gf8_prover_commit_free(ctx);
    return ret;
}

/* ================================================================
 * Verify
 * ================================================================ */

int
voleith_gf8_verify(const voleith_proof_t *proof, const voleith_params_t *params,
                   const voleith_gf8_circuit_t *circuit,
                   const uint8_t *instance, const uint8_t *fs_seed,
                   size_t fs_seed_len)
{
    if (!proof || !proof->data || !params || !circuit || !fs_seed)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t n_instance = voleith_gf8_circuit_instance_count(circuit);
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    size_t blob_size = voleith_gf8_commit_blob_size(params, circuit);
    uint8_t *blob = malloc(blob_size);
    if (!blob)
        return -1;

    voleith_gf8_verifier_reconstruct_t *ctx = NULL;
    if (voleith_gf8_verify_reconstruct(&ctx, proof, params, circuit, blob) !=
        0) {
        free(blob);
        return -1;
    }

    uint8_t chall_1[5 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_1);
        voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
        if (n_instance > 0)
            voleith_transcript_absorb(&t, inst, n_instance);
        voleith_transcript_absorb(&t, blob, blob_size);
        voleith_transcript_squeeze(&t, chall_1, 5 * nb + 8);
        voleith_transcript_clear(&t);
    }
    free(blob);

    int ret = voleith_gf8_verify_respond(ctx, circuit, instance, chall_1);
    voleith_gf8_verifier_reconstruct_free(ctx);
    return ret;
}
