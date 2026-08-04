/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_argus_gf8.c - Argus (QC-MDPC code-based) opener backend.
 *
 * Clean-room reimplementation of libtalos_syndrome's byte-exact Argus contract
 * (docs/private/VOLEITH_CONTRACT.md, A0-A7), validated against the shared Argus
 * KAT vectors.  See rs_opener_argus_gf8.h for the API and the contract mapping.
 */

#include "rs_opener_argus_gf8.h"

#include "../core/aes.h"    /* voleith_aes_key_expand, voleith_aes_ctx_clear */
#include "../core/aesdm.h"  /* voleith_aesdm_* (lambda128 KDF hash)          */
#include "../core/grostl.h" /* voleith_grostl256_* (lambda256 KDF hash)      */
#include "../core/util.h"   /* voleith_const_memcmp, voleith_secure_zero     */

#include <ichor/aes.h>  /* ichor_aes_ctr (DEM CTR path, called directly)     */
#include <ichor/gf2x.h> /* ichor_gf2x_* circulant ring (called directly)     */
#include <ichor/util.h> /* ichor_bitpack_le32 (called directly)             */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * The p-dependent working buffers (ring elements, KDF message) are heap-
 * allocated per call from the runtime p and freed (after voleith_secure_zero)
 * when the call returns; Argus verify is an offline trace operation, not a hot
 * path, so a single allocation per call is fine and it avoids sizing stack for
 * the largest set.  The small buffers below are bounded by the security-LEVEL
 * ceiling (lambda <= 256), not by p, so they stay on the stack and never drift
 * with a new (p, n0) set: K is lambda/8 <= 32 bytes, the wrapped identity is
 * 3*lambda/8 <= 96 bytes (contract A2/A6).
 */
#define ARGUS_MAX_KEY_BYTES 32u /* lambda256/8       */
#define ARGUS_MAX_ID_BYTES 96u  /* 3*lambda256/8     */

/* DEM CTR nonce label (contract A6); set-independent, only the AES key width
 * tracks lambda. */
static const uint8_t ARGUS_CTR_LABEL[12] = "Argus-OTP-v1";

/*
 * Resolved per-set table (contract A7).  Only the four A7 sets are filled; the
 * eight reserved enumerators leave a zeroed row (p == 0), which params() maps to
 * "unsupported".  DS IVs are the exact A7 bytes.
 */
static const voleith_rs_opener_argus_params_t
    ARGUS_PARAMS[VOLEITH_RS_OPENER_ARGUS_SET_COUNT] = {
        [VOLEITH_RS_OPENER_ARGUS_SET_128_2] =
            {VOLEITH_RS_OPENER_ARGUS_SET_128_2,
             128,
             13613u,
             2u,
             130u,
             27226u,
             1702u,
             15u,
             244u,
             16u,
             48u,
             VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM,
             {0x54, 0x41, 0x4C, 0x4F, 0x53, 0x41, 0x72, 0x67, 0x75, 0x73, 0x10,
              0x01, 0x02, 0x00, 0x00, 0x01}},
        [VOLEITH_RS_OPENER_ARGUS_SET_128_5] =
            {VOLEITH_RS_OPENER_ARGUS_SET_128_5,
             128,
             7829u,
             5u,
             57u,
             39145u,
             979u,
             16u,
             114u,
             16u,
             48u,
             VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM,
             {0x54, 0x41, 0x4C, 0x4F, 0x53, 0x41, 0x72, 0x67, 0x75, 0x73, 0x10,
              0x01, 0x05, 0x00, 0x00, 0x01}},
        [VOLEITH_RS_OPENER_ARGUS_SET_256_2] =
            {VOLEITH_RS_OPENER_ARGUS_SET_256_2,
             256,
             43451u,
             2u,
             261u,
             86902u,
             5432u,
             17u,
             555u,
             32u,
             96u,
             VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL256,
             {0x54, 0x41, 0x4C, 0x4F, 0x53, 0x41, 0x72, 0x67, 0x75, 0x73, 0x20,
              0x02, 0x02, 0x00, 0x00, 0x01}},
        [VOLEITH_RS_OPENER_ARGUS_SET_256_5] =
            {VOLEITH_RS_OPENER_ARGUS_SET_256_5,
             256,
             24733u,
             5u,
             113u,
             123665u,
             3092u,
             17u,
             241u,
             32u,
             96u,
             VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL256,
             {0x54, 0x41, 0x4C, 0x4F, 0x53, 0x41, 0x72, 0x67, 0x75, 0x73, 0x20,
              0x02, 0x05, 0x00, 0x00, 0x01}},
};

const voleith_rs_opener_argus_params_t *
voleith_rs_opener_argus_params(voleith_rs_opener_argus_set_t set)
{
    const voleith_rs_opener_argus_params_t *p;

    if ((unsigned)set >= (unsigned)VOLEITH_RS_OPENER_ARGUS_SET_COUNT)
        return NULL;
    p = &ARGUS_PARAMS[set];
    if (p->p == 0u) /* reserved-but-unparameterized row */
        return NULL;
    return p;
}

void
voleith_rs_opener_argus_witness(voleith_rs_opener_witness_t *w,
                                const uint32_t *indices)
{
    if (w == NULL)
        return;
    w->scheme_id = VOLEITH_RS_OPENER_SCHEME_ARGUS;
    w->data = indices;
}

size_t
voleith_rs_opener_argus_tag_bytes(
    const voleith_rs_opener_argus_params_t *params, size_t id_len)
{
    if (params == NULL)
        return 0;
    return (size_t)1 + params->block_bytes + id_len;
}

int
voleith_rs_opener_argus_tag_parse(
    const voleith_rs_opener_argus_params_t *params, const uint8_t *tag,
    size_t tag_len, size_t id_len, uint8_t *hash_id_out, const uint8_t **s_out,
    const uint8_t **ct_out)
{
    if (params == NULL || tag == NULL || hash_id_out == NULL || s_out == NULL ||
        ct_out == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    if (id_len == 0 || id_len > params->id_max)
        return VOLEITH_RS_OPENER_EARGS;
    if (tag_len != voleith_rs_opener_argus_tag_bytes(params, id_len))
        return VOLEITH_RS_OPENER_EARGS;

    *hash_id_out = tag[0];
    *s_out = tag + 1;
    *ct_out = tag + 1 + params->block_bytes;
    return VOLEITH_RS_OPENER_OK;
}

int
voleith_rs_opener_argus_syndrome(const voleith_rs_opener_argus_params_t *params,
                                 uint8_t *s_out, const uint8_t *M,
                                 const uint32_t *indices)
{
    ichor_gf2x_ring ring;
    uint64_t *work, *acc, *eb, *mb, *prod, *scratch;
    uint8_t *blk;
    size_t limbs, nwork;
    uint32_t p, n0, t, b, i;
    int ret = VOLEITH_RS_OPENER_EARGS;

    if (params == NULL || s_out == NULL || M == NULL || indices == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    p = params->p;
    n0 = params->n0;
    t = params->t;
    if (ichor_gf2x_ring_init(&ring, p) != 0 ||
        ring.block_bytes != params->block_bytes)
        return VOLEITH_RS_OPENER_EARGS;
    limbs = ring.limbs;

    /* Every index must be a valid global position in [0, n). */
    for (i = 0; i < t; i++)
        if (indices[i] >= params->n)
            return VOLEITH_RS_OPENER_EARGS;

    /*
     * One arena: acc, eb, mb, prod (limbs each) + mul scratch + one limb-buffer
     * of scratch bytes for the dense block (limbs u64 = 8*limbs >= block_bytes).
     */
    nwork = 4u * limbs + ring.mul_scratch_limbs + limbs;
    work = calloc(nwork, sizeof(uint64_t));
    if (work == NULL)
        return VOLEITH_RS_OPENER_ENOMEM;
    acc = work;
    eb = acc + limbs;
    mb = eb + limbs;
    prod = mb + limbs;
    scratch = prod + limbs;
    blk = (uint8_t *)(scratch + ring.mul_scratch_limbs);

    /* Systematic form: s = M0*e0 + ... + M_{n0-2}*e_{n0-2} + e_{n0-1}.  Seed the
     * accumulator with the implicit-identity last block e_{n0-1}. */
    ichor_gf2x_scatter(blk, params->block_bytes, indices, t, (n0 - 1u) * p, p);
    ichor_gf2x_load(&ring, acc, blk);

    for (b = 0; b + 1u < n0; b++) {
        ichor_gf2x_scatter(blk, params->block_bytes, indices, t, b * p, p);
        ichor_gf2x_load(&ring, eb, blk);
        ichor_gf2x_load(&ring, mb, M + (size_t)b * params->block_bytes);
        ichor_gf2x_mul(&ring, prod, mb, eb, scratch);
        ichor_gf2x_add(&ring, acc, acc, prod);
    }

    ichor_gf2x_store(&ring, s_out, acc);
    ret = VOLEITH_RS_OPENER_OK;

    /* The arena holds the secret error (acc / eb / prod / blk) and the Karatsuba
     * intermediates; wipe the whole allocation before freeing. */
    voleith_secure_zero(work, nwork * sizeof(uint64_t));
    free(work);
    return ret;
}

int
voleith_rs_opener_argus_kdf(const voleith_rs_opener_argus_params_t *params,
                            uint8_t *K_out, uint8_t hash_id,
                            const uint32_t *indices)
{
    uint8_t *msg;

    if (params == NULL || K_out == NULL || indices == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    /* 1.11.0 opens only this build's compiled per-lambda default (A5 staging). */
    if (hash_id != params->prim_default)
        return VOLEITH_RS_OPENER_EUNSUPPORTED;
    if (params->key_bytes > ARGUS_MAX_KEY_BYTES)
        return VOLEITH_RS_OPENER_EARGS;

    msg = calloc(params->msg_bytes, 1);
    if (msg == NULL)
        return VOLEITH_RS_OPENER_ENOMEM;

    /* Support -> bit-packed message at idx_bits per index (A3), LSB-first. */
    if (ichor_bitpack_le32(msg, params->msg_bytes, indices, params->t,
                           params->idx_bits) != 0) {
        voleith_secure_zero(msg, params->msg_bytes);
        free(msg);
        return VOLEITH_RS_OPENER_EARGS;
    }

    if (hash_id == VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM) {
        voleith_aesdm_ctx_t ctx;

        voleith_aesdm_init_iv(&ctx, params->ds_iv);
        voleith_aesdm_absorb(&ctx, msg, params->msg_bytes);
        voleith_aesdm_finalize_fixed(&ctx, K_out);
        voleith_aesdm_clear(&ctx);
    } else { /* VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL256 */
        voleith_grostl_ctx_t ctx;
        uint8_t iv[64];

        memset(iv, 0, sizeof(iv));
        memcpy(iv, params->ds_iv, sizeof(params->ds_iv));
        voleith_grostl256_init_iv(&ctx, iv);
        voleith_grostl_absorb(&ctx, msg, params->msg_bytes);
        voleith_grostl_finalize_fixed(&ctx, K_out);
        voleith_grostl_clear(&ctx);
    }

    voleith_secure_zero(msg, params->msg_bytes);
    free(msg);
    return VOLEITH_RS_OPENER_OK;
}

int
voleith_rs_opener_argus_dem_pad(const voleith_rs_opener_argus_params_t *params,
                                uint8_t *pad_out, size_t pad_len,
                                const uint8_t *K)
{
    ichor_aes_ctx_t actx;

    if (params == NULL || pad_out == NULL || K == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    if (pad_len == 0 || pad_len > params->id_max)
        return VOLEITH_RS_OPENER_EARGS;

    if (pad_len <= params->key_bytes) {
        memcpy(pad_out, K, pad_len);
        return VOLEITH_RS_OPENER_OK;
    }

    /* len(ID) > lambda bytes: K keys AES-CTR under the fixed label, counter 0
     * (A6).  pad_len <= id_max is far below the 2^32-block cap. */
    if (voleith_aes_key_expand(&actx, K, params->lambda) != 0)
        return VOLEITH_RS_OPENER_EARGS;
    (void)ichor_aes_ctr(&actx, pad_out, NULL, pad_len, ARGUS_CTR_LABEL, 0);
    voleith_aes_ctx_clear(&actx);
    return VOLEITH_RS_OPENER_OK;
}

int
voleith_rs_opener_argus_verify(const voleith_rs_opener_argus_params_t *params,
                               const uint8_t *M, const uint8_t *s,
                               const uint8_t *tag_ct, uint8_t hash_id,
                               const uint32_t *indices, const uint8_t *id,
                               size_t id_len)
{
    uint8_t *sprime;
    uint8_t kdf_root[ARGUS_MAX_KEY_BYTES];
    uint8_t pad[ARGUS_MAX_ID_BYTES];
    uint8_t recovered[ARGUS_MAX_ID_BYTES];
    size_t i;
    int rc, ret;

    if (params == NULL || M == NULL || s == NULL || tag_ct == NULL ||
        indices == NULL || id == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    if (id_len == 0 || id_len > params->id_max)
        return VOLEITH_RS_OPENER_EARGS;
    if (params->key_bytes > sizeof(kdf_root) || params->id_max > sizeof(pad))
        return VOLEITH_RS_OPENER_EARGS;

    sprime = calloc(params->block_bytes, 1);
    if (sprime == NULL)
        return VOLEITH_RS_OPENER_ENOMEM;

    /* 1. syndrome relation: recompute s' = M*e^T and require s' == s. */
    rc = voleith_rs_opener_argus_syndrome(params, sprime, M, indices);
    if (rc != VOLEITH_RS_OPENER_OK) {
        ret = rc;
        goto done;
    }
    if (voleith_const_memcmp(sprime, s, params->block_bytes) != 0) {
        ret = VOLEITH_RS_OPENER_ESYNDROME;
        goto done;
    }

    /* 2. K = H(support(e)); rejects a non-default hash_id (EUNSUPPORTED). */
    rc = voleith_rs_opener_argus_kdf(params, kdf_root, hash_id, indices);
    if (rc != VOLEITH_RS_OPENER_OK) {
        ret = rc;
        goto done;
    }

    /* 3. DEM: require id == tag_ct XOR pad(K). */
    rc = voleith_rs_opener_argus_dem_pad(params, pad, id_len, kdf_root);
    if (rc != VOLEITH_RS_OPENER_OK) {
        ret = rc;
        goto done;
    }
    for (i = 0; i < id_len; i++)
        recovered[i] = (uint8_t)(tag_ct[i] ^ pad[i]);
    ret = (voleith_const_memcmp(recovered, id, id_len) == 0)
              ? VOLEITH_RS_OPENER_OK
              : VOLEITH_RS_OPENER_EIDENTITY;

done:
    voleith_secure_zero(sprime, params->block_bytes);
    free(sprime);
    voleith_secure_zero(kdf_root, sizeof(kdf_root));
    voleith_secure_zero(pad, sizeof(pad));
    voleith_secure_zero(recovered, sizeof(recovered));
    return ret;
}

/* ---- backend ops (registered under VOLEITH_RS_OPENER_SCHEME_ARGUS) --------- */

static const void *
argus_op_params(uint32_t set)
{
    return voleith_rs_opener_argus_params((voleith_rs_opener_argus_set_t)set);
}

static size_t
argus_op_tag_bytes(const void *params, size_t id_len)
{
    return voleith_rs_opener_argus_tag_bytes(
        (const voleith_rs_opener_argus_params_t *)params, id_len);
}

static int
argus_op_verify(const void *params, const uint8_t *pk, const uint8_t *tag,
                size_t tag_len, const void *witness_data, const uint8_t *id,
                size_t id_len)
{
    const voleith_rs_opener_argus_params_t *p =
        (const voleith_rs_opener_argus_params_t *)params;
    const uint8_t *s, *ct;
    uint8_t hash_id;
    int rc;

    if (p == NULL)
        return VOLEITH_RS_OPENER_ESET;
    rc = voleith_rs_opener_argus_tag_parse(p, tag, tag_len, id_len, &hash_id,
                                           &s, &ct);
    if (rc != VOLEITH_RS_OPENER_OK)
        return rc;
    return voleith_rs_opener_argus_verify(
        p, pk, s, ct, hash_id, (const uint32_t *)witness_data, id, id_len);
}

const voleith_rs_opener_scheme_t voleith_rs_opener_argus = {
    VOLEITH_RS_OPENER_SCHEME_ARGUS,
    "argus-qcmdpc",
    argus_op_params,
    argus_op_tag_bytes,
    argus_op_verify,
};
