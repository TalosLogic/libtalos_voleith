/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_chunk_cert_proof.c - non-interactive RS chunk membership certificate
 * (Fiat-Shamir wrapper over the certificate circuit), plan T6.5.
 *
 * Wraps circuits/rs_chunk_cert_circuit.{c} in gf8_proof prove/verify, binding
 * the dataset root R into the Fiat-Shamir seed and (verify) enforcing the
 * two-layer R = H(merkle_root || H(metadata)) dataset check before checking
 * the proof.  Public-index and secret-index variants share one impl.
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_chunk_cert_proof.h"

#include "../circuits/rs_chunk_cert_circuit.h"
#include "../core/hash.h"
#include "../core/util.h"
#include "gf8_proof.h"
#include "params_fingerprint.h"

#include <stdlib.h>
#include <string.h>

/* 12-byte ASCII Fiat-Shamir domain tag for the chunk certificate. */
#define CERT_FS_DOMAIN_TAG "VOLEitH-RScc"
#define CERT_FS_DOMAIN_TAG_BYTES 12
#define CERT_FS_FMT_VERSION 0x01

/*
 * Build the Fiat-Shamir seed binding the certificate's public context: domain
 * tag + version, the parameter-set fingerprint, the CR profile, the chunk
 * count, the index mode (and, public mode only, the index), the dataset root
 * R, and the chunk_digest.  R and chunk_digest are each `digb` bytes.
 */
static int
cert_compute_fs_seed(voleith_rs_cr_profile_t cr, size_t n_chunks, int secret,
                     size_t index, const uint8_t *R,
                     const uint8_t *chunk_digest, size_t digb,
                     const voleith_params_t *params,
                     uint8_t out[VOLEITH_RS_CHUNK_CERT_FS_SEED_BYTES])
{
    voleith_hash_ctx_t ctx;
    uint8_t params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t version = CERT_FS_FMT_VERSION;
    uint8_t cr_byte = (uint8_t)cr;
    uint8_t mode_byte = secret ? 1u : 0u;
    uint8_t n_le[8], idx_le[8];

    if (voleith_params_fingerprint(params, params_fp) != 0)
        return -1;

    for (size_t i = 0; i < 8; i++) {
        n_le[i] = (uint8_t)(((uint64_t)n_chunks >> (8u * i)) & 0xffu);
        idx_le[i] = (uint8_t)(((uint64_t)index >> (8u * i)) & 0xffu);
    }

    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, &version, 1);
    voleith_shake256_absorb(&ctx, (const uint8_t *)CERT_FS_DOMAIN_TAG,
                            CERT_FS_DOMAIN_TAG_BYTES);
    voleith_shake256_absorb(&ctx, params_fp, sizeof(params_fp));
    voleith_shake256_absorb(&ctx, &cr_byte, 1);
    voleith_shake256_absorb(&ctx, n_le, sizeof(n_le));
    voleith_shake256_absorb(&ctx, &mode_byte, 1);
    if (!secret)
        voleith_shake256_absorb(&ctx, idx_le, sizeof(idx_le));
    voleith_shake256_absorb(&ctx, R, digb);
    voleith_shake256_absorb(&ctx, chunk_digest, digb);
    voleith_shake256_squeeze(&ctx, out, VOLEITH_RS_CHUNK_CERT_FS_SEED_BYTES);

    voleith_hash_ctx_clear(&ctx);
    voleith_secure_zero(params_fp, sizeof(params_fp));
    return 0;
}

static int
cert_prove_impl(voleith_proof_t *proof_out, const voleith_params_t *params,
                voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
                const uint8_t *fwk, const uint8_t *chunk_digest,
                const uint8_t *merkle_root, const uint8_t *siblings,
                const voleith_rs_metadata_t *metadata, int secret)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_chunk_cert_layout_t layout;
    const voleith_node_hash_vt *vt;
    uint8_t *witness = NULL;
    uint8_t *instance = NULL;
    uint8_t R[64];
    uint8_t fs_seed[VOLEITH_RS_CHUNK_CERT_FS_SEED_BYTES];
    voleith_proof_t proof = {NULL, 0};
    size_t W, digb;
    int rc = -1;

    if (proof_out == NULL || params == NULL || fwk == NULL ||
        chunk_digest == NULL || merkle_root == NULL || metadata == NULL)
        return -1;
    proof_out->data = NULL;
    proof_out->len = 0;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL || metadata->cr_profile != cr)
        return -1;
    W = vt->node_bytes;
    digb = voleith_rs_cr_digest_bytes(cr);

    /* Dataset root R = H(merkle_root || H(metadata)), bound into fs_seed. */
    if (voleith_rs_compute_R(merkle_root, W, metadata, R, sizeof(R)) !=
        VOLEITH_EC_OK)
        return -1;

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        goto out;
    if (secret) {
        if (voleith_rs_chunk_cert_build_circuit_secret_dir(
                circuit, cr, n_chunks, &layout) != 0)
            goto out;
    } else {
        if (voleith_rs_chunk_cert_build_circuit(circuit, cr, n_chunks, index,
                                                &layout) != 0)
            goto out;
    }

    witness = calloc(layout.witness_bytes ? layout.witness_bytes : 1, 1);
    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (witness == NULL || instance == NULL)
        goto out;

    if (secret) {
        if (voleith_rs_chunk_cert_build_witness_secret_dir(
                cr, n_chunks, index, fwk, chunk_digest, siblings, &layout,
                witness) != 0)
            goto out;
    } else {
        if (voleith_rs_chunk_cert_build_witness(cr, n_chunks, index, fwk,
                                                chunk_digest, siblings, &layout,
                                                witness) != 0)
            goto out;
    }

    memcpy(instance + layout.inst_root_off, merkle_root,
           layout.inst_root_bytes);
    memcpy(instance + layout.inst_digest_off, chunk_digest,
           layout.inst_digest_bytes);

    if (cert_compute_fs_seed(cr, n_chunks, secret, index, R, chunk_digest, digb,
                             params, fs_seed) != 0)
        goto out;

    /* prove_v2 runs circuit_eval first: a wrong FWK / sibling / index that
     * does not walk to merkle_root fails here, so only an FWK holder can
     * produce a valid certificate. */
    if (voleith_gf8_prove_v2(
            &proof, params, circuit, witness, layout.witness_bytes, instance,
            layout.instance_bytes, fs_seed, sizeof(fs_seed)) != 0)
        goto out;

    proof_out->data = proof.data;
    proof_out->len = proof.len;
    proof.data = NULL;
    proof.len = 0;
    rc = 0;

out:
    if (witness != NULL) {
        voleith_secure_zero(witness, layout.witness_bytes);
        free(witness);
    }
    free(instance);
    voleith_secure_zero(fs_seed, sizeof(fs_seed));
    voleith_secure_zero(R, sizeof(R));
    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(circuit);
    return rc;
}

static int
cert_verify_impl(const voleith_proof_t *proof, const voleith_params_t *params,
                 voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
                 const uint8_t *chunk_digest, const uint8_t *merkle_root,
                 const voleith_rs_metadata_t *metadata, const uint8_t *R_auth,
                 size_t R_len, int secret)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_chunk_cert_layout_t layout;
    const voleith_node_hash_vt *vt;
    uint8_t *instance = NULL;
    uint8_t R[64];
    uint8_t fs_seed[VOLEITH_RS_CHUNK_CERT_FS_SEED_BYTES];
    size_t W, digb;
    int rc = -1;

    if (proof == NULL || proof->data == NULL || params == NULL ||
        chunk_digest == NULL || merkle_root == NULL || metadata == NULL ||
        R_auth == NULL)
        return -1;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL || metadata->cr_profile != cr)
        return -1;
    W = vt->node_bytes;
    digb = voleith_rs_cr_digest_bytes(cr);

    /* Two-layer dataset check (design 6.7): the supplied (merkle_root,
     * metadata) must hash to the authoritative R the caller trusts. */
    if (voleith_rs_verify_R(R_auth, R_len, merkle_root, W, metadata) !=
        VOLEITH_EC_OK)
        return -1;

    /* Recompute R for the fs_seed (equals R_auth, just checked). */
    if (voleith_rs_compute_R(merkle_root, W, metadata, R, sizeof(R)) !=
        VOLEITH_EC_OK)
        return -1;

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        goto out;
    if (secret) {
        if (voleith_rs_chunk_cert_build_circuit_secret_dir(
                circuit, cr, n_chunks, &layout) != 0)
            goto out;
    } else {
        if (voleith_rs_chunk_cert_build_circuit(circuit, cr, n_chunks, index,
                                                &layout) != 0)
            goto out;
    }

    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (instance == NULL)
        goto out;
    memcpy(instance + layout.inst_root_off, merkle_root,
           layout.inst_root_bytes);
    memcpy(instance + layout.inst_digest_off, chunk_digest,
           layout.inst_digest_bytes);

    if (cert_compute_fs_seed(cr, n_chunks, secret, index, R, chunk_digest, digb,
                             params, fs_seed) != 0)
        goto out;

    if (voleith_gf8_verify_v2(proof, params, circuit, instance,
                              layout.instance_bytes, fs_seed,
                              sizeof(fs_seed)) != 0)
        goto out;

    rc = 0;

out:
    free(instance);
    voleith_secure_zero(fs_seed, sizeof(fs_seed));
    voleith_secure_zero(R, sizeof(R));
    voleith_gf8_circuit_free(circuit);
    return rc;
}

int
voleith_rs_chunk_cert_prove(voleith_proof_t *proof_out,
                            const voleith_params_t *params,
                            voleith_rs_cr_profile_t cr, size_t n_chunks,
                            size_t index, const uint8_t *fwk,
                            const uint8_t *chunk_digest,
                            const uint8_t *merkle_root, const uint8_t *siblings,
                            const voleith_rs_metadata_t *metadata)
{
    return cert_prove_impl(proof_out, params, cr, n_chunks, index, fwk,
                           chunk_digest, merkle_root, siblings, metadata, 0);
}

int
voleith_rs_chunk_cert_verify(const voleith_proof_t *proof,
                             const voleith_params_t *params,
                             voleith_rs_cr_profile_t cr, size_t n_chunks,
                             size_t index, const uint8_t *chunk_digest,
                             const uint8_t *merkle_root,
                             const voleith_rs_metadata_t *metadata,
                             const uint8_t *R, size_t R_len)
{
    return cert_verify_impl(proof, params, cr, n_chunks, index, chunk_digest,
                            merkle_root, metadata, R, R_len, 0);
}

int
voleith_rs_chunk_cert_prove_secret_dir(
    voleith_proof_t *proof_out, const voleith_params_t *params,
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *merkle_root,
    const uint8_t *siblings, const voleith_rs_metadata_t *metadata)
{
    return cert_prove_impl(proof_out, params, cr, n_chunks, index, fwk,
                           chunk_digest, merkle_root, siblings, metadata, 1);
}

int
voleith_rs_chunk_cert_verify_secret_dir(
    const voleith_proof_t *proof, const voleith_params_t *params,
    voleith_rs_cr_profile_t cr, size_t n_chunks, const uint8_t *chunk_digest,
    const uint8_t *merkle_root, const voleith_rs_metadata_t *metadata,
    const uint8_t *R, size_t R_len)
{
    /* index is hidden; 0 is a placeholder (not bound into the seed). */
    return cert_verify_impl(proof, params, cr, n_chunks, 0, chunk_digest,
                            merkle_root, metadata, R, R_len, 1);
}
