/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_consistency.c - capability-3 plaintext encoding-correctness check
 *
 * Re-encodes a decoded message M under the public generator G and confirms
 * the resulting codeword matches the per-chunk digests committed under R.
 * An optional whole-file digest check verifies H(M[0:file_len]) against the
 * digest committed in the dataset metadata.
 *
 * Design section 6.9 of docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_consistency.h"

#include <stdlib.h>

#include "hash.h"
#include "rs_membership.h"
#include "util.h"

/* ========================================================================
 * Per-profile hash H (same construction as rs_dataset.c / rs_membership.c)
 * ======================================================================== */

static int
profile_hash(voleith_rs_cr_profile_t cr, const uint8_t *data, size_t len,
             uint8_t *out, size_t out_cap)
{
    voleith_hash_ctx_t ctx;
    size_t dbytes;

    dbytes = voleith_rs_cr_digest_bytes(cr);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (out_cap < dbytes)
        return VOLEITH_EC_ERR_NOMEM;

    if (cr == VOLEITH_RS_CR_128) {
        voleith_shake128_init(&ctx);
        voleith_shake128_absorb(&ctx, data, len);
        voleith_shake128_squeeze(&ctx, out, dbytes);
    } else {
        voleith_shake256_init(&ctx);
        voleith_shake256_absorb(&ctx, data, len);
        voleith_shake256_squeeze(&ctx, out, dbytes);
    }
    voleith_hash_ctx_clear(&ctx);
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int
voleith_rs_whole_file_digest(voleith_rs_cr_profile_t cr, const uint8_t *message,
                             uint64_t file_len, uint8_t *out, size_t out_cap)
{
    if ((message == NULL && file_len != 0) || out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    return profile_hash(cr, message, (size_t)file_len, out, out_cap);
}

int
voleith_rs_check_consistency(const voleith_rs_t *rs, voleith_rs_cr_profile_t cr,
                             const uint8_t *message, size_t chunk_bytes,
                             const uint8_t *committed_digests,
                             const voleith_rs_metadata_t *meta)
{
    uint8_t digest[64]; /* max digest width (64 bytes for CR-256) */
    uint8_t *codeword;
    size_t digb, i;
    int rc;

    if (rs == NULL || message == NULL || committed_digests == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (chunk_bytes == 0 || rs->n == 0 || rs->k == 0)
        return VOLEITH_EC_ERR_PARAM;

    digb = voleith_rs_cr_digest_bytes(cr);
    if (digb == 0)
        return VOLEITH_EC_ERR_FIELD;

    codeword = calloc(rs->n, chunk_bytes);
    if (codeword == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    rc = voleith_rs_encode(rs, message, chunk_bytes, codeword);
    if (rc != VOLEITH_EC_OK)
        goto out;

    /* Compare each re-encoded chunk digest to the committed value. */
    rc = VOLEITH_EC_OK;
    for (i = 0; i < rs->n; i++) {
        int crc = voleith_rs_chunk_digest(cr, codeword + i * chunk_bytes,
                                          chunk_bytes, digest, sizeof(digest));
        if (crc != VOLEITH_EC_OK) {
            rc = crc;
            goto out;
        }
        if (voleith_const_memcmp(digest, committed_digests + i * digb, digb) !=
            0) {
            rc = VOLEITH_EC_ERR_VERIFY;
            goto out;
        }
    }

    /* Optional whole-file digest: H(message[0:file_len]). */
    if (meta != NULL && meta->whole_file_digest != NULL) {
        uint64_t file_len;
        size_t max_file_bytes;

        max_file_bytes = rs->k * chunk_bytes;
        file_len = meta->file_len;
        if ((size_t)file_len > max_file_bytes)
            file_len = (uint64_t)max_file_bytes;

        rc =
            profile_hash(cr, message, (size_t)file_len, digest, sizeof(digest));
        if (rc != VOLEITH_EC_OK)
            goto out;

        if (voleith_const_memcmp(digest, meta->whole_file_digest, digb) != 0) {
            rc = VOLEITH_EC_ERR_VERIFY;
            goto out;
        }
    }

out:
    free(codeword);
    return rc;
}
