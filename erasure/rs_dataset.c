/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_dataset.c - Dataset metadata and the metadata-to-R binding (design
 * section 6.7 / 6.10).
 *
 * The canonical metadata byte string has a fixed 19-byte head (version,
 * cr_profile, chunk_size, file_len, n, k, flags) followed by up to three
 * flag-gated, length-determined optional tail fields.  R commits to the tree
 * and the metadata together:
 *
 *     metadata_digest = H(canonical_serialize(metadata))
 *     R               = H(merkle_root || metadata_digest)
 *
 * H is the per-profile SHAKE (128 -> 32 bytes, 256 -> 64 bytes).  Public-data
 * layer, not constant-time; the one constant-time touch is comparing a
 * supplied R against the recomputed one in verify_R.
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_dataset.h"

#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "util.h"

/* ========================================================================
 * Big-endian fixed-width integer codecs (the canonical layout is BE)
 * ======================================================================== */

static void
put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void
put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void
put_u64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static uint16_t
get_u16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t
get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t
get_u64_be(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/* ========================================================================
 * Per-profile hash H
 * ======================================================================== */

/*
 * H over (data, len): SHAKE-128 squeezed to 32 bytes for the 128-bit CR
 * profile, SHAKE-256 to 64 bytes for the 256-bit profile.  out_cap must hold
 * the digest width.  A different primitive from the in-circuit node hashes,
 * so this commitment can never collide with an internal tree node.
 */
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
 * Flags and serialized length
 * ======================================================================== */

int
voleith_rs_metadata_flags(const voleith_rs_metadata_t *meta, uint8_t *flags_out)
{
    uint8_t flags = 0;

    if (meta == NULL || flags_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    if (meta->whole_file_digest != NULL)
        flags |= VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST;

    if (meta->attr_restriction != NULL) {
        if (meta->attr_restriction_len == 0)
            return VOLEITH_EC_ERR_PARAM;
        flags |= VOLEITH_RS_META_FLAG_ATTR_RESTRICTION;
    } else if (meta->attr_restriction_len != 0) {
        return VOLEITH_EC_ERR_PARAM;
    }

    if (meta->por_params != NULL) {
        if (meta->por_params_len == 0)
            return VOLEITH_EC_ERR_PARAM;
        flags |= VOLEITH_RS_META_FLAG_POR_PARAMS;
    } else if (meta->por_params_len != 0) {
        return VOLEITH_EC_ERR_PARAM;
    }

    *flags_out = flags;
    return VOLEITH_EC_OK;
}

int
voleith_rs_metadata_serialized_len(const voleith_rs_metadata_t *meta,
                                   size_t *len_out)
{
    size_t dbytes, total;
    uint8_t flags;
    int rc;

    if (meta == NULL || len_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;

    /* Design invariant: 0 < k <= n. */
    if (meta->k == 0 || meta->k > meta->n)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_metadata_flags(meta, &flags);
    if (rc != VOLEITH_EC_OK)
        return rc;

    total = 19;
    if (flags & VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST)
        total += dbytes;
    if (flags & VOLEITH_RS_META_FLAG_ATTR_RESTRICTION)
        total += 2u + meta->attr_restriction_len;
    if (flags & VOLEITH_RS_META_FLAG_POR_PARAMS)
        total += 2u + meta->por_params_len;

    *len_out = total;
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Canonical serialize / parse
 * ======================================================================== */

int
voleith_rs_metadata_serialize(const voleith_rs_metadata_t *meta, uint8_t *out,
                              size_t out_cap, size_t *out_len)
{
    size_t dbytes, need, off;
    uint8_t flags;
    int rc;

    if (meta == NULL || out == NULL || out_len == NULL)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_metadata_serialized_len(meta, &need);
    if (rc != VOLEITH_EC_OK)
        return rc;
    if (out_cap < need)
        return VOLEITH_EC_ERR_NOMEM;

    rc = voleith_rs_metadata_flags(meta, &flags);
    if (rc != VOLEITH_EC_OK)
        return rc;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);

    off = 0;
    out[off++] = VOLEITH_RS_METADATA_VERSION;
    out[off++] = (uint8_t)meta->cr_profile;
    put_u32_be(out + off, meta->chunk_size);
    off += 4;
    put_u64_be(out + off, meta->file_len);
    off += 8;
    put_u16_be(out + off, meta->n);
    off += 2;
    put_u16_be(out + off, meta->k);
    off += 2;
    out[off++] = flags;

    if (flags & VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST) {
        memcpy(out + off, meta->whole_file_digest, dbytes);
        off += dbytes;
    }
    if (flags & VOLEITH_RS_META_FLAG_ATTR_RESTRICTION) {
        put_u16_be(out + off, meta->attr_restriction_len);
        off += 2;
        memcpy(out + off, meta->attr_restriction, meta->attr_restriction_len);
        off += meta->attr_restriction_len;
    }
    if (flags & VOLEITH_RS_META_FLAG_POR_PARAMS) {
        put_u16_be(out + off, meta->por_params_len);
        off += 2;
        memcpy(out + off, meta->por_params, meta->por_params_len);
        off += meta->por_params_len;
    }

    *out_len = off;
    return VOLEITH_EC_OK;
}

int
voleith_rs_metadata_parse(const uint8_t *buf, size_t len,
                          voleith_rs_metadata_t *meta_out, size_t *consumed_out)
{
    size_t off, dbytes;
    uint16_t l;
    uint8_t flags;

    if (buf == NULL || meta_out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (len < 19)
        return VOLEITH_EC_ERR_PARAM;

    memset(meta_out, 0, sizeof(*meta_out));

    if (buf[0] != VOLEITH_RS_METADATA_VERSION)
        return VOLEITH_EC_ERR_PARAM;

    meta_out->cr_profile = (voleith_rs_cr_profile_t)buf[1];
    dbytes = voleith_rs_cr_digest_bytes(meta_out->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_PARAM;

    meta_out->chunk_size = get_u32_be(buf + 2);
    meta_out->file_len = get_u64_be(buf + 6);
    meta_out->n = get_u16_be(buf + 14);
    meta_out->k = get_u16_be(buf + 16);
    flags = buf[18];
    off = 19;

    /* Reject undefined flag bits: an unknown bit is a malformed string, not a
     * field to skip silently.  The reserved por_params bit IS defined, so a
     * future possession-enabled dataset parses through the same path. */
    if (flags & ~(uint8_t)(VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST |
                           VOLEITH_RS_META_FLAG_ATTR_RESTRICTION |
                           VOLEITH_RS_META_FLAG_POR_PARAMS))
        return VOLEITH_EC_ERR_PARAM;

    if (flags & VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST) {
        if (len - off < dbytes)
            return VOLEITH_EC_ERR_PARAM;
        meta_out->whole_file_digest = buf + off;
        off += dbytes;
    }
    if (flags & VOLEITH_RS_META_FLAG_ATTR_RESTRICTION) {
        if (len - off < 2)
            return VOLEITH_EC_ERR_PARAM;
        l = get_u16_be(buf + off);
        off += 2;
        if (l == 0 || len - off < l)
            return VOLEITH_EC_ERR_PARAM;
        meta_out->attr_restriction = buf + off;
        meta_out->attr_restriction_len = l;
        off += l;
    }
    if (flags & VOLEITH_RS_META_FLAG_POR_PARAMS) {
        if (len - off < 2)
            return VOLEITH_EC_ERR_PARAM;
        l = get_u16_be(buf + off);
        off += 2;
        if (l == 0 || len - off < l)
            return VOLEITH_EC_ERR_PARAM;
        meta_out->por_params = buf + off;
        meta_out->por_params_len = l;
        off += l;
    }

    if (consumed_out != NULL)
        *consumed_out = off;
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Metadata digest and the root R
 * ======================================================================== */

int
voleith_rs_metadata_digest(const voleith_rs_metadata_t *meta, uint8_t *out,
                           size_t out_cap)
{
    uint8_t *buf;
    size_t need, wrote;
    int rc;

    if (meta == NULL || out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_metadata_serialized_len(meta, &need);
    if (rc != VOLEITH_EC_OK)
        return rc;

    buf = calloc(need, 1);
    if (buf == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    rc = voleith_rs_metadata_serialize(meta, buf, need, &wrote);
    if (rc != VOLEITH_EC_OK) {
        free(buf);
        return rc;
    }

    rc = profile_hash(meta->cr_profile, buf, wrote, out, out_cap);
    free(buf);
    return rc;
}

int
voleith_rs_compute_R(const uint8_t *merkle_root, size_t root_len,
                     const voleith_rs_metadata_t *meta, uint8_t *R_out,
                     size_t R_cap)
{
    uint8_t mdigest[64];
    uint8_t *concat;
    size_t dbytes;
    int rc;

    if (merkle_root == NULL || meta == NULL || R_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (root_len != dbytes)
        return VOLEITH_EC_ERR_PARAM;
    if (R_cap < dbytes)
        return VOLEITH_EC_ERR_NOMEM;

    rc = voleith_rs_metadata_digest(meta, mdigest, sizeof(mdigest));
    if (rc != VOLEITH_EC_OK)
        return rc;

    /* R = H(merkle_root || metadata_digest), both dbytes long. */
    concat = calloc(2, dbytes);
    if (concat == NULL)
        return VOLEITH_EC_ERR_NOMEM;
    memcpy(concat, merkle_root, dbytes);
    memcpy(concat + dbytes, mdigest, dbytes);

    rc = profile_hash(meta->cr_profile, concat, 2 * dbytes, R_out, R_cap);
    free(concat);
    return rc;
}

int
voleith_rs_verify_R(const uint8_t *R, size_t R_len, const uint8_t *merkle_root,
                    size_t root_len, const voleith_rs_metadata_t *meta)
{
    uint8_t computed[64];
    size_t dbytes;
    int rc;

    if (R == NULL || merkle_root == NULL || meta == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;

    /* len(R) must agree with cr_profile (cheap malformed-input check). */
    if (R_len != dbytes)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_compute_R(merkle_root, root_len, meta, computed,
                              sizeof(computed));
    if (rc != VOLEITH_EC_OK)
        return rc;

    if (voleith_const_memcmp(R, computed, dbytes) != 0)
        return VOLEITH_EC_ERR_VERIFY;

    return VOLEITH_EC_OK;
}
