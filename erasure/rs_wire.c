/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_wire.c - dataset descriptor and per-chunk header wire serializers
 * (design section 6.10, plan T6.10).
 *
 * The two outer envelopes that wrap the metadata body (rs_dataset.c) and the
 * certificate blob (proof.c) on the wire:
 *
 *   descriptor   = merkle_root || canonical_serialize(metadata)
 *   chunk_header = version || flags || R || cert_len(4 BE) || cert
 *               || [possession_tag: 2-byte BE length || bytes]  (RESERVED)
 *
 * Plaintext data layer; not constant-time.  Clean-room implementation.
 * See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_wire.h"

#include <string.h>

/* ========================================================================
 * Big-endian fixed-width integer codecs (canonical layout is BE)
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

/* ========================================================================
 * Dataset descriptor
 * ======================================================================== */

int
voleith_rs_descriptor_serialized_len(const voleith_rs_metadata_t *meta,
                                     size_t *len_out)
{
    size_t dbytes, meta_len;
    int rc;

    if (meta == NULL || len_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;

    rc = voleith_rs_metadata_serialized_len(meta, &meta_len);
    if (rc != VOLEITH_EC_OK)
        return rc;

    *len_out = dbytes + meta_len;
    return VOLEITH_EC_OK;
}

int
voleith_rs_descriptor_serialize(const uint8_t *merkle_root, size_t root_len,
                                const voleith_rs_metadata_t *meta, uint8_t *out,
                                size_t out_cap, size_t *out_len)
{
    size_t dbytes, need, wrote;
    int rc;

    if (merkle_root == NULL || meta == NULL || out == NULL || out_len == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(meta->cr_profile);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (root_len != dbytes)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_descriptor_serialized_len(meta, &need);
    if (rc != VOLEITH_EC_OK)
        return rc;
    if (out_cap < need)
        return VOLEITH_EC_ERR_NOMEM;

    memcpy(out, merkle_root, dbytes);
    rc = voleith_rs_metadata_serialize(meta, out + dbytes, out_cap - dbytes,
                                       &wrote);
    if (rc != VOLEITH_EC_OK)
        return rc;

    *out_len = dbytes + wrote;
    return VOLEITH_EC_OK;
}

int
voleith_rs_descriptor_parse(const uint8_t *buf, size_t len,
                            const uint8_t **merkle_root_out,
                            size_t *root_len_out,
                            voleith_rs_metadata_t *meta_out)
{
    static const size_t candidate_widths[2] = {32, 64};
    size_t i;
    int found = 0;
    size_t found_width = 0;
    voleith_rs_metadata_t found_meta;

    if (buf == NULL || meta_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    /*
     * The merkle_root width depends on cr_profile, which lives inside the
     * trailing metadata, so we cannot split blindly.  Try each candidate
     * width; accept the one whose metadata parses, consumes exactly the
     * remainder (a descriptor has no bytes past the metadata), and whose
     * cr_profile width agrees with the split point.  Reject ambiguity.
     */
    for (i = 0; i < 2; i++) {
        size_t w = candidate_widths[i];
        voleith_rs_metadata_t meta;
        size_t consumed;

        if (len <= w)
            continue;
        if (voleith_rs_metadata_parse(buf + w, len - w, &meta, &consumed) !=
            VOLEITH_EC_OK)
            continue;
        if (consumed != len - w)
            continue;
        if (voleith_rs_cr_digest_bytes(meta.cr_profile) != w)
            continue;

        if (found)
            return VOLEITH_EC_ERR_PARAM; /* ambiguous. */
        found = 1;
        found_width = w;
        found_meta = meta;
    }

    if (!found)
        return VOLEITH_EC_ERR_PARAM;

    if (merkle_root_out != NULL)
        *merkle_root_out = buf;
    if (root_len_out != NULL)
        *root_len_out = found_width;
    *meta_out = found_meta;
    return VOLEITH_EC_OK;
}

int
voleith_rs_descriptor_parse_compute_R(const uint8_t *buf, size_t len,
                                      uint8_t *R_out, size_t R_cap,
                                      size_t *R_len_out)
{
    const uint8_t *merkle_root;
    size_t root_len;
    voleith_rs_metadata_t meta;
    int rc;

    if (R_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_descriptor_parse(buf, len, &merkle_root, &root_len, &meta);
    if (rc != VOLEITH_EC_OK)
        return rc;

    rc = voleith_rs_compute_R(merkle_root, root_len, &meta, R_out, R_cap);
    if (rc != VOLEITH_EC_OK)
        return rc;

    if (R_len_out != NULL)
        *R_len_out = root_len;
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Per-chunk header
 * ======================================================================== */

int
voleith_rs_chunk_header_serialized_len(voleith_rs_cr_profile_t cr,
                                       size_t cert_len, size_t poss_len,
                                       size_t *len_out)
{
    size_t dbytes, total;

    if (len_out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(cr);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (cert_len > 0xFFFFFFFFu)
        return VOLEITH_EC_ERR_PARAM;
    if (poss_len > 0xFFFFu)
        return VOLEITH_EC_ERR_PARAM;

    /* version(1) + flags(1) + R + cert_len(4) + cert. */
    total = 1u + 1u + dbytes + 4u + cert_len;
    if (poss_len != 0)
        total += 2u + poss_len; /* 2-byte BE length + bytes. */

    *len_out = total;
    return VOLEITH_EC_OK;
}

int
voleith_rs_chunk_header_serialize(voleith_rs_cr_profile_t cr, const uint8_t *R,
                                  size_t R_len, const uint8_t *cert,
                                  size_t cert_len, const uint8_t *poss,
                                  size_t poss_len, uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    size_t dbytes, need, off;
    uint8_t flags;
    int rc;

    if (R == NULL || cert == NULL || out == NULL || out_len == NULL)
        return VOLEITH_EC_ERR_PARAM;
    /* A possession flag without bytes (or vice versa) is inconsistent. */
    if ((poss == NULL) != (poss_len == 0))
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(cr);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (R_len != dbytes)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_chunk_header_serialized_len(cr, cert_len, poss_len, &need);
    if (rc != VOLEITH_EC_OK)
        return rc;
    if (out_cap < need)
        return VOLEITH_EC_ERR_NOMEM;

    flags = (poss_len != 0) ? VOLEITH_RS_HEADER_FLAG_POSSESSION_TAG : 0u;

    off = 0;
    out[off++] = VOLEITH_RS_HEADER_VERSION;
    out[off++] = flags;
    memcpy(out + off, R, dbytes);
    off += dbytes;
    put_u32_be(out + off, (uint32_t)cert_len);
    off += 4;
    memcpy(out + off, cert, cert_len);
    off += cert_len;
    if (poss_len != 0) {
        put_u16_be(out + off, (uint16_t)poss_len);
        off += 2;
        memcpy(out + off, poss, poss_len);
        off += poss_len;
    }

    *out_len = off;
    return VOLEITH_EC_OK;
}

int
voleith_rs_chunk_header_parse(voleith_rs_cr_profile_t cr, const uint8_t *buf,
                              size_t len, const uint8_t **R_out,
                              size_t *R_len_out, const uint8_t **cert_out,
                              size_t *cert_len_out, const uint8_t **poss_out,
                              size_t *poss_len_out, size_t *consumed_out)
{
    size_t p, dbytes, cert_len;
    uint8_t flags;
    const uint8_t *R, *cert;
    const uint8_t *poss = NULL;
    size_t poss_len = 0;

    if (buf == NULL)
        return VOLEITH_EC_ERR_PARAM;

    dbytes = voleith_rs_cr_digest_bytes(cr);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;

    /* version(1) + flags(1) + R + cert_len(4) at minimum. */
    if (len < 2u + dbytes + 4u)
        return VOLEITH_EC_ERR_PARAM;
    if (buf[0] != VOLEITH_RS_HEADER_VERSION)
        return VOLEITH_EC_ERR_PARAM;

    flags = buf[1];
    /* Only the possession-tag bit is defined; any other bit is malformed. */
    if (flags & ~(uint8_t)VOLEITH_RS_HEADER_FLAG_POSSESSION_TAG)
        return VOLEITH_EC_ERR_PARAM;

    p = 2;
    R = buf + p;
    p += dbytes;
    cert_len = get_u32_be(buf + p);
    p += 4;
    if (len - p < cert_len)
        return VOLEITH_EC_ERR_PARAM;
    cert = buf + p;
    p += cert_len;

    if (flags & VOLEITH_RS_HEADER_FLAG_POSSESSION_TAG) {
        size_t l;
        if (len - p < 2)
            return VOLEITH_EC_ERR_PARAM;
        l = get_u16_be(buf + p);
        p += 2;
        if (l == 0 || len - p < l)
            return VOLEITH_EC_ERR_PARAM;
        poss = buf + p;
        poss_len = l;
        p += l;
    }

    if (R_out != NULL)
        *R_out = R;
    if (R_len_out != NULL)
        *R_len_out = dbytes;
    if (cert_out != NULL)
        *cert_out = cert;
    if (cert_len_out != NULL)
        *cert_len_out = cert_len;
    if (poss_out != NULL)
        *poss_out = poss;
    if (poss_len_out != NULL)
        *poss_len_out = poss_len;
    if (consumed_out != NULL)
        *consumed_out = p;
    return VOLEITH_EC_OK;
}
