/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_dataset.h - Dataset metadata and the metadata-to-R binding for the RS
 * chunk membership use case (design section 6.7 / 6.10).
 *
 * A Reed-Solomon dataset is identified on the wire by a root R that commits
 * to BOTH the FWK-blinded Merkle tree of its chunks and a small per-dataset
 * metadata structure (chunk_size, file_len, (n, k), CR profile, optional
 * attribute restriction, optional whole-file digest).  Binding the metadata
 * to R is what stops a party reinterpreting a dataset under different
 * parameters in transit:
 *
 *     metadata_digest = H(canonical_serialize(metadata))
 *     R               = H(merkle_root || metadata_digest)
 *
 * H is the per-profile plaintext hash: SHAKE-128 squeezed to 32 bytes for
 * the 128-bit CR profile, SHAKE-256 to 64 bytes for the 256-bit profile.
 * It is a different primitive from the in-circuit node hashes (grostl-based),
 * so this top-level commitment can never collide with an internal tree node.
 * R costs nothing in the tree (still 256 leaves, depth 8) and nothing in the
 * circuit: the metadata binding is a single plaintext hash the verifier
 * computes OUTSIDE the proof.
 *
 * This is a plaintext data layer over public dataset parameters; it is not on
 * the constant-time proving path.  The descriptor and per-chunk header that
 * carry these fields on the wire are assembled in the certificate work
 * (plan T6.5 / T6.6); this translation unit owns only the metadata structure,
 * its canonical serializer / parser, and the R helpers.
 *
 * See docs/ERASURE_CODES_DESIGN.md sections 6.7 and 6.10.
 */

#ifndef VOLEITH_ERASURE_RS_DATASET_H
#define VOLEITH_ERASURE_RS_DATASET_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"

/* ========================================================================
 * Format versions
 * ======================================================================== */

/* Canonical metadata format version (design section 6.10, offset 0). */
#define VOLEITH_RS_METADATA_VERSION 0x01

/*
 * Per-chunk header version and flags (design section 6.10).  The header
 * itself is assembled in the certificate work (plan T6.5 / T6.6); the
 * version and the reserved possession-tag flag are defined here so the
 * forward-compatible plumbing exists from v1.9.0 on.  Enabling possession
 * later is a populate step, not a format change.
 */
#define VOLEITH_RS_HEADER_VERSION 0x01
#define VOLEITH_RS_HEADER_FLAG_POSSESSION_TAG 0x01 /* RESERVED, 0 in v1.9.0. */

/* ========================================================================
 * Collision-resistance profile
 *
 * Selects the per-profile hash, digest width, and (downstream) the in-circuit
 * node hash a dataset's tree uses.  Carried explicitly in the metadata even
 * though it is redundant with len(R): the in-circuit verification needs the
 * enum to select the node hash, and metadata_digest is computed before a party
 * necessarily holds R.
 * ======================================================================== */

typedef enum {
    VOLEITH_RS_CR_128 = 0x01, /* SHAKE-128, 32-byte digests, grostl256_fixed. */
    VOLEITH_RS_CR_256 = 0x02  /* SHAKE-256, 64-byte digests, grostl512_fixed. */
} voleith_rs_cr_profile_t;

/* Returns the per-profile digest width in bytes (32 or 64), or 0 for an
 * unknown profile.  This is also len(R) and len(merkle_root). */
static inline size_t
voleith_rs_cr_digest_bytes(voleith_rs_cr_profile_t cr)
{
    switch (cr) {
    case VOLEITH_RS_CR_128:
        return 32;
    case VOLEITH_RS_CR_256:
        return 64;
    default:
        return 0;
    }
}

/* ========================================================================
 * Metadata flag bits (design section 6.10, offset 18)
 *
 * All three are defined now, including the reserved por_params bit, so a
 * future possession-enabled dataset is produced and read by the same code
 * path (a populate step, not a format change).
 * ======================================================================== */

#define VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST 0x01
#define VOLEITH_RS_META_FLAG_ATTR_RESTRICTION 0x02
#define VOLEITH_RS_META_FLAG_POR_PARAMS 0x04 /* RESERVED, 0 in v1.9.0. */

/* ========================================================================
 * Dataset metadata
 *
 * The fixed 19-byte head plus up to three optional, flag-gated tail fields.
 * The optional tail buffers are referenced, not owned: for a constructed
 * descriptor the caller manages their lifetime; for a parsed descriptor they
 * point into the caller's serialized buffer (zero-copy), which must outlive
 * the structure.  A tail pointer is non-NULL iff its field is present.
 * ======================================================================== */

typedef struct {
    voleith_rs_cr_profile_t cr_profile;
    uint32_t chunk_size; /* Fixed length of every chunk (section 2.3). */
    uint64_t file_len;   /* Original file length, for final-chunk depad. */
    uint16_t n;          /* Total chunks (data + parity). */
    uint16_t k;          /* Data chunks (the recoverable-dataset threshold). */

    /*
     * Optional whole-file digest (flag bit0): a hash over the full encoded
     * message for a one-shot end-to-end retriever check.  NULL if absent;
     * when present it is exactly voleith_rs_cr_digest_bytes(cr_profile) bytes.
     */
    const uint8_t *whole_file_digest; /* Not owned. */

    /*
     * Optional node-attribute restriction (flag bit1): an opaque predicate,
     * or a commitment to it when the allowed-value set is secret (section
     * 6.5).  NULL if absent.
     */
    const uint8_t *attr_restriction; /* Not owned. */
    uint16_t attr_restriction_len;

    /*
     * Reserved PoR public verification parameters (flag bit2): always NULL /
     * absent in v1.9.0.  Defined so a future possession-enabled dataset binds
     * its parameters to R through the same serializer.
     */
    const uint8_t *por_params; /* Not owned; NULL in v1.9.0. */
    uint16_t por_params_len;
} voleith_rs_metadata_t;

/* ========================================================================
 * Flags and serialized length
 * ======================================================================== */

/*
 * Computes the metadata flags byte from which optional fields are present.
 * Returns a negative VOLEITH_EC_ERR_* on an inconsistent structure (a
 * non-NULL tail pointer with a zero length, or vice versa), 0 on success
 * with the flags byte written through flags_out.
 */
int voleith_rs_metadata_flags(const voleith_rs_metadata_t *meta,
                              uint8_t *flags_out);

/*
 * Computes the canonical serialized length in bytes (the fixed 19-byte head
 * plus the present optional tail fields).  Returns 0 on success with the
 * length written through len_out, or a negative VOLEITH_EC_ERR_* on bad
 * arguments (unknown cr_profile, inconsistent tail pointers).
 */
int voleith_rs_metadata_serialized_len(const voleith_rs_metadata_t *meta,
                                       size_t *len_out);

/* ========================================================================
 * Canonical serialize / parse (design section 6.10)
 * ======================================================================== */

/*
 * Serializes meta into out (capacity out_cap) in the canonical byte layout:
 * fixed field order, big-endian integers, explicit flags and lengths for the
 * optional tail fields, no padding.  Writes the byte count through out_len.
 * Returns 0 on success, VOLEITH_EC_ERR_NOMEM if out_cap is too small, or
 * another negative VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rs_metadata_serialize(const voleith_rs_metadata_t *meta,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/*
 * Parses a canonical metadata byte string from buf (length len) into meta_out.
 * The optional tail fields of meta_out point into buf (zero-copy); buf must
 * outlive meta_out.  A reserved-flag (por_params) tail is parsed and skipped
 * by the same code path so a future possession-enabled dataset is read here
 * without a format change.  Writes the number of bytes consumed through
 * consumed_out (so a trailing descriptor remainder can be located).  Returns
 * 0 on success, VOLEITH_EC_ERR_PARAM on a truncated or malformed string
 * (bad version, unknown cr_profile, length running past the buffer).
 */
int voleith_rs_metadata_parse(const uint8_t *buf, size_t len,
                              voleith_rs_metadata_t *meta_out,
                              size_t *consumed_out);

/* ========================================================================
 * Metadata digest and the root R
 * ======================================================================== */

/*
 * Computes metadata_digest = H(canonical_serialize(metadata)) into out, where
 * H is the per-profile hash and out is voleith_rs_cr_digest_bytes(cr_profile)
 * bytes.  Returns 0 on success, a negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_rs_metadata_digest(const voleith_rs_metadata_t *meta, uint8_t *out,
                               size_t out_cap);

/*
 * Computes R = H(merkle_root || H(canonical_serialize(metadata))) into R_out.
 * merkle_root and R_out are both voleith_rs_cr_digest_bytes(cr_profile) bytes;
 * root_len and R_cap are asserted against that width.  Returns 0 on success,
 * a negative VOLEITH_EC_ERR_* on a width mismatch or other failure.
 */
int voleith_rs_compute_R(const uint8_t *merkle_root, size_t root_len,
                         const voleith_rs_metadata_t *meta, uint8_t *R_out,
                         size_t R_cap);

/*
 * Recomputes R from (merkle_root, meta) and compares it in constant time
 * against the authoritative R the caller trusts.  Also performs the cheap
 * malformed-input check that len(R) agrees with cr_profile (32 iff CR-128,
 * 64 iff CR-256).  Returns 0 if R matches, VOLEITH_EC_ERR_PARAM on a width
 * disagreement or bad argument, or VOLEITH_EC_ERR_VERIFY if the recomputed
 * R does not match the supplied R.
 */
int voleith_rs_verify_R(const uint8_t *R, size_t R_len,
                        const uint8_t *merkle_root, size_t root_len,
                        const voleith_rs_metadata_t *meta);

#endif /* VOLEITH_ERASURE_RS_DATASET_H */
