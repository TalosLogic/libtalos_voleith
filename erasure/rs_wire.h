/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_wire.h - dataset descriptor and per-chunk header wire serializers for the
 * RS chunk membership use case (design section 6.10, plan T6.10).
 *
 * Design section 7.0 makes the library responsible for THREE serializable
 * types, each with a canonical serialize and a matching deserialize:
 *
 *   1. dataset metadata AND the descriptor that carries it (this file +
 *      rs_dataset.{c,h} for the metadata body);
 *   2. the per-chunk header (this file);
 *   3. the certificate / proof (proof.{c,h}: voleith_proof_t is a flat blob).
 *
 * rs_dataset owns the metadata body and the R helpers; this translation unit
 * owns the two outer envelopes that wrap them on the wire:
 *
 *   descriptor   = merkle_root (32 or 64 B) || canonical_serialize(metadata)
 *   chunk_header = header_version (1 B, 0x01)
 *               || header_flags   (1 B; bit0 = possession_tag present)
 *               || R              (32 or 64 B, width from cr_profile)
 *               || certificate    (4-byte BE length L_c, then L_c cert bytes)
 *               || possession_tag (present iff header_flags.bit0; 2-byte BE
 *                                  length, then the bytes; RESERVED, always
 *                                  absent / flag 0 in v1.9.0)
 *
 * The certificate length prefix (L_c) is a wire choice of this layer: design
 * 6.10 lists `membership_certificate` abstractly, but it is a variable-length
 * blob followed by the optional possession tail, so the header length-prefixes
 * it to stay parseable.  The membership certificate's public instance already
 * carries merkle_root / chunk_digest / (public-dir) index, so those are not
 * restated in the header.
 *
 * Plaintext data layer (sibling to rs_dataset); not on the constant-time
 * proving path.  See docs/ERASURE_CODES_DESIGN.md sections 6.10 / 7.0.
 */

#ifndef VOLEITH_ERASURE_RS_WIRE_H
#define VOLEITH_ERASURE_RS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "proof.h"      /* voleith_proof_t */
#include "rs_dataset.h" /* voleith_rs_metadata_t, voleith_rs_cr_profile_t */

/* ========================================================================
 * Dataset descriptor (design 6.10): merkle_root || serialize(metadata)
 * ======================================================================== */

/*
 * Computes the serialized descriptor length (merkle_root width + metadata
 * serialized length).  Returns 0 on success with the length through len_out,
 * or a negative VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rs_descriptor_serialized_len(const voleith_rs_metadata_t *meta,
                                         size_t *len_out);

/*
 * Serializes descriptor = merkle_root || canonical_serialize(metadata) into
 * out (capacity out_cap).  merkle_root is voleith_rs_cr_digest_bytes(
 * meta->cr_profile) bytes; root_len is asserted against that width.  Writes
 * the byte count through out_len.  Returns 0 on success, VOLEITH_EC_ERR_NOMEM
 * if out_cap is too small, or another negative VOLEITH_EC_ERR_* on bad args.
 */
int voleith_rs_descriptor_serialize(const uint8_t *merkle_root, size_t root_len,
                                    const voleith_rs_metadata_t *meta,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len);

/*
 * Parses a descriptor from buf (length len).  The merkle_root width is not
 * known up front (it depends on cr_profile, which lives inside the trailing
 * metadata), so both candidate widths (32, 64) are tried and the one whose
 * metadata parses AND whose cr_profile width matches the split point is
 * accepted; an ambiguous or inconsistent buffer is rejected.
 *
 * On success merkle_root_out points into buf at the root (zero-copy) and
 * meta_out's optional tails point into buf (zero-copy); buf must outlive both.
 * root_len_out receives the root width.  Returns 0 on success,
 * VOLEITH_EC_ERR_PARAM on a truncated / malformed / ambiguous descriptor.
 */
int voleith_rs_descriptor_parse(const uint8_t *buf, size_t len,
                                const uint8_t **merkle_root_out,
                                size_t *root_len_out,
                                voleith_rs_metadata_t *meta_out);

/*
 * Convenience for the retriever fetch-once / recompute-R flow: parses a
 * descriptor and writes R = H(merkle_root || H(metadata)) into R_out (capacity
 * R_cap; the per-profile digest width).  R_len_out receives that width.  The
 * caller then compares R against the authoritative R it trusts (or uses
 * voleith_rs_verify_R).  Returns 0 on success, a negative VOLEITH_EC_ERR_* on
 * a malformed descriptor or short R_out.
 */
int voleith_rs_descriptor_parse_compute_R(const uint8_t *buf, size_t len,
                                          uint8_t *R_out, size_t R_cap,
                                          size_t *R_len_out);

/* ========================================================================
 * Per-chunk header (design 6.10)
 * ======================================================================== */

/*
 * Computes the serialized chunk-header length for a certificate of cert_len
 * bytes under cr_profile cr, with an optional possession_tag of poss_len bytes
 * (poss_len == 0 / poss == NULL means the flag is 0 and the field absent, the
 * v1.9.0 case).  Returns 0 on success with the length through len_out, or a
 * negative VOLEITH_EC_ERR_* on an unknown profile / bad args.
 */
int voleith_rs_chunk_header_serialized_len(voleith_rs_cr_profile_t cr,
                                           size_t cert_len, size_t poss_len,
                                           size_t *len_out);

/*
 * Serializes a chunk header into out (capacity out_cap):
 *   version || flags || R || cert_len(4 BE) || cert || [poss_len(2 BE) || poss]
 *
 *   cr   - CR profile; selects len(R) and is cross-checked against R_len.
 *   R    - dataset root, voleith_rs_cr_digest_bytes(cr) bytes (R_len asserted).
 *   cert - the membership certificate blob (a gf8 proof's proof->data); cert
 *          and cert_len typically come straight from voleith_proof_t.
 *   poss - reserved possession tag, or NULL in v1.9.0; non-NULL sets
 *          header_flags.bit0 and appends a 2-byte BE length + the bytes.
 *
 * Writes the byte count through out_len.  Returns 0 on success,
 * VOLEITH_EC_ERR_NOMEM if out_cap is too small, or another negative
 * VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rs_chunk_header_serialize(voleith_rs_cr_profile_t cr,
                                      const uint8_t *R, size_t R_len,
                                      const uint8_t *cert, size_t cert_len,
                                      const uint8_t *poss, size_t poss_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len);

/*
 * Parses a chunk header from buf (length len) under a known CR profile cr.
 * cr selects len(R): a party processing a chunk always already holds the
 * dataset descriptor (hence the profile), so cr is an input rather than guessed
 * from raw bytes (a 32- and a 64-byte R are otherwise indistinguishable).
 * On success:
 *   *R_out           - points into buf at R (zero-copy), *R_len_out its width;
 *   *cert_out        - points into buf at the certificate, *cert_len_out long;
 *   *poss_out        - points into buf at the possession tag if the reserved
 *                      flag is set, else NULL; *poss_len_out its length (0 if
 *                      absent).  The reserved tail is DEFINED AND SKIPPED so a
 *                      future possession-enabled chunk parses on this path.
 *   *consumed_out    - header length (so chunk_bytes start at buf + consumed).
 *
 * Any out pointer except buf may be NULL if unwanted.  buf must outlive the
 * returned zero-copy pointers.  Returns 0 on success, VOLEITH_EC_ERR_PARAM on a
 * truncated header, a bad version byte, an undefined flag bit, or a length
 * field running past the buffer.
 */
int voleith_rs_chunk_header_parse(voleith_rs_cr_profile_t cr,
                                  const uint8_t *buf, size_t len,
                                  const uint8_t **R_out, size_t *R_len_out,
                                  const uint8_t **cert_out,
                                  size_t *cert_len_out,
                                  const uint8_t **poss_out,
                                  size_t *poss_len_out, size_t *consumed_out);

#endif /* VOLEITH_ERASURE_RS_WIRE_H */
