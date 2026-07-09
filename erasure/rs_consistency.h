/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_consistency.h - capability-3 plaintext encoding-correctness check
 *
 * After a retriever decodes k verified chunks to the message M, this module
 * verifies that M re-encodes to the codeword the owner committed under R:
 * re-encode M to C (all n chunks), compare chunk_digest(C[i]) to the
 * committed per-chunk digests, and optionally verify a whole-file digest
 * committed in the dataset metadata.
 *
 * This is the "capability 3" check from the storage design (section 6.9):
 * encoding-correctness in plaintext.  It catches a buggy or malicious owner
 * who committed an inconsistent codeword under an otherwise valid R.  No
 * circuit is used; everything is public plaintext.
 *
 * See docs/ERASURE_CODES_DESIGN.md section 6.9.
 */

#ifndef VOLEITH_ERASURE_RS_CONSISTENCY_H
#define VOLEITH_ERASURE_RS_CONSISTENCY_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "rs.h"
#include "rs_dataset.h"

/*
 * Capability-3 plaintext consistency check.
 *
 * Given the decoded message M (k * chunk_bytes bytes), re-encodes all n
 * chunks with the public generator and compares each re-encoded chunk digest
 * to the corresponding committed digest.  If meta is non-NULL and
 * meta->whole_file_digest is non-NULL, also verifies the whole-file digest
 * against H(message[0:meta->file_len]).
 *
 * Arguments:
 *   rs                 Initialized RS code with the public generator (n x k).
 *   cr                 CR profile (selects SHAKE variant and digest width).
 *   message            k * chunk_bytes decoded data chunks.
 *   chunk_bytes        Bytes per chunk (must be > 0).
 *   committed_digests  n * voleith_rs_cr_digest_bytes(cr) bytes: the
 *                      per-chunk digests that were used to build the Merkle
 *                      tree committed under R.
 *   meta               Dataset metadata; if non-NULL and
 *                      meta->whole_file_digest is non-NULL, the function also
 *                      hashes message[0:meta->file_len] and compares.  Pass
 *                      NULL to skip the whole-file check.
 *
 * Returns:
 *   VOLEITH_EC_OK        All checks pass (codeword is consistent).
 *   VOLEITH_EC_ERR_PARAM NULL required argument or zero chunk_bytes.
 *   VOLEITH_EC_ERR_FIELD Unknown cr profile.
 *   VOLEITH_EC_ERR_NOMEM Allocation failed.
 *   VOLEITH_EC_ERR_VERIFY Chunk or whole-file digest mismatch.
 */
int voleith_rs_check_consistency(const voleith_rs_t *rs,
                                 voleith_rs_cr_profile_t cr,
                                 const uint8_t *message, size_t chunk_bytes,
                                 const uint8_t *committed_digests,
                                 const voleith_rs_metadata_t *meta);

/*
 * Compute the whole-file digest: H(message[0:file_len]).
 *
 * The owner calls this before RS-encoding to produce the value stored in
 * voleith_rs_metadata_t::whole_file_digest; the retriever verifies it after
 * decoding via voleith_rs_check_consistency.
 *
 * message    At least file_len bytes of decoded message data; only the first
 *            file_len bytes are hashed so any padding beyond file_len is
 *            irrelevant.
 * file_len   Byte count to hash.  Zero is valid and produces a digest of
 *            the empty string.
 * out_cap    Must be >= voleith_rs_cr_digest_bytes(cr).
 *
 * Returns VOLEITH_EC_OK, VOLEITH_EC_ERR_PARAM, VOLEITH_EC_ERR_FIELD, or
 * VOLEITH_EC_ERR_NOMEM.
 */
int voleith_rs_whole_file_digest(voleith_rs_cr_profile_t cr,
                                 const uint8_t *message, uint64_t file_len,
                                 uint8_t *out, size_t out_cap);

#endif /* VOLEITH_ERASURE_RS_CONSISTENCY_H */
