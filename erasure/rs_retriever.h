/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_retriever.h - retriever-side sufficiency flow for the RS chunk
 * membership use case (design section 6.8, plan T6.6).
 *
 * A client downloading a dataset of root R needs to know when it holds enough
 * distinct chunks to rebuild (any k distinct, MDS) and how many more to
 * request.  This is the client's OWN local check, not a proof to a third
 * party.  The retriever collects offered chunks and, per chunk:
 *
 *   1. verifies the membership certificate against R (the genuineness gate,
 *      which also confirms the bytes hash to the committed chunk_digest);
 *   2. determines the chunk's index - public-index mode reads it from the
 *      caller, secret-index mode recovers it by trial against the tree (an
 *      authorized FWK holder, design step 5);
 *   3. deduplicates by that index, so duplicates never advance the distinct
 *      count, and identical-content chunks at different indices each count
 *      (dedup-by-recovered-index sidesteps the digest-collision undercount).
 *
 * When k distinct verified chunks are held, the retriever RS-decodes them to
 * the original message.  k, n, and chunk_size are read from the metadata
 * (bound to R).
 *
 * The RLNC transport variant (recoded packets, linear-dependence as free
 * no-ops, stop at rank k) is NOT reimplemented here: it reuses the P3 RLNC
 * rank API.  This module is the RS storage path.
 *
 * This is a plaintext integration layer: it composes the plaintext RS codec
 * (erasure/rs.h), the tree helpers (erasure/rs_membership.h), and the
 * certificate verifier (proof/rs_chunk_cert_proof.h).
 *
 * See docs/ERASURE_CODES_DESIGN.md section 6.8.
 */

#ifndef VOLEITH_ERASURE_RS_RETRIEVER_H
#define VOLEITH_ERASURE_RS_RETRIEVER_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "matrix.h" /* voleith_ec_matrix_kind_t */
#include "proof.h"  /* voleith_params_t, voleith_proof_t */
#include "rs_dataset.h"

/* Disposition of a chunk offered to the retriever. */
typedef enum {
    VOLEITH_RS_CHUNK_ACCEPTED = 0,  /* genuine, new distinct index, counted. */
    VOLEITH_RS_CHUNK_DUPLICATE = 1, /* genuine, but this index already held. */
    VOLEITH_RS_CHUNK_REJECTED = 2,  /* failed verification / not a member. */
} voleith_rs_chunk_disposition_t;

/*
 * Retriever state.  Borrowed pointers (params, merkle_root, R, metadata, fwk)
 * must outlive the retriever; the dynamic stores are owned.  Treat the fields
 * as opaque; use the accessors below.
 */
typedef struct {
    voleith_rs_cr_profile_t cr;
    const voleith_params_t *params;
    voleith_ec_matrix_kind_t kind;
    int secret_index;
    size_t n, k, chunk_bytes;
    size_t digb, node_bytes;
    const uint8_t *merkle_root;
    const uint8_t *R;
    size_t R_len;
    const voleith_rs_metadata_t *metadata;
    const uint8_t *fwk;   /* secret-index recovery only; NULL for public. */
    uint8_t *seen;        /* n bytes: seen[index] != 0 once counted. */
    size_t *idx_store;    /* first k distinct indices (decode order). */
    uint8_t *chunk_store; /* first k distinct chunks, k * chunk_bytes. */
    size_t distinct;
} voleith_rs_retriever_t;

/*
 * voleith_rs_recover_index - recover the 1-byte chunk index by trial against
 * the tree root (design step 5, secret-index authorized rebuilder).
 *
 * For each candidate index c in [0, n_chunks), forms the FWK-blinded leaf
 * leaf_hash(fwk, chunk_digest, c) and walks it up with `siblings` and the
 * directions of c; the c whose walk reaches merkle_root is the chunk's index.
 * siblings is the chunk's depth * node_bytes sibling path (NULL iff depth ==
 * 0); index_out receives the recovered index.
 *
 * Returns 0 on success, -1 on a NULL / out-of-range argument or if no
 * candidate reaches merkle_root (not a member with this path).
 */
int voleith_rs_recover_index(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                             const uint8_t *merkle_root, size_t n_chunks,
                             const uint8_t *chunk_digest,
                             const uint8_t *siblings, size_t *index_out);

/*
 * voleith_rs_retriever_init - configure a retriever for a dataset.
 *
 * n, k, and chunk_size are read from metadata (bound to R).  kind is the RS
 * generator construction the dataset was encoded with (CAUCHY for the
 * systematic MDS default).  fwk is required iff secret_index (for index
 * recovery) and must be NULL otherwise-relevant only to an authorized
 * rebuilder.  merkle_root, R, metadata, params, and fwk are borrowed.
 *
 * Returns 0 on success, a negative VOLEITH_EC_ERR_* on a bad argument or
 * allocation failure.  On success, free with voleith_rs_retriever_free.
 */
int voleith_rs_retriever_init(
    voleith_rs_retriever_t *r, voleith_rs_cr_profile_t cr,
    const voleith_params_t *params, voleith_ec_matrix_kind_t kind,
    int secret_index, const uint8_t *merkle_root, const uint8_t *R,
    size_t R_len, const voleith_rs_metadata_t *metadata, const uint8_t *fwk);

/* Releases the retriever's owned storage (zeroing the held chunk bytes).
 * Safe on a zeroed descriptor. */
void voleith_rs_retriever_free(voleith_rs_retriever_t *r);

/*
 * voleith_rs_retriever_offer - offer one downloaded chunk to the retriever.
 *
 *   chunk_bytes  - the chunk payload; chunk_len MUST equal the dataset's
 *                  chunk_size (the bytes the committed digest was taken over).
 *   cert         - the chunk's membership certificate (the matching public /
 *                  secret variant for this retriever's mode).
 *   public_index - the chunk's index; used (and bounds-checked) only in
 *                  public-index mode, ignored in secret-index mode.
 *   siblings     - the chunk's sibling path (depth * node_bytes); used only in
 *                  secret-index mode for index recovery, may be NULL otherwise.
 *
 * Verifies the certificate (genuineness + digest gate), determines the index,
 * and deduplicates.  Writes the disposition through disp_out.  Returns 0 when
 * the chunk was processed (disp_out set to ACCEPTED / DUPLICATE / REJECTED),
 * or a negative VOLEITH_EC_ERR_* on a misuse error (NULL argument, wrong
 * chunk length).
 */
int voleith_rs_retriever_offer(voleith_rs_retriever_t *r,
                               const uint8_t *chunk_bytes, size_t chunk_len,
                               const voleith_proof_t *cert, size_t public_index,
                               const uint8_t *siblings,
                               voleith_rs_chunk_disposition_t *disp_out);

/* Number of distinct verified chunks held so far. */
size_t voleith_rs_retriever_distinct(const voleith_rs_retriever_t *r);

/* Nonzero iff at least k distinct verified chunks are held (rebuild-ready). */
int voleith_rs_retriever_have_enough(const voleith_rs_retriever_t *r);

/* How many more distinct chunks to request (0 once rebuild-ready). */
size_t voleith_rs_retriever_need_more(const voleith_rs_retriever_t *r);

/*
 * voleith_rs_retriever_decode - rebuild the original message from the k held
 * distinct chunks.
 *
 * message_out receives k * chunk_size bytes (message_cap must be at least
 * that).  Returns 0 on success, VOLEITH_EC_ERR_INCOMPLETE if fewer than k
 * distinct chunks are held, or another negative VOLEITH_EC_ERR_*.
 */
int voleith_rs_retriever_decode(const voleith_rs_retriever_t *r,
                                uint8_t *message_out, size_t message_cap);

#endif /* VOLEITH_ERASURE_RS_RETRIEVER_H */
