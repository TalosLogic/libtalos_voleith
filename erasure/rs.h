/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs.h - Reed-Solomon erasure coding over GF(2^8) (storage durability).
 *
 * A systematic (n, k) Reed-Solomon code: k data chunks pass through
 * unchanged and n - k parity chunks are computed, so any k of the n chunks
 * reconstruct the original k data chunks (MDS).  Symbols are GF(2^8) bytes;
 * a chunk is chunk_bytes symbols, coded symbol-wise (column c of every
 * chunk is an independent length-k codeword).
 *
 * Plaintext, public-data layer (not constant-time).  See
 * docs/ERASURE_CODES_DESIGN.md.
 */

#ifndef VOLEITH_ERASURE_RS_H
#define VOLEITH_ERASURE_RS_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "matrix.h"

typedef struct {
    voleith_ec_matrix_t g; /* Generator, n x k over GF(2^8) (owned). */
    size_t n;              /* Total chunks. */
    size_t k;              /* Data chunks. */
} voleith_rs_t;

/*
 * Initializes a systematic (n, k) RS code with the given generator-matrix
 * construction (CAUCHY recommended: systematic and MDS).  Requires
 * 0 < k <= n and n within the GF(2^8) point budget.  Returns 0 on success,
 * a negative VOLEITH_EC_ERR_* on failure.  On success the caller must
 * voleith_rs_free() it.
 */
int voleith_rs_init(voleith_rs_t *rs, size_t n, size_t k,
                    voleith_ec_matrix_kind_t kind);

/* Releases the generator matrix.  Safe on a zeroed descriptor. */
void voleith_rs_free(voleith_rs_t *rs);

/*
 * Encodes k data chunks into n coded chunks.
 *
 *   message:    k * chunk_bytes bytes, data chunk i at message + i*chunk_bytes.
 *   codeword:   n * chunk_bytes bytes, coded chunk i at codeword + i*chunk_bytes.
 *   chunk_bytes: symbols per chunk (> 0).
 *
 * No dynamic allocation (uses the prebuilt generator).  Returns 0 on
 * success, a negative VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rs_encode(const voleith_rs_t *rs, const uint8_t *message,
                      size_t chunk_bytes, uint8_t *codeword);

/*
 * Reconstructs the k data chunks from any k (or more) received chunks.
 *
 *   chunk_idx:   n_have coded-chunk indices, each in [0, n).
 *   chunks:      n_have * chunk_bytes bytes, received chunk j at
 *                chunks + j*chunk_bytes (same order as chunk_idx).
 *   n_have:      number of received chunks (must be >= k; the first k are
 *                used, which suffices because the code is MDS).
 *   message:     output, k * chunk_bytes bytes (the recovered data chunks).
 *
 * Allocates the k-by-k submatrix and its inverse internally.  Returns 0 on
 * success, VOLEITH_EC_ERR_INCOMPLETE if n_have < k, VOLEITH_EC_ERR_SINGULAR
 * if the chosen rows are dependent, or another negative VOLEITH_EC_ERR_*.
 */
int voleith_rs_decode(const voleith_rs_t *rs, const size_t *chunk_idx,
                      const uint8_t *chunks, size_t n_have, size_t chunk_bytes,
                      uint8_t *message);

/*
 * Repairs a single missing/target chunk from k received chunks: recovers
 * the message, then re-encodes coded row missing_idx.
 *
 *   missing_idx: index in [0, n) of the chunk to reproduce.
 *   repaired:    output, chunk_bytes bytes.
 *
 * Other arguments match voleith_rs_decode.  Returns 0 on success or a
 * negative VOLEITH_EC_ERR_*.
 */
int voleith_rs_repair(const voleith_rs_t *rs, const size_t *chunk_idx,
                      const uint8_t *chunks, size_t n_have, size_t chunk_bytes,
                      size_t missing_idx, uint8_t *repaired);

/*
 * Encodes a single coded chunk `row` directly from an already-recovered
 * message: out[c] = sum_j G[row][j] * message_chunk_j[c].
 *
 *   message:     k * chunk_bytes bytes (the data chunks).
 *   row:         coded-chunk index in [0, n).
 *   out:         output, chunk_bytes bytes.
 *
 * This is the healer primitive (design section 6.2): decode the message
 * once (voleith_rs_decode), then re-encode each missing target with this,
 * rather than the decode-plus-single-row of voleith_rs_repair per chunk.
 * Returns 0 on success, a negative VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rs_encode_row(const voleith_rs_t *rs, const uint8_t *message,
                          size_t chunk_bytes, size_t row, uint8_t *out);

/*
 * Encodes an arbitrary set of coded chunks from an already-recovered
 * message: a decode-once / encode-many helper for a healer regenerating
 * several missing chunks of one dataset.
 *
 *   message:     k * chunk_bytes bytes (the data chunks).
 *   indices:     count coded-chunk indices, each in [0, n).
 *   count:       number of target chunks to produce.
 *   out:         count * chunk_bytes bytes, target j (for indices[j]) at
 *                out + j*chunk_bytes (same order as indices).
 *
 * No dynamic allocation.  Returns 0 on success, a negative VOLEITH_EC_ERR_*
 * on bad arguments (including any index >= n).
 */
int voleith_rs_encode_indices(const voleith_rs_t *rs, const uint8_t *message,
                              size_t chunk_bytes, const size_t *indices,
                              size_t count, uint8_t *out);

#endif /* VOLEITH_ERASURE_RS_H */
