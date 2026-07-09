/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs.c - Reed-Solomon erasure coding over GF(2^8).
 *
 * Encode is C = G . M applied symbol-wise: codeword chunk i, symbol c is
 * sum_j G[i][j] * message_chunk_j[c].  With a systematic generator the
 * first k rows are the identity, so data chunks pass through and only the
 * parity rows do field work.  Public-data layer, not constant-time.
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs.h"

#include <stdlib.h>

int
voleith_rs_init(voleith_rs_t *rs, size_t n, size_t k,
                voleith_ec_matrix_kind_t kind)
{
    int rc;

    if (rs == NULL)
        return VOLEITH_EC_ERR_PARAM;

    rs->g.e = NULL;
    rs->g.rows = 0;
    rs->g.cols = 0;
    rs->n = 0;
    rs->k = 0;

    rc = voleith_ec_matrix_generator(&rs->g, VOLEITH_EC_FIELD_GF8, kind, n, k);
    if (rc != VOLEITH_EC_OK)
        return rc;

    rs->n = n;
    rs->k = k;
    return VOLEITH_EC_OK;
}

void
voleith_rs_free(voleith_rs_t *rs)
{
    if (rs == NULL)
        return;
    voleith_ec_matrix_free(&rs->g);
    rs->n = 0;
    rs->k = 0;
}

/*
 * Computes coded row `row` of the generator applied to a message:
 * out[c] = sum_j G[row][j] * message_chunk_j[c].
 */
static void
encode_row(const voleith_rs_t *rs, size_t row, const uint8_t *message,
           size_t chunk_bytes, uint8_t *out)
{
    size_t j, c;

    for (c = 0; c < chunk_bytes; c++) {
        uint16_t acc = 0;
        for (j = 0; j < rs->k; j++) {
            uint16_t coeff = voleith_ec_matrix_get(&rs->g, row, j);
            uint16_t sym = message[j * chunk_bytes + c];
            acc = voleith_ec_field_add(
                acc, voleith_ec_field_mul(VOLEITH_EC_FIELD_GF8, coeff, sym));
        }
        out[c] = (uint8_t)acc;
    }
}

int
voleith_rs_encode(const voleith_rs_t *rs, const uint8_t *message,
                  size_t chunk_bytes, uint8_t *codeword)
{
    size_t i;

    if (rs == NULL || message == NULL || codeword == NULL || chunk_bytes == 0)
        return VOLEITH_EC_ERR_PARAM;
    if (rs->g.e == NULL)
        return VOLEITH_EC_ERR_PARAM;

    for (i = 0; i < rs->n; i++)
        encode_row(rs, i, message, chunk_bytes, codeword + i * chunk_bytes);
    return VOLEITH_EC_OK;
}

int
voleith_rs_decode(const voleith_rs_t *rs, const size_t *chunk_idx,
                  const uint8_t *chunks, size_t n_have, size_t chunk_bytes,
                  uint8_t *message)
{
    voleith_ec_matrix_t sub = {0}, inv = {0};
    size_t i, j, c;
    int rc;

    if (rs == NULL || chunk_idx == NULL || chunks == NULL || message == NULL ||
        chunk_bytes == 0 || rs->g.e == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (n_have < rs->k)
        return VOLEITH_EC_ERR_INCOMPLETE;

    /* Submatrix of the first k received rows, then its inverse.  Any k rows
     * of an MDS code are independent, so the first k suffice. */
    rc = voleith_ec_matrix_select_rows(&rs->g, chunk_idx, rs->k, &sub);
    if (rc != VOLEITH_EC_OK)
        return rc;
    rc = voleith_ec_matrix_invert(&sub, &inv);
    voleith_ec_matrix_free(&sub);
    if (rc != VOLEITH_EC_OK)
        return rc;

    /* message = inv . received, applied symbol-wise over chunk_bytes. */
    for (i = 0; i < rs->k; i++) {
        uint8_t *out = message + i * chunk_bytes;
        for (c = 0; c < chunk_bytes; c++) {
            uint16_t acc = 0;
            for (j = 0; j < rs->k; j++) {
                uint16_t coeff = voleith_ec_matrix_get(&inv, i, j);
                uint16_t sym = chunks[j * chunk_bytes + c];
                acc = voleith_ec_field_add(
                    acc,
                    voleith_ec_field_mul(VOLEITH_EC_FIELD_GF8, coeff, sym));
            }
            out[c] = (uint8_t)acc;
        }
    }

    voleith_ec_matrix_free(&inv);
    return VOLEITH_EC_OK;
}

int
voleith_rs_repair(const voleith_rs_t *rs, const size_t *chunk_idx,
                  const uint8_t *chunks, size_t n_have, size_t chunk_bytes,
                  size_t missing_idx, uint8_t *repaired)
{
    uint8_t *message;
    int rc;

    if (rs == NULL || repaired == NULL || chunk_bytes == 0)
        return VOLEITH_EC_ERR_PARAM;
    if (missing_idx >= rs->n)
        return VOLEITH_EC_ERR_PARAM;

    message = calloc(rs->k, chunk_bytes);
    if (message == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    rc = voleith_rs_decode(rs, chunk_idx, chunks, n_have, chunk_bytes, message);
    if (rc != VOLEITH_EC_OK) {
        free(message);
        return rc;
    }

    encode_row(rs, missing_idx, message, chunk_bytes, repaired);
    free(message);
    return VOLEITH_EC_OK;
}

int
voleith_rs_encode_row(const voleith_rs_t *rs, const uint8_t *message,
                      size_t chunk_bytes, size_t row, uint8_t *out)
{
    if (rs == NULL || message == NULL || out == NULL || chunk_bytes == 0 ||
        rs->g.e == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (row >= rs->n)
        return VOLEITH_EC_ERR_PARAM;

    encode_row(rs, row, message, chunk_bytes, out);
    return VOLEITH_EC_OK;
}

int
voleith_rs_encode_indices(const voleith_rs_t *rs, const uint8_t *message,
                          size_t chunk_bytes, const size_t *indices,
                          size_t count, uint8_t *out)
{
    size_t j;

    if (rs == NULL || message == NULL || indices == NULL || out == NULL ||
        chunk_bytes == 0 || rs->g.e == NULL)
        return VOLEITH_EC_ERR_PARAM;

    for (j = 0; j < count; j++)
        if (indices[j] >= rs->n)
            return VOLEITH_EC_ERR_PARAM;

    for (j = 0; j < count; j++)
        encode_row(rs, indices[j], message, chunk_bytes, out + j * chunk_bytes);
    return VOLEITH_EC_OK;
}
