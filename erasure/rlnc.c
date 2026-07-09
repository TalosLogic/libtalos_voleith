/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc.c - Random Linear Network Coding over GF(2^16).
 *
 * Encode produces one coded symbol as a GF(2^16) linear combination of the
 * generation's source symbols, element-wise, and packs it with its header
 * (generation id + coefficient vector).  Public-data layer, not
 * constant-time.
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rlnc.h"

#include <stdlib.h>

#include "util.h"

/* Writes a generation id into the packet header (uint32 little-endian). */
static void
write_gen_id(uint8_t *packet, uint32_t gen_id)
{
    packet[0] = (uint8_t)(gen_id & 0xff);
    packet[1] = (uint8_t)((gen_id >> 8) & 0xff);
    packet[2] = (uint8_t)((gen_id >> 16) & 0xff);
    packet[3] = (uint8_t)((gen_id >> 24) & 0xff);
}

int
voleith_rlnc_encode(uint32_t generation_id, const uint8_t *sources, size_t k,
                    size_t symbol_bytes, const voleith_gf16_t *coeffs,
                    uint8_t *packet)
{
    uint8_t *coeff_out, *payload;
    size_t elems, j, s;

    if (sources == NULL || coeffs == NULL || packet == NULL || k == 0 ||
        symbol_bytes == 0 || (symbol_bytes & 1u) != 0)
        return VOLEITH_EC_ERR_PARAM;

    elems = symbol_bytes / VOLEITH_RLNC_COEFF_BYTES;

    /* Header: generation id, then the coefficient vector. */
    write_gen_id(packet, generation_id);
    coeff_out = packet + VOLEITH_RLNC_GEN_ID_BYTES;
    for (j = 0; j < k; j++)
        voleith_gf16_to_bytes(coeff_out + VOLEITH_RLNC_COEFF_BYTES * j,
                              coeffs[j]);

    /* Payload: element-wise sum_j coeffs[j] * source_j over GF(2^16). */
    payload = packet + voleith_rlnc_header_bytes(k);
    for (s = 0; s < elems; s++) {
        voleith_gf16_t acc = 0;
        for (j = 0; j < k; j++) {
            voleith_gf16_t src = voleith_gf16_from_bytes(
                sources + j * symbol_bytes + VOLEITH_RLNC_COEFF_BYTES * s);
            acc = voleith_gf16_add(acc, voleith_gf16_mul(coeffs[j], src));
        }
        voleith_gf16_to_bytes(payload + VOLEITH_RLNC_COEFF_BYTES * s, acc);
    }
    return VOLEITH_EC_OK;
}

int
voleith_rlnc_recode(const uint8_t *const *packets, size_t num_packets, size_t k,
                    size_t symbol_bytes, const voleith_gf16_t *mix_coeffs,
                    uint8_t *out_packet)
{
    uint8_t *coeff_out, *payload_out;
    size_t elems, i, j, s;

    if (packets == NULL || mix_coeffs == NULL || out_packet == NULL ||
        num_packets == 0 || k == 0 || symbol_bytes == 0 ||
        (symbol_bytes & 1u) != 0)
        return VOLEITH_EC_ERR_PARAM;
    for (i = 0; i < num_packets; i++)
        if (packets[i] == NULL)
            return VOLEITH_EC_ERR_PARAM;

    elems = symbol_bytes / VOLEITH_RLNC_COEFF_BYTES;

    /* Recoded packet stays in the input generation. */
    write_gen_id(out_packet, voleith_rlnc_packet_gen_id(packets[0]));

    /*
     * New coefficient vector over the original sources: the same mix applied
     * to the inputs' coefficient vectors as is applied to their payloads.
     */
    coeff_out = out_packet + VOLEITH_RLNC_GEN_ID_BYTES;
    for (j = 0; j < k; j++) {
        voleith_gf16_t acc = 0;
        for (i = 0; i < num_packets; i++) {
            voleith_gf16_t c = voleith_rlnc_packet_coeff(packets[i], j);
            acc = voleith_gf16_add(acc, voleith_gf16_mul(mix_coeffs[i], c));
        }
        voleith_gf16_to_bytes(coeff_out + VOLEITH_RLNC_COEFF_BYTES * j, acc);
    }

    /* New payload: the same mix applied to the inputs' payloads. */
    payload_out = out_packet + voleith_rlnc_header_bytes(k);
    for (s = 0; s < elems; s++) {
        voleith_gf16_t acc = 0;
        for (i = 0; i < num_packets; i++) {
            const uint8_t *payload = voleith_rlnc_packet_payload(packets[i], k);
            voleith_gf16_t sym =
                voleith_gf16_from_bytes(payload + VOLEITH_RLNC_COEFF_BYTES * s);
            acc = voleith_gf16_add(acc, voleith_gf16_mul(mix_coeffs[i], sym));
        }
        voleith_gf16_to_bytes(payload_out + VOLEITH_RLNC_COEFF_BYTES * s, acc);
    }
    return VOLEITH_EC_OK;
}

int
voleith_rlnc_decoder_init(voleith_rlnc_decoder_t *dec, size_t k,
                          size_t symbol_bytes)
{
    size_t elems;

    if (dec == NULL || k == 0 || symbol_bytes == 0 || (symbol_bytes & 1u) != 0)
        return VOLEITH_EC_ERR_PARAM;
    elems = symbol_bytes / VOLEITH_RLNC_COEFF_BYTES;

    dec->coeffs = calloc(k * k, sizeof(*dec->coeffs));
    dec->payload = calloc(k * elems, sizeof(*dec->payload));
    dec->work_coeff = calloc(k, sizeof(*dec->work_coeff));
    dec->work_payload = calloc(elems, sizeof(*dec->work_payload));
    dec->pivot_col = calloc(k, sizeof(*dec->pivot_col));
    if (dec->coeffs == NULL || dec->payload == NULL ||
        dec->work_coeff == NULL || dec->work_payload == NULL ||
        dec->pivot_col == NULL) {
        voleith_rlnc_decoder_free(dec);
        return VOLEITH_EC_ERR_NOMEM;
    }

    dec->k = k;
    dec->symbol_bytes = symbol_bytes;
    dec->elems = elems;
    dec->rank = 0;
    dec->generation_id = 0;
    dec->gen_id_set = 0;
    return VOLEITH_EC_OK;
}

void
voleith_rlnc_decoder_free(voleith_rlnc_decoder_t *dec)
{
    if (dec == NULL)
        return;
    /* coeffs and payload (decoded plaintext) plus the incoming-row scratch are
     * secret; zero them before free.  pivot_col holds only column indices. */
    if (dec->coeffs != NULL)
        voleith_secure_zero(dec->coeffs,
                            dec->k * dec->k * sizeof(*dec->coeffs));
    if (dec->payload != NULL)
        voleith_secure_zero(dec->payload,
                            dec->k * dec->elems * sizeof(*dec->payload));
    if (dec->work_coeff != NULL)
        voleith_secure_zero(dec->work_coeff, dec->k * sizeof(*dec->work_coeff));
    if (dec->work_payload != NULL)
        voleith_secure_zero(dec->work_payload,
                            dec->elems * sizeof(*dec->work_payload));
    free(dec->coeffs);
    free(dec->payload);
    free(dec->work_coeff);
    free(dec->work_payload);
    free(dec->pivot_col);
    dec->coeffs = NULL;
    dec->payload = NULL;
    dec->work_coeff = NULL;
    dec->work_payload = NULL;
    dec->pivot_col = NULL;
    dec->k = 0;
    dec->elems = 0;
    dec->rank = 0;
}

/* Adds factor * (stored row r) into the incoming work row. */
static void
work_axpy_row(voleith_rlnc_decoder_t *dec, size_t r, voleith_gf16_t factor)
{
    size_t j, s;

    for (j = 0; j < dec->k; j++)
        dec->work_coeff[j] = voleith_gf16_add(
            dec->work_coeff[j],
            voleith_gf16_mul(factor, dec->coeffs[r * dec->k + j]));
    for (s = 0; s < dec->elems; s++)
        dec->work_payload[s] = voleith_gf16_add(
            dec->work_payload[s],
            voleith_gf16_mul(factor, dec->payload[r * dec->elems + s]));
}

/* Adds factor * (work row) into stored row r (back-reduction for RREF). */
static void
row_axpy_work(voleith_rlnc_decoder_t *dec, size_t r, voleith_gf16_t factor)
{
    size_t j, s;

    for (j = 0; j < dec->k; j++)
        dec->coeffs[r * dec->k + j] =
            voleith_gf16_add(dec->coeffs[r * dec->k + j],
                             voleith_gf16_mul(factor, dec->work_coeff[j]));
    for (s = 0; s < dec->elems; s++)
        dec->payload[r * dec->elems + s] =
            voleith_gf16_add(dec->payload[r * dec->elems + s],
                             voleith_gf16_mul(factor, dec->work_payload[s]));
}

int
voleith_rlnc_decoder_add(voleith_rlnc_decoder_t *dec, const uint8_t *packet)
{
    const uint8_t *payload;
    voleith_gf16_t pinv;
    size_t j, s, r, pivot;

    if (dec == NULL || packet == NULL || dec->coeffs == NULL)
        return VOLEITH_EC_ERR_PARAM;

    /* All symbols of a decode must share one generation. */
    if (!dec->gen_id_set) {
        dec->generation_id = voleith_rlnc_packet_gen_id(packet);
        dec->gen_id_set = 1;
    } else if (voleith_rlnc_packet_gen_id(packet) != dec->generation_id) {
        return VOLEITH_EC_ERR_PARAM;
    }

    /* Load the incoming coefficient vector and payload into the work row. */
    for (j = 0; j < dec->k; j++)
        dec->work_coeff[j] = voleith_rlnc_packet_coeff(packet, j);
    payload = voleith_rlnc_packet_payload(packet, dec->k);
    for (s = 0; s < dec->elems; s++)
        dec->work_payload[s] =
            voleith_gf16_from_bytes(payload + VOLEITH_RLNC_COEFF_BYTES * s);

    /* Eliminate the existing pivot columns from the work row. */
    for (r = 0; r < dec->rank; r++) {
        voleith_gf16_t f = dec->work_coeff[dec->pivot_col[r]];
        if (f != 0)
            work_axpy_row(dec, r, f);
    }

    /* First surviving nonzero coefficient is the new pivot, if any. */
    for (pivot = 0; pivot < dec->k; pivot++)
        if (dec->work_coeff[pivot] != 0)
            break;
    if (pivot == dec->k)
        return 0; /* Linearly dependent: no new information. */

    /* Normalize the work row so its pivot coefficient is 1. */
    pinv = voleith_gf16_inv(dec->work_coeff[pivot]);
    for (j = 0; j < dec->k; j++)
        dec->work_coeff[j] = voleith_gf16_mul(pinv, dec->work_coeff[j]);
    for (s = 0; s < dec->elems; s++)
        dec->work_payload[s] = voleith_gf16_mul(pinv, dec->work_payload[s]);

    /* Back-reduce the pivot column out of every stored row (keep RREF). */
    for (r = 0; r < dec->rank; r++) {
        voleith_gf16_t f = dec->coeffs[r * dec->k + pivot];
        if (f != 0)
            row_axpy_work(dec, r, f);
    }

    /* Append the normalized work row as a new pivot row. */
    for (j = 0; j < dec->k; j++)
        dec->coeffs[dec->rank * dec->k + j] = dec->work_coeff[j];
    for (s = 0; s < dec->elems; s++)
        dec->payload[dec->rank * dec->elems + s] = dec->work_payload[s];
    dec->pivot_col[dec->rank] = pivot;
    dec->rank++;
    return 1;
}

int
voleith_rlnc_decoder_recover(const voleith_rlnc_decoder_t *dec,
                             uint8_t *sources)
{
    size_t r, s;

    if (dec == NULL || sources == NULL || dec->coeffs == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (dec->rank != dec->k)
        return VOLEITH_EC_ERR_INCOMPLETE;

    /*
     * Complete RREF: the coefficient matrix is the identity (permuted by
     * pivot column), so stored row r asserts source[pivot_col[r]] == its
     * payload.
     */
    for (r = 0; r < dec->k; r++) {
        uint8_t *out = sources + dec->pivot_col[r] * dec->symbol_bytes;
        for (s = 0; s < dec->elems; s++)
            voleith_gf16_to_bytes(out + VOLEITH_RLNC_COEFF_BYTES * s,
                                  dec->payload[r * dec->elems + s]);
    }
    return VOLEITH_EC_OK;
}
