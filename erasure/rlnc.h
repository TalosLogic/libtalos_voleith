/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc.h - Random Linear Network Coding over GF(2^16) (transport layer).
 *
 * A generation is k source symbols, each symbol a vector of GF(2^16)
 * elements (symbol_bytes = 2 * element_count, little-endian).  A coded
 * symbol is a GF(2^16) linear combination of the k sources; it travels with
 * its coefficient vector and a generation identifier so any node can recode
 * (combine coded symbols, P3.T3.2) or decode (Gaussian elimination once the
 * coefficient matrix reaches rank k, P3.T3.3).
 *
 * Plaintext, public-data layer (not constant-time).  See
 * docs/ERASURE_CODES_DESIGN.md.
 *
 * Coded-symbol wire layout (a "packet"):
 *
 *     offset 0                : generation id, uint32 little-endian
 *     offset 4                : coefficient vector, k * uint16 little-endian
 *     offset 4 + 2*k          : payload, symbol_bytes bytes (the coded data)
 *
 * Total packet size = 4 + 2*k + symbol_bytes.  The generation id and
 * coefficient vector are the header; the payload is the coded symbol itself.
 */

#ifndef VOLEITH_ERASURE_RLNC_H
#define VOLEITH_ERASURE_RLNC_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "field16.h"

/* Header field sizes. */
#define VOLEITH_RLNC_GEN_ID_BYTES 4 /* uint32 little-endian generation id. */
#define VOLEITH_RLNC_COEFF_BYTES 2  /* One GF(2^16) coefficient, LE. */

/* Header size for a generation of k sources: gen id + k coefficients. */
static inline size_t
voleith_rlnc_header_bytes(size_t k)
{
    return VOLEITH_RLNC_GEN_ID_BYTES + VOLEITH_RLNC_COEFF_BYTES * k;
}

/* Total packet size for a generation of k sources and symbol_bytes payload. */
static inline size_t
voleith_rlnc_packet_bytes(size_t k, size_t symbol_bytes)
{
    return voleith_rlnc_header_bytes(k) + symbol_bytes;
}

/* ========================================================================
 * Packet accessors (read a coded-symbol packet)
 * ======================================================================== */

/* Reads the generation id from a packet. */
static inline uint32_t
voleith_rlnc_packet_gen_id(const uint8_t *packet)
{
    return (uint32_t)packet[0] | ((uint32_t)packet[1] << 8) |
           ((uint32_t)packet[2] << 16) | ((uint32_t)packet[3] << 24);
}

/* Reads coefficient j (0 <= j < k) from a packet. */
static inline voleith_gf16_t
voleith_rlnc_packet_coeff(const uint8_t *packet, size_t j)
{
    return voleith_gf16_from_bytes(packet + VOLEITH_RLNC_GEN_ID_BYTES +
                                   VOLEITH_RLNC_COEFF_BYTES * j);
}

/* Returns a pointer to the payload (coded data) of a packet. */
static inline const uint8_t *
voleith_rlnc_packet_payload(const uint8_t *packet, size_t k)
{
    return packet + voleith_rlnc_header_bytes(k);
}

/* ========================================================================
 * Encode
 * ======================================================================== */

/*
 * Encodes one coded symbol from k source symbols.
 *
 *   generation_id: identifier written into the packet header.
 *   sources:       k * symbol_bytes bytes, source j at sources + j*symbol_bytes;
 *                  each symbol is symbol_bytes/2 GF(2^16) elements (LE).
 *   k:             number of source symbols (> 0).
 *   symbol_bytes:  bytes per symbol (> 0, must be even).
 *   coeffs:        k coefficients (the linear combination for this symbol).
 *   packet:        output, voleith_rlnc_packet_bytes(k, symbol_bytes) bytes.
 *
 * The payload is sum_j coeffs[j] * source_j, element-wise in GF(2^16).  No
 * dynamic allocation.  Returns 0 on success, a negative VOLEITH_EC_ERR_* on
 * bad arguments.
 */
int voleith_rlnc_encode(uint32_t generation_id, const uint8_t *sources,
                        size_t k, size_t symbol_bytes,
                        const voleith_gf16_t *coeffs, uint8_t *packet);

/* ========================================================================
 * Recode
 * ======================================================================== */

/*
 * Recodes received coded symbols into one new coded symbol, at an
 * intermediate node, without decoding the generation.
 *
 *   packets:      num_packets coded-symbol packets (each as produced by
 *                 encode or a prior recode), all of the same generation, k,
 *                 and symbol_bytes.
 *   num_packets:  number of input packets (> 0).
 *   k:            sources in the generation (coefficient-vector length).
 *   symbol_bytes: bytes per symbol (> 0, even).
 *   mix_coeffs:   num_packets coefficients, the linear combination applied
 *                 at this node.
 *   out_packet:   output, voleith_rlnc_packet_bytes(k, symbol_bytes) bytes.
 *
 * The output is expressed over the ORIGINAL k sources: its coefficient
 * vector is the same linear combination of the inputs' coefficient vectors
 * as is applied to their payloads, so a downstream decoder sees a valid
 * coded symbol of the generation.  The generation id is copied from
 * packets[0].  No dynamic allocation.  Returns 0 on success, a negative
 * VOLEITH_EC_ERR_* on bad arguments.
 */
int voleith_rlnc_recode(const uint8_t *const *packets, size_t num_packets,
                        size_t k, size_t symbol_bytes,
                        const voleith_gf16_t *mix_coeffs, uint8_t *out_packet);

/* ========================================================================
 * Decode (rank-tracking)
 * ======================================================================== */

/*
 * Online RLNC decoder.  Coded symbols are added one at a time; the decoder
 * keeps the accumulated coefficient matrix in reduced row-echelon form, so
 * its rank (the number of linearly independent symbols seen) is always
 * current.  When rank reaches k the generation can be recovered.  Treat the
 * fields as opaque; use the accessors below.
 */
typedef struct {
    voleith_gf16_t *coeffs;  /* rank rows x k coefficients, row-major (RREF). */
    voleith_gf16_t *payload; /* rank rows x elems payload symbols, row-major. */
    voleith_gf16_t *work_coeff;   /* k scratch (incoming coefficient row). */
    voleith_gf16_t *work_payload; /* elems scratch (incoming payload row). */
    size_t *pivot_col;            /* k entries; pivot column of stored row r. */
    size_t k;                     /* Sources in the generation. */
    size_t symbol_bytes;          /* Bytes per symbol. */
    size_t elems;           /* GF(2^16) elements per symbol (symbol_bytes/2). */
    size_t rank;            /* Linearly independent symbols accumulated. */
    uint32_t generation_id; /* Set from the first added symbol. */
    int gen_id_set;         /* Whether generation_id has been latched. */
} voleith_rlnc_decoder_t;

/*
 * Initializes a decoder for a generation of k sources, symbol_bytes per
 * symbol (> 0, even).  Allocates internal storage.  Returns 0 on success, a
 * negative VOLEITH_EC_ERR_* on failure.  On success the caller must
 * voleith_rlnc_decoder_free() it.
 */
int voleith_rlnc_decoder_init(voleith_rlnc_decoder_t *dec, size_t k,
                              size_t symbol_bytes);

/* Releases decoder storage.  Safe on a zeroed descriptor. */
void voleith_rlnc_decoder_free(voleith_rlnc_decoder_t *dec);

/*
 * Adds one coded-symbol packet.  Returns 1 if the symbol was innovative
 * (rank increased), 0 if it was linearly dependent (rank unchanged), or a
 * negative VOLEITH_EC_ERR_* on error (including a generation-id mismatch
 * against earlier symbols).
 */
int voleith_rlnc_decoder_add(voleith_rlnc_decoder_t *dec,
                             const uint8_t *packet);

/* Current rank (linearly independent symbols accumulated). */
static inline size_t
voleith_rlnc_decoder_rank(const voleith_rlnc_decoder_t *dec)
{
    return dec->rank;
}

/* Nonzero once enough symbols (rank == k) have arrived to rebuild. */
static inline int
voleith_rlnc_decoder_is_complete(const voleith_rlnc_decoder_t *dec)
{
    return dec->rank == dec->k;
}

/*
 * Recovers the k source symbols into sources (k * symbol_bytes bytes, source
 * j at sources + j*symbol_bytes).  Requires a complete decoder.  Returns 0
 * on success, VOLEITH_EC_ERR_INCOMPLETE if rank < k, or another negative
 * VOLEITH_EC_ERR_*.
 */
int voleith_rlnc_decoder_recover(const voleith_rlnc_decoder_t *dec,
                                 uint8_t *sources);

#endif /* VOLEITH_ERASURE_RLNC_H */
