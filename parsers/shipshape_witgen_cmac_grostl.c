/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_cmac_grostl.c - Tier 2a native witness backends for
 * the PARAMETRIC cmac/<...> and grostl/<...> registry entries (W8.3c).
 *
 * Each backend wraps the matching builder in circuits/aes_cmac_gf8_circuit.h
 * or circuits/grostl_gf8_circuit.h.  Those builders emit inv_in bytes in the
 * exact circuit-evaluation order the generic Tier 1 evaluator
 * (parsers/shipshape_witness.c) fills, so wrapping them yields byte-identical
 * witness output (the witness-generation design SECTION 7).  No new crypto math
 * lives here: the builder is both the implementation and the equivalence
 * oracle.
 *
 * Unlike the FIXED aes/<...> backends, these are PARAMETRIC: the message length is
 * variable, so the witness buffer is sized at runtime and must be heap
 * allocated.  Each backend allocates with calloc, copies the inv tail into the
 * region span, and secure-zeroes the scratch before free (it may hold key or
 * witness bytes).
 *
 * Every backend is fail-closed: it re-checks ext, ext_len, and the region
 * witness span and returns -1 on any mismatch.  The dispatcher only calls a
 * backend on a confirmed name match against a PARAMETRIC registry entry, so
 * the shape is guaranteed in practice; these checks are belt-and-suspenders.
 */

#include "shipshape_witgen_cmac_grostl.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes_cmac_gf8_circuit.h"
#include "grostl_gf8_circuit.h"
#include "shipshape.h"
#include "shipshape_witgen_dispatch.h"
#include "util.h"

/* ================================================================
 * CMAC backends.  ext = key(key_bytes) || msg(n); the region span is the
 * inv tail (the witness layout's key prefix is stripped).
 * ================================================================ */

/*
 * Shared CMAC body.  key_bytes is 16 (AES-128) or 32 (AES-256).
 *   ext        = key(key_bytes) || msg(msg_bytes)
 *   msg_bytes  = ext_len - key_bytes
 *   span       = aes_cmac_gf8_witness_bytes(key_bytes, msg_bytes) - key_bytes
 */
static int
witgen_cmac(const voleith_shipshape_region_t *region, const uint8_t *ext,
            size_t ext_len, uint8_t *full, size_t key_bytes)
{
    uint8_t *witness;
    size_t witness_bytes, msg_bytes, span;
    const uint8_t *msg;

    if (ext == NULL || ext_len < key_bytes)
        return -1;

    msg_bytes = ext_len - key_bytes;
    msg = (msg_bytes > 0) ? ext + key_bytes : NULL;
    witness_bytes = aes_cmac_gf8_witness_bytes(key_bytes, msg_bytes);
    span = witness_bytes - key_bytes;
    if (region->n_witness != span)
        return -1;

    witness = calloc(witness_bytes, 1);
    if (witness == NULL)
        return -1;

    /* witness = [key(key_bytes) | inv...]; copy the inv tail only. */
    aes_cmac_gf8_build_witness(ext, key_bytes, msg, msg_bytes, witness, NULL);
    memcpy(full + region->first_witness, witness + key_bytes, span);

    voleith_secure_zero(witness, witness_bytes);
    free(witness);
    return 0;
}

/*
 * stdlib/crypto/cmac/aes_128:
 *   (key : byte[16], msg : byte[n]) -> (tag : byte[16]).
 */
static int
witgen_cmac_128(const voleith_shipshape_region_t *region, const uint8_t *ext,
                size_t ext_len, uint8_t *full)
{
    return witgen_cmac(region, ext, ext_len, full, 16);
}

/*
 * stdlib/crypto/cmac/aes_256:
 *   (key : byte[32], msg : byte[n]) -> (tag : byte[16]).
 */
static int
witgen_cmac_256(const voleith_shipshape_region_t *region, const uint8_t *ext,
                size_t ext_len, uint8_t *full)
{
    return witgen_cmac(region, ext, ext_len, full, 32);
}

/* ================================================================
 * Grostl backends.  ext = msg(n); the region span is the inv tail (the
 * witness layout's msg prefix is stripped).  The t27 / t59 truncations
 * affect only output wires, so hash_256 / hash_256_t27 share witgen_grostl_256
 * and hash_512 / hash_512_t59 share witgen_grostl_512.
 * ================================================================ */

/*
 * stdlib/crypto/grostl/hash_256 and stdlib/crypto/grostl/hash_256_t27:
 *   (msg : byte[n]) -> out.
 *   ext   = msg(msg_bytes), msg_bytes = ext_len
 *   span  = grostl256_gf8_witness_bytes(msg_bytes) - msg_bytes
 */
static int
witgen_grostl_256(const voleith_shipshape_region_t *region, const uint8_t *ext,
                  size_t ext_len, uint8_t *full)
{
    uint8_t *witness;
    size_t witness_bytes, msg_bytes, span;
    const uint8_t *msg;

    msg_bytes = ext_len;
    /* ext may legitimately be NULL only when msg_bytes == 0. */
    if (ext == NULL && msg_bytes != 0)
        return -1;
    msg = (msg_bytes > 0) ? ext : NULL;

    witness_bytes = grostl256_gf8_witness_bytes(msg_bytes);
    span = witness_bytes - msg_bytes;
    if (region->n_witness != span)
        return -1;

    witness = calloc(witness_bytes, 1);
    if (witness == NULL)
        return -1;

    /* witness = [msg(msg_bytes) | inv...]; copy the inv tail only. */
    grostl256_gf8_build_witness(msg, msg_bytes, witness);
    memcpy(full + region->first_witness, witness + msg_bytes, span);

    voleith_secure_zero(witness, witness_bytes);
    free(witness);
    return 0;
}

/*
 * stdlib/crypto/grostl/hash_512 and stdlib/crypto/grostl/hash_512_t59:
 *   (msg : byte[n]) -> out.
 *   ext   = msg(msg_bytes), msg_bytes = ext_len
 *   span  = grostl512_gf8_witness_bytes(msg_bytes) - msg_bytes
 */
static int
witgen_grostl_512(const voleith_shipshape_region_t *region, const uint8_t *ext,
                  size_t ext_len, uint8_t *full)
{
    uint8_t *witness;
    size_t witness_bytes, msg_bytes, span;
    const uint8_t *msg;

    msg_bytes = ext_len;
    /* ext may legitimately be NULL only when msg_bytes == 0. */
    if (ext == NULL && msg_bytes != 0)
        return -1;
    msg = (msg_bytes > 0) ? ext : NULL;

    witness_bytes = grostl512_gf8_witness_bytes(msg_bytes);
    span = witness_bytes - msg_bytes;
    if (region->n_witness != span)
        return -1;

    witness = calloc(witness_bytes, 1);
    if (witness == NULL)
        return -1;

    /* witness = [msg(msg_bytes) | inv...]; copy the inv tail only. */
    grostl512_gf8_build_witness(msg, msg_bytes, witness);
    memcpy(full + region->first_witness, witness + msg_bytes, span);

    voleith_secure_zero(witness, witness_bytes);
    free(witness);
    return 0;
}

/* ================================================================
 * Registration.  fqns are static literals borrowed by the dispatch registry.
 * ================================================================ */

typedef struct {
    const char *fqn;
    voleith_shipshape_witgen_backend_fn fn;
} witgen_parametric_entry_t;

static const witgen_parametric_entry_t s_cmac_entries[] = {
    {"stdlib/crypto/cmac/aes_128", witgen_cmac_128},
    {"stdlib/crypto/cmac/aes_256", witgen_cmac_256},
};

static const witgen_parametric_entry_t s_grostl_entries[] = {
    {"stdlib/crypto/grostl/hash_256", witgen_grostl_256},
    {"stdlib/crypto/grostl/hash_256_t27", witgen_grostl_256},
    {"stdlib/crypto/grostl/hash_512", witgen_grostl_512},
    {"stdlib/crypto/grostl/hash_512_t59", witgen_grostl_512},
};

static int
register_entries(const witgen_parametric_entry_t *entries, size_t n_entries)
{
    size_t e;

    for (e = 0; e < n_entries; e++) {
        if (voleith_shipshape_witgen_register_parametric(entries[e].fqn,
                                                         entries[e].fn) != 0)
            return -1;
    }
    return 0;
}

int
voleith_shipshape_witgen_register_cmac(void)
{
    return register_entries(s_cmac_entries,
                            sizeof(s_cmac_entries) / sizeof(s_cmac_entries[0]));
}

int
voleith_shipshape_witgen_register_grostl(void)
{
    return register_entries(s_grostl_entries, sizeof(s_grostl_entries) /
                                                  sizeof(s_grostl_entries[0]));
}
