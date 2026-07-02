/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_aes.c - Tier 2a native witness backends for the
 * FIXED aes/* registry entries (W8.3b).
 *
 * Each backend wraps the matching builder in circuits/aes_gf8_circuit.h.  Those
 * builders emit inv_in bytes in the exact circuit-evaluation order the generic
 * Tier 1 evaluator (parsers/shipshape_witness.c) fills, so wrapping them yields
 * byte-identical witness output (the witness-generation design SECTION 7).  No new
 * AES math lives here: the builder is both the implementation and the
 * equivalence oracle.
 *
 * NOTE: an x4 / AES-NI hardware witness path is deferred; wrapping the existing
 * scalar builder is the W8.3b deliverable.
 *
 * Every backend is fail-closed: it re-checks ext, ext_len, and the region
 * witness span and returns -1 on any mismatch.  The dispatcher only calls a
 * backend on a confirmed (name, frozen-hash) match, so the shape is guaranteed
 * in practice; these checks are belt-and-suspenders (a registered backend that
 * cannot run is a build error, not a silent fallthrough).
 */

#include "shipshape_witgen_aes.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes_gf8_circuit.h"
#include "field.h"
#include "shipshape.h"
#include "shipshape_registry.h"
#include "shipshape_witgen_dispatch.h"
#include "util.h"

/* ================================================================
 * Backends.  Each writes region->n_witness inv-witness bytes into
 * full[region->first_witness .. first_witness + n_witness - 1].
 * ================================================================ */

/* stdlib/crypto/aes/sbox: (in : byte) -> (out : byte). */
static int
witgen_aes_sbox(const voleith_shipshape_region_t *region, const uint8_t *ext,
                size_t ext_len, uint8_t *full)
{
    if (ext == NULL || ext_len != 1 || region->n_witness != 1)
        return -1;

    /*
     * inv_in convention: in^{-1}, or 0 when in == 0.  voleith_gf8_inv computes
     * a^254, which is a^{-1} for nonzero a and 0 for a == 0, so no special
     * case is needed.
     */
    full[region->first_witness] = (uint8_t)voleith_gf8_inv(ext[0]);
    return 0;
}

/* stdlib/crypto/aes/keyschedule_128: (key : byte[16]) -> (rk : byte[176]). */
static int
witgen_aes_keyschedule_128(const voleith_shipshape_region_t *region,
                           const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t inv_out[AES128_GF8_KS_INVIN_BYTES];
    uint8_t rk_out[11][16];

    if (ext == NULL || ext_len != 16 ||
        region->n_witness != AES128_GF8_KS_INVIN_BYTES)
        return -1;

    aes128_gf8_expand_key_witness(ext, inv_out, rk_out);
    memcpy(full + region->first_witness, inv_out, AES128_GF8_KS_INVIN_BYTES);

    voleith_secure_zero(inv_out, sizeof(inv_out));
    voleith_secure_zero(rk_out, sizeof(rk_out));
    return 0;
}

/*
 * stdlib/crypto/aes/encrypt_rounds_128:
 *   (rk : byte[176], pt : byte[16]) -> (ct : byte[16]).
 * ext = rk(176 round-major) || pt(16).
 */
static int
witgen_aes_encrypt_rounds_128(const voleith_shipshape_region_t *region,
                              const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t rk[11][16];
    uint8_t inv_out[AES128_GF8_ENC_INVIN_BYTES];

    if (ext == NULL || ext_len != 192 ||
        region->n_witness != AES128_GF8_ENC_INVIN_BYTES)
        return -1;

    memcpy(rk, ext, 176);
    aes128_gf8_encrypt_rk_witness(rk, ext + 176, inv_out, NULL);
    memcpy(full + region->first_witness, inv_out, AES128_GF8_ENC_INVIN_BYTES);

    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(inv_out, sizeof(inv_out));
    return 0;
}

/* stdlib/crypto/aes/encrypt_128: (key : byte[16], pt : byte[16]) -> ct. */
static int
witgen_aes_encrypt_128(const voleith_shipshape_region_t *region,
                       const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t witness[216];

    if (ext == NULL || ext_len != 32 || region->n_witness != 200)
        return -1;

    /* witness = [key(16) | inv(200)]; copy the 200 inv bytes only. */
    aes128_gf8_build_witness(ext, ext + 16, witness, NULL);
    memcpy(full + region->first_witness, witness + 16, 200);

    voleith_secure_zero(witness, sizeof(witness));
    return 0;
}

/* stdlib/crypto/aes/keyschedule_256: (key : byte[32]) -> (rk : byte[240]). */
static int
witgen_aes_keyschedule_256(const voleith_shipshape_region_t *region,
                           const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t inv_out[AES256_GF8_KS_INVIN_BYTES];
    uint8_t rk_out[15][16];

    if (ext == NULL || ext_len != 32 ||
        region->n_witness != AES256_GF8_KS_INVIN_BYTES)
        return -1;

    aes256_gf8_expand_key_witness(ext, inv_out, rk_out);
    memcpy(full + region->first_witness, inv_out, AES256_GF8_KS_INVIN_BYTES);

    voleith_secure_zero(inv_out, sizeof(inv_out));
    voleith_secure_zero(rk_out, sizeof(rk_out));
    return 0;
}

/*
 * stdlib/crypto/aes/encrypt_rounds_256:
 *   (rk : byte[240], pt : byte[16]) -> (ct : byte[16]).
 * ext = rk(240 round-major) || pt(16).
 */
static int
witgen_aes_encrypt_rounds_256(const voleith_shipshape_region_t *region,
                              const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t rk[15][16];
    uint8_t inv_out[AES256_GF8_ENC_INVIN_BYTES];

    if (ext == NULL || ext_len != 256 ||
        region->n_witness != AES256_GF8_ENC_INVIN_BYTES)
        return -1;

    memcpy(rk, ext, 240);
    aes256_gf8_encrypt_rk_witness(rk, ext + 240, inv_out, NULL);
    memcpy(full + region->first_witness, inv_out, AES256_GF8_ENC_INVIN_BYTES);

    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(inv_out, sizeof(inv_out));
    return 0;
}

/* stdlib/crypto/aes/encrypt_256: (key : byte[32], pt : byte[16]) -> ct. */
static int
witgen_aes_encrypt_256(const voleith_shipshape_region_t *region,
                       const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    uint8_t witness[308];

    if (ext == NULL || ext_len != 48 || region->n_witness != 276)
        return -1;

    /* witness = [key(32) | inv(276)]; copy the 276 inv bytes only. */
    aes256_gf8_build_witness(ext, ext + 32, witness, NULL);
    memcpy(full + region->first_witness, witness + 32, 276);

    voleith_secure_zero(witness, sizeof(witness));
    return 0;
}

/* ================================================================
 * Registration.
 * ================================================================ */

/*
 * One (static fqn, backend) pair to register.  fqn must be a static literal:
 * the dispatch registry borrows the pointer (it is not copied).
 */
typedef struct {
    const char *fqn;
    voleith_shipshape_witgen_backend_fn fn;
} witgen_aes_entry_t;

static const witgen_aes_entry_t s_aes_entries[] = {
    {"stdlib/crypto/aes/sbox", witgen_aes_sbox},
    {"stdlib/crypto/aes/keyschedule_128", witgen_aes_keyschedule_128},
    {"stdlib/crypto/aes/encrypt_rounds_128", witgen_aes_encrypt_rounds_128},
    {"stdlib/crypto/aes/encrypt_128", witgen_aes_encrypt_128},
    {"stdlib/crypto/aes/keyschedule_256", witgen_aes_keyschedule_256},
    {"stdlib/crypto/aes/encrypt_rounds_256", witgen_aes_encrypt_rounds_256},
    {"stdlib/crypto/aes/encrypt_256", witgen_aes_encrypt_256},
};

/*
 * Resolve fqn to its index in the frozen crypto-v1 registry.  Returns the
 * index on success, or the registry count (an out-of-range sentinel) if the
 * name is not present.
 */
static size_t
registry_index_of(const char *fqn)
{
    size_t n = voleith_shipshape_registry_count;
    size_t i;

    for (i = 0; i < n; i++) {
        if (strcmp(voleith_shipshape_registry[i].fqn, fqn) == 0)
            return i;
    }
    return n;
}

int
voleith_shipshape_witgen_register_aes(void)
{
    size_t n_entries = sizeof(s_aes_entries) / sizeof(s_aes_entries[0]);
    size_t e;

    for (e = 0; e < n_entries; e++) {
        uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
        size_t idx;

        idx = registry_index_of(s_aes_entries[e].fqn);
        if (idx >= voleith_shipshape_registry_count)
            return -1;

        /* FIXED entry: single frozen body hash at param 0. */
        if (voleith_shipshape_registry_body_hash(idx, 0, hash) != 0)
            return -1;

        if (voleith_shipshape_witgen_register(s_aes_entries[e].fqn, hash,
                                              s_aes_entries[e].fn) != 0)
            return -1;
    }
    return 0;
}
