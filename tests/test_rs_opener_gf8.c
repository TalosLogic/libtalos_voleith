/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_opener_gf8.c - designated-opener software syndrome layer (OP.SYN).
 *
 * Track 1 (self-contained): build a tag from a fixed (M, support, id) with the
 * voleith opener's own syndrome / KDF / DEM, then exercise verify: accept the
 * matching tuple, reject each tampered field with the right typed status, and
 * cover the generic dispatch (scheme lookup, witness-tag guard, reserved set)
 * and all three OTP id-length regimes at both lambda defaults.
 *
 * Track 2 (cross-firewall): assert voleith reproduces libtalos_syndrome's exact
 * seal bytes from the shared KAT vectors (rs_opener_argus_vectors.h); skipped
 * until those are captured and pinned.
 */
#include "../proof/rs_opener_argus_gf8.h"
#include "../proof/rs_opener_gf8.h"

#include "rs_opener_argus_vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests = 0;
static int fails = 0;

static void
check(const char *name, int cond)
{
    tests++;
    if (!cond) {
        fails++;
        printf("  FAIL: %s\n", name);
    }
}

/* Canonical opener key M: (n0-1) circulant blocks, deterministic bytes, top pad
 * bits of each block cleared (A0). */
static void
fill_M(uint8_t *M, const voleith_rs_opener_argus_params_t *p)
{
    size_t nb = (size_t)(p->n0 - 1u) * p->block_bytes;
    unsigned padbits = (unsigned)(8u * p->block_bytes - p->p);
    uint8_t mask = (uint8_t)(padbits ? (0xffu >> padbits) : 0xffu);
    size_t i;
    uint32_t b;

    for (i = 0; i < nb; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (b = 0; b + 1u < p->n0; b++)
        M[(size_t)(b + 1u) * p->block_bytes - 1u] &= mask;
}

/* t distinct ascending support positions in [0, n). */
static void
fill_indices(uint32_t *idx, const voleith_rs_opener_argus_params_t *p)
{
    uint32_t stride = p->n / p->t; /* >= 2 for every shipped set */
    uint32_t j;

    for (j = 0; j < p->t; j++)
        idx[j] = j * stride;
}

/*
 * Track 1: full round-trip + tamper matrix for one set at its default hash,
 * across the three OTP id-length regimes.
 */
static void
run_set(voleith_rs_opener_argus_set_t set)
{
    const voleith_rs_opener_argus_params_t *p =
        voleith_rs_opener_argus_params(set);
    const voleith_rs_opener_scheme_t *scheme =
        voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);
    size_t id_lens[3];
    uint8_t hash_id;
    uint8_t *M;
    uint32_t *idx;
    size_t block, k;

    if (p == NULL) {
        check("params for shipped set", 0);
        return;
    }
    hash_id = p->prim_default;
    block = p->block_bytes;
    id_lens[0] = 8;            /* short: truncated root pad          */
    id_lens[1] = p->key_bytes; /* full width: whole root pad         */
    id_lens[2] = p->id_max;    /* over-long: AES-CTR extension (A6)  */

    M = malloc((size_t)(p->n0 - 1u) * block);
    idx = malloc((size_t)p->t * sizeof(uint32_t));
    if (M == NULL || idx == NULL) {
        check("alloc M/idx", 0);
        free(M);
        free(idx);
        return;
    }
    fill_M(M, p);
    fill_indices(idx, p);

    /* Determinism: two syndrome recomputes agree. */
    {
        uint8_t *s1 = malloc(block), *s2 = malloc(block);

        check("syndrome recompute #1",
              voleith_rs_opener_argus_syndrome(p, s1, M, idx) ==
                  VOLEITH_RS_OPENER_OK);
        check("syndrome recompute #2",
              voleith_rs_opener_argus_syndrome(p, s2, M, idx) ==
                  VOLEITH_RS_OPENER_OK);
        check("syndrome deterministic", memcmp(s1, s2, block) == 0);
        free(s1);
        free(s2);
    }

    for (k = 0; k < 3; k++) {
        size_t id_len = id_lens[k];
        size_t tag_len = (size_t)1 + block + id_len;
        uint8_t *s = malloc(block);
        uint8_t *K = malloc(p->key_bytes);
        uint8_t *pad = malloc(id_len);
        uint8_t *ct = malloc(id_len);
        uint8_t *id = malloc(id_len);
        uint8_t *tag = malloc(tag_len);
        voleith_rs_opener_witness_t w;
        size_t i;

        if (!s || !K || !pad || !ct || !id || !tag) {
            check("alloc case buffers", 0);
            goto case_done;
        }
        for (i = 0; i < id_len; i++)
            id[i] = (uint8_t)(0x5au + i);

        /* Build the tag with voleith's own syndrome / KDF / DEM. */
        check("build s", voleith_rs_opener_argus_syndrome(p, s, M, idx) ==
                             VOLEITH_RS_OPENER_OK);
        check("build K", voleith_rs_opener_argus_kdf(p, K, hash_id, idx) ==
                             VOLEITH_RS_OPENER_OK);
        check("build pad", voleith_rs_opener_argus_dem_pad(p, pad, id_len, K) ==
                               VOLEITH_RS_OPENER_OK);
        for (i = 0; i < id_len; i++)
            ct[i] = (uint8_t)(id[i] ^ pad[i]);
        tag[0] = hash_id;
        memcpy(tag + 1, s, block);
        memcpy(tag + 1 + block, ct, id_len);

        /* Accept: typed and generic paths. */
        check("typed verify accepts",
              voleith_rs_opener_argus_verify(p, M, s, ct, hash_id, idx, id,
                                             id_len) == VOLEITH_RS_OPENER_OK);
        voleith_rs_opener_argus_witness(&w, idx);
        check("generic verify accepts",
              voleith_rs_opener_verify(scheme, (uint32_t)set, M, tag, tag_len,
                                       &w, id, id_len) == VOLEITH_RS_OPENER_OK);
        check("tag_bytes matches",
              voleith_rs_opener_tag_bytes(scheme, (uint32_t)set, id_len) ==
                  tag_len);

        /* Tamper s -> ESYNDROME. */
        s[0] ^= 0x01u;
        check("tampered s -> ESYNDROME",
              voleith_rs_opener_argus_verify(p, M, s, ct, hash_id, idx, id,
                                             id_len) ==
                  VOLEITH_RS_OPENER_ESYNDROME);
        s[0] ^= 0x01u;

        /* Tamper ct -> EIDENTITY (syndrome still matches). */
        ct[0] ^= 0x01u;
        check("tampered ct -> EIDENTITY",
              voleith_rs_opener_argus_verify(p, M, s, ct, hash_id, idx, id,
                                             id_len) ==
                  VOLEITH_RS_OPENER_EIDENTITY);
        ct[0] ^= 0x01u;

        /* Tamper support -> recomputed s differs -> ESYNDROME. */
        {
            uint32_t saved = idx[1];

            idx[1] = idx[1] + 1u; /* still < n, still a valid position */
            check("tampered support -> ESYNDROME",
                  voleith_rs_opener_argus_verify(p, M, s, ct, hash_id, idx, id,
                                                 id_len) ==
                      VOLEITH_RS_OPENER_ESYNDROME);
            idx[1] = saved;
        }

        /* Wrong hash_id (not the compiled default) -> EUNSUPPORTED. */
        {
            uint8_t bad =
                (uint8_t)(hash_id == VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM
                              ? VOLEITH_RS_OPENER_ARGUS_PRIM_HIROSE
                              : VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM);
            check("wrong hash_id -> EUNSUPPORTED",
                  voleith_rs_opener_argus_verify(p, M, s, ct, bad, idx, id,
                                                 id_len) ==
                      VOLEITH_RS_OPENER_EUNSUPPORTED);
        }

        /* Wrong witness scheme tag -> ESCHEME (generic layer). */
        {
            voleith_rs_opener_witness_t bw = w;

            bw.scheme_id = 0xffu;
            check("wrong witness scheme -> ESCHEME",
                  voleith_rs_opener_verify(scheme, (uint32_t)set, M, tag,
                                           tag_len, &bw, id, id_len) ==
                      VOLEITH_RS_OPENER_ESCHEME);
        }

    case_done:
        free(s);
        free(K);
        free(pad);
        free(ct);
        free(id);
        free(tag);
    }

    free(M);
    free(idx);
}

/* Generic-layer edge cases independent of a full tag build. */
static void
run_generic(void)
{
    const voleith_rs_opener_scheme_t *scheme =
        voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);

    check("argus scheme registered",
          scheme != NULL &&
              scheme->scheme_id == VOLEITH_RS_OPENER_SCHEME_ARGUS);
    check("unknown scheme id -> NULL", voleith_rs_opener_scheme(0xffu) == NULL);

    /* A reserved-but-unparameterized set resolves to no params. */
    check("reserved set -> NULL params",
          voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_3) ==
              NULL);
    check("reserved set -> tag_bytes 0",
          voleith_rs_opener_tag_bytes(
              scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_3, 16) == 0);
    check(
        "out-of-range set -> NULL params",
        voleith_rs_opener_argus_params(
            (voleith_rs_opener_argus_set_t)VOLEITH_RS_OPENER_ARGUS_SET_COUNT) ==
            NULL);
}

/* Track 2 helpers: voleith must reproduce syndrome's exact K and tag_ct from the
 * same support + id (the clean-room KDF/DEM framing, A3-A6). */
#if VOLEITH_ARGUS_VECTORS_128_2_PINNED ||                                      \
    VOLEITH_ARGUS_VECTORS_128_5_PINNED ||                                      \
    VOLEITH_ARGUS_VECTORS_256_2_PINNED || VOLEITH_ARGUS_VECTORS_256_5_PINNED
static void
xcheck_kdf(const voleith_rs_opener_argus_params_t *p, const uint32_t *support,
           const uint8_t *K_exp)
{
    uint8_t K[32];

    check("xfw: kdf ok",
          voleith_rs_opener_argus_kdf(p, K, p->prim_default, support) ==
              VOLEITH_RS_OPENER_OK);
    check("xfw: K matches syndrome", memcmp(K, K_exp, p->key_bytes) == 0);
}

static void
xcheck_dem(const voleith_rs_opener_argus_params_t *p, const uint8_t *K,
           const uint8_t *id, size_t id_len, const uint8_t *ct_exp)
{
    uint8_t pad[96];
    uint8_t got[96];
    size_t i;

    check("xfw: dem_pad ok", voleith_rs_opener_argus_dem_pad(
                                 p, pad, id_len, K) == VOLEITH_RS_OPENER_OK);
    for (i = 0; i < id_len; i++)
        got[i] = (uint8_t)(id[i] ^ pad[i]);
    check("xfw: tag_ct matches syndrome", memcmp(got, ct_exp, id_len) == 0);
}
#endif

/* Track 2: cross-firewall byte-equality against syndrome's captured vectors. */
static void
run_cross_firewall(void)
{
    int any = 0;

#if VOLEITH_ARGUS_VECTORS_128_2_PINNED
    {
        const voleith_rs_opener_argus_params_t *p =
            voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_2);

        xcheck_kdf(p, V128_2_SUPPORT, V128_2_K);
        xcheck_dem(p, V128_2_K, V128_2_ID0, sizeof(V128_2_ID0), V128_2_CT0);
        xcheck_dem(p, V128_2_K, V128_2_ID1, sizeof(V128_2_ID1), V128_2_CT1);
        xcheck_dem(p, V128_2_K, V128_2_ID2, sizeof(V128_2_ID2), V128_2_CT2);
        any = 1;
    }
#endif
#if VOLEITH_ARGUS_VECTORS_256_2_PINNED
    {
        const voleith_rs_opener_argus_params_t *p =
            voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_256_2);

        xcheck_kdf(p, V256_2_SUPPORT, V256_2_K);
        xcheck_dem(p, V256_2_K, V256_2_ID0, sizeof(V256_2_ID0), V256_2_CT0);
        xcheck_dem(p, V256_2_K, V256_2_ID1, sizeof(V256_2_ID1), V256_2_CT1);
        xcheck_dem(p, V256_2_K, V256_2_ID2, sizeof(V256_2_ID2), V256_2_CT2);
        any = 1;
    }
#endif
#if VOLEITH_ARGUS_VECTORS_128_5_PINNED
    {
        const voleith_rs_opener_argus_params_t *p =
            voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_5);

        xcheck_kdf(p, V128_5_SUPPORT, V128_5_K);
        xcheck_dem(p, V128_5_K, V128_5_ID0, sizeof(V128_5_ID0), V128_5_CT0);
        xcheck_dem(p, V128_5_K, V128_5_ID1, sizeof(V128_5_ID1), V128_5_CT1);
        xcheck_dem(p, V128_5_K, V128_5_ID2, sizeof(V128_5_ID2), V128_5_CT2);
        any = 1;
    }
#endif
#if VOLEITH_ARGUS_VECTORS_256_5_PINNED
    {
        const voleith_rs_opener_argus_params_t *p =
            voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_256_5);

        xcheck_kdf(p, V256_5_SUPPORT, V256_5_K);
        xcheck_dem(p, V256_5_K, V256_5_ID0, sizeof(V256_5_ID0), V256_5_CT0);
        xcheck_dem(p, V256_5_K, V256_5_ID1, sizeof(V256_5_ID1), V256_5_CT1);
        xcheck_dem(p, V256_5_K, V256_5_ID2, sizeof(V256_5_ID2), V256_5_CT2);
        any = 1;
    }
#endif

    if (!any)
        printf("  NOTE: cross-firewall Argus vectors unpinned; build "
               "libtalos_syndrome and run argus_vectors_128_2 / _256_2, then "
               "paste into tests/rs_opener_argus_vectors.h.\n");
}

int
main(void)
{
    printf("rs_opener_gf8: Argus software syndrome layer (OP.SYN)\n");

    run_generic();
    run_set(VOLEITH_RS_OPENER_ARGUS_SET_128_2); /* AES-DM KDF     */
    run_set(VOLEITH_RS_OPENER_ARGUS_SET_128_5); /* AES-DM, n0=5   */
    run_set(VOLEITH_RS_OPENER_ARGUS_SET_256_2); /* Grostl-256 KDF */
    run_set(VOLEITH_RS_OPENER_ARGUS_SET_256_5); /* Grostl-256, n0=5 */
    run_cross_firewall();

    printf("  %d / %d passed\n", tests - fails, tests);
    return fails == 0 ? 0 : 1;
}
