/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_syndrome_opener_e2e_gf8.c - OP.SYNG step 3d, full opener e2e (SLOW).
 *
 * Ties the in-circuit syndrome gadget to the production software Argus opener
 * over the SAME real (M, support, s):
 *
 *   1. At the quickest release-gate set (128_2): real dimensions (p=13613,
 *      n=27226, t=130, idx_bits=15) with a SPARSE synthetic M (see fill_M for
 *      why: dense M makes the reference prover multi-minute; M is public and the
 *      opener accepts any M, and dense-M relation is covered by
 *      test_syndrome_gf8's clear-domain cross-check).  Compute s / K / tag_ct
 *      with the production syndrome / KDF / DEM.
 *   2. The SOFTWARE opener (voleith_rs_opener_argus_verify) accepts that tuple
 *      and rejects a tampered s.
 *   3. A full in-circuit VOLEitH proof of the syndrome relation over the same
 *      (support, s) proves and verifies through the public prove_v2 / verify_v2
 *      pipeline at opening degree d = idx_bits (> 2).
 *
 * Both halves accepting the same tuple is the end-to-end agreement between the
 * degree-d gadget and the shipped opener.  Labelled `slow`: the straightforward
 * (reference) syndrome prover is O(t*n*idx_bits^2), tens of seconds at real p.
 * The full opener-in-circuit (syndrome + KDF + DEM + id recovery) lands with
 * OP.CIRC / OP.ORACLE; this validates the syndrome half before the gf16 mirror.
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "proof.h"        /* voleith_params_em_128f, voleith_proof_t */
#include "proof_header.h" /* VOLEITH_PROOF_HEADER_BYTES */
#include "../proof/rs_opener_argus_gf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_pass = 0, g_fail = 0;
static void
check(const char *name, int cond)
{
    if (cond) {
        g_pass++;
        printf("  ok   %s\n", name);
    } else {
        g_fail++;
        printf("  FAIL %s\n", name);
    }
}

/*
 * SPARSE circulant first-row per block.  M is public and the opener accepts any
 * M, so a sparse M preserves the "same (M, support, s) through both paths" tie
 * while keeping the reference prover tractable: its accumulation is O(t*n*wM)
 * in the row weight wM, and a dense M (wM ~ p/2, as a real Niederreiter
 * systematic M is) makes the real-p reference prover multi-minute (the exact
 * per-column p-row scatter the section 8 Horner collapse removes).  Dense-M
 * relation correctness is covered separately and cheaply by test_syndrome_gf8's
 * clear-domain cross-check against this same production helper.
 */
#define E2E_M_ROW_WEIGHT 24u
static void
fill_M(uint8_t *M, const voleith_rs_opener_argus_params_t *p)
{
    size_t nb = (size_t)(p->n0 - 1u) * p->block_bytes;
    memset(M, 0, nb);
    for (uint32_t b = 0; b + 1u < p->n0; b++) {
        uint8_t *mb = M + (size_t)b * p->block_bytes;
        for (uint32_t w = 0; w < E2E_M_ROW_WEIGHT; w++) {
            uint32_t pos = (uint32_t)(((uint64_t)w * 2654435761u + 1013u * b) %
                                      p->p); /* distinct-ish, in [0, p) */
            mb[pos >> 3] |= (uint8_t)(1u << (pos & 7u));
        }
    }
}
static void
fill_indices(uint32_t *idx, const voleith_rs_opener_argus_params_t *p)
{
    uint32_t stride = p->n / p->t;
    for (uint32_t j = 0; j < p->t; j++)
        idx[j] = j * stride;
}

int
main(void)
{
    printf("=== test_syndrome_opener_e2e_gf8 (SLOW) ===\n");

    const voleith_rs_opener_argus_set_t set = VOLEITH_RS_OPENER_ARGUS_SET_128_2;
    const voleith_rs_opener_argus_params_t *pp =
        voleith_rs_opener_argus_params(set);
    if (!pp) {
        check("params 128_2 available", 0);
        goto end;
    }
    printf("  set 128_2: p=%u n0=%u t=%u idx_bits=%u n=%u\n", pp->p, pp->n0,
           pp->t, pp->idx_bits, pp->n);

    uint8_t hash_id = pp->prim_default;
    size_t block = pp->block_bytes;
    size_t id_len = 8;

    uint8_t *M = malloc((size_t)(pp->n0 - 1u) * block);
    uint32_t *idx = malloc((size_t)pp->t * sizeof(uint32_t));
    uint8_t *s = malloc(block);
    uint8_t *K = malloc(pp->key_bytes);
    uint8_t *pad = malloc(id_len);
    uint8_t *ct = malloc(id_len);
    uint8_t *id = malloc(id_len);
    if (!M || !idx || !s || !K || !pad || !ct || !id) {
        check("alloc", 0);
        goto free_all;
    }

    fill_M(M, pp);
    fill_indices(idx, pp);
    for (size_t i = 0; i < id_len; i++)
        id[i] = (uint8_t)(0x5au + i);

    /* --- Production syndrome / KDF / DEM. --- */
    check("build s (production helper)",
          voleith_rs_opener_argus_syndrome(pp, s, M, idx) ==
              VOLEITH_RS_OPENER_OK);
    check("build K (production KDF)",
          voleith_rs_opener_argus_kdf(pp, K, hash_id, idx) ==
              VOLEITH_RS_OPENER_OK);
    check("build DEM pad", voleith_rs_opener_argus_dem_pad(
                               pp, pad, id_len, K) == VOLEITH_RS_OPENER_OK);
    for (size_t i = 0; i < id_len; i++)
        ct[i] = (uint8_t)(id[i] ^ pad[i]);

    /* --- Software opener accepts the tuple, rejects a tampered s. --- */
    check("software opener accepts (M, support, s, ct)",
          voleith_rs_opener_argus_verify(pp, M, s, ct, hash_id, idx, id,
                                         id_len) == VOLEITH_RS_OPENER_OK);
    {
        s[0] ^= 1u;
        check("software opener rejects tampered s",
              voleith_rs_opener_argus_verify(pp, M, s, ct, hash_id, idx, id,
                                             id_len) != VOLEITH_RS_OPENER_OK);
        s[0] ^= 1u; /* restore */
    }

    /* --- Full in-circuit VOLEitH proof of the SAME (support, s). --- */
    {
        uint32_t p = pp->p, n0 = pp->n0, t = pp->t, idx_bits = pp->idx_bits;
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        size_t nib = (size_t)t * idx_bits;
        gf8_wire_id *idx_w = malloc(nib * sizeof(gf8_wire_id));
        gf8_wire_id *s_w = malloc((size_t)p * sizeof(gf8_wire_id));
        uint8_t *witness = malloc(nib);
        uint8_t *instance = malloc(p);

        for (uint32_t k = 0; k < t; k++)
            for (uint32_t b = 0; b < idx_bits; b++) {
                idx_w[k * idx_bits + b] = voleith_gf8_add_witness(c);
                witness[k * idx_bits + b] =
                    (uint8_t)((idx[k] >> (idx_bits - 1u - b)) & 1u);
            }
        for (uint32_t j = 0; j < p; j++) {
            s_w[j] = voleith_gf8_add_instance(c);
            instance[j] = (uint8_t)((s[j >> 3] >> (j & 7u)) & 1u);
        }
        voleith_gf8_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);
        free(idx_w);
        free(s_w);

        check("qs_degree == idx_bits (in-circuit d>2)",
              voleith_gf8_circuit_qs_degree(c) == idx_bits);

        const voleith_params_t *params = &voleith_params_em_128f;
        uint8_t fs_seed[16];
        memset(fs_seed, 0x4e, sizeof(fs_seed));
        voleith_proof_t proof;
        memset(&proof, 0, sizeof(proof));

        printf("  proving in-circuit syndrome (real p, reference prover)...\n");
        check("in-circuit prove_v2 succeeds",
              voleith_gf8_prove_v2(&proof, params, c, witness, nib, instance, p,
                                   fs_seed, sizeof(fs_seed)) == 0);
        check("in-circuit verify_v2 accepts",
              voleith_gf8_verify_v2(&proof, params, c, instance, p, fs_seed,
                                    sizeof(fs_seed)) == 0);
        check("proof_byte_size_circuit matches",
              voleith_gf8_proof_byte_size_circuit(params, c) == proof.len);

        /* Tampered public s at verify must reject (instance binding). */
        instance[0] ^= 1u;
        check("in-circuit verify_v2 rejects tampered public s",
              voleith_gf8_verify_v2(&proof, params, c, instance, p, fs_seed,
                                    sizeof(fs_seed)) != 0);
        instance[0] ^= 1u;

        voleith_proof_free(&proof);
        free(witness);
        free(instance);
        voleith_gf8_circuit_free(c);
    }

free_all:
    free(M);
    free(idx);
    free(s);
    free(K);
    free(pad);
    free(ct);
    free(id);

end:
    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
