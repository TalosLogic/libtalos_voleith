/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs_chunk_cert_circuit.c - eval-level tests for the public-index
 * RS chunk membership certificate circuit (circuits/rs_chunk_cert_circuit.c,
 * plan T6.3).
 *
 * Builds the circuit and a matching witness, fills the instance from the
 * plaintext helpers (erasure/rs_membership.c) that the circuit must agree
 * with, and checks that voleith_gf8_circuit_eval accepts a genuine
 * (FWK, chunk_digest, index, siblings, merkle_root) tuple and rejects every
 * single-field tamper.  Covers depth 0 (n=1), a depth-7 dataset, and the
 * full depth-8 tree, on both CR profiles.  The full Fiat-Shamir proof and
 * its tamper matrix land in plan T6.5.
 */

#include "rs_chunk_cert_circuit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-48s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

/*
 * Builds the certificate circuit and witness for chunk `index` of an
 * n-chunk dataset and exercises eval on the genuine tuple plus a battery of
 * single-field tampers.  Returns 1 on full success, 0 on any failure.
 */
static int
run_case(voleith_rs_cr_profile_t cr, size_t n, size_t index)
{
    const voleith_node_hash_vt *vt = voleith_rs_chunk_node_vt(cr);
    size_t W, digb, fwkb, depth, wirec;
    uint8_t fwk[32];
    uint8_t root[64];
    uint8_t *digests = NULL, *siblings = NULL;
    uint8_t *witness = NULL, *instance = NULL, *wire_vals = NULL;
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_chunk_cert_layout_t layout;
    int ok = 0;

    if (vt == NULL)
        return 0;
    W = vt->node_bytes;
    digb = voleith_rs_cr_digest_bytes(cr);
    fwkb = voleith_rs_fwk_bytes(cr);
    depth = voleith_rs_tree_depth_for_n(n);

    for (size_t i = 0; i < fwkb; i++)
        fwk[i] = (uint8_t)(0xA0 + i);

    /* Per-chunk digests over distinct content. */
    digests = calloc(n, digb);
    if (digests == NULL)
        goto done;
    for (size_t i = 0; i < n; i++) {
        uint8_t chunk[32];
        for (size_t j = 0; j < sizeof(chunk); j++)
            chunk[j] = (uint8_t)(i * 7u + j);
        if (voleith_rs_chunk_digest(cr, chunk, sizeof(chunk),
                                    digests + i * digb, digb) != VOLEITH_EC_OK)
            goto done;
    }

    if (voleith_rs_tree_root(cr, fwk, digests, n, root, sizeof(root)) !=
        VOLEITH_EC_OK)
        goto done;

    if (depth > 0) {
        siblings = calloc(depth, W);
        if (siblings == NULL)
            goto done;
        if (voleith_rs_tree_sibling_path(cr, fwk, digests, n, index, siblings,
                                         depth * W) != VOLEITH_EC_OK)
            goto done;
    }

    c = voleith_gf8_circuit_new();
    if (c == NULL)
        goto done;
    if (voleith_rs_chunk_cert_build_circuit(c, cr, n, index, &layout) != 0)
        goto done;
    if (!voleith_gf8_circuit_ok(c) || voleith_gf8_circuit_validate(c) != 0)
        goto done;

    /* Layout totals agree with the circuit's wire counts. */
    if (layout.witness_bytes != voleith_gf8_circuit_witness_count(c) ||
        layout.instance_bytes != voleith_gf8_circuit_instance_count(c) ||
        layout.instance_bytes != W + digb)
        goto done;

    /* instance = merkle_root || chunk_digest[index]. */
    instance = calloc(layout.instance_bytes, 1);
    if (instance == NULL)
        goto done;
    memcpy(instance + layout.inst_root_off, root, W);
    memcpy(instance + layout.inst_digest_off, digests + index * digb, digb);

    witness = calloc(layout.witness_bytes, 1);
    if (witness == NULL)
        goto done;
    if (voleith_rs_chunk_cert_build_witness(cr, n, index, fwk,
                                            digests + index * digb, siblings,
                                            &layout, witness) != 0)
        goto done;

    wirec = voleith_gf8_circuit_wire_count(c);
    wire_vals = calloc(wirec, 1);
    if (wire_vals == NULL)
        goto done;

    /* Genuine tuple verifies. */
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 1)
        goto done;

    /* Tamper: instance chunk_digest. */
    instance[layout.inst_digest_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    instance[layout.inst_digest_off] ^= 0x01;

    /* Tamper: instance merkle_root. */
    instance[layout.inst_root_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    instance[layout.inst_root_off] ^= 0x01;

    /* Tamper: witness FWK byte (breaks the leaf hash). */
    witness[layout.fwk_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    witness[layout.fwk_off] ^= 0x01;

    /* Tamper: a sibling byte (breaks the path), when there is a path. */
    if (depth > 0) {
        witness[layout.siblings_off] ^= 0x01;
        if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
            goto done;
        witness[layout.siblings_off] ^= 0x01;
    }

    /* Restored tuple verifies again. */
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 1)
        goto done;

    ok = 1;

done:
    if (c != NULL)
        voleith_gf8_circuit_free(c);
    free(digests);
    free(siblings);
    free(witness);
    free(instance);
    free(wire_vals);
    return ok;
}

/*
 * Secret-index variant: same genuine-tuple acceptance plus the secret-dir
 * soundness tampers (a flipped direction bit or committed-index byte must
 * break indexed-consistency, a non-boolean direction must break booleanity).
 * Returns 1 on full success, 0 on any failure.
 */
static int
run_case_secret(voleith_rs_cr_profile_t cr, size_t n, size_t index)
{
    const voleith_node_hash_vt *vt = voleith_rs_chunk_node_vt(cr);
    size_t W, digb, fwkb, depth, wirec;
    uint8_t fwk[32];
    uint8_t root[64];
    uint8_t *digests = NULL, *siblings = NULL;
    uint8_t *witness = NULL, *instance = NULL, *wire_vals = NULL;
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_chunk_cert_layout_t layout;
    int ok = 0;

    if (vt == NULL)
        return 0;
    W = vt->node_bytes;
    digb = voleith_rs_cr_digest_bytes(cr);
    fwkb = voleith_rs_fwk_bytes(cr);
    depth = voleith_rs_tree_depth_for_n(n);

    for (size_t i = 0; i < fwkb; i++)
        fwk[i] = (uint8_t)(0x5C + i);

    digests = calloc(n, digb);
    if (digests == NULL)
        goto done;
    for (size_t i = 0; i < n; i++) {
        uint8_t chunk[32];
        for (size_t j = 0; j < sizeof(chunk); j++)
            chunk[j] = (uint8_t)(i * 11u + j + 3u);
        if (voleith_rs_chunk_digest(cr, chunk, sizeof(chunk),
                                    digests + i * digb, digb) != VOLEITH_EC_OK)
            goto done;
    }

    if (voleith_rs_tree_root(cr, fwk, digests, n, root, sizeof(root)) !=
        VOLEITH_EC_OK)
        goto done;

    if (depth > 0) {
        siblings = calloc(depth, W);
        if (siblings == NULL)
            goto done;
        if (voleith_rs_tree_sibling_path(cr, fwk, digests, n, index, siblings,
                                         depth * W) != VOLEITH_EC_OK)
            goto done;
    }

    c = voleith_gf8_circuit_new();
    if (c == NULL)
        goto done;
    if (voleith_rs_chunk_cert_build_circuit_secret_dir(c, cr, n, &layout) != 0)
        goto done;
    if (!voleith_gf8_circuit_ok(c) || voleith_gf8_circuit_validate(c) != 0)
        goto done;
    if (!layout.secret_dir || layout.dirs_bytes != depth ||
        layout.witness_bytes != voleith_gf8_circuit_witness_count(c) ||
        layout.instance_bytes != W + digb)
        goto done;

    instance = calloc(layout.instance_bytes, 1);
    if (instance == NULL)
        goto done;
    memcpy(instance + layout.inst_root_off, root, W);
    memcpy(instance + layout.inst_digest_off, digests + index * digb, digb);

    witness = calloc(layout.witness_bytes, 1);
    if (witness == NULL)
        goto done;
    if (voleith_rs_chunk_cert_build_witness_secret_dir(
            cr, n, index, fwk, digests + index * digb, siblings, &layout,
            witness) != 0)
        goto done;

    wirec = voleith_gf8_circuit_wire_count(c);
    wire_vals = calloc(wirec, 1);
    if (wire_vals == NULL)
        goto done;

    /* Genuine tuple verifies (index hidden in the witness). */
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 1)
        goto done;

    /* Tamper: instance chunk_digest / merkle_root / witness FWK. */
    instance[layout.inst_digest_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    instance[layout.inst_digest_off] ^= 0x01;

    instance[layout.inst_root_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    instance[layout.inst_root_off] ^= 0x01;

    witness[layout.fwk_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    witness[layout.fwk_off] ^= 0x01;

    /* Tamper: committed-index byte (breaks indexed-consistency + leaf). */
    witness[layout.index_off] ^= 0x01;
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
        goto done;
    witness[layout.index_off] ^= 0x01;

    if (depth > 0) {
        /* Tamper: sibling. */
        witness[layout.siblings_off] ^= 0x01;
        if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
            goto done;
        witness[layout.siblings_off] ^= 0x01;

        /* Soundness: a direction bit diverging from the committed index must
         * fail indexed-consistency (position cannot diverge from index). */
        witness[layout.dirs_off] ^= 0x01;
        if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
            goto done;
        witness[layout.dirs_off] ^= 0x01;

        /* Soundness: a non-boolean direction must fail booleanity. */
        {
            uint8_t save = witness[layout.dirs_off];
            witness[layout.dirs_off] = 0x02;
            if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 0)
                goto done;
            witness[layout.dirs_off] = save;
        }
    }

    /* Restored tuple verifies again. */
    if (voleith_gf8_circuit_eval(c, witness, instance, wire_vals) != 1)
        goto done;

    ok = 1;

done:
    if (c != NULL)
        voleith_gf8_circuit_free(c);
    free(digests);
    free(siblings);
    free(witness);
    free(instance);
    free(wire_vals);
    return ok;
}

int
main(void)
{
    struct {
        voleith_rs_cr_profile_t cr;
        size_t n;
        size_t index;
        const char *name;
    } cases[] = {
        {VOLEITH_RS_CR_128, 1, 0, "CR-128 n=1 idx=0 (depth 0)"},
        {VOLEITH_RS_CR_128, 5, 3, "CR-128 n=5 idx=3 (depth 3)"},
        {VOLEITH_RS_CR_128, 100, 42, "CR-128 n=100 idx=42 (depth 7)"},
        {VOLEITH_RS_CR_128, 256, 255, "CR-128 n=256 idx=255 (depth 8)"},
        {VOLEITH_RS_CR_256, 20, 7, "CR-256 n=20 idx=7 (depth 5)"},
        {VOLEITH_RS_CR_256, 128, 100, "CR-256 n=128 idx=100 (depth 7)"},
    };
    size_t ncases = sizeof(cases) / sizeof(cases[0]);

    struct {
        voleith_rs_cr_profile_t cr;
        size_t n;
        size_t index;
        const char *name;
    } secret_cases[] = {
        {VOLEITH_RS_CR_128, 1, 0, "secret CR-128 n=1 idx=0 (depth 0)"},
        {VOLEITH_RS_CR_128, 5, 3, "secret CR-128 n=5 idx=3 (depth 3)"},
        {VOLEITH_RS_CR_128, 100, 42, "secret CR-128 n=100 idx=42 (depth 7)"},
        {VOLEITH_RS_CR_128, 256, 255, "secret CR-128 n=256 idx=255 (depth 8)"},
        {VOLEITH_RS_CR_256, 20, 7, "secret CR-256 n=20 idx=7 (depth 5)"},
    };
    size_t nsecret = sizeof(secret_cases) / sizeof(secret_cases[0]);

    printf("=== RS chunk membership certificate circuit tests ===\n");

    for (size_t i = 0; i < ncases; i++) {
        TEST(cases[i].name);
        if (run_case(cases[i].cr, cases[i].n, cases[i].index))
            PASS();
        else
            FAIL("eval/binding");
    }

    for (size_t i = 0; i < nsecret; i++) {
        TEST(secret_cases[i].name);
        if (run_case_secret(secret_cases[i].cr, secret_cases[i].n,
                            secret_cases[i].index))
            PASS();
        else
            FAIL("eval/binding/soundness");
    }

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
