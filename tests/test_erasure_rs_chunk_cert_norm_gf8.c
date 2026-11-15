/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs_chunk_cert_norm_gf8.c - norm-S-box node-hash selection in
 * the RS chunk-membership certificate.
 *
 * The chunk tree's node hash used to be hardcoded per CR profile
 * (grostl256_fixed / grostl512_fixed).  It is now a caller-supplied
 * conforming vt (NULL = the profile default), so a caller can build and
 * prove a chunk-cert tree on the norm twin.  This test exercises that
 * selection at eval level (the vt-test convention: circuit_eval
 * satisfaction, not a full prove/verify):
 *
 *   - the norm twin yields a BYTE-IDENTICAL Merkle root to the frozen
 *     default (same hash output, different circuit),
 *   - the norm cert circuit + witness satisfy circuit_eval,
 *   - a tampered witness byte is rejected,
 *   - a non-conforming vt (wrong node width / strength) is rejected.
 *
 * Grostl fixed norm twins only (CR_128 -> grostl256_fixed_norm, CR_256 ->
 * grostl512_fixed_norm); these are the node hashes the chunk tree uses.
 */

#include "rs_chunk_cert_circuit.h"
#include "rs_membership.h"

#include "gf8_circuit.h"
#include "node_hash_vt.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_CHUNKS 5u
#define TARGET 2u

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* One eval-level pass for (cr, norm vt).  Returns on first hard failure. */
static void
run_case(const char *label, voleith_rs_cr_profile_t cr,
         const voleith_node_hash_vt *norm_vt)
{
    char name[96];
    size_t fwkb = voleith_rs_fwk_bytes(cr);
    size_t digb = voleith_rs_cr_digest_bytes(cr);
    size_t W = norm_vt->node_bytes;
    size_t depth = voleith_rs_tree_depth_for_n(N_CHUNKS);
    uint8_t fwk[32];
    uint8_t *digests = NULL, *siblings = NULL, *witness = NULL,
            *instance = NULL;
    uint8_t *wires = NULL;
    uint8_t root_norm[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t root_def[MERKLE_VT_MAX_NODE_BYTES];
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_chunk_cert_layout_t layout;

    assert(fwkb <= sizeof(fwk));
    for (size_t i = 0; i < fwkb; i++)
        fwk[i] = (uint8_t)(0x40u + i);

    /* Deterministic chunk digests. */
    digests = calloc(N_CHUNKS, digb);
    assert(digests != NULL);
    for (size_t i = 0; i < N_CHUNKS; i++) {
        uint8_t chunk[16];
        for (size_t j = 0; j < sizeof(chunk); j++)
            chunk[j] = (uint8_t)(i * 17u + j);
        if (voleith_rs_chunk_digest(cr, chunk, sizeof(chunk),
                                    digests + i * digb,
                                    digb) != VOLEITH_EC_OK) {
            check("chunk_digest", 0);
            goto done;
        }
    }

    /* Root parity: norm twin vs profile default produce the same root. */
    if (voleith_rs_tree_root(cr, norm_vt, fwk, digests, N_CHUNKS, root_norm,
                             sizeof(root_norm)) != VOLEITH_EC_OK ||
        voleith_rs_tree_root(cr, NULL, fwk, digests, N_CHUNKS, root_def,
                             sizeof(root_def)) != VOLEITH_EC_OK) {
        check("tree_root", 0);
        goto done;
    }
    snprintf(name, sizeof(name), "%s: norm root == default root", label);
    check(name, memcmp(root_norm, root_def, W) == 0);

    /* Sibling path for the target, built with the norm vt. */
    siblings = calloc(depth ? depth : 1, W);
    assert(siblings != NULL);
    if (voleith_rs_tree_sibling_path(cr, norm_vt, fwk, digests, N_CHUNKS,
                                     TARGET, siblings,
                                     depth * W) != VOLEITH_EC_OK) {
        check("sibling_path", 0);
        goto done;
    }

    /* Build the norm cert circuit + witness and eval. */
    c = voleith_gf8_circuit_new();
    assert(c != NULL);
    if (voleith_rs_chunk_cert_build_circuit(c, cr, norm_vt, N_CHUNKS, TARGET,
                                            &layout) != 0) {
        check("build_circuit(norm)", 0);
        goto done;
    }

    witness = calloc(layout.witness_bytes, 1);
    instance = calloc(layout.instance_bytes, 1);
    assert(witness && instance);
    if (voleith_rs_chunk_cert_build_witness(cr, norm_vt, N_CHUNKS, TARGET, fwk,
                                            digests + TARGET * digb, siblings,
                                            &layout, witness) != 0) {
        check("build_witness(norm)", 0);
        goto done;
    }
    memcpy(instance + layout.inst_root_off, root_norm, layout.inst_root_bytes);
    memcpy(instance + layout.inst_digest_off, digests + TARGET * digb,
           layout.inst_digest_bytes);

    wires = calloc(voleith_gf8_circuit_wire_count(c), 1);
    assert(wires != NULL);

    snprintf(name, sizeof(name), "%s: norm witness satisfies circuit", label);
    check(name, voleith_gf8_circuit_eval(c, witness, instance, wires) == 1);

    /* Tamper a witness byte (first FWK byte): eval must reject. */
    witness[layout.fwk_off] ^= 0x01;
    snprintf(name, sizeof(name), "%s: tampered witness rejected", label);
    check(name, voleith_gf8_circuit_eval(c, witness, instance, wires) == 0);
    witness[layout.fwk_off] ^= 0x01;

done:
    free(digests);
    free(siblings);
    free(witness);
    free(instance);
    free(wires);
    voleith_gf8_circuit_free(c);
}

/*
 * A non-conforming vt (wrong node width / strength for the profile) is
 * rejected by the resolver.  aes-dm is 16-byte / 64-bit CR, which matches
 * neither CR_128 (32-byte / 128-bit) nor CR_256.
 */
static void
test_conformance_rejection(void)
{
    check("resolve: NULL -> profile default (CR_128)",
          voleith_rs_chunk_node_vt_resolve(VOLEITH_RS_CR_128, NULL) ==
              &voleith_node_hash_grostl256_fixed);
    check("resolve: NULL -> profile default (CR_256)",
          voleith_rs_chunk_node_vt_resolve(VOLEITH_RS_CR_256, NULL) ==
              &voleith_node_hash_grostl512_fixed);

    check("resolve: conforming norm twin accepted (CR_128)",
          voleith_rs_chunk_node_vt_resolve(
              VOLEITH_RS_CR_128, &voleith_node_hash_grostl256_fixed_norm) ==
              &voleith_node_hash_grostl256_fixed_norm);

    check("resolve: wrong-width vt rejected (CR_128 vs aes-dm 16B)",
          voleith_rs_chunk_node_vt_resolve(VOLEITH_RS_CR_128,
                                           &voleith_node_hash_aes_dm) == NULL);
    check("resolve: wrong-width vt rejected (CR_256 vs grostl256 32B)",
          voleith_rs_chunk_node_vt_resolve(
              VOLEITH_RS_CR_256, &voleith_node_hash_grostl256_fixed_norm) ==
              NULL);
}

int
main(void)
{
    printf("test_erasure_rs_chunk_cert_norm_gf8: starting\n");
    run_case("grostl256-fixed", VOLEITH_RS_CR_128,
             &voleith_node_hash_grostl256_fixed_norm);
    run_case("grostl512-fixed", VOLEITH_RS_CR_256,
             &voleith_node_hash_grostl512_fixed_norm);
    test_conformance_rejection();
    printf("test_erasure_rs_chunk_cert_norm_gf8: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
