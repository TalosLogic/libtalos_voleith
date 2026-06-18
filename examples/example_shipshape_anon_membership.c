/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_shipshape_anon_membership.c - anonymous group MEMBERSHIP proof
 * (a secret-direction Merkle inclusion proof) expressed in the Shipshape
 * `.ship` format.
 *
 * This is one building block, not a full KVAC credential system: it proves
 * inclusion only.  KVAC-style lifecycle management (issuing members, revoking
 * them, proving non-membership) is shown in example_shipshape_kvac.
 *
 * Claim proved: "I know a credential that is a leaf of the public group tree,
 * without revealing which leaf."  The membership statement is loaded from
 * tests/data/shipshape/anon_membership_hirose.ship, which uses the crypto-v2
 * construction stdlib/crypto/merkle/path_secret[hirose_fixed_32].
 *
 * Privacy model: the leaf credential, the sibling path, and the per-level
 * directions are ALL witness (private).  Only the group root is public
 * (INSTANCE).  Because the directions are secret, the path shape leaks nothing,
 * so distinct membership proofs are unlinkable: nothing but the root is
 * revealed.
 *
 * Hash choice: hirose_fixed_32 uses 32-byte nodes (128-bit collision
 * resistance) with a fixed 32-byte single-block leaf record for minimal proving
 * cost.
 *
 * Tree depth: 8 (256-leaf group).  The node width is fixed at 32 bytes by
 * hirose_fixed_32, so depth scales by changing only the sibling and direction
 * widths: for depth D, sib = D * 32 bytes, dirs = D bytes, N_LEAVES = 2^D, and
 * ext = 32 + D * 32 + D.  The .ship %sib / %dirs widths must match D; %leaf,
 * %root, and the 32 ASSERT_EQUAL lines are depth-independent (the root is one
 * 32-byte node).  Proving cost is linear in D (one hirose inode hash per level).
 *
 *   ./example_shipshape_anon_membership [path/to/file.ship]
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "shipshape.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VOLEITH_SHIPSHAPE_DATA_DIR
#define VOLEITH_SHIPSHAPE_DATA_DIR "tests/data/shipshape"
#endif

/* Tree shape: depth 8 (256-leaf group); the secret member sits at index 100.
 * The node width is fixed at 32 bytes (hirose_fixed_32), so depth scales by
 * changing only MEM_DEPTH: sib = MEM_DEPTH * 32, dirs = MEM_DEPTH,
 * N_LEAVES = 2^MEM_DEPTH, ext = 32 + MEM_DEPTH * 32 + MEM_DEPTH. */
#define MEM_DEPTH 8
#define MEM_N_LEAVES (1u << MEM_DEPTH)
#define MEMBER_INDEX 100u

int
main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1]
                                  : VOLEITH_SHIPSHAPE_DATA_DIR
                           "/anon_membership_hirose.ship";
    const voleith_params_t *params = &voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose_fixed32;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t member_cred[32];
    uint8_t leaf_secret[32]; /* scratch for each non-member leaf secret */
    uint8_t *leaf_nodes =
        NULL; /* MEM_N_LEAVES * 32 = 8 KiB: heap (grows with depth) */
    uint8_t sib[MEM_DEPTH * 32]; /* 256 bytes */
    uint8_t dirs[MEM_DEPTH];
    uint8_t root[32];
    uint8_t ext[32 + MEM_DEPTH * 32 + MEM_DEPTH]; /* leaf | sib | dirs = 296 */
    uint8_t fs_seed[16];
    uint8_t *witness = NULL;
    size_t witness_len = 0;
    size_t node_bytes = 32;
    size_t ext_len, inst_count;
    size_t i;
    int rc = 1;
    int tamper_detected = 0;
    int r;

    printf("Shipshape anonymous membership example\n");
    printf("  file: %s\n\n", path);

    /* 1. Parse the .ship file into a GF(2^8) circuit. */
    r = voleith_shipshape_parse_file(&p, path, NULL);
    if (r != 0 || p.circuit == NULL) {
        fprintf(stderr, "parse failed (%d): %s\n", r, path);
        return 1;
    }

    printf("Parsed circuit:\n");
    printf("  wires:        %zu\n", voleith_gf8_circuit_wire_count(p.circuit));
    printf("  witness:      %zu\n",
           voleith_gf8_circuit_witness_count(p.circuit));
    printf("  instance:     %zu\n",
           voleith_gf8_circuit_instance_count(p.circuit));
    printf("  gates:        %zu\n", voleith_gf8_circuit_gate_count(p.circuit));
    printf("  nonlinear mul:%zu\n", voleith_gf8_circuit_mul_count(p.circuit));
    printf("  constraints:  %zu\n\n",
           voleith_gf8_circuit_constraint_count(p.circuit));

    /* Confirm the file matches the depth-8 hirose_fixed_32 membership layout. */
    ext_len = voleith_shipshape_external_witness_len(&p);
    inst_count = voleith_gf8_circuit_instance_count(p.circuit);
    if (ext_len != sizeof(ext) || inst_count != node_bytes) {
        fprintf(stderr,
                "circuit layout is not depth-8 hirose anonymous membership "
                "(external witness %zu != %zu or instance %zu != %zu)\n",
                ext_len, sizeof(ext), inst_count, node_bytes);
        goto out;
    }

    /*
     * 2. Build the public group tree with the hirose_fixed_32 vt.
     *
     * The secret member credential is the RAW 32-byte preimage; the
     * construction hashes it into a leaf internally.  Every other leaf secret
     * is derived from its index so the tree is non-trivial.  leaf_nodes
     * (MEM_N_LEAVES * 32) lives on the heap (calloc) so it scales with depth.
     */
    leaf_nodes = calloc(MEM_N_LEAVES, 32);
    if (leaf_nodes == NULL) {
        fprintf(stderr, "leaf_nodes alloc failed\n");
        goto out;
    }
    memset(member_cred, 0xA5, sizeof(member_cred));
    for (i = 0; i < MEM_N_LEAVES; i++) {
        if (i == MEMBER_INDEX) {
            if (vt->leaf_hash(member_cred, 32, &leaf_nodes[i * 32]) != 0) {
                fprintf(stderr, "leaf_hash failed (member)\n");
                goto out;
            }
            continue;
        }
        /* Distinct 32-byte secret per leaf (both index bytes mixed in). */
        memset(leaf_secret, (uint8_t)(0x10 + (i & 0xff)), sizeof(leaf_secret));
        leaf_secret[0] = (uint8_t)(i & 0xff);
        leaf_secret[1] = (uint8_t)((i >> 8) & 0xff);
        if (vt->leaf_hash(leaf_secret, 32, &leaf_nodes[i * 32]) != 0) {
            fprintf(stderr, "leaf_hash failed (leaf %zu)\n", i);
            voleith_secure_zero(leaf_secret, sizeof(leaf_secret));
            goto out;
        }
    }
    voleith_secure_zero(leaf_secret, sizeof(leaf_secret));

    /* Sibling path for the member, plus the public root. */
    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, MEM_N_LEAVES,
                                       MEMBER_INDEX, sib) != 0) {
        fprintf(stderr, "compute_path failed\n");
        goto out;
    }
    if (voleith_merkle_vt_build(vt, leaf_nodes, MEM_N_LEAVES, root) != 0) {
        fprintf(stderr, "merkle build failed\n");
        goto out;
    }

    /* dirs[k] = bit k of the leaf index, LSB first (MEM_DEPTH bits). */
    for (i = 0; i < MEM_DEPTH; i++)
        dirs[i] = (uint8_t)((MEMBER_INDEX >> i) & 1);

    /* 3. Assemble ext in declaration order: leaf(32) | sib(384) | dirs(12). */
    memcpy(ext + 0, member_cred, 32);
    memcpy(ext + 32, sib, MEM_DEPTH * 32);
    memcpy(ext + 32 + MEM_DEPTH * 32, dirs, MEM_DEPTH);

    /*
     * 4. Register the W8 Tier 2a native hirose construction backend so witness
     * dispatch uses the fast path.  The generic Tier 1 evaluator is an
     * always-correct fallback when no backend is registered (the W8
     * fail-closed speed layer).
     */
    voleith_shipshape_witgen_reset();
    if (voleith_shipshape_witgen_register_constructions() != 0) {
        fprintf(stderr, "register_constructions failed\n");
        goto out;
    }
    printf("Tier 2a native hirose backend: registered (witness dispatch "
           "active)\n");

    /* 5. Generate the full witness from the external input. */
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, node_bytes,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &witness, &witness_len);
    if (r != 0) {
        fprintf(stderr, "witness generation failed (%d)\n", r);
        goto out;
    }
    printf("Generated witness: %zu bytes\n", witness_len);

    /* 6. Prove. */
    memset(fs_seed, 0x5A, sizeof(fs_seed));
    r = voleith_gf8_prove_v2(&proof, params, p.circuit, witness, witness_len,
                             root, node_bytes, fs_seed, sizeof(fs_seed));
    if (r != 0) {
        fprintf(stderr, "prove failed (%d)\n", r);
        goto out_witness;
    }
    printf("Proof:             %zu bytes\n\n", proof.len);

    /* 7. Verify. */
    r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, node_bytes,
                              fs_seed, sizeof(fs_seed));
    printf("Verification: %s\n", r == 0 ? "PASS" : "FAIL");

    /* 8. Tamper check: flip proof byte 0; verify must reject. */
    if (r == 0) {
        proof.data[0] ^= 0xFF;
        r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, node_bytes,
                                  fs_seed, sizeof(fs_seed));
        tamper_detected = (r != 0);
        proof.data[0] ^= 0xFF;
        printf("Tamper detection: %s\n", tamper_detected ? "PASS" : "FAIL");

        /* Overall success requires a clean verify AND a detected tamper. */
        rc = tamper_detected ? 0 : 1;
    } else {
        rc = 1;
    }

    voleith_proof_free(&proof);

out_witness:
    voleith_secure_zero(witness, witness_len);
    free(witness);
out:
    voleith_secure_zero(member_cred, sizeof(member_cred));
    free(leaf_nodes);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
    return rc;
}
