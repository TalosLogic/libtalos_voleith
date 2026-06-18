/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_shipshape_ring_sig.c - RSv1 ring SIGNATURE expressed in the
 * Shipshape `.ship` format and driven through a parsed GF(2^8) circuit.
 *
 * This is the .ship-driven equivalent of the C-API example
 * example_ring_sig_v1_gf8.c.  Where that example wires up the RSv1 layer
 * directly through the C ring-signature API, this one loads the same
 * statement from tests/data/shipshape/ring_sig_v1_hirose.ship and proves it
 * via the generic Shipshape witness generator + prover.
 *
 * Statement proved: "I am one of N enrolled members in the ring whose public
 * root is R (a depth-d secret-direction Merkle tree under hirose_fixed_32),
 * and I am binding the message m to this signature via Fiat-Shamir."
 *
 * Anonymity: the signer's per-level directions are secret (witness), so the
 * proof reveals nothing about WHICH member produced it.  Any of the N members
 * could have made it; the verifier cannot tell which.  That hidden signer
 * index is exactly what distinguishes a ring signature from a named one.
 *
 * Message binding (the signature property): the message m is NOT a circuit
 * wire.  The proof's Fiat-Shamir seed is derived from m via
 *   fs_seed = first 16 bytes of sha3_256(m).
 * A proof made under fs_seed(m) does not verify under a seed derived from any
 * other message m'.  The message-tamper step below flips one byte of m,
 * re-derives the seed, and verifies the SAME proof against it: that verify
 * MUST reject.  Fiat-Shamir non-malleability over m is what makes this a
 * signature rather than a bare membership proof.
 *
 * Privacy model: sk, dirs, and sib are all witness (private); only the ring
 * root is public (INSTANCE).  The root is asserted internally by the
 * ring_sig/v1 construction (assertion-only entry), so there is no ASSERT_EQUAL
 * block in the .ship file.
 *
 * Hash choice: ring_sig/v1[hirose_fixed_32] uses 32-byte nodes (128-bit
 * collision resistance).  The secret key IS the signer's leaf record: sk_bytes
 * is frozen at 32 (fixed_leaf_bytes = 32) and node_bytes = 32.
 *
 *   ./example_shipshape_ring_sig [path/to/file.ship]
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "hash.h"
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

/*
 * Ring shape: depth 5 (32-member ring); the hidden signer sits at index 5.
 * The node width is fixed at 32 bytes (hirose_fixed_32, sk_bytes frozen at
 * 32), so depth scales by changing only RING_DEPTH: sib = RING_DEPTH * 32,
 * dirs = RING_DEPTH, N_MEMBERS = 2^RING_DEPTH.
 *
 * ext (declaration order) = sk(32) | dirs(RING_DEPTH) | sib(RING_DEPTH * 32).
 * The root (32 bytes) is the INSTANCE and is NOT part of ext.  For depth 5:
 *   ext = 32 + 5 + 160 = 197 bytes.
 */
#define RING_DEPTH 5
#define RING_N_MEMBERS (1u << RING_DEPTH)
#define SIGNER_INDEX 5u
#define RING_NODE_BYTES 32u
#define RING_SK_BYTES 32u
#define RING_EXT_LEN (RING_SK_BYTES + RING_DEPTH + RING_DEPTH * RING_NODE_BYTES)

int
main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1]
                                  : VOLEITH_SHIPSHAPE_DATA_DIR
                           "/ring_sig_v1_hirose.ship";
    const voleith_params_t *params = &voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose_fixed32;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t sk[RING_SK_BYTES];
    uint8_t leaf_secret[RING_SK_BYTES]; /* scratch for each non-signer leaf */
    uint8_t *leaf_nodes = NULL;         /* RING_N_MEMBERS * 32 on the heap */
    uint8_t sib[RING_DEPTH * RING_NODE_BYTES]; /* 160 bytes */
    uint8_t dirs[RING_DEPTH];
    uint8_t root[RING_NODE_BYTES]; /* 32 bytes */
    uint8_t ext[RING_EXT_LEN];     /* sk | dirs | sib = 197 */
    uint8_t digest[32];
    uint8_t fs_seed[16];
    uint8_t *witness = NULL;
    size_t witness_len = 0;
    size_t node_bytes = RING_NODE_BYTES;
    size_t ext_len, inst_count;
    size_t i;
    int rc = 1;
    int sig_ok = 0;
    int tamper_ok = 0;
    int r;

    /*
     * The message the signature binds.  It is hashed into the Fiat-Shamir seed
     * below; it never becomes a circuit wire.
     */
    static const uint8_t message[] = "ring-sig over this message";
    const size_t message_len = sizeof(message) - 1;

    printf("Shipshape RSv1 ring signature example\n");
    printf("  file:   %s\n", path);
    printf("  ring:   %u members, depth %d (signer index %u, hidden)\n\n",
           (unsigned)RING_N_MEMBERS, RING_DEPTH, (unsigned)SIGNER_INDEX);

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

    /* Confirm the file matches the depth-5 hirose_fixed_32 ring layout. */
    ext_len = voleith_shipshape_external_witness_len(&p);
    inst_count = voleith_gf8_circuit_instance_count(p.circuit);
    if (ext_len != sizeof(ext) || inst_count != node_bytes) {
        fprintf(stderr,
                "circuit layout is not depth-5 hirose ring signature "
                "(external witness %zu != %zu or instance %zu != %zu)\n",
                ext_len, sizeof(ext), inst_count, node_bytes);
        goto out;
    }

    /*
     * 2. Enroll the ring.
     *
     * The signer's secret key sk is the RAW 32-byte preimage; the construction
     * hashes it into the signer's leaf node internally.  We build the same leaf
     * here (vt->leaf_hash) so we can compute the public root and the signer's
     * authentication path.  Every other member's leaf secret is derived from
     * its index so the tree is non-trivial.  leaf_nodes (RING_N_MEMBERS * 32)
     * lives on the heap (calloc) so it scales with depth.
     */
    leaf_nodes = calloc(RING_N_MEMBERS, RING_NODE_BYTES);
    if (leaf_nodes == NULL) {
        fprintf(stderr, "leaf_nodes alloc failed\n");
        goto out;
    }
    memset(sk, 0x2B, sizeof(sk));
    for (i = 0; i < RING_N_MEMBERS; i++) {
        if (i == SIGNER_INDEX) {
            if (vt->leaf_hash(sk, RING_SK_BYTES,
                              &leaf_nodes[i * RING_NODE_BYTES]) != 0) {
                fprintf(stderr, "leaf_hash failed (signer)\n");
                goto out;
            }
            continue;
        }
        /* Distinct 32-byte secret per member (both index bytes mixed in). */
        memset(leaf_secret, (uint8_t)(0x10 + (i & 0xff)), sizeof(leaf_secret));
        leaf_secret[0] = (uint8_t)(i & 0xff);
        leaf_secret[1] = (uint8_t)((i >> 8) & 0xff);
        if (vt->leaf_hash(leaf_secret, RING_SK_BYTES,
                          &leaf_nodes[i * RING_NODE_BYTES]) != 0) {
            fprintf(stderr, "leaf_hash failed (member %zu)\n", i);
            voleith_secure_zero(leaf_secret, sizeof(leaf_secret));
            goto out;
        }
    }
    voleith_secure_zero(leaf_secret, sizeof(leaf_secret));

    /* 3. Signer authentication path, public ring root, and direction bits. */
    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, RING_N_MEMBERS,
                                       SIGNER_INDEX, sib) != 0) {
        fprintf(stderr, "compute_path failed\n");
        goto out;
    }
    if (voleith_merkle_vt_build(vt, leaf_nodes, RING_N_MEMBERS, root) != 0) {
        fprintf(stderr, "merkle build failed\n");
        goto out;
    }
    /* dirs[k] = bit k of the signer index, LSB first (RING_DEPTH bits). */
    for (i = 0; i < RING_DEPTH; i++)
        dirs[i] = (uint8_t)((SIGNER_INDEX >> i) & 1);

    /*
     * 4. Assemble ext in declaration order: sk(32) | dirs(5) | sib(160).
     * The root is the INSTANCE and is NOT part of ext.
     */
    memcpy(ext + 0, sk, RING_SK_BYTES);
    memcpy(ext + RING_SK_BYTES, dirs, RING_DEPTH);
    memcpy(ext + RING_SK_BYTES + RING_DEPTH, sib, RING_DEPTH * RING_NODE_BYTES);

    /*
     * 5. Register the W8 Tier 2a native hirose construction backend so witness
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

    /*
     * 6. Message binding.  Derive the Fiat-Shamir seed from the message:
     * fs_seed = first 16 bytes of sha3_256(message).  Generate the witness,
     * then prove with that seed so the proof is bound to this message.
     */
    voleith_sha3_256(digest, message, message_len);
    memcpy(fs_seed, digest, sizeof(fs_seed));

    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, node_bytes,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &witness, &witness_len);
    if (r != 0) {
        fprintf(stderr, "witness generation failed (%d)\n", r);
        goto out;
    }
    printf("Generated witness: %zu bytes\n", witness_len);

    r = voleith_gf8_prove_v2(&proof, params, p.circuit, witness, witness_len,
                             root, node_bytes, fs_seed, sizeof(fs_seed));
    if (r != 0) {
        fprintf(stderr, "prove failed (%d)\n", r);
        goto out_witness;
    }
    printf("Signature (proof): %zu bytes\n\n", proof.len);

    /* 7. Verify the signature under the message-derived seed. */
    r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, node_bytes,
                              fs_seed, sizeof(fs_seed));
    sig_ok = (r == 0);
    printf("Signature verifies: %s\n", sig_ok ? "PASS" : "FAIL");

    /*
     * 8. Message-tamper (the RSv1 headline).  Flip one byte of m, re-derive the
     * Fiat-Shamir seed from the tampered message, and verify the SAME proof
     * against it.  It MUST reject: a proof made under fs_seed(m) does not
     * verify under fs_seed(m').  This shows Fiat-Shamir binds the message.
     */
    if (sig_ok) {
        uint8_t tampered[sizeof(message)];
        uint8_t digest2[32];
        uint8_t fs_seed2[16];

        memcpy(tampered, message, message_len);
        tampered[0] ^= 0x01;
        voleith_sha3_256(digest2, tampered, message_len);
        memcpy(fs_seed2, digest2, sizeof(fs_seed2));

        r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, node_bytes,
                                  fs_seed2, sizeof(fs_seed2));
        tamper_ok = (r != 0);
        printf("Tampered-message signature rejected: %s\n",
               tamper_ok ? "PASS" : "FAIL");
    }

    /* Overall success requires a clean verify AND a rejected tampered verify. */
    rc = (sig_ok && tamper_ok) ? 0 : 1;

    voleith_proof_free(&proof);

out_witness:
    voleith_secure_zero(witness, witness_len);
    free(witness);
out:
    voleith_secure_zero(sk, sizeof(sk));
    free(leaf_nodes);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
    return rc;
}
