/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v2_equiv.c - Equivalence tests for hash-parametric
 * registry entries (MR4 / 4a of SHIPSHAPE_CRYPTO_V2_SECRETDIR_IMPL_PLAN.md).
 *
 * For each tested entry + type combination, a minimal `stdlib crypto-v2`
 * `.ship` file is parsed and its lowered circuit is compared
 * BYTE-FOR-BYTE against the same circuit built by the hand-written C vt
 * builder: wire-table and constraint-table counts, then every entry's
 * kind / inputs / constant / matrix in order, then the 16-byte
 * fingerprint.  This pins the lowered tables against the C builders so
 * any divergence (wrong wire order, wrong builder call, wrong inliner
 * argument slice) is caught structurally, not just by hash.
 *
 * Entries tested:
 *   merkle/path_secret[grostl_256]   (node=32, depth=2, L=32)
 *   ring_sig/v1[aes_dm]              (node=16, depth=2, sk=16)
 *   indexed_merkle/nonmember_secret[aes_dm]  (node=16, depth=2, tb=8, ib=8)
 *
 * The `ref` circuit mirrors the wire declaration order of the .ship source
 * EXACTLY: witness wires are added in top-to-bottom declaration order, then
 * instance wires (INSTANCE lines), then the C vt builder is called.  This
 * matches what the parser produces when it lowers the .ship body.
 */

#include "gf8_circuit.h"
#include "gf8_circuit_fingerprint.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "shipshape.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

/* crypto-v2 header used for all sources in this file. */
#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/* Equal wire-, witness-, instance-, gate-, mul-, and constraint-counts. */
static int
counts_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    return voleith_gf8_circuit_wire_count(a) ==
               voleith_gf8_circuit_wire_count(b) &&
           voleith_gf8_circuit_witness_count(a) ==
               voleith_gf8_circuit_witness_count(b) &&
           voleith_gf8_circuit_instance_count(a) ==
               voleith_gf8_circuit_instance_count(b) &&
           voleith_gf8_circuit_gate_count(a) ==
               voleith_gf8_circuit_gate_count(b) &&
           voleith_gf8_circuit_mul_count(a) ==
               voleith_gf8_circuit_mul_count(b) &&
           voleith_gf8_circuit_constraint_count(a) ==
               voleith_gf8_circuit_constraint_count(b) &&
           voleith_gf8_circuit_assert_product_count(a) ==
               voleith_gf8_circuit_assert_product_count(b);
}

/* Every wire entry equal in order: kind, both inputs, constant, matrix. */
static int
wires_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    const gf8_wire_entry_t *wa = voleith_gf8_circuit_wires(a);
    const gf8_wire_entry_t *wb = voleith_gf8_circuit_wires(b);
    size_t n = voleith_gf8_circuit_wire_count(a);

    if (n != voleith_gf8_circuit_wire_count(b))
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (wa[i].kind != wb[i].kind || wa[i].a != wb[i].a ||
            wa[i].b != wb[i].b || wa[i].const_val != wb[i].const_val ||
            memcmp(wa[i].matrix, wb[i].matrix, sizeof(wa[i].matrix)) != 0)
            return 0;
    }
    return 1;
}

/* Every constraint entry equal in order: kind, a, b, c. */
static int
constraints_equal(const voleith_gf8_circuit_t *a,
                  const voleith_gf8_circuit_t *b)
{
    const gf8_constraint_entry_t *ca = voleith_gf8_circuit_constraints(a);
    const gf8_constraint_entry_t *cb = voleith_gf8_circuit_constraints(b);
    size_t n = voleith_gf8_circuit_constraint_count(a);

    if (n != voleith_gf8_circuit_constraint_count(b))
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (ca[i].kind != cb[i].kind || ca[i].a != cb[i].a ||
            ca[i].b != cb[i].b || ca[i].c != cb[i].c)
            return 0;
    }
    return 1;
}

static int
fp_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    uint8_t fa[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fb[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    if (voleith_gf8_circuit_fingerprint(a, fa) != 0 ||
        voleith_gf8_circuit_fingerprint(b, fb) != 0)
        return 0;
    return memcmp(fa, fb, sizeof(fa)) == 0;
}

/*
 * Parse `src`, then deep-compare its circuit against `ref` (the C builder's
 * output): counts, wire table, constraint table, and fingerprint, each as a
 * separate named check.  Frees both the parsed result and `ref`.
 */
static void
compare_entry(const char *name, const char *src, voleith_gf8_circuit_t *ref)
{
    voleith_shipshape_parsed_t p;
    char label[96];
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);

    snprintf(label, sizeof(label), "%s: parses", name);
    check(label, r == 0 && p.circuit != NULL);

    if (r == 0 && p.circuit != NULL) {
        snprintf(label, sizeof(label), "%s: counts", name);
        check(label, counts_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: wire table", name);
        check(label, wires_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: constraint table", name);
        check(label, constraints_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: fingerprint", name);
        check(label, fp_equal(p.circuit, ref));
    }

    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(ref);
}

/* Append `n` witness wires to `c`, writing their ids into `out`. */
static void
add_witnesses(voleith_gf8_circuit_t *c, gf8_wire_id *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = voleith_gf8_add_witness(c);
}

/* Append `n` instance wires to `c`, writing their ids into `out`. */
static void
add_instances(voleith_gf8_circuit_t *c, gf8_wire_id *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = voleith_gf8_add_instance(c);
}

/*
 * merkle/path_secret[grostl_256], depth 2, L 32, node 32.
 *
 * .ship declaration order:
 *   WITNESS %leaf : byte[32]     -> 32 witness wires
 *   WITNESS %sib  : byte[64]     -> 64 witness wires
 *   WITNESS %dirs : byte[2]      ->  2 witness wires
 *   -> %root (output, 32 wires, no instance declaration)
 *
 * The ref must add wires in the SAME order so the wire-id numbering
 * matches the lowered circuit exactly.
 */
static void
test_merkle_path_secret_grostl256(void)
{
    static const char src[] = HDR "WITNESS  -> %leaf : byte[32]\n"
                                  "WITNESS  -> %sib  : byte[64]\n"
                                  "WITNESS  -> %dirs : byte[2]\n"
                                  "stdlib/crypto/merkle/path_secret[grostl_256]"
                                  "(%leaf, %sib, %dirs) -> %root\n";

    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256;
    size_t node = vt->node_bytes; /* 32 */
    voleith_gf8_circuit_t *c;
    gf8_wire_id leaf[32], sib[64], dirs[2];
    gf8_wire_id root[32];

    c = voleith_gf8_circuit_new();
    add_witnesses(c, leaf, 32);
    add_witnesses(c, sib, 64);
    add_witnesses(c, dirs, 2);

    /* ref: merkle_vt_gf8_path_circuit_secret_dir(leaf, sib, dirs, depth=2) */
    (void)merkle_vt_gf8_path_circuit_secret_dir(c, vt, leaf, node, sib, dirs, 2,
                                                root);

    compare_entry("merkle/path_secret[grostl_256]", src, c);
}

/*
 * ring_sig/v1[aes_dm], depth 2, sk 16, node 16.
 *
 * .ship declaration order:
 *   WITNESS  %sk   : byte[16]    -> 16 witness wires
 *   WITNESS  %dirs : byte[2]     ->  2 witness wires
 *   WITNESS  %sib  : byte[32]    -> 32 witness wires
 *   INSTANCE %root : byte[16]    -> 16 instance wires
 *
 * The ref replicates inl_ring_sig_v1:
 *   vt->leaf_circuit(c, sk, 16, leaf_node)
 *   merkle_vt_gf8_path_from_leaf_node_secret_dir(c, vt, leaf_node, sib,
 *       dirs, depth=2, computed)
 *   voleith_gf8_assert_equal(c, computed[k], root[k]) for k in 0..15
 */
static void
test_ring_sig_v1_aes_dm(void)
{
    static const char src[] =
        HDR "WITNESS  -> %sk   : byte[16]\n"
            "WITNESS  -> %dirs : byte[2]\n"
            "WITNESS  -> %sib  : byte[32]\n"
            "INSTANCE -> %root : byte[16]\n"
            "stdlib/crypto/ring_sig/v1[aes_dm](%sk, %dirs, %sib, %root)\n";

    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    size_t node = vt->node_bytes; /* 16 */
    voleith_gf8_circuit_t *c;
    gf8_wire_id sk[16], dirs[2], sib[32], root[16];
    gf8_wire_id leaf_node[16], computed[16];
    size_t k;

    c = voleith_gf8_circuit_new();
    /* Witnesses in declaration order. */
    add_witnesses(c, sk, 16);
    add_witnesses(c, dirs, 2);
    add_witnesses(c, sib, 32);
    /* Instance: root (public, assertion target). */
    add_instances(c, root, 16);

    /* Replicate inl_ring_sig_v1. */
    vt->leaf_circuit(c, sk, 16, leaf_node);
    (void)merkle_vt_gf8_path_from_leaf_node_secret_dir(c, vt, leaf_node, sib,
                                                       dirs, 2, computed);
    for (k = 0; k < node; k++)
        voleith_gf8_assert_equal(c, computed[k], root[k]);

    compare_entry("ring_sig/v1[aes_dm]", src, c);
}

/*
 * indexed_merkle/nonmember_secret[aes_dm], depth 2, tb 8, ib 8, node 16.
 *
 * .ship declaration order:
 *   WITNESS  %target : byte[8]   ->  8 witness wires
 *   WITNESS  %low    : byte[8]   ->  8 witness wires
 *   WITNESS  %hi     : byte[8]   ->  8 witness wires
 *   WITNESS  %nidx   : byte[8]   ->  8 witness wires
 *   WITNESS  %sib    : byte[32]  -> 32 witness wires
 *   WITNESS  %dirs   : byte[2]   ->  2 witness wires
 *   INSTANCE %root   : byte[16]  -> 16 instance wires
 *
 * The ref replicates inl_indexed_nonmember_secret:
 *   merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(c, vt,
 *       target, 8, low, hi, nidx, 8, sib, dirs, 2, computed)
 *   voleith_gf8_assert_equal(c, computed[k], root[k]) for k in 0..15
 */
static void
test_indexed_merkle_nonmember_secret_aes_dm(void)
{
    static const char src[] =
        HDR "WITNESS  -> %target : byte[8]\n"
            "WITNESS  -> %low    : byte[8]\n"
            "WITNESS  -> %hi     : byte[8]\n"
            "WITNESS  -> %nidx   : byte[8]\n"
            "WITNESS  -> %sib    : byte[32]\n"
            "WITNESS  -> %dirs   : byte[2]\n"
            "INSTANCE -> %root   : byte[16]\n"
            "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]"
            "(%target, %low, %hi, %nidx, %sib, %dirs, %root)\n";

    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    size_t node = vt->node_bytes; /* 16 */
    voleith_gf8_circuit_t *c;
    gf8_wire_id target[8], low[8], hi[8], nidx[8], sib[32], dirs[2], root[16];
    gf8_wire_id computed[16];
    size_t k;

    c = voleith_gf8_circuit_new();
    /* Witnesses in declaration order. */
    add_witnesses(c, target, 8);
    add_witnesses(c, low, 8);
    add_witnesses(c, hi, 8);
    add_witnesses(c, nidx, 8);
    add_witnesses(c, sib, 32);
    add_witnesses(c, dirs, 2);
    /* Instance. */
    add_instances(c, root, 16);

    /* Replicate inl_indexed_nonmember_secret. */
    (void)merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
        c, vt, target, 8, low, hi, nidx, 8, sib, dirs, 2, computed);
    for (k = 0; k < node; k++)
        voleith_gf8_assert_equal(c, computed[k], root[k]);

    compare_entry("indexed_merkle/nonmember_secret[aes_dm]", src, c);
}

int
main(void)
{
    printf("test_shipshape_crypto_v2_equiv: starting\n");
    test_merkle_path_secret_grostl256();
    test_ring_sig_v1_aes_dm();
    test_indexed_merkle_nonmember_secret_aes_dm();
    printf("test_shipshape_crypto_v2_equiv: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
