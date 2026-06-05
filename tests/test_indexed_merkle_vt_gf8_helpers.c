/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_indexed_merkle_vt_gf8_helpers.c - exercise voleith_imt_vt_build
 * and voleith_imt_vt_lookup_nonmember across every wrapped node-hash vt.
 *
 * Plan items (per docs/RSV1_IMPLEMENTATION_PLAN.md T5b):
 *   1. Depth-1 (2-leaf) IMT: verify build's root against a by-hand
 *      leaf_hash + inode_hash.
 *   2. Depth-3 (8-leaf) IMT: for several non-member targets, look up
 *      the straddling record + path and assert the result drives
 *      merkle_vt_gf8_indexed_nonmember_circuit_secret_dir to a valid
 *      root match (circuit eval returns 1, root wires equal the
 *      helper-computed root).
 *   3. Lookup with target equal to an existing record's value (member)
 *      returns -1.
 *
 * Covers all eight wrapped vts.
 */

#include "indexed_merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_helpers.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "../proof/gf8_circuit.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

#define VALUE_BYTES 1
#define INDEX_BYTES 1
#define LEAF_DATA_BYTES (2 * VALUE_BYTES + INDEX_BYTES)

#define D3_DEPTH 3
#define D3_N_LEAVES (1u << D3_DEPTH)

#define D1_DEPTH 1
#define D1_N_LEAVES (1u << D1_DEPTH)

static int total_tests = 0;
static int total_pass = 0;

static void
check(const char *what, int cond)
{
    total_tests++;
    if (cond) {
        total_pass++;
    } else {
        printf("    FAIL: %s\n", what);
    }
}

/*
 * voleith_node_hash_hirose_fixed32 is intentionally NOT covered here:
 * its leaf_hash silently consumes 32 input bytes regardless of the
 * declared leaf_data_bytes (see merkle_hirose_fixed32_leaf_hash), which
 * is incompatible with the 1+1+1-byte IMT record payload this test
 * uses.  The variable-leaf Hirose vt has no such restriction.
 */
static const voleith_node_hash_vt *const VTS[] = {
    &voleith_node_hash_hirose,        &voleith_node_hash_aes_dm,
    &voleith_node_hash_aes_cmac128,   &voleith_node_hash_grostl256,
    &voleith_node_hash_grostl256_t27, &voleith_node_hash_grostl512,
    &voleith_node_hash_grostl512_t59,
};
#define N_VTS (sizeof(VTS) / sizeof(VTS[0]))

/*
 * Build the 8-record IMT used by the depth-3 tests.  Sort order is by
 * `value` ascending; next_index is the array slot of the next record in
 * sort order (the last record wraps back to 0).
 */
static const uint8_t D3_VALUES[D3_N_LEAVES] = {
    0x05, 0x10, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0,
};
static const uint8_t D3_NEXTS[D3_N_LEAVES] = {
    0x10, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xFF,
};
static const uint8_t D3_NEXT_IDX[D3_N_LEAVES] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00,
};

static void
fill_d3_records(voleith_imt_record_t *records)
{
    for (size_t i = 0; i < D3_N_LEAVES; i++) {
        records[i].value = &D3_VALUES[i];
        records[i].next_value = &D3_NEXTS[i];
        records[i].next_index = &D3_NEXT_IDX[i];
    }
}

/*
 * Independent reference root: hashes each record's leaf payload via
 * vt->leaf_hash and walks the inode levels inline.  Lets the test
 * catch a divergence in voleith_imt_vt_build or its underlying
 * voleith_merkle_vt_build without sharing internals.
 */
static void
reference_root(const voleith_node_hash_vt *vt,
               const voleith_imt_record_t *records, size_t n_records,
               uint8_t *root_out)
{
    size_t W = vt->node_bytes;
    uint8_t *cur = calloc(n_records, W);
    uint8_t *nxt = calloc(n_records / 2u > 0 ? n_records / 2u : 1, W);
    assert(cur != NULL && nxt != NULL);

    for (size_t i = 0; i < n_records; i++) {
        uint8_t leaf_data[LEAF_DATA_BYTES];
        leaf_data[0] = records[i].value[0];
        leaf_data[1] = records[i].next_value[0];
        leaf_data[2] = records[i].next_index[0];
        MUST_OK(vt->leaf_hash(leaf_data, LEAF_DATA_BYTES, cur + i * W));
    }

    size_t cur_n = n_records;
    while (cur_n > 1) {
        size_t next_n = cur_n >> 1;
        for (size_t j = 0; j < next_n; j++)
            MUST_OK(vt->inode_hash(cur + (2u * j) * W, cur + (2u * j + 1u) * W,
                                   nxt + j * W));
        memcpy(cur, nxt, next_n * W);
        cur_n = next_n;
    }

    memcpy(root_out, cur, W);
    free(cur);
    free(nxt);
}

/*
 * Drive merkle_vt_gf8_indexed_nonmember_circuit_secret_dir with the
 * lookup helper's output.  Returns 0 on success and writes the root
 * wire bytes into root_bytes_out.
 *
 * Witness layout (matches the wire-declaration order below):
 *   target | low_value | low_next | next_index | path_nodes | dirs
 *   | leaf_inv_in | per-level inode_inv_in
 */
static int
drive_circuit(const voleith_node_hash_vt *vt, uint8_t target_val,
              const voleith_imt_record_t *adj, const uint8_t *siblings,
              const uint8_t *dirs, size_t depth, uint8_t *root_bytes_out)
{
    size_t W = vt->node_bytes;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (c == NULL)
        return -1;

    gf8_wire_id tgt = voleith_gf8_add_witness(c);
    gf8_wire_id lv = voleith_gf8_add_witness(c);
    gf8_wire_id ln = voleith_gf8_add_witness(c);
    gf8_wire_id ni = voleith_gf8_add_witness(c);

    gf8_wire_id *path_wires = calloc(depth * W, sizeof(gf8_wire_id));
    gf8_wire_id dir_wires[16];
    assert(depth <= sizeof(dir_wires) / sizeof(dir_wires[0]));

    for (size_t i = 0; i < depth * W; i++)
        path_wires[i] = voleith_gf8_add_witness(c);
    for (size_t k = 0; k < depth; k++)
        dir_wires[k] = voleith_gf8_add_witness(c);

    gf8_wire_id root_wires[MERKLE_VT_MAX_NODE_BYTES];
    int rc = merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
        c, vt, &tgt, VALUE_BYTES, &lv, &ln, &ni, INDEX_BYTES, path_wires,
        dir_wires, depth, root_wires);
    if (rc != 0) {
        free(path_wires);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    /* Assemble the witness. */
    size_t n_witness = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(n_witness > 0 ? n_witness : 1, 1);
    uint8_t *wp = witness;
    *wp++ = target_val;
    *wp++ = adj->value[0];
    *wp++ = adj->next_value[0];
    *wp++ = adj->next_index[0];
    memcpy(wp, siblings, depth * W);
    wp += depth * W;
    for (size_t k = 0; k < depth; k++)
        wp[k] = dirs[k];
    wp += depth;

    /* leaf inv_in */
    uint8_t leaf_data[LEAF_DATA_BYTES] = {adj->value[0], adj->next_value[0],
                                          adj->next_index[0]};
    MUST_OK(vt->leaf_build_witness(leaf_data, LEAF_DATA_BYTES, wp));
    wp += vt->leaf_invin_bytes(LEAF_DATA_BYTES);

    /* per-level inode inv_in */
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    MUST_OK(vt->leaf_hash(leaf_data, LEAF_DATA_BYTES, current));
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;

        MUST_OK(vt->inode_build_witness(L, R, wp));
        wp += vt->inode_invin_bytes();

        uint8_t next[MERKLE_VT_MAX_NODE_BYTES];
        MUST_OK(vt->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
    assert((size_t)(wp - witness) == n_witness);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(n_wires > 0 ? n_wires : 1, 1);
    int eval_rc = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);

    int ok = (eval_rc == 1);
    if (ok) {
        for (size_t i = 0; i < W; i++)
            root_bytes_out[i] = wire_vals[root_wires[i]];
    }

    free(witness);
    free(wire_vals);
    free(path_wires);
    voleith_gf8_circuit_free(c);
    return ok ? 0 : -1;
}

static void
run_depth1(const voleith_node_hash_vt *vt)
{
    static const uint8_t v0 = 0x10, n0 = 0xC0, ni0 = 0x01;
    static const uint8_t v1 = 0xC0, n1 = 0xFF, ni1 = 0x00;

    voleith_imt_record_t recs[D1_N_LEAVES] = {
        {&v0, &n0, &ni0},
        {&v1, &n1, &ni1},
    };

    /* By-hand root: leaf0 = leaf_hash([v0,n0,ni0]); same for leaf1;
     * root = inode_hash(leaf0, leaf1).  Independent of the helper's
     * internal walk. */
    size_t W = vt->node_bytes;
    uint8_t leaf0[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t leaf1[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t expected_root[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t ld0[LEAF_DATA_BYTES] = {v0, n0, ni0};
    uint8_t ld1[LEAF_DATA_BYTES] = {v1, n1, ni1};
    MUST_OK(vt->leaf_hash(ld0, LEAF_DATA_BYTES, leaf0));
    MUST_OK(vt->leaf_hash(ld1, LEAF_DATA_BYTES, leaf1));
    MUST_OK(vt->inode_hash(leaf0, leaf1, expected_root));

    uint8_t helper_root[MERKLE_VT_MAX_NODE_BYTES];
    check("depth-1 build returns 0",
          voleith_imt_vt_build(vt, recs, D1_N_LEAVES, VALUE_BYTES, INDEX_BYTES,
                               helper_root) == 0);
    check("depth-1 root matches by-hand computation",
          memcmp(helper_root, expected_root, W) == 0);
}

/*
 * Run depth-3 build + lookup probes for one vt.
 */
static void
run_depth3(const voleith_node_hash_vt *vt)
{
    size_t W = vt->node_bytes;

    voleith_imt_record_t records[D3_N_LEAVES];
    fill_d3_records(records);

    uint8_t expected_root[MERKLE_VT_MAX_NODE_BYTES];
    reference_root(vt, records, D3_N_LEAVES, expected_root);

    uint8_t helper_root[MERKLE_VT_MAX_NODE_BYTES];
    check("depth-3 build returns 0",
          voleith_imt_vt_build(vt, records, D3_N_LEAVES, VALUE_BYTES,
                               INDEX_BYTES, helper_root) == 0);
    check("depth-3 root matches reference",
          memcmp(helper_root, expected_root, W) == 0);

    /*
     * Non-member probes: each target falls strictly between an adjacent
     * pair of record values.  Verify both the adjacency index returned
     * by lookup and that the path drives the indexed non-member
     * secret-dir circuit to the expected root.
     */
    struct {
        uint8_t target;
        size_t expected_adj;
    } probes[] = {
        {0x08, 0}, /* between 0x05 and 0x10 */
        {0x18, 1}, /* between 0x10 and 0x20 */
        {0x30, 2}, /* between 0x20 and 0x40 */
        {0xB0, 6}, /* between 0xA0 and 0xC0 */
    };
    size_t n_probes = sizeof(probes) / sizeof(probes[0]);

    for (size_t p = 0; p < n_probes; p++) {
        uint8_t target = probes[p].target;
        size_t adj_index = (size_t)-1;
        uint8_t path[D3_DEPTH * MERKLE_VT_MAX_NODE_BYTES];
        int rc = voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES,
                                                 VALUE_BYTES, INDEX_BYTES,
                                                 &target, &adj_index, path);

        char label[96];
        snprintf(label, sizeof(label), "lookup target=0x%02x returns 0",
                 target);
        check(label, rc == 0);

        snprintf(label, sizeof(label), "lookup target=0x%02x adj index matches",
                 target);
        check(label, adj_index == probes[p].expected_adj);

        uint8_t dirs[D3_DEPTH];
        for (size_t k = 0; k < D3_DEPTH; k++)
            dirs[k] = (uint8_t)((adj_index >> k) & 1u);

        uint8_t circ_root[MERKLE_VT_MAX_NODE_BYTES];
        int drc = drive_circuit(vt, target, &records[adj_index], path, dirs,
                                D3_DEPTH, circ_root);
        snprintf(label, sizeof(label), "circuit eval ok (target=0x%02x)",
                 target);
        check(label, drc == 0);

        if (drc == 0) {
            snprintf(label, sizeof(label),
                     "circuit root matches helper root (target=0x%02x)",
                     target);
            check(label, memcmp(circ_root, expected_root, W) == 0);
        }
    }

    /* Member: target equal to an existing record's value -> -1. */
    uint8_t member_target = D3_VALUES[3];
    size_t adj = 0;
    uint8_t path[D3_DEPTH * MERKLE_VT_MAX_NODE_BYTES];
    int rc = voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES,
                                             VALUE_BYTES, INDEX_BYTES,
                                             &member_target, &adj, path);
    check("lookup of existing value returns -1 (member)", rc == -1);
}

static void
run_validation(void)
{
    printf("  argument validation\n");
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;

    voleith_imt_record_t records[D3_N_LEAVES];
    fill_d3_records(records);

    uint8_t root[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t path[D3_DEPTH * MERKLE_VT_MAX_NODE_BYTES];
    uint8_t target = 0x08;
    size_t adj = 0;

    check("build rejects NULL vt",
          voleith_imt_vt_build(NULL, records, D3_N_LEAVES, VALUE_BYTES,
                               INDEX_BYTES, root) == -1);
    check("build rejects NULL records",
          voleith_imt_vt_build(vt, NULL, D3_N_LEAVES, VALUE_BYTES, INDEX_BYTES,
                               root) == -1);
    check("build rejects NULL root_out",
          voleith_imt_vt_build(vt, records, D3_N_LEAVES, VALUE_BYTES,
                               INDEX_BYTES, NULL) == -1);
    check("build rejects n_records=0",
          voleith_imt_vt_build(vt, records, 0, VALUE_BYTES, INDEX_BYTES,
                               root) == -1);
    check("build rejects non-power-of-two n_records",
          voleith_imt_vt_build(vt, records, 6, VALUE_BYTES, INDEX_BYTES,
                               root) == -1);
    check("build rejects value_bytes=0",
          voleith_imt_vt_build(vt, records, D3_N_LEAVES, 0, INDEX_BYTES,
                               root) == -1);
    check("build rejects index_bytes=0",
          voleith_imt_vt_build(vt, records, D3_N_LEAVES, VALUE_BYTES, 0,
                               root) == -1);

    check("lookup rejects NULL target",
          voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES, VALUE_BYTES,
                                          INDEX_BYTES, NULL, &adj, path) == -1);
    check("lookup rejects NULL adj_leaf_index_out",
          voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES, VALUE_BYTES,
                                          INDEX_BYTES, &target, NULL,
                                          path) == -1);
    check("lookup rejects NULL path_out when n_records>1",
          voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES, VALUE_BYTES,
                                          INDEX_BYTES, &target, &adj,
                                          NULL) == -1);

    /* Target out of range (below all values): no straddling record. */
    uint8_t below = 0x00;
    check("lookup of below-range target returns -1",
          voleith_imt_vt_lookup_nonmember(vt, records, D3_N_LEAVES, VALUE_BYTES,
                                          INDEX_BYTES, &below, &adj,
                                          path) == -1);
}

static void
run_vt(const voleith_node_hash_vt *vt)
{
    printf("  %-22s W=%zu\n", vt->name, vt->node_bytes);
    run_depth1(vt);
    run_depth3(vt);
}

/*
 * Validator-direct tests.  Covers the soundness invariants
 * voleith_imt_vt_validate_records enforces, plus the friendly cases
 * (well-formed strict chain + degenerate "max sentinel" padding) it
 * must accept.
 */
static void
run_record_validator(void)
{
    printf("  record validator\n");

    /* 1. The strict D3 fixture (no degenerates) accepts. */
    {
        voleith_imt_record_t recs[D3_N_LEAVES];
        fill_d3_records(recs);
        check("validator accepts strict-chain fixture",
              voleith_imt_vt_validate_records(recs, D3_N_LEAVES, VALUE_BYTES) ==
                  0);
    }

    /* 2. Padded sentinel pattern (the revocable example's shape):
     *      rec[0] = [0x00, 0xFF)        -- non-degenerate
     *      rec[1..3] = [0xFF, 0xFF)     -- degenerate "max sentinel" padding
     *    The padding records repeat value == next_value == 0xFF; the
     *    validator must accept equality in the sort order and skip the
     *    overlap check on degenerates. */
    {
        static const uint8_t v0 = 0x00, n0 = 0xFF, ni0 = 0x01;
        static const uint8_t v_max = 0xFF, ni_max = 0x00;
        voleith_imt_record_t recs[4] = {
            {&v0, &n0, &ni0},
            {&v_max, &v_max, &ni_max},
            {&v_max, &v_max, &ni_max},
            {&v_max, &v_max, &ni_max},
        };
        check("validator accepts degenerate sentinel padding",
              voleith_imt_vt_validate_records(recs, 4, VALUE_BYTES) == 0);
    }

    /* 3. Sort order broken (rec[1] < rec[0]).  Rejected. */
    {
        static const uint8_t v0 = 0x50, n0 = 0x60, ni0 = 0x01;
        static const uint8_t v1 = 0x10, n1 = 0x55, ni1 = 0x00;
        voleith_imt_record_t recs[2] = {
            {&v0, &n0, &ni0},
            {&v1, &n1, &ni1},
        };
        check("validator rejects out-of-order records",
              voleith_imt_vt_validate_records(recs, 2, VALUE_BYTES) == -1);
    }

    /* 4. Overlap (rec[0].next_value > rec[1].value).  This is the
     *    soundness-critical pattern: an adversarial prover could use
     *    rec[0] as the adjacent record to assert_lt on target =
     *    rec[1].value, forging a non-membership proof for a member. */
    {
        static const uint8_t v0 = 0x10, n0 = 0x30, ni0 = 0x01;
        static const uint8_t v1 = 0x20, n1 = 0x40, ni1 = 0x00;
        voleith_imt_record_t recs[2] = {
            {&v0, &n0, &ni0},
            {&v1, &n1, &ni1},
        };
        check("validator rejects overlapping intervals (forge "
              "target=rec[1].value)",
              voleith_imt_vt_validate_records(recs, 2, VALUE_BYTES) == -1);
    }

    /* 5. The common foot-gun: insert a new record without updating the
     *    predecessor's next_value.  Result is an overlap that survives
     *    the in-helper membership check (target = the new value) but
     *    fails to bind correctly. */
    {
        static const uint8_t v0 = 0x00, n0 = 0xFF, ni0 = 0x01;
        static const uint8_t v1 = 0x50, n1 = 0xFF, ni1 = 0x00;
        voleith_imt_record_t recs[2] = {
            {&v0, &n0, &ni0}, /* forgot to update n0 to 0x50 */
            {&v1, &n1, &ni1},
        };
        check("validator rejects 'forgot to update predecessor' foot-gun",
              voleith_imt_vt_validate_records(recs, 2, VALUE_BYTES) == -1);
    }

    /* 6. Wrap-around interval (next_value < value).  Rejected. */
    {
        static const uint8_t v0 = 0x80, n0 = 0x10, ni0 = 0x00;
        voleith_imt_record_t recs[2] = {
            {&v0, &n0, &ni0},
            {&v0, &n0, &ni0},
        };
        check("validator rejects wrap-around interval (next_value < value)",
              voleith_imt_vt_validate_records(recs, 2, VALUE_BYTES) == -1);
    }

    /* 7. NULL guards. */
    {
        check("validator rejects NULL records",
              voleith_imt_vt_validate_records(NULL, D3_N_LEAVES, VALUE_BYTES) ==
                  -1);

        static const uint8_t v0 = 0x10, n0 = 0x20, ni0 = 0x00;
        voleith_imt_record_t recs[1] = {{&v0, &n0, &ni0}};
        check("validator rejects n_records=0",
              voleith_imt_vt_validate_records(recs, 0, VALUE_BYTES) == -1);
        check("validator rejects value_bytes=0",
              voleith_imt_vt_validate_records(recs, 1, 0) == -1);

        voleith_imt_record_t recs_null_value[1] = {{NULL, &n0, &ni0}};
        check("validator rejects NULL value pointer",
              voleith_imt_vt_validate_records(recs_null_value, 1,
                                              VALUE_BYTES) == -1);

        voleith_imt_record_t recs_null_next[1] = {{&v0, NULL, &ni0}};
        check("validator rejects NULL next_value pointer",
              voleith_imt_vt_validate_records(recs_null_next, 1, VALUE_BYTES) ==
                  -1);
    }

    /* 8. Build / lookup auto-reject malformed input.  The validator is
     *    wired into validate_common, so the existing public entry points
     *    surface the malformed-record rejection without explicit
     *    pre-validation by the caller. */
    {
        const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
        static const uint8_t v0 = 0x10, n0 = 0x30, ni0 = 0x01;
        static const uint8_t v1 = 0x20, n1 = 0x40, ni1 = 0x00;
        voleith_imt_record_t recs[2] = {
            {&v0, &n0, &ni0},
            {&v1, &n1, &ni1},
        };
        uint8_t root[MERKLE_VT_MAX_NODE_BYTES];
        uint8_t path[MERKLE_VT_MAX_NODE_BYTES];
        uint8_t target = 0x15;
        size_t adj = 0;

        check("build rejects overlapping records",
              voleith_imt_vt_build(vt, recs, 2, VALUE_BYTES, INDEX_BYTES,
                                   root) == -1);
        check("lookup rejects overlapping records",
              voleith_imt_vt_lookup_nonmember(vt, recs, 2, VALUE_BYTES,
                                              INDEX_BYTES, &target, &adj,
                                              path) == -1);
    }
}

int
main(void)
{
    printf("test_indexed_merkle_vt_gf8_helpers\n");

    for (size_t i = 0; i < N_VTS; i++)
        run_vt(VTS[i]);

    run_validation();
    run_record_validator();

    printf("\n%d/%d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
