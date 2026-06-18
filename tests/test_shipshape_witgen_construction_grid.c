/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_construction_grid.c - W8.6 per-(entry, node-hash type)
 * property test for the native crypto-v2 CONSTRUCTION witness backends
 * (parsers/shipshape_witgen_construction.c).
 *
 * For each of the three secret-direction constructions (merkle/path_secret,
 * ring_sig/v1, indexed_merkle/nonmember_secret), for EACH of the frozen
 * node-hash types (looped from voleith_shipshape_node_hash_types[]), and for a
 * representative set of depths, the full witness is generated twice over the
 * same external inputs:
 *
 *   baseline:   no backend registered (generic Tier 1 evaluator).
 *   dispatched: voleith_shipshape_witgen_register_constructions() registered.
 *
 * The two MUST be byte-identical (same length, memcmp == 0).  This is the
 * STDLIB equivalence-oracle property extended across the whole (entry, type,
 * depth) grid: a Tier 2a construction backend is a pure speed layer that must
 * reproduce the generic witness exactly for every node-hash type.
 *
 * No prove / verify is performed.  A valid tree is NOT required: both the
 * generic and handler paths derive the inv bytes deterministically from the
 * same ext via the same node-hash primitive, so the byte-equivalence holds
 * regardless of whether the tree is consistent.  The only ext constraint is
 * that dir bytes must be in {0, 1} (the secret-dir mux / booleanity require it);
 * all other ext bytes are arbitrary deterministic values.
 *
 * SELF_CHECK is intentionally NOT set: the ASSERT_EQUAL root constraints would
 * fail on an inconsistent tree, but the inv-witness span we compare is
 * independent of constraint satisfaction.
 */

#include "shipshape.h"
#include "shipshape_node_hash_types.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* crypto-v2 header. */
#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/* Upper bound on a generated .ship source.  The longest body has seven WITNESS
 * lines plus an INSTANCE line plus a bracketed call; each line is short. */
#define SRC_CAP 768u

/* Fixed leaf width for merkle / ring (the merkle leaf secret and the ring sk).
 * Per-type node width W is the meaningful width axis here. */
#define LEAF_BYTES 16u

/* Indexed construction target / index widths. */
#define IDX_TB 4u
#define IDX_IB 4u

/*
 * Fill buf[0..len-1] with deterministic non-trivial bytes.  The seed offsets
 * the pattern so distinct buffers do not collide trivially.
 */
static void
fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)((i * 7u + seed * 13u + 0x5Au) & 0xff);
}

/* Set the depth dir bytes at buf[0..depth-1] to a deterministic {0,1} pattern. */
static void
fill_dirs(uint8_t *buf, size_t depth)
{
    size_t k;

    for (k = 0; k < depth; k++)
        buf[k] = (uint8_t)(k & 1u);
}

/*
 * merkle/path_secret[TYPE]:
 *   WITNESS leaf : byte[L], sib : byte[D*W], dirs : byte[D]
 *   call (%leaf, %sib, %dirs) -> %root   (root is an OUTPUT wire, not INSTANCE)
 *   ext = leaf(L) | sib(D*W) | dirs(D), len = L + D*W + D
 *
 * Returns bytes written, or -1 on overflow.
 */
static int
build_merkle_src(char *buf, size_t cap, const char *type_name, size_t leaf,
                 size_t W, size_t D)
{
    int n = snprintf(buf, cap,
                     HDR_V2 "WITNESS  -> %%leaf : byte[%zu]\n"
                            "WITNESS  -> %%sib  : byte[%zu]\n"
                            "WITNESS  -> %%dirs : byte[%zu]\n"
                            "stdlib/crypto/merkle/path_secret[%s]"
                            "(%%leaf, %%sib, %%dirs) -> %%root\n",
                     leaf, D * W, D, type_name);

    if (n < 0 || (size_t)n >= cap)
        return -1;
    return n;
}

/*
 * ring_sig/v1[TYPE]:
 *   WITNESS sk : byte[L], dirs : byte[D], sib : byte[D*W]
 *   INSTANCE root : byte[W]
 *   call (%sk, %dirs, %sib, %root)   (root is INSTANCE)
 *   ext = sk(L) | dirs(D) | sib(D*W), len = L + D + D*W
 */
static int
build_ring_src(char *buf, size_t cap, const char *type_name, size_t sk,
               size_t W, size_t D)
{
    int n = snprintf(buf, cap,
                     HDR_V2 "WITNESS  -> %%sk   : byte[%zu]\n"
                            "WITNESS  -> %%dirs : byte[%zu]\n"
                            "WITNESS  -> %%sib  : byte[%zu]\n"
                            "INSTANCE -> %%root : byte[%zu]\n"
                            "stdlib/crypto/ring_sig/v1[%s]"
                            "(%%sk, %%dirs, %%sib, %%root)\n",
                     sk, D, D * W, W, type_name);

    if (n < 0 || (size_t)n >= cap)
        return -1;
    return n;
}

/*
 * indexed_merkle/nonmember_secret[TYPE]:
 *   WITNESS tgt : byte[tb], low : byte[tb], hi : byte[tb], nidx : byte[ib],
 *           sib : byte[D*W], dirs : byte[D]
 *   INSTANCE root : byte[W]
 *   call (%tgt, %low, %hi, %nidx, %sib, %dirs, %root)   (root is INSTANCE)
 *   ext = tgt(tb) | low(tb) | hi(tb) | nidx(ib) | sib(D*W) | dirs(D),
 *   len = 3*tb + ib + D*W + D
 */
static int
build_indexed_src(char *buf, size_t cap, const char *type_name, size_t tb,
                  size_t ib, size_t W, size_t D)
{
    int n = snprintf(buf, cap,
                     HDR_V2 "WITNESS  -> %%tgt  : byte[%zu]\n"
                            "WITNESS  -> %%low  : byte[%zu]\n"
                            "WITNESS  -> %%hi   : byte[%zu]\n"
                            "WITNESS  -> %%nidx : byte[%zu]\n"
                            "WITNESS  -> %%sib  : byte[%zu]\n"
                            "WITNESS  -> %%dirs : byte[%zu]\n"
                            "INSTANCE -> %%root : byte[%zu]\n"
                            "stdlib/crypto/indexed_merkle/nonmember_secret[%s]"
                            "(%%tgt, %%low, %%hi, %%nidx, %%sib, %%dirs, "
                            "%%root)\n",
                     tb, tb, tb, ib, D * W, D, W, type_name);

    if (n < 0 || (size_t)n >= cap)
        return -1;
    return n;
}

/*
 * Run one equivalence case: parse `src`, build the instance filler, generate
 * witness without backends (baseline) and with the construction backends
 * registered (dispatched), assert byte-identical.  `label` is used to print a
 * clear failure line; `ext`/`ext_len` are the external WITNESS bytes in
 * declaration order.
 *
 * Returns 1 if every sub-check for this case passed, 0 otherwise.
 */
static int
run_case(const char *label, const char *src, const uint8_t *ext, size_t ext_len)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t *baseline = NULL, *dispatched = NULL;
    uint8_t *inst = NULL;
    size_t baseline_len = 0, dispatched_len = 0, inst_len = 0;
    int before = pass_count;
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    if (r != 0 || p.circuit == NULL) {
        /* Loud parse failure: this construction/type/depth must parse. */
        printf("  FAIL: %s parse\n", label);
        test_count++;
        voleith_shipshape_parsed_free(&p);
        return 0;
    }
    check(label, 1); /* parse ok */

    /* Sanity: ext_len must match the circuit's external witness length. */
    check(label, voleith_shipshape_external_witness_len(&p) == ext_len);

    /* Instance filler (root): deterministic, value-irrelevant to the span. */
    inst_len = voleith_gf8_circuit_instance_count(p.circuit);
    if (inst_len > 0) {
        inst = calloc(inst_len, 1);
        if (inst == NULL) {
            check(label, 0);
            voleith_shipshape_parsed_free(&p);
            return 0;
        }
        fill_pattern(inst, inst_len, 0xC3);
    }

    /* Baseline: no backend registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len, 0,
                                      &baseline, &baseline_len);
    check(label, r == 0 && baseline != NULL);

    /* Dispatched: construction backends registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register_constructions();
    check(label, r == 0);
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len, 0,
                                      &dispatched, &dispatched_len);
    check(label, r == 0 && dispatched != NULL);

    /* Equivalence oracle: byte-for-byte identical. */
    check(label, baseline != NULL && dispatched != NULL &&
                     baseline_len == dispatched_len &&
                     memcmp(baseline, dispatched, baseline_len) == 0);

    free(baseline);
    free(dispatched);
    free(inst);
    voleith_shipshape_parsed_free(&p);
    voleith_shipshape_witgen_reset();

    /* This case passed iff all six sub-checks since `before` passed. */
    return (pass_count - before) == 6;
}

/* The construction kinds in the grid. */
enum { KIND_MERKLE = 0, KIND_RING = 1, KIND_INDEXED = 2, N_KINDS = 3 };

/*
 * Build the ext buffer for one (kind, W, D) point and run the case.  Node width
 * W varies per type.  The leaf-record width is W-independent but type-dependent:
 * a vt with fixed_leaf_bytes != 0 (hirose_fixed_32 = 32) requires its leaf
 * record to equal that value, so the merkle leaf, the ring sk, and the indexed
 * record (2*tb + ib) are sized to fixed_leaf for those types and to the default
 * widths otherwise.  Feeding a mismatching leaf is a parse error by design.
 * Returns 1 if the case fully passed, 0 otherwise.
 */
static int
run_grid_point(int kind, const char *type_name, size_t W, size_t D,
               size_t fixed_leaf)
{
    char src[SRC_CAP];
    char label[160];
    /* ext capacity: largest layout is 3*tb + ib + D*W + D.  Across the grid the
     * max is grostl_512 (W=64) at D=4 with the default record (276 bytes); the
     * fixed-leaf type has W=32 so its wider record stays well under.  Round up. */
    uint8_t ext[16 + 4 * 64 + 32];
    size_t ext_len;
    int n;

    if (kind == KIND_MERKLE) {
        /* leaf = fixed_leaf when pinned, else the default width. */
        size_t leaf = (fixed_leaf != 0) ? fixed_leaf : LEAF_BYTES;

        /* ext = leaf(leaf) | sib(D*W) | dirs(D). */
        ext_len = leaf + D * W + D;
        n = build_merkle_src(src, sizeof(src), type_name, leaf, W, D);
        snprintf(label, sizeof(label),
                 "merkle/path_secret[%s] D=%zu W=%zu leaf=%zu", type_name, D, W,
                 leaf);
        if (n < 0) {
            printf("  FAIL: %s src overflow\n", label);
            test_count++;
            return 0;
        }
        fill_pattern(ext, leaf + D * W, 0x11);
        fill_dirs(ext + leaf + D * W, D);
    } else if (kind == KIND_RING) {
        /* sk = fixed_leaf when pinned, else the default width. */
        size_t sk = (fixed_leaf != 0) ? fixed_leaf : LEAF_BYTES;

        /* ext = sk(sk) | dirs(D) | sib(D*W). */
        ext_len = sk + D + D * W;
        n = build_ring_src(src, sizeof(src), type_name, sk, W, D);
        snprintf(label, sizeof(label), "ring_sig/v1[%s] D=%zu W=%zu sk=%zu",
                 type_name, D, W, sk);
        if (n < 0) {
            printf("  FAIL: %s src overflow\n", label);
            test_count++;
            return 0;
        }
        fill_pattern(ext, sk, 0x22);
        fill_dirs(ext + sk, D);
        fill_pattern(ext + sk + D, D * W, 0x33);
    } else {
        /* Indexed leaf record = 2*tb + ib.  When pinned it must equal
         * fixed_leaf; mirror the freeze grid's tb=12 choice (so ib=fixed-24,
         * e.g. 8 for hirose_fixed_32=32).  Otherwise use the default widths. */
        size_t tb = (fixed_leaf != 0) ? 12u : IDX_TB;
        size_t ib = (fixed_leaf != 0) ? (fixed_leaf - 2u * tb) : IDX_IB;

        /* ext = tgt(tb) | low(tb) | hi(tb) | nidx(ib) | sib(D*W) | dirs(D). */
        ext_len = 3 * tb + ib + D * W + D;
        n = build_indexed_src(src, sizeof(src), type_name, tb, ib, W, D);
        snprintf(label, sizeof(label),
                 "indexed_merkle/nonmember_secret[%s] D=%zu W=%zu rec=%zu",
                 type_name, D, W, 2 * tb + ib);
        if (n < 0) {
            printf("  FAIL: %s src overflow\n", label);
            test_count++;
            return 0;
        }
        fill_pattern(ext, 3 * tb + ib + D * W, 0x44);
        fill_dirs(ext + 3 * tb + ib + D * W, D);
    }

    return run_case(label, src, ext, ext_len);
}

/*
 * The full grid: 3 constructions x 8 node-hash types x 3 depths = 72 cases.
 * Plus one extra merkle leaf-width point per type to exercise the leaf-width
 * axis explicitly (leaf = 32 at depth 2): + 8 cases.
 */
static void
test_grid(void)
{
    static const size_t depths[] = {1, 2, 4};
    size_t n_types = voleith_shipshape_node_hash_types_count;
    size_t ti, di;
    int kind;

    for (kind = 0; kind < N_KINDS; kind++) {
        for (ti = 0; ti < n_types; ti++) {
            const voleith_node_hash_vt *vt =
                voleith_shipshape_node_hash_types[ti].vt;
            const char *type_name = voleith_shipshape_node_hash_types[ti].name;
            size_t W = vt->node_bytes;
            size_t fixed_leaf = vt->fixed_leaf_bytes;

            for (di = 0; di < sizeof(depths) / sizeof(depths[0]); di++)
                (void)run_grid_point(kind, type_name, W, depths[di],
                                     fixed_leaf);
        }
    }

    /* Extra leaf-width axis point: merkle with a 32-byte leaf, depth 2. */
    for (ti = 0; ti < n_types; ti++) {
        const char *type_name = voleith_shipshape_node_hash_types[ti].name;
        size_t W = voleith_shipshape_node_hash_types[ti].vt->node_bytes;
        char src[SRC_CAP];
        char label[160];
        uint8_t ext[32 + 2 * 64 + 16];
        size_t D = 2, leaf = 32, ext_len = leaf + D * W + D;
        int n = build_merkle_src(src, sizeof(src), type_name, leaf, W, D);

        snprintf(label, sizeof(label),
                 "merkle/path_secret[%s] D=2 W=%zu leaf=32", type_name, W);
        if (n < 0) {
            printf("  FAIL: %s src overflow\n", label);
            test_count++;
            continue;
        }
        fill_pattern(ext, leaf + D * W, 0x55);
        fill_dirs(ext + leaf + D * W, D);
        (void)run_case(label, src, ext, ext_len);
    }
}

int
main(void)
{
    printf("test_shipshape_witgen_construction_grid\n");

    test_grid();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
