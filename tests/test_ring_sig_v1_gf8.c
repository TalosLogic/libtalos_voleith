/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_ring_sig_v1_gf8.c - data-layer, builder, and witness-packer
 * tests for RSv1.
 *
 * Coverage by ticket:
 *
 *   T2 (data layer):
 *     voleith_rs_membership_validate
 *       - canonical config accepted
 *       - each documented malformed shape rejected (NULL cfg, NULL
 *         tree_hash, depth_m == 0, depth_m / depth_r above ceiling,
 *         sk_bytes == 0, mismatched owf node_bytes, weaker owf
 *         cr_bits, fixed-leaf sk_bytes mismatch)
 *     voleith_rsv1_config_fingerprint
 *       - determinism: same cfg twice == same 16 bytes
 *       - each field bound: changing any field changes the fingerprint
 *       - NULL args rejected
 *       - canonical-fixture KAT pin (regression guard)
 *
 *   T3 (circuit builder):
 *     voleith_rs_membership_build_circuit
 *       - hand-derived counts / offsets pin the aes-dm canonical layout
 *       - same cfg -> byte-identical layout struct + identical wire /
 *         mul / assert_product counts
 *       - eval positive (canonical witness satisfies)
 *       - eval negative on wrong sk, wrong sibling
 *       - asymmetric (tree_hash != owf_hash) round-trip
 *       - validate failure short-circuits with no wires added
 *
 *   T4 (witness packer):
 *     voleith_rs_membership_pack_witness
 *       - drives every t3_setup call (so the T3 eval-positive case is
 *         implicitly T4's "pack then eval works" acceptance)
 *       - wrong leaf_index packs cleanly but eval rejects
 *       - out-of-range leaf_index rejected at pack time
 *       - NULL args rejected
 *       - byte-deterministic output
 *
 *   T5c (ring builder):
 *     voleith_rsv1_ring_build
 *       - 8-member depth-3 ring drives every path through the membership
 *         circuit positively
 *       - 5-member depth-3 ring pins the all-zero sentinel padding
 *       - NULL / capacity / cfg-validation rejections
 *
 *   T6 (sign / verify + fs_seed):
 *     voleith_rsv1_compute_fs_seed
 *       - determinism, each-field-binding, NULL-arg rejection
 *     voleith_rsv1_sign / voleith_rsv1_verify
 *       - canonical round-trip accepts
 *       - tampered sig, R, m, cfg all rejected at verify
 *       - wrong sk / wrong sibling rejected at sign (X-10 discipline)
 *       - asymmetric (aes-dm tree, aes-cmac128 owf) round-trip accepts
 *       - NULL args + revocation != NULL rejected
 *
 *   T6a (fs_seed KAT pin):
 *     - byte-exact match of the design §5.1 canonical fixture against
 *       a baked 16-byte constant; once tagged it is a compat boundary
 */

#include "ring_sig_v1_gf8.h"

#include "gf8_circuit.h"
#include "indexed_merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "rs_membership_gf8_circuit.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wraps a fallible call so the call is ALWAYS evaluated, even when
 * NDEBUG elides assert().  Same idiom used across the test suite. */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

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

static voleith_rs_membership_config_t
canonical_cfg(void)
{
    voleith_rs_membership_config_t cfg;
    cfg.tree_hash = &voleith_node_hash_aes_dm;
    cfg.owf_hash = NULL;
    cfg.sk_bytes = 16;
    cfg.depth_m = 3;
    cfg.depth_r = 0;
    return cfg;
}

/* ================================================================
 * Test 1: validate accepts canonical config.
 * ================================================================ */
static void
test_validate_accepts_canonical(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    check("validate: canonical cfg accepted",
          voleith_rs_membership_validate(&cfg) == 0);

    /* Same cfg with depth_r != 0 (but still <= max) also accepted. */
    cfg.depth_r = 5;
    check("validate: depth_r > 0 accepted",
          voleith_rs_membership_validate(&cfg) == 0);

    /* Asymmetric vt pair where node_bytes and cr_bits match. */
    cfg = canonical_cfg();
    cfg.tree_hash = &voleith_node_hash_aes_dm;
    cfg.owf_hash = &voleith_node_hash_aes_cmac128; /* both 16B, 64-bit CR */
    check("validate: matching-size asymmetric owf accepted",
          voleith_rs_membership_validate(&cfg) == 0);

    /* Stronger owf than tree is allowed (owf >= tree). */
    cfg = canonical_cfg();
    cfg.tree_hash = &voleith_node_hash_aes_dm; /* 16B, 64-bit CR */
    cfg.owf_hash = &voleith_node_hash_aes_dm;  /* equal CR ok */
    check("validate: equal-cr asymmetric owf accepted",
          voleith_rs_membership_validate(&cfg) == 0);
}

/* ================================================================
 * Test 2: validate rejects each malformed shape.
 * ================================================================ */
static void
test_validate_rejects_malformed(void)
{
    voleith_rs_membership_config_t cfg;

    check("validate: NULL cfg rejected",
          voleith_rs_membership_validate(NULL) != 0);

    cfg = canonical_cfg();
    cfg.tree_hash = NULL;
    check("validate: NULL tree_hash rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    cfg = canonical_cfg();
    cfg.depth_m = 0;
    check("validate: depth_m == 0 rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    cfg = canonical_cfg();
    cfg.depth_m = VOLEITH_RS_MEMBERSHIP_MAX_DEPTH + 1;
    check("validate: depth_m above ceiling rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    cfg = canonical_cfg();
    cfg.depth_r = VOLEITH_RS_MEMBERSHIP_MAX_DEPTH + 1;
    check("validate: depth_r above ceiling rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    cfg = canonical_cfg();
    cfg.sk_bytes = 0;
    check("validate: sk_bytes == 0 rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    /* Mismatched node_bytes: aes-dm (16) vs grostl-256 (32). */
    cfg = canonical_cfg();
    cfg.tree_hash = &voleith_node_hash_aes_dm;
    cfg.owf_hash = &voleith_node_hash_grostl256;
    check("validate: mismatched owf node_bytes rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    /*
     * Weaker owf cr_bits: no shipped vt pair has same node_bytes and
     * different cr_bits, so fabricate a vt by copying an existing one
     * and weakening its cr_bits.  validate only reads .node_bytes,
     * .cr_bits, .fixed_leaf_bytes, .name; the function pointers are
     * not invoked by validate so the copy is safe.
     */
    {
        voleith_node_hash_vt weak_owf = voleith_node_hash_aes_dm;
        weak_owf.cr_bits = 32; /* weaker than tree's 64 */
        cfg = canonical_cfg();
        cfg.tree_hash = &voleith_node_hash_aes_dm; /* 16B, 64-bit CR */
        cfg.owf_hash = &weak_owf;                  /* 16B, 32-bit CR */
        check("validate: weaker owf cr_bits rejected",
              voleith_rs_membership_validate(&cfg) != 0);
    }

    /* Fixed-leaf sk_bytes mismatch: hirose-fixed32 requires sk_bytes == 32. */
    cfg = canonical_cfg();
    cfg.tree_hash = &voleith_node_hash_hirose_fixed32;
    cfg.owf_hash = NULL;
    cfg.sk_bytes = 16; /* wrong: vt requires 32 */
    check("validate: fixed-leaf sk_bytes mismatch rejected",
          voleith_rs_membership_validate(&cfg) != 0);

    /* And the correct width is accepted: */
    cfg.sk_bytes = 32;
    check("validate: fixed-leaf sk_bytes == 32 accepted",
          voleith_rs_membership_validate(&cfg) == 0);

    /* Asymmetric: fixed-leaf as the owf_hash, tree variable-leaf. */
    cfg = canonical_cfg();
    cfg.tree_hash = &voleith_node_hash_hirose;        /* variable, 32B, 128 */
    cfg.owf_hash = &voleith_node_hash_hirose_fixed32; /* fixed-32 */
    cfg.sk_bytes = 16; /* wrong for the fixed-leaf owf */
    check("validate: fixed-leaf owf sk_bytes mismatch rejected",
          voleith_rs_membership_validate(&cfg) != 0);
}

/* ================================================================
 * Test 3: fingerprint determinism.
 * ================================================================ */
static void
test_fingerprint_determinism(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t fp1[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];

    check("fingerprint: canonical cfg succeeds",
          voleith_rsv1_config_fingerprint(&cfg, fp1) == 0);
    check("fingerprint: canonical cfg succeeds (again)",
          voleith_rsv1_config_fingerprint(&cfg, fp2) == 0);
    check("fingerprint: repeated calls identical",
          memcmp(fp1, fp2, sizeof(fp1)) == 0);
}

/* ================================================================
 * Test 4: each field is bound (changing any field changes the
 * fingerprint).
 * ================================================================ */
static void
test_fingerprint_each_field_bound(void)
{
    voleith_rs_membership_config_t base = canonical_cfg();
    voleith_rs_membership_config_t mut;
    uint8_t fp_base[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp_mut[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];

    (void)voleith_rsv1_config_fingerprint(&base, fp_base);

    /* tree_hash (changes via name). */
    mut = base;
    mut.tree_hash = &voleith_node_hash_aes_cmac128;
    (void)voleith_rsv1_config_fingerprint(&mut, fp_mut);
    check("field bound: tree_hash",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* owf_hash (NULL -> non-NULL with same effective name still changes
     * the encoding because owf_name is taken from owf_vt directly, but
     * here the NULL fallback uses tree_hash->name = "aes-dm" while a
     * distinct owf_hash also named "aes-dm" would tie - pick a vt with
     * a different name so the binding test is meaningful). */
    mut = base;
    mut.owf_hash = &voleith_node_hash_aes_cmac128;
    (void)voleith_rsv1_config_fingerprint(&mut, fp_mut);
    check("field bound: owf_hash",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* sk_bytes. */
    mut = base;
    mut.sk_bytes = base.sk_bytes + 1;
    (void)voleith_rsv1_config_fingerprint(&mut, fp_mut);
    check("field bound: sk_bytes",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* depth_m. */
    mut = base;
    mut.depth_m = base.depth_m + 1;
    (void)voleith_rsv1_config_fingerprint(&mut, fp_mut);
    check("field bound: depth_m",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* depth_r. */
    mut = base;
    mut.depth_r = base.depth_r + 1;
    (void)voleith_rsv1_config_fingerprint(&mut, fp_mut);
    check("field bound: depth_r",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);
}

/* ================================================================
 * Test 5: NULL args rejected.
 * ================================================================ */
static void
test_fingerprint_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];

    check("fingerprint: NULL cfg rejected",
          voleith_rsv1_config_fingerprint(NULL, fp) != 0);
    check("fingerprint: NULL out rejected",
          voleith_rsv1_config_fingerprint(&cfg, NULL) != 0);

    cfg.tree_hash = NULL;
    check("fingerprint: NULL tree_hash rejected",
          voleith_rsv1_config_fingerprint(&cfg, fp) != 0);
}

/* ================================================================
 * Test 6: canonical-fixture KAT pin.
 *
 * Pins the byte-exact fingerprint of the fixture from design §5.1 (and
 * the T6a fs_seed KAT):
 *
 *   cfg = { tree_hash = &voleith_node_hash_aes_dm,  (name = "aes-dm")
 *           owf_hash  = NULL,  (effective owf = tree, name = "aes-dm")
 *           sk_bytes  = 16,
 *           depth_m   = 3,
 *           depth_r   = 0 }
 *
 * Expected absorbed bytes (canonical encoding, hex):
 *   "voleith-rsv1-cf-v1\x00"
 *   06000000  "aes-dm"
 *   06000000  "aes-dm"
 *   1000000000000000
 *   0300000000000000
 *   0000000000000000
 *
 * Expected fingerprint (SHAKE-256 truncated to 16 bytes, derived once
 * with Python hashlib.shake_256; bake it in as a regression KAT):
 *   3f 60 4d 04 78 7e a0 f5 b2 ad ea bf f5 83 78 7a
 *
 * Any future change to the canonical encoding or the canonical fixture
 * breaks this KAT loudly - that is the point.
 * ================================================================ */
static void
test_fingerprint_kat_pin(void)
{
    static const uint8_t expected[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES] = {
        0x3f, 0x60, 0x4d, 0x04, 0x78, 0x7e, 0xa0, 0xf5,
        0xb2, 0xad, 0xea, 0xbf, 0xf5, 0x83, 0x78, 0x7a,
    };
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];

    check("KAT: fingerprint computes for canonical fixture",
          voleith_rsv1_config_fingerprint(&cfg, fp) == 0);
    check("KAT: canonical fixture fingerprint matches pinned bytes",
          memcmp(fp, expected, sizeof(expected)) == 0);

    if (memcmp(fp, expected, sizeof(expected)) != 0) {
        printf("    expected:");
        for (size_t i = 0; i < sizeof(expected); i++)
            printf(" %02x", expected[i]);
        printf("\n    actual:  ");
        for (size_t i = 0; i < sizeof(fp); i++)
            printf(" %02x", fp[i]);
        printf("\n");
    }
}

/* ================================================================
 * T3: voleith_rs_membership_build_circuit tests.
 *
 * Common test fixture:
 *   - 8-leaf depth-3 membership tree
 *   - Each member's sk is a 16-byte pattern; leaf node = owf_vt.leaf_hash(sk)
 *   - Target sits at leaf index 5 (arbitrary, exercises non-trivial dirs:
 *     5 = 0b101 -> dirs = [1, 0, 1] LSB first)
 *
 * Witness packing convention matches the wire-declaration order
 * documented in rs_membership_gf8_circuit.h and exposed via the layout
 * struct: sk | dirs | owf_invin | per-level inode_invin.
 *
 * T4 replaces this hand-rolled packing with voleith_rs_membership_pack_witness.
 * ================================================================ */

#define T3_DEPTH 3u
#define T3_N_LEAVES (1u << T3_DEPTH)
#define T3_TARGET 5u

/*
 * Build an N_LEAVES depth-D Merkle tree from pre-hashed leaf nodes
 * using vt->inode_hash level by level.  Emits root and the target
 * leaf's siblings.  Direction bits are derived locally to extract
 * siblings; the caller does not see them - voleith_rs_membership_pack_witness
 * recomputes them from leaf_index.
 *
 * leaf_nodes: array of N_LEAVES contiguous node_bytes blocks (OWF
 * outputs).  siblings_out: depth * node_bytes, leaf-level first.
 */
static void
t3_build_tree(const voleith_node_hash_vt *vt, size_t depth, size_t n_leaves,
              size_t target, const uint8_t *leaf_nodes, uint8_t *root_out,
              uint8_t *siblings_out)
{
    size_t W = vt->node_bytes;
    uint8_t *layer[16];
    size_t k;

    assert(depth + 1 < (sizeof(layer) / sizeof(layer[0])));
    for (k = 0; k <= depth; k++) {
        size_t n_at_k = (n_leaves >> k) ? (n_leaves >> k) : 1;
        layer[k] = calloc(n_at_k, W);
        assert(layer[k] != NULL);
    }
    memcpy(layer[0], leaf_nodes, n_leaves * W);

    for (k = 0; k < depth; k++) {
        size_t n_parents = n_leaves >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(vt->inode_hash(layer[k] + (2 * j) * W,
                                   layer[k] + (2 * j + 1) * W,
                                   layer[k + 1] + j * W));
    }
    memcpy(root_out, layer[depth], W);

    for (k = 0; k < depth; k++) {
        size_t cur = target >> k;
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }
    for (k = 0; k <= depth; k++)
        free(layer[k]);
}

/*
 * Pack the instance buffer for the T3 fixture: just the root (siblings
 * are witness now, packed by voleith_rs_membership_pack_witness).
 */
static void
t3_pack_instance(const voleith_rs_membership_layout_t *layout,
                 const uint8_t *root, uint8_t *instance)
{
    memcpy(instance + layout->inst_root_off, root, layout->inst_root_bytes);
}

/*
 * Build the ring (N_LEAVES distinct sks + their owf leaf nodes), build
 * the circuit + layout, software-build the tree, pack the witness via
 * voleith_rs_membership_pack_witness and the instance for the target member,
 * and return everything via out pointers so each test can mutate
 * before evaluating.
 */
static void
t3_setup(const voleith_rs_membership_config_t *cfg,
         voleith_gf8_circuit_t **c_out,
         voleith_rs_membership_layout_t *layout_out, uint8_t **sk_out,
         uint8_t **siblings_out, uint8_t **root_out, uint8_t **witness_out,
         uint8_t **instance_out)
{
    const voleith_node_hash_vt *owf_vt =
        cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    size_t W = cfg->tree_hash->node_bytes;
    uint8_t *leaf_nodes;
    uint8_t *sk;
    uint8_t *siblings;
    uint8_t *root;
    uint8_t *witness;
    uint8_t *instance;
    voleith_rs_membership_path_t path;

    leaf_nodes = calloc(T3_N_LEAVES, W);
    assert(leaf_nodes != NULL);
    for (size_t i = 0; i < T3_N_LEAVES; i++) {
        uint8_t sk_i[64];
        assert(cfg->sk_bytes <= sizeof(sk_i));
        for (size_t j = 0; j < cfg->sk_bytes; j++)
            sk_i[j] = (uint8_t)(i * 7 + j);
        MUST_OK(owf_vt->leaf_hash(sk_i, cfg->sk_bytes, leaf_nodes + i * W));
    }

    sk = calloc(cfg->sk_bytes ? cfg->sk_bytes : 1, 1);
    assert(sk != NULL);
    for (size_t j = 0; j < cfg->sk_bytes; j++)
        sk[j] = (uint8_t)(T3_TARGET * 7 + j);

    siblings = calloc(cfg->depth_m * W, 1);
    root = calloc(W, 1);
    assert(siblings && root);
    t3_build_tree(cfg->tree_hash, cfg->depth_m, T3_N_LEAVES, T3_TARGET,
                  leaf_nodes, root, siblings);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    assert(c != NULL);
    MUST_OK(voleith_rs_membership_build_circuit(c, cfg, layout_out));

    witness = calloc(layout_out->witness_bytes, 1);
    instance = calloc(layout_out->instance_bytes, 1);
    assert(witness && instance);

    path.leaf_index = T3_TARGET;
    path.siblings = siblings;
    MUST_OK(voleith_rs_membership_pack_witness(cfg, layout_out, sk, &path, NULL,
                                               witness));
    t3_pack_instance(layout_out, root, instance);

    free(leaf_nodes);

    *c_out = c;
    *sk_out = sk;
    *siblings_out = siblings;
    *root_out = root;
    *witness_out = witness;
    *instance_out = instance;
}

static void
t3_teardown(voleith_gf8_circuit_t *c, uint8_t *sk, uint8_t *siblings,
            uint8_t *root, uint8_t *witness, uint8_t *instance)
{
    voleith_gf8_circuit_free(c);
    free(sk);
    free(siblings);
    free(root);
    free(witness);
    free(instance);
}

/* ================================================================
 * T3 test 1: layout / count sanity for the canonical (aes-dm)
 * config.  Hand-derived from:
 *
 *   W                = 16 (aes-dm node_bytes)
 *   leaf_invin       = dm_n_aes(16) * 200 = 1 * 200 = 200
 *   inode_invin      = 200 (one AES-128 per DM inode)
 *   depth_m          = 3
 *
 *   witness bytes    = sk(16) + dirs(3) + siblings(48) + leaf_invin(200)
 *                    + 3 * inode_invin(200)
 *                    = 16 + 3 + 48 + 200 + 600 = 867
 *   instance bytes   = W (root) = 16
 * ================================================================ */
static void
test_build_circuit_counts_aes_dm(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    voleith_rs_membership_layout_t layout;

    assert(c != NULL);
    check("build: aes-dm canonical succeeds",
          voleith_rs_membership_build_circuit(c, &cfg, &layout) == 0);

    check("layout: sk_off == 0", layout.sk_off == 0);
    check("layout: sk_bytes == 16", layout.sk_bytes == 16);
    check("layout: dirs_off == 16", layout.dirs_off == 16);
    check("layout: dirs_bytes == 3", layout.dirs_bytes == 3);
    check("layout: siblings_off == 19", layout.siblings_off == 19);
    check("layout: siblings_bytes == 48", layout.siblings_bytes == 48);
    check("layout: owf_invin_off == 67", layout.owf_invin_off == 67);
    check("layout: owf_invin_bytes == 200", layout.owf_invin_bytes == 200);
    check("layout: path_invin_off == 267", layout.path_invin_off == 267);
    check("layout: path_invin_per_level == 200",
          layout.path_invin_per_level == 200);
    check("layout: path_invin_bytes == 600", layout.path_invin_bytes == 600);
    check("layout: witness_bytes == 867", layout.witness_bytes == 867);

    check("layout: inst_root_off == 0", layout.inst_root_off == 0);
    check("layout: inst_root_bytes == 16", layout.inst_root_bytes == 16);
    check("layout: instance_bytes == 16", layout.instance_bytes == 16);

    check("layout: depth_m == 3", layout.depth_m == 3);
    check("layout: node_bytes == 16", layout.node_bytes == 16);

    check("counts: witness wires match layout",
          voleith_gf8_circuit_witness_count(c) == layout.witness_bytes);
    check("counts: instance wires match layout",
          voleith_gf8_circuit_instance_count(c) == layout.instance_bytes);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * T3 test 2: build_circuit determinism - same cfg twice produces the
 * same layout (offsets and counts).  Stronger than the in-process
 * fingerprint determinism: the wire-declaration order is part of the
 * builder contract that T4's witness packer depends on.
 * ================================================================ */
static void
test_build_circuit_layout_deterministic(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    voleith_rs_membership_layout_t L1, L2;

    assert(c1 && c2);
    MUST_OK(voleith_rs_membership_build_circuit(c1, &cfg, &L1));
    MUST_OK(voleith_rs_membership_build_circuit(c2, &cfg, &L2));

    check("determinism: layouts byte-equal", memcmp(&L1, &L2, sizeof(L1)) == 0);
    check("determinism: witness counts match",
          voleith_gf8_circuit_witness_count(c1) ==
              voleith_gf8_circuit_witness_count(c2));
    check("determinism: instance counts match",
          voleith_gf8_circuit_instance_count(c1) ==
              voleith_gf8_circuit_instance_count(c2));
    check("determinism: mul counts match",
          voleith_gf8_circuit_mul_count(c1) ==
              voleith_gf8_circuit_mul_count(c2));
    check("determinism: assert_product counts match",
          voleith_gf8_circuit_assert_product_count(c1) ==
              voleith_gf8_circuit_assert_product_count(c2));

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * T3 test 3: positive eval - the canonical witness satisfies the
 * canonical-cfg circuit.
 * ================================================================ */
static void
test_build_circuit_eval_positive(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wires = calloc(nW > 0 ? nW : 1, 1);
    assert(wires);

    check("eval: canonical witness satisfies aes-dm circuit",
          voleith_gf8_circuit_eval(c, witness, instance, wires) == 1);

    free(wires);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

/* ================================================================
 * T3 test 4: wrong sk -> circuit rejects.
 *
 * Mutating sk changes the OWF output, which changes the computed leaf
 * node, which propagates up the merkle path to a computed root that
 * disagrees with the membership_root instance wires.  The
 * assert_equal_root constraints fire.
 * ================================================================ */
static void
test_build_circuit_eval_wrong_sk(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    /* Corrupt the sk byte in the witness only - leaving siblings + root
     * instance bytes and inv_in witnesses intact.  The OWF circuit will
     * recompute a different leaf node from the mutated sk, and the
     * inode chain will end at a root that doesn't match the instance
     * root.  Several constraints fire; eval returns 0. */
    witness[layout.sk_off] ^= 0x01;

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wires = calloc(nW > 0 ? nW : 1, 1);
    assert(wires);

    check("eval: wrong sk rejected",
          voleith_gf8_circuit_eval(c, witness, instance, wires) == 0);

    free(wires);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

/* ================================================================
 * T3 test 5: wrong sibling -> circuit rejects.
 *
 * Mutating a sibling WITNESS byte changes the inode walk's input at
 * that level, which changes the computed root.  assert_equal_root
 * fires.
 * ================================================================ */
static void
test_build_circuit_eval_wrong_sibling(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    witness[layout.siblings_off] ^= 0x01;

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wires = calloc(nW > 0 ? nW : 1, 1);
    assert(wires);

    check("eval: tampered sibling rejected",
          voleith_gf8_circuit_eval(c, witness, instance, wires) == 0);

    free(wires);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

/* ================================================================
 * T3 test 6: asymmetric vt pair (tree_hash != owf_hash) with matching
 * node_bytes round-trips.
 *
 * tree = aes-dm (16B, 64-bit CR), owf = aes-cmac128 (16B, 64-bit CR).
 * Validate accepts (equal cr_bits is allowed).  Eval succeeds.
 * ================================================================ */
static void
test_build_circuit_eval_asymmetric_owf(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;

    cfg.tree_hash = &voleith_node_hash_aes_dm;
    cfg.owf_hash = &voleith_node_hash_aes_cmac128;
    cfg.sk_bytes = 16;
    cfg.depth_m = 3;
    cfg.depth_r = 0;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wires = calloc(nW > 0 ? nW : 1, 1);
    assert(wires);

    check("eval: asymmetric (aes-dm tree, aes-cmac owf) satisfies",
          voleith_gf8_circuit_eval(c, witness, instance, wires) == 1);

    free(wires);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

/* ================================================================
 * T3 test 7: validate failure short-circuits the builder (no wires
 * added, layout untouched).
 * ================================================================ */
static void
test_build_circuit_validate_failure(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    voleith_rs_membership_layout_t layout;
    voleith_rs_membership_layout_t sentinel;

    assert(c != NULL);
    memset(&sentinel, 0xff, sizeof(sentinel));
    layout = sentinel;

    cfg.depth_m = 0; /* validate rejects */
    check("build: depth_m == 0 returns -1",
          voleith_rs_membership_build_circuit(c, &cfg, &layout) == -1);
    check("build: failure leaves layout untouched",
          memcmp(&layout, &sentinel, sizeof(layout)) == 0);
    check("build: failure declares no witness wires",
          voleith_gf8_circuit_witness_count(c) == 0);
    check("build: failure declares no instance wires",
          voleith_gf8_circuit_instance_count(c) == 0);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * T4 tests: voleith_rs_membership_pack_witness.
 *
 * t3_setup already routes through voleith_rs_membership_pack_witness, so the
 * T3 eval-positive / wrong-sk / wrong-sibling / asymmetric tests above
 * collectively cover the "pack then eval works" acceptance criterion.
 *
 * These T4-specific tests add coverage that T3 does not exercise:
 *   - leaf_index drives dirs correctly (eval rejects when leaf_index
 *     disagrees with the path the siblings describe)
 *   - leaf_index out of range rejected
 *   - NULL args rejected
 *   - byte-for-byte deterministic output
 * ================================================================ */

static void
test_pack_witness_wrong_leaf_index(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;
    voleith_rs_membership_path_t path;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    /*
     * Re-pack with a leaf_index that differs from T3_TARGET by one bit
     * - the siblings still match T3_TARGET's path, but the dir bytes
     * now describe a different path through them.  The computed root
     * disagrees with the instance root.  eval returns 0.
     */
    path.leaf_index = T3_TARGET ^ 1u;
    path.siblings = siblings;
    check("pack: re-pack with wrong leaf_index succeeds (no validation here)",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                             witness) == 0);

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wires = calloc(nW > 0 ? nW : 1, 1);
    assert(wires);

    check("eval: wrong leaf_index rejected",
          voleith_gf8_circuit_eval(c, witness, instance, wires) == 0);

    free(wires);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

static void
test_pack_witness_leaf_index_out_of_range(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;
    voleith_rs_membership_path_t path;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    /* depth_m = 3 -> ring capacity 2^3 = 8.  Index 8 is one past the
     * end.  Index 0xFF is well past. */
    path.leaf_index = 1u << cfg.depth_m;
    path.siblings = siblings;
    check("pack: leaf_index == 2^depth_m rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                             witness) == -1);

    path.leaf_index = (size_t)-1;
    check("pack: leaf_index = SIZE_MAX rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                             witness) == -1);

    /* And the valid boundary works. */
    path.leaf_index = (1u << cfg.depth_m) - 1u;
    check("pack: leaf_index == 2^depth_m - 1 accepted",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                             witness) == 0);

    t3_teardown(c, sk, siblings, root, witness, instance);
}

static void
test_pack_witness_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;
    voleith_rs_membership_path_t path;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    path.leaf_index = T3_TARGET;
    path.siblings = siblings;

    check("pack: NULL cfg rejected",
          voleith_rs_membership_pack_witness(NULL, &layout, sk, &path, NULL,
                                             witness) == -1);
    check("pack: NULL layout rejected",
          voleith_rs_membership_pack_witness(&cfg, NULL, sk, &path, NULL,
                                             witness) == -1);
    check("pack: NULL sk rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, NULL, &path, NULL,
                                             witness) == -1);
    check("pack: NULL membership rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, NULL, NULL,
                                             witness) == -1);
    check("pack: NULL witness rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                             NULL) == -1);

    voleith_rs_membership_path_t bad_path = path;
    bad_path.siblings = NULL;
    check("pack: NULL membership->siblings rejected",
          voleith_rs_membership_pack_witness(&cfg, &layout, sk, &bad_path, NULL,
                                             witness) == -1);

    t3_teardown(c, sk, siblings, root, witness, instance);
}

static void
test_pack_witness_deterministic(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_gf8_circuit_t *c = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *sk, *siblings, *root, *witness, *instance;
    voleith_rs_membership_path_t path;

    t3_setup(&cfg, &c, &layout, &sk, &siblings, &root, &witness, &instance);

    uint8_t *witness2 = calloc(layout.witness_bytes, 1);
    assert(witness2);

    path.leaf_index = T3_TARGET;
    path.siblings = siblings;
    MUST_OK(voleith_rs_membership_pack_witness(&cfg, &layout, sk, &path, NULL,
                                               witness2));

    check("pack: re-pack produces byte-identical witness",
          memcmp(witness, witness2, layout.witness_bytes) == 0);

    free(witness2);
    t3_teardown(c, sk, siblings, root, witness, instance);
}

/* ================================================================
 * T5c (ring builder) tests.
 *
 * voleith_rsv1_ring_build packages the inline ring-construction
 * pattern in t3_setup into a single library call.  These tests cover:
 *   - 8-member depth-3 ring: every emitted path drives the membership
 *     circuit to a satisfying witness (pack + eval positive per member).
 *   - 5-member depth-3 ring (3 sentinel slots): every real member's
 *     path satisfies, AND a hand-derived sentinel-side sibling matches
 *     the expected hash output (pins the all-zero padding convention).
 *   - Argument-validation rejection.
 * ================================================================ */

#define T5C_SK_BYTES 16u

/*
 * Drive the membership circuit for one member of a ring built via
 * voleith_rsv1_ring_build.  Returns the circuit_eval result: 1 if
 * satisfied, 0 if any constraint fails, -1 on error.
 */
static int
t5c_eval_member(const voleith_rs_membership_config_t *cfg, const uint8_t *sk,
                const voleith_rs_membership_path_t *path, const uint8_t *root)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    assert(c != NULL);

    voleith_rs_membership_layout_t layout;
    MUST_OK(voleith_rs_membership_build_circuit(c, cfg, &layout));

    uint8_t *witness = calloc(layout.witness_bytes, 1);
    uint8_t *instance = calloc(layout.instance_bytes, 1);
    assert(witness && instance);

    MUST_OK(voleith_rs_membership_pack_witness(cfg, &layout, sk, path, NULL,
                                               witness));
    memcpy(instance + layout.inst_root_off, root, layout.inst_root_bytes);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(n_wires > 0 ? n_wires : 1, 1);
    assert(wire_vals);
    int rc = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);

    free(wire_vals);
    free(witness);
    free(instance);
    voleith_gf8_circuit_free(c);
    return rc;
}

static void
test_ring_build_full_8_members(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    size_t W = cfg.tree_hash->node_bytes;
    size_t depth_m = cfg.depth_m;
    size_t n = (size_t)1u << depth_m; /* 8 */

    uint8_t *sks = calloc(n * T5C_SK_BYTES, 1);
    assert(sks);
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < T5C_SK_BYTES; j++)
            sks[i * T5C_SK_BYTES + j] = (uint8_t)(i * 7u + j * 13u + 1u);

    uint8_t *root = calloc(W, 1);
    voleith_rs_membership_path_t *paths =
        calloc(n, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage = calloc(n * depth_m * W, 1);
    assert(root && paths && sib_storage);

    check("ring_build (full): returns 0",
          voleith_rsv1_ring_build(&cfg, sks, n, root, paths, sib_storage) == 0);

    for (size_t i = 0; i < n; i++) {
        char label[64];
        snprintf(label, sizeof(label),
                 "ring_build (full): paths[%zu].leaf_index == %zu", i, i);
        check(label, paths[i].leaf_index == i);

        snprintf(label, sizeof(label),
                 "ring_build (full): paths[%zu].siblings wired into storage",
                 i);
        check(label, paths[i].siblings == sib_storage + i * depth_m * W);

        int eval =
            t5c_eval_member(&cfg, sks + i * T5C_SK_BYTES, &paths[i], root);
        snprintf(label, sizeof(label),
                 "ring_build (full): member %zu satisfies circuit", i);
        check(label, eval == 1);
    }

    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_ring_build_padded_5_members(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    const voleith_node_hash_vt *vt = cfg.tree_hash;
    size_t W = vt->node_bytes;
    size_t depth_m = cfg.depth_m;
    size_t capacity = (size_t)1u << depth_m; /* 8 */
    size_t n = 5;

    uint8_t *sks = calloc(n * T5C_SK_BYTES, 1);
    assert(sks);
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < T5C_SK_BYTES; j++)
            sks[i * T5C_SK_BYTES + j] = (uint8_t)(i * 11u + j * 17u + 3u);

    uint8_t *root = calloc(W, 1);
    voleith_rs_membership_path_t *paths =
        calloc(n, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage = calloc(n * depth_m * W, 1);
    assert(root && paths && sib_storage);

    check("ring_build (padded): returns 0",
          voleith_rsv1_ring_build(&cfg, sks, n, root, paths, sib_storage) == 0);

    /*
     * Hand-derive the sentinel-side siblings to pin the padding shape.
     * Slots [5,6,7] are sentinel = all-zero leaf nodes (size W).  For
     * member 4 (leaf_index 4 = 0b100):
     *   level 0 sibling = leaf_nodes[5] = all zeros
     *   level 1 sibling = inode_hash(leaf_nodes[6], leaf_nodes[7])
     *                   = inode_hash(0, 0)
     *   level 2 sibling = inode_hash(inode_hash(leaf[0], leaf[1]),
     *                                inode_hash(leaf[2], leaf[3]))
     */
    uint8_t zero_node[MERKLE_VT_MAX_NODE_BYTES] = {0};

    check("ring_build (padded): member 4 level-0 sibling is sentinel zero",
          memcmp(paths[4].siblings + 0 * W, zero_node, W) == 0);

    uint8_t expected_zz[MERKLE_VT_MAX_NODE_BYTES];
    MUST_OK(vt->inode_hash(zero_node, zero_node, expected_zz));
    check("ring_build (padded): member 4 level-1 sibling = inode(0,0)",
          memcmp(paths[4].siblings + 1 * W, expected_zz, W) == 0);

    /* Per-member eval positives. */
    for (size_t i = 0; i < n; i++) {
        char label[64];
        int eval =
            t5c_eval_member(&cfg, sks + i * T5C_SK_BYTES, &paths[i], root);
        snprintf(label, sizeof(label),
                 "ring_build (padded): member %zu satisfies circuit", i);
        check(label, eval == 1);
    }

    /*
     * Sub-capacity sanity: building the same ring with capacity-many
     * members but with the trailing slots' sks chosen so they hash to
     * all-zero nodes would also produce the same root.  We can't
     * synthesize that, but we CAN verify that voleith_rsv1_ring_build
     * with n == capacity and arbitrary sks produces a DIFFERENT root
     * (i.e. the padding really is in effect here).
     */
    uint8_t *root_full = calloc(W, 1);
    uint8_t *sks_full = calloc(capacity * T5C_SK_BYTES, 1);
    voleith_rs_membership_path_t *paths_full =
        calloc(capacity, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage_full = calloc(capacity * depth_m * W, 1);
    assert(root_full && sks_full && paths_full && sib_storage_full);

    memcpy(sks_full, sks, n * T5C_SK_BYTES);
    for (size_t i = n; i < capacity; i++)
        for (size_t j = 0; j < T5C_SK_BYTES; j++)
            sks_full[i * T5C_SK_BYTES + j] = (uint8_t)(0xA0u + i + j);

    MUST_OK(voleith_rsv1_ring_build(&cfg, sks_full, capacity, root_full,
                                    paths_full, sib_storage_full));
    check("ring_build (padded): padded root != fully-populated root with "
          "non-sentinel trailing members",
          memcmp(root, root_full, W) != 0);

    free(root_full);
    free(sks_full);
    free(paths_full);
    free(sib_storage_full);

    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_ring_build_argument_validation(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    size_t W = cfg.tree_hash->node_bytes;
    size_t depth_m = cfg.depth_m;
    size_t capacity = (size_t)1u << depth_m;

    uint8_t sks[8 * T5C_SK_BYTES] = {0};
    uint8_t root[64];
    voleith_rs_membership_path_t paths[8];
    uint8_t sib_storage[8 * 3 * 64];

    check("ring_build: NULL cfg rejected",
          voleith_rsv1_ring_build(NULL, sks, 1, root, paths, sib_storage) ==
              -1);
    check("ring_build: NULL sks rejected",
          voleith_rsv1_ring_build(&cfg, NULL, 1, root, paths, sib_storage) ==
              -1);
    check("ring_build: NULL root_out rejected",
          voleith_rsv1_ring_build(&cfg, sks, 1, NULL, paths, sib_storage) ==
              -1);
    check("ring_build: NULL paths_out rejected",
          voleith_rsv1_ring_build(&cfg, sks, 1, root, NULL, sib_storage) == -1);
    check("ring_build: NULL siblings_storage rejected",
          voleith_rsv1_ring_build(&cfg, sks, 1, root, paths, NULL) == -1);
    check("ring_build: n_members == 0 rejected",
          voleith_rsv1_ring_build(&cfg, sks, 0, root, paths, sib_storage) ==
              -1);
    check("ring_build: n_members > capacity rejected",
          voleith_rsv1_ring_build(&cfg, sks, capacity + 1u, root, paths,
                                  sib_storage) == -1);

    /* Malformed cfg propagates from voleith_rs_membership_validate. */
    voleith_rs_membership_config_t bad = cfg;
    bad.depth_m = 0;
    check("ring_build: malformed cfg rejected",
          voleith_rsv1_ring_build(&bad, sks, 1, root, paths, sib_storage) ==
              -1);

    (void)W;
}

/* ================================================================
 * T6 (sign / verify + fs_seed) tests.
 *
 * Coverage:
 *   - fs_seed determinism + NULL-arg rejection + each-field-bound
 *   - sign/verify round-trip (canonical aes-dm cfg)
 *   - tamper sig / R / m / cfg all rejected at verify
 *   - wrong sk / wrong sibling rejected at sign (X-10 discipline:
 *     prove sees a non-satisfying witness and returns nonzero)
 *   - asymmetric (aes-dm tree, aes-cmac128 owf) round-trip
 *
 * EM-128f is the cheapest standard parameter set and gives reasonable
 * grinding-loop time for a depth-3 8-leaf ring.
 * ================================================================ */

#define T6_DEPTH 3u
#define T6_N (1u << T6_DEPTH)
#define T6_SIGNER 5u
#define T6_SK_BYTES 16u

static voleith_params_t
t6_params(void)
{
    return voleith_params_em_128f;
}

/* Build a ring of T6_N members at depth T6_DEPTH using cfg.  Caller
 * frees all four output buffers (sks, root, paths, sib_storage). */
static void
t6_build_ring(const voleith_rs_membership_config_t *cfg, uint8_t **sks_out,
              uint8_t **root_out, voleith_rs_membership_path_t **paths_out,
              uint8_t **sib_storage_out)
{
    size_t W = cfg->tree_hash->node_bytes;
    size_t sk_bytes = cfg->sk_bytes;
    uint8_t *sks = calloc(T6_N * sk_bytes, 1);
    uint8_t *root = calloc(W, 1);
    voleith_rs_membership_path_t *paths =
        calloc(T6_N, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage = calloc(T6_N * cfg->depth_m * W, 1);
    assert(sks && root && paths && sib_storage);

    for (size_t i = 0; i < T6_N; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    MUST_OK(voleith_rsv1_ring_build(cfg, sks, T6_N, root, paths, sib_storage));

    *sks_out = sks;
    *root_out = root;
    *paths_out = paths;
    *sib_storage_out = sib_storage;
}

static void
test_fs_seed_determinism(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t R[16];
    uint8_t s1[VOLEITH_RSV1_FS_SEED_BYTES];
    uint8_t s2[VOLEITH_RSV1_FS_SEED_BYTES];
    const char *m = "T6 fs_seed determinism";
    for (size_t i = 0; i < 16; i++)
        R[i] = (uint8_t)(i + 1);

    check("fs_seed: canonical inputs succeed",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, (const uint8_t *)m,
                                       strlen(m), s1) == 0);
    check("fs_seed: canonical inputs succeed (again)",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, (const uint8_t *)m,
                                       strlen(m), s2) == 0);
    check("fs_seed: repeated calls byte-identical",
          memcmp(s1, s2, sizeof(s1)) == 0);
}

static void
test_fs_seed_each_field_bound(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t R[16];
    uint8_t base[VOLEITH_RSV1_FS_SEED_BYTES];
    uint8_t mut[VOLEITH_RSV1_FS_SEED_BYTES];
    const char *m = "hi";
    for (size_t i = 0; i < 16; i++)
        R[i] = (uint8_t)(i + 1);

    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R, NULL, (const uint8_t *)m,
                                         strlen(m), base));

    /* R: flip a bit. */
    uint8_t R2[16];
    memcpy(R2, R, 16);
    R2[0] ^= 0x01;
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R2, NULL, (const uint8_t *)m,
                                         strlen(m), mut));
    check("fs_seed: bound to membership_root", memcmp(base, mut, 16) != 0);

    /* m: change message. */
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R, NULL, (const uint8_t *)"ho",
                                         2, mut));
    check("fs_seed: bound to m", memcmp(base, mut, 16) != 0);

    /* m_len: same byte stream but different m_len (truncated). */
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R, NULL, (const uint8_t *)m, 1,
                                         mut));
    check("fs_seed: bound to m_len", memcmp(base, mut, 16) != 0);

    /* cfg: change depth_m -> different fingerprint. */
    voleith_rs_membership_config_t cfg2 = cfg;
    cfg2.depth_m = cfg.depth_m + 1;
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg2, R, NULL, (const uint8_t *)m,
                                         strlen(m), mut));
    check("fs_seed: bound to cfg (depth_m)", memcmp(base, mut, 16) != 0);

    /* V: NULL vs zero buffer produce the same fs_seed (zero placeholder
     * is the documented expansion).  Then a non-zero V differs. */
    uint8_t V_zero[16] = {0};
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R, V_zero, (const uint8_t *)m,
                                         strlen(m), mut));
    check("fs_seed: V=NULL == V=zeros", memcmp(base, mut, 16) == 0);

    uint8_t V_nz[16];
    for (size_t i = 0; i < 16; i++)
        V_nz[i] = 0xA0u;
    MUST_OK(voleith_rsv1_compute_fs_seed(&cfg, R, V_nz, (const uint8_t *)m,
                                         strlen(m), mut));
    check("fs_seed: V non-zero changes seed", memcmp(base, mut, 16) != 0);
}

static void
test_fs_seed_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t R[16] = {0};
    uint8_t out[VOLEITH_RSV1_FS_SEED_BYTES];

    check("fs_seed: NULL cfg rejected",
          voleith_rsv1_compute_fs_seed(NULL, R, NULL, NULL, 0, out) == -1);
    check("fs_seed: NULL R rejected",
          voleith_rsv1_compute_fs_seed(&cfg, NULL, NULL, NULL, 0, out) == -1);
    check("fs_seed: NULL out rejected",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, NULL, 0, NULL) == -1);
    check("fs_seed: NULL m with m_len > 0 rejected",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, NULL, 1, out) == -1);
    check("fs_seed: NULL m with m_len == 0 accepted",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, NULL, 0, out) == 0);
}

/* ================================================================
 * T6a: byte-exact fs_seed KAT pin (design §5.1).
 *
 * Canonical fixture:
 *   cfg = { tree_hash = &voleith_node_hash_aes_dm, owf_hash = NULL,
 *           sk_bytes = 16, depth_m = 3, depth_r = 0 }
 *   R   = 0x01 0x02 ... 0x10           (16 bytes counting up)
 *   V   = NULL (revocation disabled)    (absorbs 16 zero bytes)
 *   m   = "RSv1 KAT message"            (16 ASCII bytes)
 *
 * Absorb stream (89 bytes total):
 *   01                                                  version
 *   564f4c456974482d52537631 00000000                   domain tag
 *   3f604d04787ea0f5b2adeabff583787a                    cfg_fingerprint
 *   0102030405060708090a0b0c0d0e0f10                    R
 *   00000000000000000000000000000000                    V_zero
 *   0000000000000010                                    m_len BE
 *   52537631204b4154206d657373616765                    m
 *
 * Expected SHAKE-256 squeeze-16:
 *   6f 30 c8 27 cd b0 7c 88 36 37 0a 0a a0 a2 ae 59
 *
 * Reference derivation (one-off Python; reproduce by hand if needed):
 *   python3 -c '
 *     import hashlib
 *     absorb = (
 *       bytes([1])
 *       + b"VOLEitH-RSv1" + bytes(4)
 *       + bytes.fromhex("3f604d04787ea0f5b2adeabff583787a")
 *       + bytes(range(1, 17))
 *       + bytes(16)
 *       + (16).to_bytes(8, "big")
 *       + b"RSv1 KAT message")
 *     print(hashlib.shake_256(absorb).digest(16).hex())
 *   '
 *
 * Once this KAT is tagged it is a compat boundary: any subsequent
 * change to the §5 absorb layout MUST bump
 * VOLEITH_RSV1_FS_SEED_FMT_VERSION and ship a parallel KAT for the new
 * version (this one still pins format 0x01).
 * ================================================================ */
static void
test_fs_seed_kat_pin(void)
{
    static const uint8_t expected[VOLEITH_RSV1_FS_SEED_BYTES] = {
        0x6f, 0x30, 0xc8, 0x27, 0xcd, 0xb0, 0x7c, 0x88,
        0x36, 0x37, 0x0a, 0x0a, 0xa0, 0xa2, 0xae, 0x59,
    };
    voleith_rs_membership_config_t cfg = canonical_cfg();
    uint8_t R[16];
    const uint8_t m[] = "RSv1 KAT message"; /* 16 bytes + implicit NUL */
    uint8_t fs_seed[VOLEITH_RSV1_FS_SEED_BYTES];

    for (size_t i = 0; i < 16; i++)
        R[i] = (uint8_t)(i + 1);

    check("KAT: fs_seed computes for canonical §5.1 fixture",
          voleith_rsv1_compute_fs_seed(&cfg, R, NULL, m, sizeof(m) - 1,
                                       fs_seed) == 0);
    check("KAT: fs_seed canonical fixture matches pinned bytes",
          memcmp(fs_seed, expected, sizeof(expected)) == 0);

    if (memcmp(fs_seed, expected, sizeof(expected)) != 0) {
        printf("    expected:");
        for (size_t i = 0; i < sizeof(expected); i++)
            printf(" %02x", expected[i]);
        printf("\n    actual:  ");
        for (size_t i = 0; i < sizeof(fs_seed); i++)
            printf(" %02x", fs_seed[i]);
        printf("\n");
    }
}

static void
test_rsv1_sign_verify_roundtrip(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};
    const uint8_t m[] = "T6 round-trip message";
    size_t m_len = sizeof(m) - 1;

    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    int sign_rc =
        voleith_rsv1_sign(&sig, &cfg, &params, sks + T6_SIGNER * T6_SK_BYTES,
                          root, &paths[T6_SIGNER], NULL, NULL, m, m_len);
    check("sign: canonical roundtrip succeeds", sign_rc == 0);
    check("sign: sig.data populated", sig.data != NULL && sig.len > 0);

    if (sign_rc == 0) {
        int verify_rc =
            voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m, m_len);
        check("verify: matching sig accepts", verify_rc == 0);

        /* Tamper proof bytes. */
        sig.data[0] ^= 0x01;
        check("verify: tampered sig rejects",
              voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m, m_len) ==
                  -1);
        sig.data[0] ^= 0x01;

        /* Tamper R. */
        uint8_t bad_root[MERKLE_VT_MAX_NODE_BYTES];
        memcpy(bad_root, root, cfg.tree_hash->node_bytes);
        bad_root[0] ^= 0x01;
        check("verify: tampered R rejects",
              voleith_rsv1_verify(&sig, &cfg, &params, bad_root, NULL, m,
                                  m_len) == -1);

        /* Tamper m. */
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        check("verify: tampered m rejects",
              voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, bad_m,
                                  m_len) == -1);

        /* Tamper cfg (different depth_m -> different fingerprint -> different
         * fs_seed -> verifier-side challenges desynchronised). */
        voleith_rs_membership_config_t cfg_bad = cfg;
        cfg_bad.depth_m = cfg.depth_m + 1;
        check("verify: tampered cfg rejects",
              voleith_rsv1_verify(&sig, &cfg_bad, &params, root, NULL, m,
                                  m_len) == -1);
    }

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_sign_wrong_sk_rejected(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};

    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    /*
     * Use the signer slot's path but a different sk (member 2 instead
     * of member 5).  The circuit's leaf computed from sk(2) doesn't sit
     * at index 5's position, so eval fails -> voleith_gf8_prove rejects
     * the witness up-front (X-10 discipline).
     */
    int rc = voleith_rsv1_sign(&sig, &cfg, &params, sks + 2 * T6_SK_BYTES, root,
                               &paths[T6_SIGNER], NULL, NULL,
                               (const uint8_t *)"x", 1);
    check("sign: wrong sk rejected", rc == -1);
    check("sign: failed sign leaves sig zeroed",
          sig.data == NULL && sig.len == 0);

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_sign_wrong_sibling_rejected(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};
    size_t W = cfg.tree_hash->node_bytes;

    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    /*
     * Build a bad sibling buffer: copy the signer's real path, then
     * flip a byte in the leaf-level sibling.  Reconstructed root will
     * not match the real ring root, and the in-circuit assert_equal
     * fails -> voleith_gf8_prove returns -1.
     */
    uint8_t *bad_sib = calloc(cfg.depth_m * W, 1);
    assert(bad_sib);
    memcpy(bad_sib, paths[T6_SIGNER].siblings, cfg.depth_m * W);
    bad_sib[0] ^= 0x01;

    voleith_rs_membership_path_t bad_path = paths[T6_SIGNER];
    bad_path.siblings = bad_sib;

    int rc =
        voleith_rsv1_sign(&sig, &cfg, &params, sks + T6_SIGNER * T6_SK_BYTES,
                          root, &bad_path, NULL, NULL, (const uint8_t *)"x", 1);
    check("sign: tampered sibling rejected", rc == -1);

    free(bad_sib);
    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_sign_verify_asymmetric_owf(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    cfg.tree_hash = &voleith_node_hash_aes_dm;
    cfg.owf_hash = &voleith_node_hash_aes_cmac128;
    cfg.sk_bytes = T6_SK_BYTES;

    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};

    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    const uint8_t m[] = "asymmetric roundtrip";
    size_t m_len = sizeof(m) - 1;
    int sign_rc =
        voleith_rsv1_sign(&sig, &cfg, &params, sks + T6_SIGNER * T6_SK_BYTES,
                          root, &paths[T6_SIGNER], NULL, NULL, m, m_len);
    check("sign (asymmetric): succeeds", sign_rc == 0);

    if (sign_rc == 0) {
        check("verify (asymmetric): accepts",
              voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m, m_len) ==
                  0);
    }

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

/*
 * Anonymity smoke test (design §8 test 9).
 *
 * Two distinct members sign the same m.  Assert:
 *   (a) the two proof bytestreams are not byte-identical (different
 *       witnesses -> different VOLE commitments -> different proof
 *       bytes);
 *   (b) neither proof contains any member's leaf node (the public ring
 *       contents) as a contiguous byte substring.  The proof bytes are
 *       VOLE/GGM-committed, so a memcmp scan should never hit a leaf
 *       node value verbatim; this is a smoke test that pins the
 *       expectation rather than the cryptographic anonymity property.
 */
static int
contains_subseq(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
                size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len)
        return 0;
    for (size_t i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return 1;
    return 0;
}

static void
test_rsv1_anonymity_smoke(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    const uint8_t m[] = "anonymity-smoke message";
    size_t m_len = sizeof(m) - 1;
    voleith_ring_sig_t sigA = {NULL, 0};
    voleith_ring_sig_t sigB = {NULL, 0};
    const size_t signerA = 2;
    const size_t signerB = 5;
    size_t W = cfg.tree_hash->node_bytes;
    const voleith_node_hash_vt *owf_vt = cfg.tree_hash;

    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    int rcA =
        voleith_rsv1_sign(&sigA, &cfg, &params, sks + signerA * T6_SK_BYTES,
                          root, &paths[signerA], NULL, NULL, m, m_len);
    int rcB =
        voleith_rsv1_sign(&sigB, &cfg, &params, sks + signerB * T6_SK_BYTES,
                          root, &paths[signerB], NULL, NULL, m, m_len);
    check("anonymity: signerA signs", rcA == 0);
    check("anonymity: signerB signs", rcB == 0);

    if (rcA == 0 && rcB == 0) {
        /* Both proofs verify. */
        check("anonymity: signerA proof verifies",
              voleith_rsv1_verify(&sigA, &cfg, &params, root, NULL, m, m_len) ==
                  0);
        check("anonymity: signerB proof verifies",
              voleith_rsv1_verify(&sigB, &cfg, &params, root, NULL, m, m_len) ==
                  0);

        /* (a) Distinct proof bytes. */
        int same_len = (sigA.len == sigB.len);
        int byte_equal =
            same_len && memcmp(sigA.data, sigB.data, sigA.len) == 0;
        check("anonymity: distinct signers -> distinct proof bytestreams",
              !byte_equal);

        /* (b) No leaf node appears verbatim in either proof.  Compute
         * the 8 leaf nodes (the public ring contents) and scan each
         * proof for a contiguous-byte match. */
        for (size_t i = 0; i < T6_N; i++) {
            uint8_t leaf[MERKLE_VT_MAX_NODE_BYTES];
            MUST_OK(
                owf_vt->leaf_hash(sks + i * T6_SK_BYTES, T6_SK_BYTES, leaf));
            check("anonymity: leaf node not embedded in sigA",
                  !contains_subseq(sigA.data, sigA.len, leaf, W));
            check("anonymity: leaf node not embedded in sigB",
                  !contains_subseq(sigB.data, sigB.len, leaf, W));
        }
    }

    voleith_ring_sig_free(&sigA);
    voleith_ring_sig_free(&sigB);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

/*
 * Sign/verify roundtrip with the production-default Hirose tree
 * (32-byte nodes, 2^128 collision resistance).  Exercises the
 * node_bytes > 16 path in build_circuit and pack_witness, complementing
 * the canonical aes_dm case.  Per design §8 test 1.
 */
static void
test_rsv1_sign_verify_hirose_roundtrip(void)
{
    voleith_rs_membership_config_t cfg = {
        .tree_hash = &voleith_node_hash_hirose,
        .owf_hash = NULL,
        .sk_bytes = 32, /* matches hirose node_bytes */
        .depth_m = 3,
        .depth_r = 0,
    };
    voleith_params_t params = t6_params();
    size_t W = cfg.tree_hash->node_bytes;
    size_t sk_bytes = cfg.sk_bytes;
    size_t n = 1u << cfg.depth_m; /* 8 members */

    uint8_t *sks = calloc(n * sk_bytes, 1);
    uint8_t *root = calloc(W, 1);
    voleith_rs_membership_path_t *paths =
        calloc(n, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage = calloc(n * cfg.depth_m * W, 1);
    assert(sks && root && paths && sib_storage);

    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    MUST_OK(voleith_rsv1_ring_build(&cfg, sks, n, root, paths, sib_storage));

    const uint8_t m[] = "hirose-tree roundtrip";
    size_t m_len = sizeof(m) - 1;
    size_t signer = 5;
    voleith_ring_sig_t sig = {NULL, 0};

    int sign_rc =
        voleith_rsv1_sign(&sig, &cfg, &params, sks + signer * sk_bytes, root,
                          &paths[signer], NULL, NULL, m, m_len);
    check("hirose: sign succeeds", sign_rc == 0);
    check("hirose: sig.data populated", sig.data != NULL && sig.len > 0);

    if (sign_rc == 0) {
        check("hirose: verify accepts",
              voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m, m_len) ==
                  0);

        /* Tamper m: verify must reject. */
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        check("hirose: verify rejects tampered m",
              voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, bad_m,
                                  m_len) == -1);
    }

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_sign_verify_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    voleith_ring_sig_t sig = {NULL, 0};
    uint8_t sk[T6_SK_BYTES] = {0};
    uint8_t R[16] = {0};
    uint8_t siblings_buf[16 * 3] = {0};
    voleith_rs_membership_path_t path = {0, siblings_buf};
    /* Dummy non-NULL sig for verify NULL-checks that come before the
     * sig.data NULL check.  We never reach actual verification. */
    uint8_t dummy_buf = 0;
    voleith_ring_sig_t dummy_sig = {&dummy_buf, 1};

    check("sign: NULL sig_out rejected",
          voleith_rsv1_sign(NULL, &cfg, &params, sk, R, &path, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: NULL cfg rejected",
          voleith_rsv1_sign(&sig, NULL, &params, sk, R, &path, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: NULL params rejected",
          voleith_rsv1_sign(&sig, &cfg, NULL, sk, R, &path, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: NULL sk rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, NULL, R, &path, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: NULL membership_root rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, NULL, &path, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: NULL membership rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, NULL, NULL, NULL,
                            (const uint8_t *)"x", 1) == -1);
    {
        voleith_rs_membership_path_t bad = {0};
        check("sign: NULL membership->siblings rejected",
              voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &bad, NULL, NULL,
                                (const uint8_t *)"x", 1) == -1);
    }
    check("sign: m=NULL with m_len > 0 rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, NULL, NULL, NULL,
                            1) == -1);
    /* When depth_r == 0, supplying either revocation arg is invalid. */
    check("sign: revocation_root != NULL rejected (depth_r == 0)",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, R, NULL,
                            (const uint8_t *)"x", 1) == -1);
    check("sign: revocation != NULL rejected (depth_r == 0)",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, NULL, &path,
                            (const uint8_t *)"x", 1) == -1);

    check("verify: NULL sig rejected",
          voleith_rsv1_verify(NULL, &cfg, &params, R, NULL, NULL, 0) == -1);
    check("verify: NULL cfg rejected",
          voleith_rsv1_verify(&dummy_sig, NULL, &params, R, NULL, NULL, 0) ==
              -1);
    check("verify: NULL params rejected",
          voleith_rsv1_verify(&dummy_sig, &cfg, NULL, R, NULL, NULL, 0) == -1);
    check("verify: NULL R rejected",
          voleith_rsv1_verify(&dummy_sig, &cfg, &params, NULL, NULL, NULL, 0) ==
              -1);
    check("verify: NULL sig.data rejected",
          voleith_rsv1_verify(&sig, &cfg, &params, R, NULL, NULL, 0) == -1);
    check("verify: m=NULL with m_len > 0 rejected",
          voleith_rsv1_verify(&dummy_sig, &cfg, &params, R, NULL, NULL, 1) ==
              -1);
    check("verify: V_or_null != NULL rejected (depth_r == 0)",
          voleith_rsv1_verify(&dummy_sig, &cfg, &params, R, R, NULL, 0) == -1);

    /* ring_sig_free safe on zeroed / NULL data. */
    voleith_ring_sig_free(&sig);
    voleith_ring_sig_free(NULL);
    check("ring_sig_free: idempotent on zero data",
          sig.data == NULL && sig.len == 0);
}

/* ================================================================
 * T7: voleith_ring_sig_t serialization (pack / unpack).
 * ================================================================ */

/* Helper: produce a real signature against the canonical T6 ring so
 * the pack/unpack tests operate on a non-trivial buffer.  Caller
 * voleith_ring_sig_free's the returned sig and frees the four ring
 * buffers via the existing T6 cleanup pattern. */
static void
t7_make_sig(voleith_rs_membership_config_t *cfg_out,
            voleith_params_t *params_out, voleith_ring_sig_t *sig_out,
            uint8_t **sks_out, uint8_t **root_out,
            voleith_rs_membership_path_t **paths_out, uint8_t **sib_storage_out)
{
    *cfg_out = canonical_cfg();
    *params_out = t6_params();
    t6_build_ring(cfg_out, sks_out, root_out, paths_out, sib_storage_out);
    sig_out->data = NULL;
    sig_out->len = 0;
    MUST_OK(voleith_rsv1_sign(sig_out, cfg_out, params_out,
                              *sks_out + T6_SIGNER * T6_SK_BYTES, *root_out,
                              &(*paths_out)[T6_SIGNER], NULL, NULL,
                              (const uint8_t *)"T7", 2));
    assert(sig_out->data != NULL && sig_out->len > 0);
}

static void
t7_free_ring(uint8_t *sks, uint8_t *root, voleith_rs_membership_path_t *paths,
             uint8_t *sib_storage)
{
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_ring_sig_packed_len_formula(void)
{
    voleith_ring_sig_t sig = {NULL, 0};
    uint8_t dummy[3] = {1, 2, 3};

    check("packed_len: NULL sig -> 0", voleith_ring_sig_packed_len(NULL) == 0);
    check("packed_len: empty sig -> header bytes only",
          voleith_ring_sig_packed_len(&sig) ==
              (size_t)VOLEITH_RING_SIG_HEADER_BYTES);

    sig.data = dummy;
    sig.len = 3;
    check("packed_len: header + len",
          voleith_ring_sig_packed_len(&sig) ==
              (size_t)VOLEITH_RING_SIG_HEADER_BYTES + 3);
    check("packed_len: header bytes constant equals 41",
          VOLEITH_RING_SIG_HEADER_BYTES == 41);
}

static void
test_ring_sig_pack_header_bytes(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t cfg_fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t *buf;
    size_t buf_len;
    size_t written = 0;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);

    check("pack: succeeds", voleith_ring_sig_pack(buf, buf_len, &written, &sig,
                                                  &cfg, &params) == 0);
    check("pack: written matches packed_len", written == buf_len);

    /* Magic bytes 0..3 = 'V','R','S','1'. */
    check("pack: magic[0]='V'", buf[0] == 'V');
    check("pack: magic[1]='R'", buf[1] == 'R');
    check("pack: magic[2]='S'", buf[2] == 'S');
    check("pack: magic[3]='1'", buf[3] == '1');

    /* Version byte at offset 4. */
    check("pack: version == 1",
          buf[4] == (uint8_t)VOLEITH_RING_SIG_FORMAT_VERSION);

    /* cfg fingerprint at offset 5..20. */
    MUST_OK(voleith_rsv1_config_fingerprint(&cfg, cfg_fp));
    check("pack: cfg_fingerprint matches recomputation",
          memcmp(buf + 5, cfg_fp, sizeof(cfg_fp)) == 0);

    /* params fingerprint at offset 21..36. */
    MUST_OK(voleith_params_fingerprint(&params, params_fp));
    check("pack: params_fingerprint matches recomputation",
          memcmp(buf + 5 + sizeof(cfg_fp), params_fp, sizeof(params_fp)) == 0);

    /* Length field at offset 37..40, big-endian. */
    {
        size_t off = 5 + sizeof(cfg_fp) + sizeof(params_fp);
        uint32_t enc = ((uint32_t)buf[off] << 24) |
                       ((uint32_t)buf[off + 1] << 16) |
                       ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
        check("pack: length field big-endian == sig.len",
              (size_t)enc == sig.len);
    }

    /* Body identical to sig.data. */
    check("pack: body == sig.data",
          memcmp(buf + VOLEITH_RING_SIG_HEADER_BYTES, sig.data, sig.len) == 0);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_pack_unpack_roundtrip(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);

    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));
    check("unpack: succeeds",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == 0);
    check("unpack: len matches", sig2.len == sig.len);
    check("unpack: data matches",
          sig2.data != NULL && memcmp(sig2.data, sig.data, sig.len) == 0);

    /* Unpacked sig still verifies against the original ring. */
    check("unpack: roundtripped sig verifies",
          voleith_rsv1_verify(&sig2, &cfg, &params, root, NULL,
                              (const uint8_t *)"T7", 2) == 0);

    free(buf);
    voleith_ring_sig_free(&sig);
    voleith_ring_sig_free(&sig2);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_unpack_magic_mismatch(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);
    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));

    buf[0] ^= 0xff;
    check("unpack: magic[0] mismatch rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);
    check("unpack: failed unpack leaves sig zeroed",
          sig2.data == NULL && sig2.len == 0);
    buf[0] ^= 0xff;

    buf[3] = 'X';
    check("unpack: magic[3] mismatch rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_unpack_version_mismatch(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);
    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));

    buf[4] = (uint8_t)(VOLEITH_RING_SIG_FORMAT_VERSION + 1u);
    check("unpack: version+1 rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    buf[4] = 0;
    check("unpack: version=0 rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_unpack_cfg_fp_mismatch(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;
    voleith_rs_membership_config_t cfg_bad;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);
    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));

    /* Untouched buf, but caller supplies a different cfg -> recomputed
     * cfg_fp differs from the packed bytes. */
    cfg_bad = cfg;
    cfg_bad.depth_m = cfg.depth_m + 1;
    check("unpack: cfg fingerprint mismatch (different cfg) rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg_bad, &params) ==
              -1);

    /* Tamper the packed cfg_fp bytes directly. */
    buf[5] ^= 0x01;
    check("unpack: tampered cfg_fp rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_unpack_params_fp_mismatch(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_params_t params_bad;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);
    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));

    params_bad = voleith_params_em_128s; /* distinct param set */
    check("unpack: params fingerprint mismatch rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params_bad) ==
              -1);

    /* Tamper the packed params_fp bytes directly. */
    buf[5 + VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES] ^= 0x01;
    check("unpack: tampered params_fp rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_unpack_length_mismatch(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    voleith_ring_sig_t sig;
    voleith_ring_sig_t sig2 = {NULL, 0};
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    uint8_t *buf;
    size_t buf_len;
    size_t len_off;

    t7_make_sig(&cfg, &params, &sig, &sks, &root, &paths, &sib_storage);

    buf_len = voleith_ring_sig_packed_len(&sig);
    buf = malloc(buf_len);
    assert(buf != NULL);
    MUST_OK(voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, &params));

    /* Truncated buffer: claim full length-field, hand a shorter buf_len. */
    check("unpack: truncated buf_len rejected (1 byte short)",
          voleith_ring_sig_unpack(&sig2, buf, buf_len - 1, &cfg, &params) ==
              -1);
    check("unpack: header-sized buf with proof_len > 0 rejected",
          voleith_ring_sig_unpack(&sig2, buf, VOLEITH_RING_SIG_HEADER_BYTES,
                                  &cfg, &params) == -1);
    check("unpack: too-small buf rejected",
          voleith_ring_sig_unpack(&sig2, buf, VOLEITH_RING_SIG_HEADER_BYTES - 1,
                                  &cfg, &params) == -1);

    /* Oversized buf: tell the unpacker buf_len is larger than the
     * declared length field. */
    {
        uint8_t *big = malloc(buf_len + 1);
        assert(big != NULL);
        memcpy(big, buf, buf_len);
        big[buf_len] = 0;
        check("unpack: oversized buf_len rejected",
              voleith_ring_sig_unpack(&sig2, big, buf_len + 1, &cfg, &params) ==
                  -1);
        free(big);
    }

    /* Tamper the encoded length field to claim a longer body. */
    len_off = 5 + VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES +
              VOLEITH_PARAMS_FINGERPRINT_BYTES;
    buf[len_off + 3] = (uint8_t)((sig.len + 1u) & 0xffu);
    check("unpack: tampered len-field rejected",
          voleith_ring_sig_unpack(&sig2, buf, buf_len, &cfg, &params) == -1);

    free(buf);
    voleith_ring_sig_free(&sig);
    t7_free_ring(sks, root, paths, sib_storage);
}

static void
test_ring_sig_pack_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    uint8_t dummy_proof = 0;
    voleith_ring_sig_t sig = {&dummy_proof, 1};
    uint8_t buf[VOLEITH_RING_SIG_HEADER_BYTES + 1];
    size_t buf_len = sizeof(buf);

    check("pack: NULL out_buf rejected",
          voleith_ring_sig_pack(NULL, buf_len, NULL, &sig, &cfg, &params) ==
              -1);
    check("pack: NULL sig rejected",
          voleith_ring_sig_pack(buf, buf_len, NULL, NULL, &cfg, &params) == -1);
    check("pack: NULL cfg rejected",
          voleith_ring_sig_pack(buf, buf_len, NULL, &sig, NULL, &params) == -1);
    check("pack: NULL params rejected",
          voleith_ring_sig_pack(buf, buf_len, NULL, &sig, &cfg, NULL) == -1);

    /* out_len mismatch rejected. */
    check("pack: out_len too small rejected",
          voleith_ring_sig_pack(buf, buf_len - 1, NULL, &sig, &cfg, &params) ==
              -1);
    check("pack: out_len too large rejected",
          voleith_ring_sig_pack(buf, buf_len + 1, NULL, &sig, &cfg, &params) ==
              -1);

    /* Inconsistent sig: data != NULL but len == 0, or data == NULL but
     * len != 0. */
    {
        voleith_ring_sig_t bad = {&dummy_proof, 0};
        check("pack: sig.data != NULL with len == 0 rejected",
              voleith_ring_sig_pack(buf, VOLEITH_RING_SIG_HEADER_BYTES, NULL,
                                    &bad, &cfg, &params) == -1);
    }
    {
        voleith_ring_sig_t bad = {NULL, 1};
        check("pack: sig.data == NULL with len != 0 rejected",
              voleith_ring_sig_pack(buf, VOLEITH_RING_SIG_HEADER_BYTES + 1,
                                    NULL, &bad, &cfg, &params) == -1);
    }
}

static void
test_ring_sig_unpack_null_args(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    voleith_params_t params = t6_params();
    voleith_ring_sig_t sig = {NULL, 0};
    uint8_t buf[VOLEITH_RING_SIG_HEADER_BYTES] = {0};

    check("unpack: NULL sig_out rejected",
          voleith_ring_sig_unpack(NULL, buf, sizeof(buf), &cfg, &params) == -1);
    check("unpack: NULL buf rejected",
          voleith_ring_sig_unpack(&sig, NULL, sizeof(buf), &cfg, &params) ==
              -1);
    check("unpack: NULL cfg rejected",
          voleith_ring_sig_unpack(&sig, buf, sizeof(buf), NULL, &params) == -1);
    check("unpack: NULL params rejected",
          voleith_ring_sig_unpack(&sig, buf, sizeof(buf), &cfg, NULL) == -1);
}

/* ================================================================
 * T8: revocation branch.
 *
 * Build a depth-2 IMT (4 records) covering the full byte-LE range
 * with widely-spaced values so the signer's leaf node (an OWF output)
 * falls cleanly between two of them.  Sign + verify with both
 * membership and revocation; exercise the documented tamper /
 * rejection paths.
 * ================================================================ */

#define T8_DEPTH_R 2u
#define T8_N_REV (1u << T8_DEPTH_R) /* 4 IMT records */
#define T8_VALUE_BYTES 16u          /* matches aes_dm node_bytes */
#define T8_INDEX_BYTES VOLEITH_RSV1_REV_INDEX_BYTES

typedef struct {
    uint8_t value[T8_VALUE_BYTES];
    uint8_t next_value[T8_VALUE_BYTES];
    uint8_t next_index[T8_INDEX_BYTES];
} t8_rec_t;

/* Fill `r` so the MOST significant byte (byte 15 for VALUE_BYTES = 16,
 * since byte 0 is LSB in the IMT's little-endian comparison) equals
 * msb, all other bytes zero.  Partitioning on the MSB makes any random
 * 16-byte target (e.g., an OWF output) fall cleanly into one of the
 * four buckets defined below, since the LSB-end bytes are uniformly
 * distributed and the relative ordering is decided by the MSB byte
 * for non-equality cases. */
static void
t8_msb_value(uint8_t r[T8_VALUE_BYTES], uint8_t msb)
{
    memset(r, 0, T8_VALUE_BYTES);
    r[T8_VALUE_BYTES - 1] = msb;
}

static void
t8_le_index(uint8_t r[T8_INDEX_BYTES], uint8_t lsb)
{
    memset(r, 0, T8_INDEX_BYTES);
    r[0] = lsb;
}

static void
t8_fill_records(t8_rec_t recs[T8_N_REV])
{
    /* Partition the LE 128-bit range by byte 15 (MSB):
     *   rec[0]: [{0..0, 0x00},  {0..0, 0x40})
     *   rec[1]: [{0..0, 0x40},  {0..0, 0x80})
     *   rec[2]: [{0..0, 0x80},  {0..0, 0xC0})
     *   rec[3]: [{0..0, 0xC0},  {0xFF.. 0xFF})
     * For a random 16-byte target the MSB falls into one of the four
     * open intervals with overwhelming probability; equality to a
     * boundary value is ~2^-120 and ignored. */
    t8_msb_value(recs[0].value, 0x00);
    t8_msb_value(recs[0].next_value, 0x40);
    t8_le_index(recs[0].next_index, 1);

    t8_msb_value(recs[1].value, 0x40);
    t8_msb_value(recs[1].next_value, 0x80);
    t8_le_index(recs[1].next_index, 2);

    t8_msb_value(recs[2].value, 0x80);
    t8_msb_value(recs[2].next_value, 0xC0);
    t8_le_index(recs[2].next_index, 3);

    t8_msb_value(recs[3].value, 0xC0);
    memset(recs[3].next_value, 0xFF, T8_VALUE_BYTES);
    t8_le_index(recs[3].next_index, 0);
}

static void
t8_records_to_imt(const voleith_node_hash_vt *vt, const t8_rec_t recs[T8_N_REV],
                  voleith_imt_record_t imt[T8_N_REV])
{
    for (size_t i = 0; i < T8_N_REV; i++) {
        imt[i].value = recs[i].value;
        imt[i].next_value = recs[i].next_value;
        imt[i].next_index = recs[i].next_index;
    }
    (void)vt;
}

/* Builds membership ring + revocation IMT; computes signer's leaf and
 * the adjacent record + path for revocation.  All four output buffers
 * are caller-freed by t6_free + t8_free pattern. */
static void
t8_setup(voleith_rs_membership_config_t *cfg_out, voleith_params_t *params_out,
         uint8_t **sks_out, uint8_t **root_out,
         voleith_rs_membership_path_t **paths_out, uint8_t **sib_storage_out,
         t8_rec_t recs[T8_N_REV], uint8_t rev_root_out[T8_VALUE_BYTES],
         uint8_t *adj_value_out, uint8_t *adj_next_value_out,
         uint8_t *adj_next_index_out, size_t *adj_leaf_index_out,
         uint8_t rev_siblings_out[T8_DEPTH_R * T8_VALUE_BYTES])
{
    voleith_imt_record_t imt[T8_N_REV];
    uint8_t signer_leaf[T8_VALUE_BYTES];
    const voleith_node_hash_vt *vt;
    int rc;

    *cfg_out = canonical_cfg();
    cfg_out->depth_r = T8_DEPTH_R;
    *params_out = t6_params();

    t6_build_ring(cfg_out, sks_out, root_out, paths_out, sib_storage_out);
    vt = cfg_out->tree_hash;

    /* Compute signer's leaf node. */
    {
        const voleith_node_hash_vt *owf_vt =
            cfg_out->owf_hash ? cfg_out->owf_hash : cfg_out->tree_hash;
        MUST_OK(owf_vt->leaf_hash(*sks_out + T6_SIGNER * T6_SK_BYTES,
                                  cfg_out->sk_bytes, signer_leaf));
    }

    t8_fill_records(recs);
    t8_records_to_imt(vt, recs, imt);

    /* Build IMT root. */
    MUST_OK(voleith_imt_vt_build(vt, imt, T8_N_REV, T8_VALUE_BYTES,
                                 T8_INDEX_BYTES, rev_root_out));

    /* Look up the adjacent record straddling signer's leaf. */
    rc = voleith_imt_vt_lookup_nonmember(vt, imt, T8_N_REV, T8_VALUE_BYTES,
                                         T8_INDEX_BYTES, signer_leaf,
                                         adj_leaf_index_out, rev_siblings_out);
    /* If the leaf happens to fall outside (0x10, 0xD0) we abort the
     * test scaffold rather than ship a non-deterministic result.  In
     * practice the canonical T6 sks are deterministic and the chosen
     * member's OWF output's byte 0 has been verified to fall in the
     * covered range by running this assertion. */
    assert(rc == 0);

    memcpy(adj_value_out, recs[*adj_leaf_index_out].value, T8_VALUE_BYTES);
    memcpy(adj_next_value_out, recs[*adj_leaf_index_out].next_value,
           T8_VALUE_BYTES);
    memcpy(adj_next_index_out, recs[*adj_leaf_index_out].next_index,
           T8_INDEX_BYTES);
}

static void
test_rsv1_revocation_roundtrip(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    t8_rec_t recs[T8_N_REV];
    uint8_t rev_root[T8_VALUE_BYTES];
    uint8_t adj_value[T8_VALUE_BYTES];
    uint8_t adj_next_value[T8_VALUE_BYTES];
    uint8_t adj_next_index[T8_INDEX_BYTES];
    uint8_t rev_siblings[T8_DEPTH_R * T8_VALUE_BYTES];
    size_t adj_idx;
    voleith_ring_sig_t sig = {NULL, 0};
    const uint8_t m[] = "T8 revocation roundtrip";
    size_t m_len = sizeof(m) - 1;

    t8_setup(&cfg, &params, &sks, &root, &paths, &sib_storage, recs, rev_root,
             adj_value, adj_next_value, adj_next_index, &adj_idx, rev_siblings);

    voleith_rs_membership_path_t rev_path = {0};
    rev_path.rev_adj_leaf_index = adj_idx;
    rev_path.rev_siblings = rev_siblings;
    rev_path.rev_low_value = adj_value;
    rev_path.rev_low_next = adj_next_value;
    rev_path.rev_next_index = adj_next_index;

    int sign_rc = voleith_rsv1_sign(
        &sig, &cfg, &params, sks + T6_SIGNER * T6_SK_BYTES, root,
        &paths[T6_SIGNER], rev_root, &rev_path, m, m_len);
    check("rev: sign succeeds (leaf not in V)", sign_rc == 0);
    check("rev: sig.data populated", sig.data != NULL && sig.len > 0);

    if (sign_rc == 0) {
        check("rev: verify accepts canonical roundtrip",
              voleith_rsv1_verify(&sig, &cfg, &params, root, rev_root, m,
                                  m_len) == 0);

        /* Tamper V at verify: byte flip on rev_root. */
        uint8_t bad_rev[T8_VALUE_BYTES];
        memcpy(bad_rev, rev_root, T8_VALUE_BYTES);
        bad_rev[0] ^= 0x01;
        check("rev: verify rejects tampered V",
              voleith_rsv1_verify(&sig, &cfg, &params, root, bad_rev, m,
                                  m_len) == -1);

        /* Tamper m. */
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x02;
        check("rev: verify rejects tampered m",
              voleith_rsv1_verify(&sig, &cfg, &params, root, rev_root, bad_m,
                                  m_len) == -1);
    }

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_revocation_tampered_sibling_rejected(void)
{
    voleith_rs_membership_config_t cfg;
    voleith_params_t params;
    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    t8_rec_t recs[T8_N_REV];
    uint8_t rev_root[T8_VALUE_BYTES];
    uint8_t adj_value[T8_VALUE_BYTES];
    uint8_t adj_next_value[T8_VALUE_BYTES];
    uint8_t adj_next_index[T8_INDEX_BYTES];
    uint8_t rev_siblings[T8_DEPTH_R * T8_VALUE_BYTES];
    size_t adj_idx;
    voleith_ring_sig_t sig = {NULL, 0};

    t8_setup(&cfg, &params, &sks, &root, &paths, &sib_storage, recs, rev_root,
             adj_value, adj_next_value, adj_next_index, &adj_idx, rev_siblings);

    /* Corrupt one byte of rev_siblings before signing. */
    rev_siblings[0] ^= 0x01;

    voleith_rs_membership_path_t rev_path = {0};
    rev_path.rev_adj_leaf_index = adj_idx;
    rev_path.rev_siblings = rev_siblings;
    rev_path.rev_low_value = adj_value;
    rev_path.rev_low_next = adj_next_value;
    rev_path.rev_next_index = adj_next_index;

    int sign_rc = voleith_rsv1_sign(
        &sig, &cfg, &params, sks + T6_SIGNER * T6_SK_BYTES, root,
        &paths[T6_SIGNER], rev_root, &rev_path, (const uint8_t *)"x", 1);
    /* The recomputed V root inside the circuit disagrees with the
     * supplied V; circuit_eval fails; X-10 prove rejects up-front. */
    check("rev: sign rejects tampered rev_sibling", sign_rc == -1);

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_revocation_lookup_rejects_member(void)
{
    /*
     * Build an IMT that contains a record whose value EQUALS the
     * signer's leaf node.  voleith_imt_vt_lookup_nonmember must return
     * -1 (target is a member, no non-membership proof possible).
     */
    voleith_rs_membership_config_t cfg = canonical_cfg();
    cfg.depth_r = T8_DEPTH_R;

    uint8_t *sks, *root, *sib_storage;
    voleith_rs_membership_path_t *paths;
    t6_build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    const voleith_node_hash_vt *owf_vt = cfg.tree_hash;
    uint8_t signer_leaf[T8_VALUE_BYTES];
    MUST_OK(owf_vt->leaf_hash(sks + T6_SIGNER * T6_SK_BYTES, cfg.sk_bytes,
                              signer_leaf));

    /* Construct an IMT with 4 records where rec[1].value == signer_leaf.
     * lookup_nonmember does an equality-membership check first and
     * returns -1 the moment ANY record's value equals target; the
     * other records' sort order does not matter for this rejection
     * path so we leave them as placeholders. */
    t8_rec_t recs[T8_N_REV];
    t8_fill_records(recs);
    memcpy(recs[1].value, signer_leaf, T8_VALUE_BYTES);

    voleith_imt_record_t imt[T8_N_REV];
    for (size_t i = 0; i < T8_N_REV; i++) {
        imt[i].value = recs[i].value;
        imt[i].next_value = recs[i].next_value;
        imt[i].next_index = recs[i].next_index;
    }

    uint8_t sib_buf[T8_DEPTH_R * T8_VALUE_BYTES];
    size_t adj_idx = (size_t)-1;
    int rc = voleith_imt_vt_lookup_nonmember(owf_vt, imt, T8_N_REV,
                                             T8_VALUE_BYTES, T8_INDEX_BYTES,
                                             signer_leaf, &adj_idx, sib_buf);
    check("rev: lookup_nonmember rejects member target", rc == -1);

    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

static void
test_rsv1_revocation_missing_args_rejected(void)
{
    voleith_rs_membership_config_t cfg = canonical_cfg();
    cfg.depth_r = T8_DEPTH_R;
    voleith_params_t params = t6_params();
    voleith_ring_sig_t sig = {NULL, 0};
    uint8_t sk[T6_SK_BYTES] = {0};
    uint8_t R[16] = {0};
    uint8_t V[16] = {0};
    uint8_t sib_buf[16 * 3] = {0};
    voleith_rs_membership_path_t path = {0};
    path.siblings = sib_buf;

    voleith_rs_membership_path_t rev_path = {0};
    /* leave rev_* NULL */
    uint8_t dummy_buf = 0;
    voleith_ring_sig_t dummy_sig = {&dummy_buf, 1};

    /* depth_r > 0: missing revocation_root rejected. */
    check("sign: depth_r > 0 with NULL revocation_root rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, NULL, &rev_path,
                            (const uint8_t *)"x", 1) == -1);
    /* depth_r > 0: missing revocation rejected. */
    check("sign: depth_r > 0 with NULL revocation rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, V, NULL,
                            (const uint8_t *)"x", 1) == -1);
    /* depth_r > 0: revocation supplied but NULL rev_siblings rejected. */
    check("sign: depth_r > 0 with NULL rev_siblings rejected",
          voleith_rsv1_sign(&sig, &cfg, &params, sk, R, &path, V, &rev_path,
                            (const uint8_t *)"x", 1) == -1);

    /* Verify side: depth_r > 0 with NULL V rejected. */
    check("verify: depth_r > 0 with NULL V rejected",
          voleith_rsv1_verify(&dummy_sig, &cfg, &params, R, NULL, NULL, 0) ==
              -1);
}

int
main(void)
{
    printf("test_ring_sig_v1_gf8: starting\n");
    test_validate_accepts_canonical();
    test_validate_rejects_malformed();
    test_fingerprint_determinism();
    test_fingerprint_each_field_bound();
    test_fingerprint_null_args();
    test_fingerprint_kat_pin();
    test_build_circuit_counts_aes_dm();
    test_build_circuit_layout_deterministic();
    test_build_circuit_eval_positive();
    test_build_circuit_eval_wrong_sk();
    test_build_circuit_eval_wrong_sibling();
    test_build_circuit_eval_asymmetric_owf();
    test_build_circuit_validate_failure();
    test_pack_witness_wrong_leaf_index();
    test_pack_witness_leaf_index_out_of_range();
    test_pack_witness_null_args();
    test_pack_witness_deterministic();
    test_ring_build_full_8_members();
    test_ring_build_padded_5_members();
    test_ring_build_argument_validation();
    test_fs_seed_determinism();
    test_fs_seed_each_field_bound();
    test_fs_seed_null_args();
    test_fs_seed_kat_pin();
    test_rsv1_sign_verify_null_args();
    test_rsv1_sign_wrong_sk_rejected();
    test_rsv1_sign_wrong_sibling_rejected();
    test_rsv1_sign_verify_roundtrip();
    test_rsv1_sign_verify_asymmetric_owf();
    test_rsv1_anonymity_smoke();
    test_rsv1_sign_verify_hirose_roundtrip();
    test_ring_sig_packed_len_formula();
    test_ring_sig_pack_header_bytes();
    test_ring_sig_pack_unpack_roundtrip();
    test_ring_sig_unpack_magic_mismatch();
    test_ring_sig_unpack_version_mismatch();
    test_ring_sig_unpack_cfg_fp_mismatch();
    test_ring_sig_unpack_params_fp_mismatch();
    test_ring_sig_unpack_length_mismatch();
    test_ring_sig_pack_null_args();
    test_ring_sig_unpack_null_args();
    test_rsv1_revocation_roundtrip();
    test_rsv1_revocation_tampered_sibling_rejected();
    test_rsv1_revocation_lookup_rejects_member();
    test_rsv1_revocation_missing_args_rejected();
    printf("test_ring_sig_v1_gf8: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
