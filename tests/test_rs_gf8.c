/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_gf8.c - data-layer tests for the composable ring-signature
 * config (RS.CFG).
 *
 * Coverage:
 *   voleith_rs_module_bitmap
 *     - empty config (all modules off) -> 0
 *     - each module sets its own bit, in isolation and combined
 *     - all-NONE attr schema does NOT set the predicate bit
 *     - NULL cfg -> 0
 *   voleith_rs_config_validate
 *     - canonical (all off) accepted; each single-module preset accepted
 *     - membership failure propagates
 *     - fixed-input OWF carries attributes up to its block capacity
 *       (grostl256_fixed 64, hirose_fixed32 32); narrow sk accepted
 *     - attr schema: n_fields == 0, NULL fields, width 0, pred out of
 *       range, total over cap, preimage over block capacity all rejected
 *     - spent_set without nullifier rejected; depth_s over ceiling rejected
 *     - commitment with zero id / rand bytes rejected
 *   voleith_rs_config_fingerprint
 *     - determinism: same cfg twice == same 16 bytes
 *     - module binding: enabling each module changes the fingerprint
 *     - field binding: changing a module sizing field changes it
 *     - NULL args rejected
 *     - combined-config KAT pin (regression guard)
 *   V6 epoch module (EP.CFG)
 *     - bitmap bit 5 set iff depth_e > 0
 *     - validate: node/cr/epoch_sk/salt/capacity/strength shapes, the
 *       preimage_ok relaxation, sk_bytes==0 rule, and epoch-fields-set-
 *       while-off guard
 *     - fingerprint: per-field binding + epoch-config KAT pin (bootstrap)
 */

#include "rs_gf8.h"

#include "aes_cmac_gf8_circuit.h"
#include "gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"
#include "rs_epoch_gf8.h"
#include "rs_gf8_circuit.h"
#include "rs_leaf_gf8_circuit.h"
#include "rs_membership_gf8_circuit.h"
#include "rs_opener_gf8_circuit.h"

#include <ichor/util.h>   /* ichor_bitpack_le32 (support packing) */
#include <ichor/aesdm.h>  /* AES-DM KDF oracle (OP.CIRC.3a) */
#include <ichor/grostl.h> /* Grostl-256 KDF oracle (OP.CIRC.3b) */
#include <ichor/hash.h>   /* ichor_sha3_256 (variable-length KAT digests) */

#include <stdlib.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Wraps a fallible call so the call is ALWAYS evaluated, even when
 * NDEBUG elides assert().  Same idiom used across the test suite. */
#define MUST_OK_FP(expr)                                                       \
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

/* All-modules-off config over the variable-leaf aes-dm vt (sk == leaf
 * preimage; no fixed-leaf width constraint). */
static voleith_rs_config_t
canonical_cfg(void)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.owf_hash = NULL;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;
    cfg.membership.depth_r = 0;
    return cfg;
}

/* ================================================================
 * Module bitmap.
 * ================================================================ */
static void
test_module_bitmap(void)
{
    voleith_rs_config_t cfg = canonical_cfg();
    static const voleith_rs_attr_field_t pred_fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_NONE},
        {2, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    static const voleith_rs_attr_field_t hidden_fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_NONE},
    };
    voleith_rs_attr_schema_t pred_schema = {pred_fields, 2};
    voleith_rs_attr_schema_t hidden_schema = {hidden_fields, 1};

    check("bitmap: empty cfg == 0", voleith_rs_module_bitmap(&cfg) == 0);
    check("bitmap: NULL cfg == 0", voleith_rs_module_bitmap(NULL) == 0);

    cfg = canonical_cfg();
    cfg.membership.depth_r = 4;
    check("bitmap: revocation bit",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_REVOCATION);

    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    check("bitmap: nullifier bit",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_NULLIFIER);

    cfg = canonical_cfg();
    cfg.attr_schema = &pred_schema;
    check("bitmap: predicate bit (some pred != NONE)",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_PREDICATE);

    cfg = canonical_cfg();
    cfg.attr_schema = &hidden_schema;
    check("bitmap: all-NONE schema sets no predicate bit",
          voleith_rs_module_bitmap(&cfg) == 0);

    cfg = canonical_cfg();
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("bitmap: commitment bit",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_COMMITMENT);

    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    cfg.depth_s = 5;
    check("bitmap: spent_set bit (with nullifier)",
          voleith_rs_module_bitmap(&cfg) ==
              (VOLEITH_RS_MODULE_NULLIFIER | VOLEITH_RS_MODULE_SPENT_SET));

    /* Everything on. */
    cfg = canonical_cfg();
    cfg.membership.depth_r = 4;
    cfg.scope_bytes = 12;
    cfg.depth_s = 5;
    cfg.attr_schema = &pred_schema;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("bitmap: all modules on",
          voleith_rs_module_bitmap(&cfg) ==
              (VOLEITH_RS_MODULE_REVOCATION | VOLEITH_RS_MODULE_NULLIFIER |
               VOLEITH_RS_MODULE_PREDICATE | VOLEITH_RS_MODULE_COMMITMENT |
               VOLEITH_RS_MODULE_SPENT_SET));
}

/* ================================================================
 * Validate.
 * ================================================================ */
static void
test_validate_accepts(void)
{
    voleith_rs_config_t cfg = canonical_cfg();
    static const voleith_rs_attr_field_t fields[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
        {4, VOLEITH_RS_ATTR_PRED_EQ},
        {2, VOLEITH_RS_ATTR_PRED_NONE},
    };
    voleith_rs_attr_schema_t schema = {fields, 3};

    check("validate: canonical accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = canonical_cfg();
    cfg.membership.depth_r = 5;
    check("validate: revocation accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    check("validate: nullifier accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    cfg.depth_s = 6;
    check("validate: spent_set (with nullifier) accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = canonical_cfg();
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("validate: commitment accepted",
          voleith_rs_config_validate(&cfg) == 0);

    /* Variable-leaf vt accepts any attribute total. */
    cfg = canonical_cfg();
    cfg.attr_schema = &schema;
    check("validate: attr schema (variable leaf) accepted",
          voleith_rs_config_validate(&cfg) == 0);

    /* Fixed-input OWF carries attributes up to its single-compression
     * block capacity.  grostl256_fixed leaf_block_bytes == 64; sk 32 +
     * 16 attr = 48 <= 64. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.sk_bytes = 32;
    {
        static const voleith_rs_attr_field_t f[] = {
            {16, VOLEITH_RS_ATTR_PRED_EQ},
        };
        voleith_rs_attr_schema_t s = {f, 1};
        cfg.attr_schema = &s;
        check("validate: fixed-input OWF attrs within block accepted",
              voleith_rs_config_validate(&cfg) == 0);
    }

    /* sk may be narrower than node_bytes: the preimage bound is the block
     * capacity, not the node size.  grostl256_fixed: sk 16 + 16 = 32 <=
     * 64. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.sk_bytes = 16;
    {
        static const voleith_rs_attr_field_t f[] = {
            {16, VOLEITH_RS_ATTR_PRED_RANGE},
        };
        voleith_rs_attr_schema_t s = {f, 1};
        cfg.attr_schema = &s;
        check("validate: fixed-input OWF narrow sk + attrs accepted",
              voleith_rs_config_validate(&cfg) == 0);
    }

    /* Minimal 128-bit sk (16 B) frees the rest of the block for
     * attributes: grostl256_fixed sk 16 + 48 attr = 64, exactly the
     * block capacity. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.sk_bytes = 16;
    {
        static const voleith_rs_attr_field_t f[] = {
            {32, VOLEITH_RS_ATTR_PRED_RANGE},
            {16, VOLEITH_RS_ATTR_PRED_EQ},
        };
        voleith_rs_attr_schema_t s = {f, 2};
        cfg.attr_schema = &s;
        check("validate: minimal sk + attrs filling grostl256 block accepted",
              voleith_rs_config_validate(&cfg) == 0);
    }

    /* hirose_fixed32 budget is exactly the 32-byte fixed leaf: sk 16 +
     * 16 = 32 <= 32. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_hirose_fixed32;
    cfg.membership.sk_bytes = 16;
    {
        static const voleith_rs_attr_field_t f[] = {
            {16, VOLEITH_RS_ATTR_PRED_EQ},
        };
        voleith_rs_attr_schema_t s = {f, 1};
        cfg.attr_schema = &s;
        check("validate: hirose fixed32 attrs filling budget accepted",
              voleith_rs_config_validate(&cfg) == 0);
    }

    /* Everything on. */
    cfg = canonical_cfg();
    cfg.membership.depth_r = 4;
    cfg.scope_bytes = 12;
    cfg.depth_s = 5;
    cfg.attr_schema = &schema;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("validate: all modules accepted",
          voleith_rs_config_validate(&cfg) == 0);
}

static void
test_validate_rejects(void)
{
    voleith_rs_config_t cfg;
    static const voleith_rs_attr_field_t ok_field[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    static const voleith_rs_attr_field_t zero_width[] = {
        {0, VOLEITH_RS_ATTR_PRED_NONE},
    };
    static const voleith_rs_attr_field_t bad_pred[] = {
        {4, (voleith_rs_attr_pred_kind_t)99},
    };
    static const voleith_rs_attr_field_t huge_field[] = {
        {VOLEITH_RS_ATTR_TOTAL_MAX_BYTES + 1, VOLEITH_RS_ATTR_PRED_NONE},
    };
    static const voleith_rs_attr_field_t big_attr[] = {
        {48, VOLEITH_RS_ATTR_PRED_NONE}, /* 32 sk + 48 = 80 > grostl256 64 */
    };
    static const voleith_rs_attr_field_t wide_attr[] = {
        {17, VOLEITH_RS_ATTR_PRED_NONE}, /* 16 sk + 17 = 33 > hirose32 32 */
    };
    voleith_rs_attr_schema_t schema;

    check("validate: NULL cfg rejected",
          voleith_rs_config_validate(NULL) == -1);

    /* Membership failure propagates. */
    cfg = canonical_cfg();
    cfg.membership.depth_m = 0;
    check("validate: membership failure propagates",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr: n_fields == 0. */
    cfg = canonical_cfg();
    schema.fields = ok_field;
    schema.n_fields = 0;
    cfg.attr_schema = &schema;
    check("validate: attr n_fields == 0 rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr: NULL fields. */
    cfg = canonical_cfg();
    schema.fields = NULL;
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: attr NULL fields rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr: width 0. */
    cfg = canonical_cfg();
    schema.fields = zero_width;
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: attr width 0 rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr: pred out of enum range. */
    cfg = canonical_cfg();
    schema.fields = bad_pred;
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: attr pred out of range rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr: total over cap. */
    cfg = canonical_cfg();
    schema.fields = huge_field;
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: attr total over cap rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* attr on a fixed-input OWF where sk + attrs exceeds the single-
     * compression leaf capacity.  grostl256_fixed has leaf_block_bytes
     * == 64 (the 2*node_bytes Grostl block); sk 32 + 48 attr = 80 > 64
     * overflows it. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.sk_bytes = 32;
    schema.fields = big_attr; /* one 48-byte field */
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: fixed-input OWF preimage over block capacity rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* Same for hirose_fixed32 (leaf_block_bytes == 32): sk 16 + 17 = 33
     * > 32. */
    cfg = canonical_cfg();
    cfg.membership.tree_hash = &voleith_node_hash_hirose_fixed32;
    cfg.membership.sk_bytes = 16;
    schema.fields = wide_attr; /* one 17-byte field */
    schema.n_fields = 1;
    cfg.attr_schema = &schema;
    check("validate: hirose fixed32 preimage over block capacity rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* spent_set without nullifier. */
    cfg = canonical_cfg();
    cfg.depth_s = 5;
    check("validate: spent_set without nullifier rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* depth_s over ceiling. */
    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    cfg.depth_s = VOLEITH_RS_MEMBERSHIP_MAX_DEPTH + 1;
    check("validate: depth_s over ceiling rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* commitment with zero id bytes. */
    cfg = canonical_cfg();
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 0;
    cfg.commit_rand_bytes = 16;
    check("validate: commitment zero id bytes rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* commitment with zero rand bytes. */
    cfg = canonical_cfg();
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 0;
    check("validate: commitment zero rand bytes rejected",
          voleith_rs_config_validate(&cfg) == -1);
}

/* ================================================================
 * Fingerprint.
 * ================================================================ */
static void
test_fingerprint_determinism(void)
{
    voleith_rs_config_t cfg = canonical_cfg();
    uint8_t fp1[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];

    check("fingerprint: returns 0",
          voleith_rs_config_fingerprint(&cfg, fp1) == 0);
    check("fingerprint: deterministic",
          voleith_rs_config_fingerprint(&cfg, fp2) == 0 &&
              memcmp(fp1, fp2, sizeof(fp1)) == 0);

    check("fingerprint: NULL cfg rejected",
          voleith_rs_config_fingerprint(NULL, fp1) == -1);
    check("fingerprint: NULL out rejected",
          voleith_rs_config_fingerprint(&cfg, NULL) == -1);
}

static void
test_fingerprint_module_binding(void)
{
    voleith_rs_config_t base = canonical_cfg();
    voleith_rs_config_t cfg;
    uint8_t fp_base[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    static const voleith_rs_attr_field_t fields[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};

    check("fingerprint: base computed",
          voleith_rs_config_fingerprint(&base, fp_base) == 0);

    cfg = canonical_cfg();
    cfg.membership.depth_r = 4;
    check("fingerprint: revocation flips fp",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_base, sizeof(fp)) != 0);

    cfg = canonical_cfg();
    cfg.scope_bytes = 12;
    check("fingerprint: nullifier flips fp",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_base, sizeof(fp)) != 0);

    cfg = canonical_cfg();
    cfg.attr_schema = &schema;
    check("fingerprint: predicate flips fp",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_base, sizeof(fp)) != 0);

    cfg = canonical_cfg();
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("fingerprint: commitment flips fp",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_base, sizeof(fp)) != 0);
}

static void
test_fingerprint_field_binding(void)
{
    voleith_rs_config_t ref;
    voleith_rs_config_t cfg;
    uint8_t fp_ref[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    static const voleith_rs_attr_field_t fields_a[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    static const voleith_rs_attr_field_t fields_b[] = {
        {8, VOLEITH_RS_ATTR_PRED_EQ}, /* same width, different pred */
    };
    voleith_rs_attr_schema_t schema_a = {fields_a, 1};
    voleith_rs_attr_schema_t schema_b = {fields_b, 1};

    /* nullifier: scope_bytes / depth_s both bound. */
    ref = canonical_cfg();
    ref.scope_bytes = 12;
    ref.depth_s = 4;
    MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp_ref));

    cfg = ref;
    cfg.scope_bytes = 13;
    check("fingerprint: scope_bytes bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    cfg = ref;
    cfg.depth_s = 5;
    check("fingerprint: depth_s bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    /* commitment: commit_id_bytes / commit_rand_bytes both bound. */
    ref = canonical_cfg();
    ref.enable_commitment = 1;
    ref.commit_id_bytes = 16;
    ref.commit_rand_bytes = 16;
    MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp_ref));

    cfg = ref;
    cfg.commit_id_bytes = 32;
    check("fingerprint: commit_id_bytes bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    cfg = ref;
    cfg.commit_rand_bytes = 32;
    check("fingerprint: commit_rand_bytes bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    /* predicate: per-field pred kind bound (width fixed). */
    ref = canonical_cfg();
    ref.attr_schema = &schema_a;
    MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp_ref));

    cfg = canonical_cfg();
    cfg.attr_schema = &schema_b;
    check("fingerprint: per-field pred kind bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);
}

/*
 * Combined-config KAT pin.
 *
 * Pins the fingerprint of a fixed all-modules-on config so any
 * unintended change to the absorb stream (domain tag, field order,
 * encoding) is caught as a regression and so the value is a compat
 * boundary once 1.8.0 tags.
 *
 * BOOTSTRAP: the expected bytes below are a placeholder.  On the first
 * build, this test prints the computed fingerprint; copy those 16 bytes
 * into kat_expected and flip RS_CFG_KAT_PINNED to 1 to arm the hard
 * check.  (Same bootstrap pattern as the RSv1 fs_seed KAT.)
 */
#define RS_CFG_KAT_PINNED 1
static void
test_fingerprint_kat_pin(void)
{
    static const voleith_rs_attr_field_t fields[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
        {4, VOLEITH_RS_ATTR_PRED_EQ},
    };
    voleith_rs_attr_schema_t schema = {fields, 2};
    voleith_rs_config_t cfg = canonical_cfg();
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    static const uint8_t kat_expected[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES] = {
        0x37, 0x59, 0x05, 0xe0, 0xad, 0xff, 0xd4, 0x3a,
        0x19, 0x54, 0xff, 0x4e, 0x48, 0xc0, 0x6d, 0x8f};

    cfg.membership.depth_r = 4;
    cfg.scope_bytes = 12;
    cfg.depth_s = 5;
    cfg.attr_schema = &schema;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    check("kat: fingerprint computed",
          voleith_rs_config_fingerprint(&cfg, fp) == 0);

    printf("  RS.CFG combined-config fingerprint:");
    for (size_t i = 0; i < sizeof(fp); i++)
        printf(" %02x", fp[i]);
    printf("\n");

    if (RS_CFG_KAT_PINNED) {
        check("kat: matches pinned constant",
              memcmp(fp, kat_expected, sizeof(fp)) == 0);
    } else {
        printf("  (KAT not yet pinned: copy the bytes above into "
               "kat_expected and set RS_CFG_KAT_PINNED to 1)\n");
        (void)kat_expected;
    }
}

/* ================================================================
 * EP.CFG: V6 epoch module (bitmap bit 5, validate, fingerprint).
 * ================================================================ */

/*
 * Stub vts exercising the V6 strength rule.  validate/fingerprint read
 * only .name and the size fields, never the (NULL) circuit callbacks, so
 * these are safe here.  node_bytes 32 matches the grostl-256-fixed tree
 * used by epoch_cfg() so the node-width check passes and the cr_bits
 * comparison is what is under test.
 */
static const voleith_node_hash_vt epoch_stub_cr128 = {.name = "stub32-cr128",
                                                      .node_bytes = 32,
                                                      .cr_bits = 128,
                                                      .fixed_leaf_bytes = 32,
                                                      .leaf_block_bytes = 64};
static const voleith_node_hash_vt epoch_stub_cr64 = {.name = "stub32-cr64",
                                                     .node_bytes = 32,
                                                     .cr_bits = 64,
                                                     .fixed_leaf_bytes = 32,
                                                     .leaf_block_bytes = 64};
static const voleith_node_hash_vt epoch_stub_cap16 = {.name = "stub32-cap16",
                                                      .node_bytes = 32,
                                                      .cr_bits = 128,
                                                      .fixed_leaf_bytes = 16,
                                                      .leaf_block_bytes = 16};

/* Valid V6-only base: grostl-256-fixed tree (node32, cr128), epoch tree =
 * tree_hash, sk_t width 32, membership sk absent. */
static voleith_rs_config_t
epoch_cfg(void)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.owf_hash = NULL;
    cfg.membership.sk_bytes = 0; /* V6: absent */
    cfg.membership.depth_m = 3;
    cfg.depth_e = 8;
    cfg.epoch_hash = NULL; /* = tree_hash */
    cfg.epoch_sk_bytes = 32;
    return cfg;
}

static void
test_epoch_bitmap(void)
{
    voleith_rs_config_t cfg = epoch_cfg();
    check("bitmap: epoch bit (depth_e > 0)",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_EPOCH);

    cfg.scope_bytes = 12; /* V2 nullifier keys off sk_t (Q5) */
    check("bitmap: epoch + nullifier",
          voleith_rs_module_bitmap(&cfg) ==
              (VOLEITH_RS_MODULE_EPOCH | VOLEITH_RS_MODULE_NULLIFIER));

    cfg = epoch_cfg();
    cfg.depth_e = 0;
    cfg.membership.sk_bytes = 32; /* non-V6 again */
    check("bitmap: depth_e == 0 clears epoch bit",
          (voleith_rs_module_bitmap(&cfg) & VOLEITH_RS_MODULE_EPOCH) == 0);
}

static void
test_epoch_validate(void)
{
    static const voleith_rs_attr_field_t fields[] = {
        {8, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;

    /* --- accepts --- */
    cfg = epoch_cfg();
    check("epoch validate: V6-only accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.epoch_sk_bytes = 16;
    check("epoch validate: epoch_sk_bytes 16 accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.epoch_hash = &voleith_node_hash_hirose_fixed32; /* node32, cr128 */
    check("epoch validate: explicit epoch_hash (node/cr match) accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.epoch_hash = &epoch_stub_cr128; /* node32, cr128 == tree */
    check("epoch validate: epoch_hash cr == tree cr accepted (default rule)",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.attr_schema = &schema; /* V6 + V3: leaf = OWF(epoch_root||attrs) */
    check("epoch validate: V6+V3 accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.attr_schema = &schema;
    cfg.leaf_salt_bytes = 8; /* 32 root + 8 attr + 8 salt = 48 <= 64 */
    check("epoch validate: V6+V3+salt within capacity accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = epoch_cfg();
    cfg.epoch_hash = &epoch_stub_cr64; /* cr64 < tree cr128 */
    cfg.epoch_hash_preimage_ok = 1;    /* 2*64 >= 128 */
    check("epoch validate: preimage_ok relaxes strength (2*cr>=tree)",
          voleith_rs_config_validate(&cfg) == 0);

    /* --- rejects --- */
    cfg = epoch_cfg();
    cfg.depth_e = VOLEITH_RS_EPOCH_MAX_DEPTH + 1;
    check("epoch validate: depth_e over cap rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.epoch_hash = &voleith_node_hash_aes_dm; /* node16 != tree node32 */
    check("epoch validate: epoch_hash node width mismatch rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.epoch_sk_bytes = 24; /* not 16 or 32 */
    check("epoch validate: epoch_sk_bytes not in {16,32} rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.epoch_hash = &epoch_stub_cap16; /* leaf_block 16 < sk 32 */
    check("epoch validate: epoch_sk over epoch_hash capacity rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.membership.sk_bytes = 16; /* must be 0 under V6 */
    check("epoch validate: nonzero membership.sk_bytes rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.epoch_hash = &epoch_stub_cr64; /* cr64 < tree cr128, no relax */
    check("epoch validate: weak epoch_hash rejected without preimage_ok",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.leaf_salt_bytes = 8; /* salt without V3 (no attr_schema) */
    check("epoch validate: salt without attributes rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = epoch_cfg();
    cfg.attr_schema = &schema;
    cfg.leaf_salt_bytes = 32; /* 32 + 8 + 32 = 72 > 64 capacity */
    check("epoch validate: salt over leaf capacity rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* Epoch fields set while V6 is off: silently-dropped-field guard. */
    cfg = canonical_cfg();
    cfg.epoch_sk_bytes = 16;
    check("epoch validate: epoch_sk_bytes with depth_e==0 rejected",
          voleith_rs_config_validate(&cfg) == -1);
    cfg = canonical_cfg();
    cfg.leaf_salt_bytes = 8;
    check("epoch validate: leaf_salt_bytes with depth_e==0 rejected",
          voleith_rs_config_validate(&cfg) == -1);
    cfg = canonical_cfg();
    cfg.epoch_hash = &voleith_node_hash_aes_dm;
    check("epoch validate: epoch_hash with depth_e==0 rejected",
          voleith_rs_config_validate(&cfg) == -1);
    cfg = canonical_cfg();
    cfg.epoch_hash_preimage_ok = 1;
    check("epoch validate: preimage_ok with depth_e==0 rejected",
          voleith_rs_config_validate(&cfg) == -1);
}

/*
 * Epoch fingerprint: determinism, per-field binding, and a KAT pin.
 *
 * BOOTSTRAP: RS_CFG_EPOCH_KAT_PINNED starts at 0 so the test prints the
 * computed fingerprint without hard-failing; copy the printed bytes into
 * epoch_kat and flip the flag to 1 to arm the regression check.  Same
 * pattern as test_fingerprint_kat_pin.
 */
#define RS_CFG_EPOCH_KAT_PINNED 1
static void
test_epoch_fingerprint(void)
{
    voleith_rs_config_t ref = epoch_cfg();
    voleith_rs_config_t cfg;
    uint8_t fp_ref[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];

    MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp_ref));
    check("epoch fingerprint: deterministic",
          voleith_rs_config_fingerprint(&ref, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) == 0);

    cfg = epoch_cfg();
    cfg.depth_e = 9;
    check("epoch fingerprint: depth_e bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    cfg = epoch_cfg();
    cfg.epoch_sk_bytes = 16;
    check("epoch fingerprint: epoch_sk_bytes bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    cfg = epoch_cfg();
    cfg.epoch_hash = &voleith_node_hash_hirose_fixed32; /* different name */
    check("epoch fingerprint: epoch_hash name bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    cfg = epoch_cfg();
    cfg.epoch_hash_preimage_ok = 1;
    check("epoch fingerprint: preimage_ok flag bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    /* leaf_salt_bytes bound (needs V3 to validate, but the fingerprint
     * absorbs it whenever the epoch bit is set). */
    {
        static const voleith_rs_attr_field_t f[] = {
            {8, VOLEITH_RS_ATTR_PRED_NONE}};
        voleith_rs_attr_schema_t s = {f, 1};
        voleith_rs_config_t a = epoch_cfg();
        voleith_rs_config_t b = epoch_cfg();
        uint8_t fpa[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
        uint8_t fpb[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
        a.attr_schema = &s;
        b.attr_schema = &s;
        b.leaf_salt_bytes = 8;
        MUST_OK_FP(voleith_rs_config_fingerprint(&a, fpa));
        check("epoch fingerprint: leaf_salt_bytes bound",
              voleith_rs_config_fingerprint(&b, fpb) == 0 &&
                  memcmp(fpa, fpb, sizeof(fpa)) != 0);
    }

    /* KAT pin (bootstrap). */
    {
        static const uint8_t epoch_kat[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES] = {
            0x1f, 0x43, 0x15, 0x31, 0xc2, 0xbe, 0xde, 0x47,
            0x09, 0x5f, 0x01, 0xc1, 0x88, 0xb1, 0xa9, 0xb7};
        MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp));
        printf("  RS.CFG epoch-config fingerprint:");
        for (size_t i = 0; i < sizeof(fp); i++)
            printf(" %02x", fp[i]);
        printf("\n");
        if (RS_CFG_EPOCH_KAT_PINNED) {
            check("epoch kat: matches pinned constant",
                  memcmp(fp, epoch_kat, sizeof(fp)) == 0);
        } else {
            printf("  (epoch KAT not yet pinned: copy the bytes above into "
                   "epoch_kat and set RS_CFG_EPOCH_KAT_PINNED to 1)\n");
            (void)epoch_kat;
        }
    }
}

/* ================================================================
 * OP.CFG: V5 designated-opener module (bitmap bit 6, validate,
 * fingerprint).  The opener carries the Argus public matrix M and a
 * parameter-set selector; a lambda/8 id joins the leaf preimage (Q2) and
 * is shared with the V4 commitment id (Q8).
 * ================================================================ */

/* Deterministic M (the (n0-1) circulant blocks) for a shipped set.  Content
 * is arbitrary for validate (only length matters) and fixed for the
 * fingerprint KAT.  Returns NULL length via *out_len == 0 for a reserved set. */
static uint8_t *
opener_M_alloc(voleith_rs_opener_argus_set_t set, size_t *out_len)
{
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(set);
    size_t len = op ? (size_t)(op->n0 - 1u) * op->block_bytes : 0;
    uint8_t *M = malloc(len ? len : 1);
    for (size_t i = 0; i < len; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    *out_len = len;
    return M;
}

/*
 * Valid opener base: grostl-256-fixed tree (node32, leaf cap 64) so the
 * sk(16) + id(16) preimage fits.  opener_set 128_2 => id = key_bytes = 16.
 * The membership lambda and the opener lambda are independent in the config
 * surface (the opener params are set-derived), so the tree choice here is
 * only about leaf capacity.
 */
static voleith_rs_config_t
opener_cfg(const uint8_t *M, size_t Mlen)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.owf_hash = NULL;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;
    cfg.enable_opener = 1;
    cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_2;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;
    return cfg;
}

static void
test_opener_bitmap(void)
{
    size_t Mlen;
    uint8_t *M = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_128_2, &Mlen);
    voleith_rs_config_t cfg = opener_cfg(M, Mlen);

    check("bitmap: opener bit (enable_opener)",
          voleith_rs_module_bitmap(&cfg) == VOLEITH_RS_MODULE_OPENER);

    cfg.scope_bytes = 12; /* V2 nullifier alongside the opener */
    check("bitmap: opener + nullifier",
          voleith_rs_module_bitmap(&cfg) ==
              (VOLEITH_RS_MODULE_OPENER | VOLEITH_RS_MODULE_NULLIFIER));

    cfg = opener_cfg(M, Mlen);
    cfg.enable_opener = 0;
    cfg.opener_pk = NULL;
    cfg.opener_pk_bytes = 0;
    check("bitmap: enable_opener==0 clears opener bit",
          (voleith_rs_module_bitmap(&cfg) & VOLEITH_RS_MODULE_OPENER) == 0);

    free(M);
}

static void
test_opener_validate(void)
{
    size_t Mlen;
    uint8_t *M = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_128_2, &Mlen);
    voleith_rs_config_t cfg;

    /* --- accepts --- */
    cfg = opener_cfg(M, Mlen);
    check("opener validate: opener-only accepted",
          voleith_rs_config_validate(&cfg) == 0);

    cfg = opener_cfg(M, Mlen);
    cfg.enable_commitment = 1; /* V4 + V5 share the id: commit_id_bytes==16 */
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;
    check("opener validate: V4+V5 with commit_id_bytes==lambda/8 accepted",
          voleith_rs_config_validate(&cfg) == 0);

    /* --- rejects --- */
    cfg = opener_cfg(M, Mlen);
    cfg.opener_set =
        VOLEITH_RS_OPENER_ARGUS_SET_128_3; /* reserved: params NULL */
    check("opener validate: reserved/unshipped set rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = opener_cfg(M, Mlen);
    cfg.opener_pk = NULL;
    check("opener validate: NULL opener_pk rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = opener_cfg(M, Mlen);
    cfg.opener_pk_bytes = Mlen + 1; /* wrong M length for the set */
    check("opener validate: wrong opener_pk_bytes rejected",
          voleith_rs_config_validate(&cfg) == -1);

    cfg = opener_cfg(M, Mlen);
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 8; /* != lambda/8; Q8 id-sharing violated */
    cfg.commit_rand_bytes = 16;
    check("opener validate: V4 commit_id_bytes != lambda/8 rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* enable_opener off but opener_pk left set: silently-dropped-field guard. */
    cfg = opener_cfg(M, Mlen);
    cfg.enable_opener = 0; /* opener_pk still non-NULL */
    check("opener validate: opener_pk set with enable_opener==0 rejected",
          voleith_rs_config_validate(&cfg) == -1);

    /* Leaf capacity includes the id: sk(56) + id(16) = 72 > 64 rejects with
     * the opener on, but sk(56) alone (opener off) fits, isolating the id. */
    cfg = opener_cfg(M, Mlen);
    cfg.membership.sk_bytes = 56;
    check("opener validate: id pushes leaf preimage over capacity rejected",
          voleith_rs_config_validate(&cfg) == -1);
    cfg.enable_opener = 0;
    cfg.opener_pk = NULL;
    cfg.opener_pk_bytes = 0;
    check("opener validate: same sk without opener (no id) accepted",
          voleith_rs_config_validate(&cfg) == 0);

    free(M);
}

/*
 * Opener fingerprint: determinism, per-field binding (set, M digest, and the
 * hash_id via the per-lambda prim_default), a bit-6-off regression check, and
 * a KAT pin.
 *
 * BOOTSTRAP: RS_CFG_OPENER_KAT_PINNED starts at 0 so the first build prints
 * the computed fingerprint without hard-failing; copy the printed bytes into
 * opener_kat and flip the flag to 1 to arm the regression check.  Same pattern
 * as test_epoch_fingerprint.
 */
#define RS_CFG_OPENER_KAT_PINNED 1
static void
test_opener_fingerprint(void)
{
    size_t Mlen, Mlen256;
    uint8_t *M = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_128_2, &Mlen);
    uint8_t *M256 = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_256_2, &Mlen256);
    voleith_rs_config_t ref = opener_cfg(M, Mlen);
    voleith_rs_config_t cfg;
    uint8_t fp_ref[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];

    MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp_ref));
    check("opener fingerprint: deterministic",
          voleith_rs_config_fingerprint(&ref, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) == 0);

    /* opener_set (and its prim_default hash_id) bound: a different shipped set
     * at a different lambda changes the absorbed set id and hash_id. */
    cfg = opener_cfg(M256, Mlen256);
    cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_256_2;
    check("opener fingerprint: opener_set + hash_id bound",
          voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
              memcmp(fp, fp_ref, sizeof(fp)) != 0);

    /* M digest bound: flip one byte of M. */
    {
        uint8_t *Mbad = malloc(Mlen ? Mlen : 1);
        memcpy(Mbad, M, Mlen);
        Mbad[0] ^= 0x01u;
        cfg = opener_cfg(Mbad, Mlen);
        check("opener fingerprint: M digest bound",
              voleith_rs_config_fingerprint(&cfg, fp) == 0 &&
                  memcmp(fp, fp_ref, sizeof(fp)) != 0);
        free(Mbad);
    }

    /* Bit-6-off regression: the opener section is absorbed only when bit 6 is
     * set, so an opener-off config equals its own opener-fields-zeroed twin.
     * (The pre-opener combined/epoch KATs staying green is the compat guard.) */
    {
        voleith_rs_config_t a = canonical_cfg();
        voleith_rs_config_t b = canonical_cfg();
        uint8_t fpa[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
        uint8_t fpb[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
        b.opener_set =
            VOLEITH_RS_OPENER_ARGUS_SET_256_2; /* ignored: bit 6 off */
        MUST_OK_FP(voleith_rs_config_fingerprint(&a, fpa));
        check("opener fingerprint: opener_set ignored when bit 6 off",
              voleith_rs_config_fingerprint(&b, fpb) == 0 &&
                  memcmp(fpa, fpb, sizeof(fpa)) == 0);
    }

    /* KAT pin (bootstrap). */
    {
        static const uint8_t opener_kat[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES] = {
            0xe8, 0xb2, 0xef, 0xfa, 0x30, 0x1e, 0xa3, 0xba,
            0xa6, 0x34, 0xb3, 0xbd, 0x66, 0xfb, 0x03, 0x96};
        MUST_OK_FP(voleith_rs_config_fingerprint(&ref, fp));
        printf("  RS.CFG opener-config fingerprint:");
        for (size_t i = 0; i < sizeof(fp); i++)
            printf(" %02x", fp[i]);
        printf("\n");
        if (RS_CFG_OPENER_KAT_PINNED) {
            check("opener kat: matches pinned constant",
                  memcmp(fp, opener_kat, sizeof(fp)) == 0);
        } else {
            printf("  (opener KAT not yet pinned: copy the bytes above into "
                   "opener_kat and set RS_CFG_OPENER_KAT_PINNED to 1)\n");
            (void)opener_kat;
        }
    }

    free(M);
    free(M256);
}

/* ================================================================
 * RS.LEAF: leaf over sk || attributes.
 * ================================================================ */

/* Widest node among the tested vts is Grostl-512 (64 bytes). */
#define RS_LEAF_MAX_NODE 64

/* Build leaf_node = OWF(sk || attrs) in-circuit, eval, write node_bytes
 * to out_node. */
static void
rs_leaf_incircuit(const voleith_node_hash_vt *vt, const uint8_t *sk,
                  size_t sk_bytes, const uint8_t *attrs, size_t attr_bytes,
                  uint8_t *out_node)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t total = sk_bytes + attr_bytes;
    gf8_wire_id *sk_w = sk_bytes ? calloc(sk_bytes, sizeof(gf8_wire_id)) : NULL;
    gf8_wire_id *at_w =
        attr_bytes ? calloc(attr_bytes, sizeof(gf8_wire_id)) : NULL;
    gf8_wire_id out_w[RS_LEAF_MAX_NODE];
    size_t inv;
    uint8_t *witness;
    uint8_t pre[RS_LEAF_MAX_NODE * 4];
    size_t nW;
    uint8_t *wire_vals;

    /* Witnesses declared sk-first then attrs, matching the preimage the
     * builder assembles and the witness it packs. */
    for (size_t i = 0; i < sk_bytes; i++)
        sk_w[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < attr_bytes; i++)
        at_w[i] = voleith_gf8_add_witness(c);

    MUST_OK_FP(rs_leaf_gf8_build_circuit(c, vt, sk_w, sk_bytes, at_w,
                                         attr_bytes, out_w));

    inv = rs_leaf_gf8_invin_bytes(vt, sk_bytes, attr_bytes);
    witness = calloc(total + inv, 1);
    memcpy(pre, sk, sk_bytes);
    memcpy(pre + sk_bytes, attrs, attr_bytes);
    memcpy(witness, pre, total);
    MUST_OK_FP(rs_leaf_gf8_build_witness(vt, sk, sk_bytes, attrs, attr_bytes,
                                         witness + total));

    nW = voleith_gf8_circuit_wire_count(c);
    wire_vals = calloc(nW > 0 ? nW : 1, 1);
    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (size_t i = 0; i < vt->node_bytes; i++)
        out_node[i] = wire_vals[out_w[i]];

    free(wire_vals);
    free(witness);
    free(sk_w);
    free(at_w);
    voleith_gf8_circuit_free(c);
}

/* One vt: attr==0 equivalence, in-circuit==software, and attr binding. */
static void
rs_leaf_check_vt(const char *label, const voleith_node_hash_vt *vt,
                 size_t sk_bytes, size_t attr_bytes)
{
    uint8_t sk[RS_LEAF_MAX_NODE];
    uint8_t attrs[RS_LEAF_MAX_NODE];
    uint8_t sw[RS_LEAF_MAX_NODE], circ[RS_LEAF_MAX_NODE];
    uint8_t ref[RS_LEAF_MAX_NODE], flipped[RS_LEAF_MAX_NODE];
    char name[160];

    for (size_t i = 0; i < sk_bytes; i++)
        sk[i] = (uint8_t)(0x11 + i);
    for (size_t i = 0; i < attr_bytes; i++)
        attrs[i] = (uint8_t)(0xC0 + i);

    /* attr == 0: rs_leaf reproduces the bare OWF(sk). */
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sk, sk_bytes, NULL, 0, sw));
    MUST_OK_FP(vt->leaf_hash(sk, sk_bytes, ref));
    snprintf(name, sizeof(name), "[%s] rs_leaf attr==0 == OWF(sk)", label);
    check(name, memcmp(sw, ref, vt->node_bytes) == 0);

    /* invin matches the vt over the concatenated width. */
    snprintf(name, sizeof(name), "[%s] rs_leaf invin == vt(sk+attr)", label);
    check(name, rs_leaf_gf8_invin_bytes(vt, sk_bytes, attr_bytes) ==
                    vt->leaf_invin_bytes(sk_bytes + attr_bytes));

    /* With attributes: in-circuit leaf == software leaf. */
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sk, sk_bytes, attrs, attr_bytes, sw));
    rs_leaf_incircuit(vt, sk, sk_bytes, attrs, attr_bytes, circ);
    snprintf(name, sizeof(name), "[%s] rs_leaf in-circuit == software", label);
    check(name, memcmp(circ, sw, vt->node_bytes) == 0);

    /* Binding: flipping an attribute byte changes the leaf (proves the
     * attrs are actually absorbed, not dropped by a fixed-width leaf). */
    attrs[attr_bytes - 1] ^= 0x01;
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sk, sk_bytes, attrs, attr_bytes, flipped));
    snprintf(name, sizeof(name), "[%s] rs_leaf binds attribute bytes", label);
    check(name, memcmp(flipped, sw, vt->node_bytes) != 0);
}

static void
test_rs_leaf(void)
{
    /* Variable-leaf vt: any width. */
    rs_leaf_check_vt("aes-dm", &voleith_node_hash_aes_dm, 16, 8);
    /* Fixed-input vts: sk + attrs within the block capacity, sk narrower
     * than node_bytes (the security floor, not the node width). */
    rs_leaf_check_vt("hirose-fixed32", &voleith_node_hash_hirose_fixed32, 16,
                     16);
    rs_leaf_check_vt("grostl256-fixed", &voleith_node_hash_grostl256_fixed, 16,
                     32);
    rs_leaf_check_vt("grostl512-fixed", &voleith_node_hash_grostl512_fixed, 32,
                     32);
}

/* ================================================================
 * OP.CIRC.1: V5 opener id in the leaf preimage.
 *
 * The full consistent-tuple eval (support / s / tag_ct) lands with the
 * packer in OP.CIRC.4; here we validate the layout wiring (dedicated vs
 * V4-shared id per Q8), that the id widens the OWF leaf preimage, and that
 * appending an id changes the leaf node (the binding mechanism), plus the
 * opener-off no-op.
 * ================================================================ */
/* Independent schoolbook circulant syndrome (out-of-range index = no column),
 * matching the in-circuit per-support-element XOR semantics. */
static void
opener_synd_oracle(uint8_t *s, uint32_t p, uint32_t n0, uint32_t t,
                   const uint32_t *idx, const uint8_t *M)
{
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    uint8_t *e = calloc((size_t)n0 * p, 1);
    uint32_t k, j, b, a, cpos;
    for (k = 0; k < t; k++)
        if (idx[k] < (uint32_t)n0 * p)
            e[idx[k]] = 1;
    for (j = 0; j < p; j++)
        s[j] = e[(size_t)(n0 - 1u) * p + j];
    for (b = 0; b + 1u < n0; b++) {
        const uint8_t *mb = M + (size_t)b * block_bytes;
        for (a = 0; a < p; a++)
            if ((mb[a >> 3] >> (a & 7u)) & 1u)
                for (cpos = 0; cpos < p; cpos++)
                    s[(a + cpos) % p] ^= e[(size_t)b * p + cpos];
    }
    free(e);
}

/* Build a standalone opener-syndrome circuit at reduced params: commit the
 * bit-packed support (LSB-first at idx_bits, via ichor_bitpack_le32), declare p
 * syndrome bit instance wires, emit the helper, and eval.  Returns 1 if all
 * constraints pass, 0 if any fails, -1 on error.  This exercises the MSB-first
 * extraction + syndrome + LT well-formedness without the (opener-unaware) full
 * packer. */
static int
opener_synd_eval(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
                 const uint32_t *idx, const uint8_t *M, const uint8_t *s)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t msg_bytes = ((size_t)t * idx_bits + 7u) / 8u;
    gf8_wire_id *sup_w = malloc(msg_bytes * sizeof(gf8_wire_id));
    gf8_wire_id *s_w = malloc((size_t)p * sizeof(gf8_wire_id));
    uint8_t *witness = calloc(msg_bytes ? msg_bytes : 1, 1);
    uint8_t *instance = malloc(p);
    uint8_t *wire_vals;
    size_t i;
    int res;

    ichor_bitpack_le32(witness, msg_bytes, idx, t, idx_bits);
    for (i = 0; i < msg_bytes; i++)
        sup_w[i] = voleith_gf8_add_witness(c);
    for (i = 0; i < p; i++) {
        s_w[i] = voleith_gf8_add_instance(c);
        instance[i] = (uint8_t)(s[i] & 1u);
    }
    res = voleith_rs_opener_syndrome_gf8(c, sup_w, s_w, t, idx_bits, p, n0, M);
    if (res != 0) {
        res = -1;
        goto done;
    }
    wire_vals = malloc(voleith_gf8_circuit_wire_count(c));
    res = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);
    if (res != 1 && res != 0)
        res = -1;
    free(wire_vals);
done:
    free(sup_w);
    free(s_w);
    free(witness);
    free(instance);
    voleith_gf8_circuit_free(c);
    return res;
}

static void
test_opener_syndrome_reduced(void)
{
    /* Tiny synthetic set (same shape as test_syndrome_gf8): p=7, n0=2 (n=14),
     * t=2, idx_bits=4, one circulant block M = 0x5a. */
    const uint32_t p = 7, n0 = 2, t = 2, idx_bits = 4;
    const uint8_t M[1] = {0x5a};
    uint32_t idx[2] = {2, 9};
    uint8_t s[7];

    opener_synd_oracle(s, p, n0, t, idx, M);
    check("opener syndrome: honest support + s accepts (packed->extract)",
          opener_synd_eval(p, n0, t, idx_bits, idx, M, s) == 1);

    /* Wrong s bit rejects. */
    {
        uint8_t sbad[7];
        memcpy(sbad, s, 7);
        sbad[3] ^= 1u;
        check("opener syndrome: wrong s bit rejects",
              opener_synd_eval(p, n0, t, idx_bits, idx, M, sbad) == 0);
    }
    /* Duplicate index (weight < t): XOR cancels, commit s = 0; ascending LT
     * rejects. */
    {
        uint32_t dup[2] = {5, 5};
        uint8_t s0[7] = {0};
        check("opener syndrome: duplicate support rejects (LT)",
              opener_synd_eval(p, n0, t, idx_bits, dup, M, s0) == 0);
    }
    /* Descending order: commutative XOR keeps honest s; ascending LT rejects. */
    {
        uint32_t desc[2] = {9, 2};
        check("opener syndrome: descending support rejects (LT)",
              opener_synd_eval(p, n0, t, idx_bits, desc, M, s) == 0);
    }
    /* Out-of-range index (== n): no column, s matches remainder; range LT
     * rejects. */
    {
        uint32_t oor[2] = {2, 14};
        uint8_t soor[7];
        opener_synd_oracle(soor, p, n0, t, oor, M);
        check("opener syndrome: out-of-range support rejects (range)",
              opener_synd_eval(p, n0, t, idx_bits, oor, M, soor) == 0);
    }
}

/* Build a standalone lambda=128 KDF+DEM circuit at reduced size and eval it.
 * K = AES-DM(ds_iv, msg) is computed by ichor_aesdm_* (the SAME primitive the
 * argus KDF calls), so a passing eval proves the in-circuit chain is byte-exact.
 * tamper: 0 = honest, 1 = flip tag_ct, 2 = flip committed id.  Witness layout =
 * support(msg_bytes) || id(16) || kdf_invin; instance = tag_ct(16). */
static int
opener_dem_aesdm_eval(const uint8_t ds_iv[16], const uint8_t *msg,
                      size_t msg_bytes, const uint8_t id[16], int tamper)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t invin = voleith_rs_opener_kdf_aesdm_invin_bytes(msg_bytes);
    gf8_wire_id *sup_w = malloc(msg_bytes * sizeof(gf8_wire_id));
    gf8_wire_id id_w[16], tag_w[16];
    uint8_t K[16], tag_ct[16];
    uint8_t *witness = malloc(msg_bytes + 16 + invin);
    uint8_t instance[16];
    uint8_t *wire_vals;
    ichor_aesdm_ctx_t kc;
    size_t i;
    int res;

    ichor_aesdm_init_iv(&kc, ds_iv);
    ichor_aesdm_absorb(&kc, msg, msg_bytes);
    ichor_aesdm_finalize_fixed(&kc, K);
    ichor_aesdm_clear(&kc);
    for (i = 0; i < 16; i++)
        tag_ct[i] = (uint8_t)(K[i] ^ id[i]);

    for (i = 0; i < msg_bytes; i++)
        sup_w[i] = voleith_gf8_add_witness(c);
    for (i = 0; i < 16; i++)
        id_w[i] = voleith_gf8_add_witness(c);
    for (i = 0; i < 16; i++)
        tag_w[i] = voleith_gf8_add_instance(c);
    res = voleith_rs_opener_dem_aesdm_gf8(c, sup_w, msg_bytes, ds_iv, id_w,
                                          tag_w, 16);
    if (res != 0) {
        res = -1;
        goto done;
    }

    memcpy(witness, msg, msg_bytes);
    memcpy(witness + msg_bytes, id, 16);
    voleith_rs_opener_kdf_aesdm_build_witness(ds_iv, msg, msg_bytes,
                                              witness + msg_bytes + 16);
    memcpy(instance, tag_ct, 16);
    if (tamper == 1)
        instance[0] ^= 1u; /* wrong tag_ct */
    if (tamper == 2)
        witness[msg_bytes] ^= 1u; /* wrong committed id (K unchanged) */

    wire_vals = malloc(voleith_gf8_circuit_wire_count(c));
    res = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);
    if (res != 1 && res != 0)
        res = -1;
    free(wire_vals);
done:
    free(sup_w);
    free(witness);
    voleith_gf8_circuit_free(c);
    return res;
}

static void
test_opener_dem_aesdm_reduced(void)
{
    uint8_t ds_iv[16], msg[20], id[16];
    size_t i;
    for (i = 0; i < 16; i++)
        ds_iv[i] = (uint8_t)(0x10 + i);
    for (i = 0; i < 20; i++)
        msg[i] = (uint8_t)(0x40 + i);
    for (i = 0; i < 16; i++)
        id[i] = (uint8_t)(0xA0 + i);

    /* 20 bytes = 1 full block + 4-byte partial (finalize zero-pads + 1 iter). */
    check("opener DEM aesdm: honest tag_ct==K^id accepts (byte-exact ichor)",
          opener_dem_aesdm_eval(ds_iv, msg, 20, id, 0) == 1);
    check("opener DEM aesdm: wrong tag_ct rejects",
          opener_dem_aesdm_eval(ds_iv, msg, 20, id, 1) == 0);
    check("opener DEM aesdm: wrong committed id rejects",
          opener_dem_aesdm_eval(ds_iv, msg, 20, id, 2) == 0);
    /* Exact block multiple: finalize adds no extra block. */
    check("opener DEM aesdm: exact-block-multiple accepts",
          opener_dem_aesdm_eval(ds_iv, msg, 16, id, 0) == 1);
    /* Empty message: K = ds_iv (finalize adds nothing). */
    check("opener DEM aesdm: empty support (K == ds_iv) accepts",
          opener_dem_aesdm_eval(ds_iv, msg, 0, id, 0) == 1);
}

/* lambda=256 twin of opener_dem_aesdm_eval: K = Grostl-256(ds_iv-padded, msg)
 * via ichor_grostl256_init_iv/absorb/finalize_fixed (the same primitive the
 * argus KDF calls).  key_bytes = 32. */
static int
opener_dem_grostl_eval(const uint8_t ds_iv[16], const uint8_t *msg,
                       size_t msg_bytes, const uint8_t id[32], int tamper)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t invin = voleith_rs_opener_kdf_grostl256_invin_bytes(msg_bytes);
    gf8_wire_id *sup_w =
        malloc((msg_bytes ? msg_bytes : 1) * sizeof(gf8_wire_id));
    gf8_wire_id id_w[32], tag_w[32];
    uint8_t iv64[64], K[32], tag_ct[32];
    uint8_t *witness = malloc(msg_bytes + 32 + invin);
    uint8_t instance[32];
    uint8_t *wire_vals;
    ichor_grostl_ctx_t gc;
    size_t i;
    int res;

    memset(iv64, 0, 64);
    memcpy(iv64, ds_iv, 16);
    ichor_grostl256_init_iv(&gc, iv64);
    ichor_grostl_absorb(&gc, msg, msg_bytes);
    ichor_grostl_finalize_fixed(&gc, K);
    ichor_grostl_clear(&gc);
    for (i = 0; i < 32; i++)
        tag_ct[i] = (uint8_t)(K[i] ^ id[i]);

    for (i = 0; i < msg_bytes; i++)
        sup_w[i] = voleith_gf8_add_witness(c);
    for (i = 0; i < 32; i++)
        id_w[i] = voleith_gf8_add_witness(c);
    for (i = 0; i < 32; i++)
        tag_w[i] = voleith_gf8_add_instance(c);
    res = voleith_rs_opener_dem_grostl256_gf8(c, sup_w, msg_bytes, ds_iv, id_w,
                                              tag_w, 32);
    if (res != 0) {
        res = -1;
        goto done;
    }

    memcpy(witness, msg, msg_bytes);
    memcpy(witness + msg_bytes, id, 32);
    voleith_rs_opener_kdf_grostl256_build_witness(ds_iv, msg, msg_bytes,
                                                  witness + msg_bytes + 32);
    memcpy(instance, tag_ct, 32);
    if (tamper == 1)
        instance[0] ^= 1u;
    if (tamper == 2)
        witness[msg_bytes] ^= 1u;

    wire_vals = malloc(voleith_gf8_circuit_wire_count(c));
    res = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);
    if (res != 1 && res != 0)
        res = -1;
    free(wire_vals);
done:
    free(sup_w);
    free(witness);
    voleith_gf8_circuit_free(c);
    return res;
}

static void
test_opener_dem_grostl_reduced(void)
{
    uint8_t ds_iv[16], msg[70], id[32];
    size_t i;
    for (i = 0; i < 16; i++)
        ds_iv[i] = (uint8_t)(0x21 + i);
    for (i = 0; i < 70; i++)
        msg[i] = (uint8_t)(0x30 + i);
    for (i = 0; i < 32; i++)
        id[i] = (uint8_t)(0xC0 + i);

    /* 70 bytes = 1 full 64-byte block + 6-byte partial (finalize zero-pads). */
    check("opener DEM grostl: honest tag_ct==K^id accepts (byte-exact ichor)",
          opener_dem_grostl_eval(ds_iv, msg, 70, id, 0) == 1);
    check("opener DEM grostl: wrong tag_ct rejects",
          opener_dem_grostl_eval(ds_iv, msg, 70, id, 1) == 0);
    check("opener DEM grostl: wrong committed id rejects",
          opener_dem_grostl_eval(ds_iv, msg, 70, id, 2) == 0);
    /* Exact block multiple (64): finalize adds no extra block. */
    check("opener DEM grostl: exact-block-multiple accepts",
          opener_dem_grostl_eval(ds_iv, msg, 64, id, 0) == 1);
    /* Empty message: a single zero block is compressed. */
    check("opener DEM grostl: empty support accepts",
          opener_dem_grostl_eval(ds_iv, msg, 0, id, 0) == 1);
}

/* aes-dm (variable-input) opener base so owf_invin scales with the preimage
 * length; opener_cfg() uses the fixed-input grostl256 whose invin is constant. */
static voleith_rs_config_t
opener_circuit_cfg(const uint8_t *M, size_t Mlen)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;
    cfg.enable_opener = 1;
    cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_2;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;
    return cfg;
}

static void
test_opener_circuit(void)
{
    size_t Mlen;
    uint8_t *M = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_128_2, &Mlen);
    voleith_gf8_circuit_t *c;

    /* opener off: no id section, build unaffected. */
    {
        voleith_rs_config_t cfg = canonical_cfg();
        voleith_rs_layout_t L;
        c = voleith_gf8_circuit_new();
        MUST_OK_FP(voleith_rs_build_circuit(c, &cfg, &L));
        check("opener circuit: off => no id section",
              L.opener_id_off == 0 && L.opener_id_bytes == 0);
        voleith_gf8_circuit_free(c);
    }

    /* opener on, V4 off: dedicated id witness of key_bytes; the id widens the
     * OWF leaf preimage (owf_invin grows vs the same config with the opener
     * off) and the witness grows by at least id_bytes. */
    {
        voleith_rs_config_t on = opener_circuit_cfg(M, Mlen); /* aes-dm, sk16 */
        voleith_rs_config_t off = on;
        voleith_rs_layout_t Lon, Loff;
        off.enable_opener = 0;
        off.opener_pk = NULL;
        off.opener_pk_bytes = 0;

        c = voleith_gf8_circuit_new();
        MUST_OK_FP(voleith_rs_build_circuit(c, &on, &Lon));
        voleith_gf8_circuit_free(c);
        c = voleith_gf8_circuit_new();
        MUST_OK_FP(voleith_rs_build_circuit(c, &off, &Loff));
        voleith_gf8_circuit_free(c);

        check("opener circuit: id_bytes == lambda/8 (128)",
              Lon.opener_id_bytes == 16);
        check("opener circuit: dedicated id witness when V4 off",
              Lon.opener_id_off != 0);
        check("opener circuit: id widens OWF leaf preimage",
              Lon.membership.owf_invin_bytes > Loff.membership.owf_invin_bytes);
        check("opener circuit: witness grows by >= id_bytes",
              Lon.witness_bytes >= Loff.witness_bytes + 16);

        /* OP.CIRC.2: support witness (msg_bytes) + s bit instance (p). */
        {
            const voleith_rs_opener_argus_params_t *op =
                voleith_rs_opener_argus_params(
                    VOLEITH_RS_OPENER_ARGUS_SET_128_2);
            check("opener circuit: support section == msg_bytes",
                  Lon.opener_support_bytes == op->msg_bytes &&
                      Lon.opener_support_off != 0);
            check("opener circuit: s instance section == p",
                  Lon.inst_opener_s_bytes == op->p);
            check("opener circuit: off => no support/s sections",
                  Loff.opener_support_bytes == 0 &&
                      Loff.inst_opener_s_bytes == 0);
            /* OP.CIRC.3: tag_ct instance == key_bytes (DEM ciphertext). */
            check("opener circuit: tag_ct instance == key_bytes",
                  Lon.inst_opener_tag_ct_bytes == op->key_bytes);
            check("opener circuit: off => no tag_ct section",
                  Loff.inst_opener_tag_ct_bytes == 0);
            /* OP.CIRC.4: KDF inv_in section == aesdm(msg_bytes) at lambda128. */
            check("opener circuit: kdf invin == aesdm(msg_bytes)",
                  Lon.opener_kdf_invin_bytes ==
                      voleith_rs_opener_kdf_aesdm_invin_bytes(op->msg_bytes));
        }
    }

    /* opener on + V4 on: Q8 shared id witness (opener_id_off==commit_id_off). */
    {
        voleith_rs_config_t cfg = opener_circuit_cfg(M, Mlen);
        voleith_rs_layout_t L;
        cfg.enable_commitment = 1;
        cfg.commit_id_bytes = 16;
        cfg.commit_rand_bytes = 16;
        c = voleith_gf8_circuit_new();
        MUST_OK_FP(voleith_rs_build_circuit(c, &cfg, &L));
        check("opener circuit: Q8 id shared with V4 commit id",
              L.opener_id_bytes == 16 && L.opener_id_off == L.commit_id_off);
        voleith_gf8_circuit_free(c);
    }

    /* id changes the leaf: OWF(sk) != OWF(sk || id).  The id joins the OWF
     * preimage as tail bytes exactly as build_circuit appends it. */
    {
        const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256_fixed;
        uint8_t sk[16], id[16];
        uint8_t n_noid[RS_LEAF_MAX_NODE], n_id[RS_LEAF_MAX_NODE];
        for (int k = 0; k < 16; k++) {
            sk[k] = (uint8_t)k;
            id[k] = (uint8_t)(0xA0 + k);
        }
        rs_leaf_incircuit(vt, sk, 16, NULL, 0, n_noid);
        rs_leaf_incircuit(vt, sk, 16, id, 16, n_id);
        check("opener circuit: id changes the leaf node",
              memcmp(n_noid, n_id, vt->node_bytes) != 0);
    }

    /* lambda=256 opener (Grostl-256 KDF path): build succeeds and the id +
     * tag_ct sections are 32 bytes.  Uses 256_5 (smallest 256 set). */
    {
        size_t Mlen5;
        uint8_t *M5 = opener_M_alloc(VOLEITH_RS_OPENER_ARGUS_SET_256_5, &Mlen5);
        const voleith_rs_opener_argus_params_t *op5 =
            voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_256_5);
        voleith_rs_config_t cfg;
        voleith_rs_layout_t L;
        memset(&cfg, 0, sizeof(cfg));
        cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
        cfg.membership.sk_bytes = 16;
        cfg.membership.depth_m = 3;
        cfg.enable_opener = 1;
        cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_256_5;
        cfg.opener_pk = M5;
        cfg.opener_pk_bytes = Mlen5;
        c = voleith_gf8_circuit_new();
        MUST_OK_FP(voleith_rs_build_circuit(c, &cfg, &L));
        check("opener circuit: lambda256 grostl id + tag_ct == 32",
              op5->key_bytes == 32 && L.opener_id_bytes == 32 &&
                  L.inst_opener_tag_ct_bytes == 32);
        voleith_gf8_circuit_free(c);
        free(M5);
    }

    free(M);
}

/* ================================================================
 * V2.CIRC: nullifier branch.
 * ================================================================ */

/* Eval the built circuit on (witness, instance); returns the eval result
 * (1 = all constraints pass). */
static int
eval_circuit(voleith_gf8_circuit_t *c, const uint8_t *witness,
             const uint8_t *instance)
{
    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(nW > 0 ? nW : 1, 1);
    int rc = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);
    free(wire_vals);
    return rc;
}

static void
test_rs_nullifier(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t layout;
    voleith_gf8_circuit_t *c;
    const size_t depth_m = 2;
    const size_t n_members = 4;
    const size_t W = 16; /* aes_dm node_bytes */
    const size_t scope_bytes = 12;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t siblings_storage[4 * 2 * 16];
    voleith_rs_membership_path_t paths[4];
    uint8_t scope[12];
    uint8_t *witness;
    uint8_t *instance;
    uint8_t *cmac_tmp;
    uint8_t t_tag[16];
    size_t cmac_buf;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = depth_m;
    cfg.scope_bytes = scope_bytes;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90 + i);

    c = voleith_gf8_circuit_new();
    check("nullifier: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &layout) == 0);

    /* Slot-count derivation: 2 AES calls for a 12-byte CMAC message,
     * AES-128 = 200 inv per call. */
    check("nullifier: invin bytes == n_aes_calls * 200",
          layout.nullifier_invin_bytes ==
              aes_cmac_gf8_n_aes_calls(scope_bytes) * 200u);
    check("nullifier: T instance is 16 bytes", layout.inst_t_bytes == 16);
    check("nullifier: scope instance is scope_bytes",
          layout.inst_scope_bytes == scope_bytes);

    /* Build the ring and the signer's membership path (index 0). */
    MUST_OK_FP(voleith_rsv1_ring_build(&cfg.membership, sks, n_members, root,
                                       paths, siblings_storage));

    /* Witness: membership part via the core packer, then the nullifier
     * CMAC inv_in (key prefix stripped). */
    witness = calloc(layout.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_membership_pack_witness(
        &cfg.membership, &layout.membership, sks, &paths[0], NULL, witness));

    cmac_buf = aes_cmac_gf8_witness_bytes(16, scope_bytes);
    cmac_tmp = calloc(cmac_buf, 1);
    aes_cmac_gf8_build_witness(sks, 16, scope, scope_bytes, cmac_tmp, t_tag);
    memcpy(witness + layout.nullifier_invin_off, cmac_tmp + 16,
           layout.nullifier_invin_bytes);

    /* Instance: root | scope | T. */
    instance = calloc(layout.instance_bytes, 1);
    memcpy(instance + layout.membership.inst_root_off, root, W);
    memcpy(instance + layout.inst_scope_off, scope, scope_bytes);
    memcpy(instance + layout.inst_t_off, t_tag, 16);

    check("nullifier: correct (sk, scope, T) eval == 1",
          eval_circuit(c, witness, instance) == 1);

    /* Wrong T: flip a published-nullifier byte. */
    instance[layout.inst_t_off] ^= 0x01;
    check("nullifier: wrong T eval == 0",
          eval_circuit(c, witness, instance) == 0);
    instance[layout.inst_t_off] ^= 0x01;

    /* Wrong sk: flip an sk witness byte (breaks both the leaf and T). */
    witness[layout.membership.sk_off] ^= 0x01;
    check("nullifier: wrong sk eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[layout.membership.sk_off] ^= 0x01;

    free(witness);
    free(instance);
    free(cmac_tmp);
    voleith_gf8_circuit_free(c);
}

/*
 * Build the wide-nullifier KDF FixedInputData into out (must hold
 * VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + scope_bytes + 4 bytes):
 *   Label || 0x00 || scope || [L]_2 (L in bits, 32-bit big-endian).
 * Returns the byte length written.
 */
static size_t
build_nullifier_fixed_input(const uint8_t *scope, size_t scope_bytes,
                            size_t l_bits, uint8_t *out)
{
    size_t p = 0;

    memcpy(out + p, VOLEITH_RS_NULLIFIER_KDF_LABEL,
           VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES);
    p += VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES;
    out[p++] = 0x00;
    memcpy(out + p, scope, scope_bytes);
    p += scope_bytes;
    out[p++] = (uint8_t)((l_bits >> 24) & 0xFF);
    out[p++] = (uint8_t)((l_bits >> 16) & 0xFF);
    out[p++] = (uint8_t)((l_bits >> 8) & 0xFF);
    out[p++] = (uint8_t)(l_bits & 0xFF);
    return p;
}

/*
 * 256-bit nullifier over a 2^256-CR tree (grostl512_fixed): the nullifier
 * widens to 32 bytes and is computed in-circuit by SP 800-108 KDF-CTR-CMAC
 * (L = 256).  Verifies the width derivation, the in-circuit binding, a
 * pinned KAT on T (independent Python AES-CMAC oracle), linkability, and
 * the wrong-T / wrong-sk negatives.
 */
static void
test_rs_nullifier_wide(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t layout;
    voleith_gf8_circuit_t *c;
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl512_fixed;
    const size_t depth_m = 2;
    const size_t n_members = 4;
    const size_t W = 64; /* grostl512_fixed node_bytes */
    const size_t sk_bytes = 32;
    const size_t scope_bytes = 12;
    const size_t t_bytes = 32;
    /* Pinned by tools (Python `cryptography` AES-CMAC), see ticket 5:
     * KDF-CTR-CMAC(sk=0x40.., FixedInput=Label||0x00||scope=0x90..||[256]),
     * L = 256. */
    static const uint8_t kat_T[32] = {
        0x55, 0xe8, 0x2b, 0x99, 0xbf, 0x6d, 0xf3, 0xbc, 0xe3, 0x99, 0x0b,
        0x4c, 0x2e, 0xd8, 0xd4, 0xa4, 0xbe, 0x2b, 0x4a, 0x88, 0x2f, 0x76,
        0x21, 0x2a, 0xfb, 0x2c, 0x8b, 0x47, 0x76, 0xb4, 0x35, 0x7d};
    uint8_t sks[4 * 32];
    uint8_t root[64];
    uint8_t siblings_storage[4 * 2 * 64];
    voleith_rs_path_t paths[4];
    voleith_rs_path_t path;
    uint8_t scope[12];
    uint8_t scope2[12];
    uint8_t fixed_input[VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + 12 + 4];
    uint8_t fixed_input2[VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + 12 + 4];
    uint8_t t_tag[32];
    uint8_t t_tag2[32];
    uint8_t *witness;
    uint8_t *instance;
    uint8_t *kdf_tmp;
    size_t fi_bytes;
    size_t kdf_buf;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.scope_bytes = scope_bytes;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < scope_bytes; i++) {
        scope[i] = (uint8_t)(0x90 + i);
        scope2[i] = (uint8_t)(0xA0 + i);
    }

    check("nullifier-wide: width derives to 32 from 256-bit-CR tree",
          voleith_rs_nullifier_bytes(&cfg) == t_bytes);

    c = voleith_gf8_circuit_new();
    check("nullifier-wide: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &layout) == 0);

    fi_bytes = build_nullifier_fixed_input(scope, scope_bytes, t_bytes * 8u,
                                           fixed_input);
    check("nullifier-wide: T instance is 32 bytes", layout.inst_t_bytes == 32);
    check("nullifier-wide: invin bytes match KDF formula",
          layout.nullifier_invin_bytes ==
              kdf_ctr_cmac_gf8_witness_bytes(sk_bytes, t_bytes, fi_bytes) -
                  sk_bytes);

    /* Ring + signer path (index 0), via the superset builder + packer so
     * the leaf model matches the superset circuit (rs_leaf fixed-block
     * padding, which the V1 owf-leaf packer does not reproduce for a
     * fixed-input OWF like grostl512). */
    MUST_OK_FP(voleith_rs_ring_build(&cfg, sks, NULL, n_members, root, paths,
                                     siblings_storage));
    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    path.scope = scope;

    witness = calloc(layout.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_pack_witness(&cfg, &layout, sks, NULL, &path, NULL,
                                       NULL, witness));

    /* Independently recompute T for the instance and the KAT. */
    kdf_buf = kdf_ctr_cmac_gf8_witness_bytes(sk_bytes, t_bytes, fi_bytes);
    kdf_tmp = calloc(kdf_buf, 1);
    MUST_OK_FP(kdf_ctr_cmac_gf8_build_witness(
        sks, sk_bytes, fixed_input, fi_bytes, t_bytes, kdf_tmp, t_tag));

    /* KAT: T matches the independent oracle (freezes the FixedInputData
     * layout and the L = 256 two-iteration construction). */
    check("nullifier-wide: T matches pinned KAT",
          memcmp(t_tag, kat_T, 32) == 0);

    /* Linkability: a different scope yields a different T. */
    build_nullifier_fixed_input(scope2, scope_bytes, t_bytes * 8u,
                                fixed_input2);
    MUST_OK_FP(kdf_ctr_cmac_gf8_build_witness(
        sks, sk_bytes, fixed_input2, fi_bytes, t_bytes, kdf_tmp, t_tag2));
    check("nullifier-wide: different scope -> different T",
          memcmp(t_tag, t_tag2, 32) != 0);

    /* Instance: root | scope | T. */
    instance = calloc(layout.instance_bytes, 1);
    memcpy(instance + layout.membership.inst_root_off, root, W);
    memcpy(instance + layout.inst_scope_off, scope, scope_bytes);
    memcpy(instance + layout.inst_t_off, t_tag, t_bytes);

    check("nullifier-wide: correct (sk, scope, T) eval == 1",
          eval_circuit(c, witness, instance) == 1);

    instance[layout.inst_t_off] ^= 0x01;
    check("nullifier-wide: wrong T eval == 0",
          eval_circuit(c, witness, instance) == 0);
    instance[layout.inst_t_off] ^= 0x01;

    witness[layout.membership.sk_off] ^= 0x01;
    check("nullifier-wide: wrong sk eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[layout.membership.sk_off] ^= 0x01;

    free(witness);
    free(instance);
    free(kdf_tmp);
    voleith_gf8_circuit_free(c);
}

/* Disabled nullifier leaves the layout V1-identical. */
static void
test_rs_nullifier_disabled_matches_v1(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t super;
    voleith_rs_membership_layout_t base;
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;

    MUST_OK_FP(voleith_rs_build_circuit(c1, &cfg, &super));
    MUST_OK_FP(voleith_rs_membership_build_circuit(c2, &cfg.membership, &base));

    check("disabled nullifier: witness layout matches V1",
          super.membership.sk_off == base.sk_off &&
              super.membership.dirs_off == base.dirs_off &&
              super.membership.siblings_off == base.siblings_off &&
              super.membership.owf_invin_off == base.owf_invin_off &&
              super.membership.path_invin_off == base.path_invin_off &&
              super.witness_bytes == base.witness_bytes &&
              super.instance_bytes == base.instance_bytes);
    check("disabled nullifier: module fields zero",
          super.nullifier_invin_bytes == 0 && super.inst_scope_bytes == 0 &&
              super.inst_t_bytes == 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * V2.SPENT: spent-set non-membership on T.
 * ================================================================ */

#define SPENT_VALUE_BYTES 16u
#define SPENT_INDEX_BYTES 8u /* = VOLEITH_RSV1_REV_INDEX_BYTES */

/* 16-byte value with MSB (byte 15, the LE high byte) = msb, rest zero. */
static void
spent_msb_value(uint8_t r[SPENT_VALUE_BYTES], uint8_t msb)
{
    memset(r, 0, SPENT_VALUE_BYTES);
    r[SPENT_VALUE_BYTES - 1] = msb;
}

static void
spent_le_index(uint8_t r[SPENT_INDEX_BYTES], uint64_t v)
{
    for (size_t i = 0; i < SPENT_INDEX_BYTES; i++)
        r[i] = (uint8_t)(v >> (8 * i));
}

/* Fill the spent-set IMT witness section (leaf inv_in + per-level inode
 * inv_in), mirroring the revocation walk in
 * voleith_rs_membership_pack_witness. */
static void
pack_imt_branch(const voleith_node_hash_vt *vt, const uint8_t *low_value,
                const uint8_t *low_next, const uint8_t *next_index,
                size_t value_bytes, size_t adj_idx, const uint8_t *siblings,
                size_t depth, uint8_t *leaf_invin_out, uint8_t *path_invin_out)
{
    size_t W = vt->node_bytes;
    size_t per = vt->inode_invin_bytes();
    size_t ld_bytes = 2 * value_bytes + SPENT_INDEX_BYTES;
    uint8_t leaf_data[2 * VOLEITH_RS_NULLIFIER_MAX_BYTES + SPENT_INDEX_BYTES];
    uint8_t current[64], next[64];

    memcpy(leaf_data, low_value, value_bytes);
    memcpy(leaf_data + value_bytes, low_next, value_bytes);
    memcpy(leaf_data + 2 * value_bytes, next_index, SPENT_INDEX_BYTES);

    MUST_OK_FP(vt->leaf_build_witness(leaf_data, ld_bytes, leaf_invin_out));
    MUST_OK_FP(vt->leaf_hash(leaf_data, ld_bytes, current));

    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = (uint8_t)((adj_idx >> k) & 1u);
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK_FP(vt->inode_build_witness(L, R, path_invin_out + k * per));
        MUST_OK_FP(vt->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
}

static void
test_rs_spent(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t layout;
    voleith_gf8_circuit_t *c;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t depth_s = 2;
    const size_t n_spent = 4; /* 2^depth_s */
    const size_t W = 16;
    const size_t scope_bytes = 12;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t siblings_storage[4 * 2 * 16];
    voleith_rs_membership_path_t paths[4];
    uint8_t scope[12];
    uint8_t t_tag[16];
    uint8_t *cmac_tmp;
    size_t cmac_buf;
    uint8_t vals[4][SPENT_VALUE_BYTES];
    uint8_t nexts[4][SPENT_VALUE_BYTES];
    uint8_t idxs[4][SPENT_INDEX_BYTES];
    voleith_imt_record_t imt[4];
    uint8_t spent_root[16];
    uint8_t spent_siblings[2 * 16];
    size_t adj_idx;
    uint8_t *witness;
    uint8_t *instance;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.scope_bytes = scope_bytes;
    cfg.depth_s = depth_s;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90 + i);

    c = voleith_gf8_circuit_new();
    check("spent: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &layout) == 0);
    check("spent: depth_s recorded", layout.depth_s == depth_s);
    check("spent: spent value width is 16", layout.spent_low_value_bytes == 16);

    MUST_OK_FP(voleith_rsv1_ring_build(&cfg.membership, sks, 4, root, paths,
                                       siblings_storage));

    cmac_buf = aes_cmac_gf8_witness_bytes(16, scope_bytes);
    cmac_tmp = calloc(cmac_buf, 1);
    aes_cmac_gf8_build_witness(sks, 16, scope, scope_bytes, cmac_tmp, t_tag);

    /* Spent set: 4 records partitioned by the LE high byte, straddling
     * the whole 128-bit range (rec[i] covers [0x40*i, 0x40*(i+1)) in the
     * high byte, with rec[3] wrapping to all-0xFF). */
    spent_msb_value(vals[0], 0x00);
    spent_msb_value(nexts[0], 0x40);
    spent_le_index(idxs[0], 1);
    spent_msb_value(vals[1], 0x40);
    spent_msb_value(nexts[1], 0x80);
    spent_le_index(idxs[1], 2);
    spent_msb_value(vals[2], 0x80);
    spent_msb_value(nexts[2], 0xC0);
    spent_le_index(idxs[2], 3);
    spent_msb_value(vals[3], 0xC0);
    memset(nexts[3], 0xFF, SPENT_VALUE_BYTES);
    spent_le_index(idxs[3], 0);
    for (size_t i = 0; i < n_spent; i++) {
        imt[i].value = vals[i];
        imt[i].next_value = nexts[i];
        imt[i].next_index = idxs[i];
    }

    MUST_OK_FP(voleith_imt_vt_build(vt, imt, n_spent, SPENT_VALUE_BYTES,
                                    SPENT_INDEX_BYTES, spent_root));

    /* T is overwhelmingly a non-member (CMAC tag equal to a record value
     * is ~2^-128); the canonical sks/scope land it inside an interval. */
    MUST_OK_FP(voleith_imt_vt_lookup_nonmember(
        vt, imt, n_spent, SPENT_VALUE_BYTES, SPENT_INDEX_BYTES, t_tag, &adj_idx,
        spent_siblings));

    witness = calloc(layout.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_membership_pack_witness(
        &cfg.membership, &layout.membership, sks, &paths[0], NULL, witness));

    /* nullifier CMAC inv_in (key prefix stripped). */
    memcpy(witness + layout.nullifier_invin_off, cmac_tmp + 16,
           layout.nullifier_invin_bytes);

    /* spent-set adjacent record + dirs + siblings + inv_ins. */
    memcpy(witness + layout.spent_low_value_off, vals[adj_idx],
           SPENT_VALUE_BYTES);
    memcpy(witness + layout.spent_low_next_off, nexts[adj_idx],
           SPENT_VALUE_BYTES);
    memcpy(witness + layout.spent_next_index_off, idxs[adj_idx],
           SPENT_INDEX_BYTES);
    for (size_t k = 0; k < depth_s; k++)
        witness[layout.spent_dirs_off + k] = (uint8_t)((adj_idx >> k) & 1u);
    memcpy(witness + layout.spent_siblings_off, spent_siblings, depth_s * W);
    pack_imt_branch(vt, vals[adj_idx], nexts[adj_idx], idxs[adj_idx],
                    SPENT_VALUE_BYTES, adj_idx, spent_siblings, depth_s,
                    witness + layout.spent_leaf_invin_off,
                    witness + layout.spent_path_invin_off);

    instance = calloc(layout.instance_bytes, 1);
    memcpy(instance + layout.membership.inst_root_off, root, W);
    memcpy(instance + layout.inst_scope_off, scope, scope_bytes);
    memcpy(instance + layout.inst_t_off, t_tag, 16);
    memcpy(instance + layout.inst_spent_root_off, spent_root, W);

    check("spent: T not in set eval == 1",
          eval_circuit(c, witness, instance) == 1);

    /* Tamper spent_root. */
    instance[layout.inst_spent_root_off] ^= 0x01;
    check("spent: tampered spent_root eval == 0",
          eval_circuit(c, witness, instance) == 0);
    instance[layout.inst_spent_root_off] ^= 0x01;

    /* Wrong adjacent record: corrupt low_value so it no longer straddles
     * T (assert_lt / leaf hash mismatch). */
    witness[layout.spent_low_value_off] ^= 0x01;
    check("spent: wrong adjacent record eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[layout.spent_low_value_off] ^= 0x01;

    /* T in set fails up-front: lookup on an existing record value is
     * rejected (cannot prove non-membership of a member). */
    check("spent: member target rejected by lookup",
          voleith_imt_vt_lookup_nonmember(vt, imt, n_spent, SPENT_VALUE_BYTES,
                                          SPENT_INDEX_BYTES, vals[1], &adj_idx,
                                          spent_siblings) == -1);

    free(witness);
    free(instance);
    free(cmac_tmp);
    voleith_gf8_circuit_free(c);
}

/*
 * Spent-set non-membership on the 32-byte (wide) nullifier over a 2^256-CR
 * tree: the IMT value width follows the nullifier width, so records, the
 * lookup, and the leaf preimage all span 32 bytes.
 */
static void
test_rs_spent_wide(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t layout;
    voleith_gf8_circuit_t *c;
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl512_fixed;
    const size_t depth_m = 2;
    const size_t depth_s = 2;
    const size_t n_spent = 4;
    const size_t W = 64; /* grostl512_fixed node_bytes */
    const size_t TV = 32;
    const size_t sk_bytes = 32;
    const size_t scope_bytes = 12;
    uint8_t sks[4 * 32];
    uint8_t root[64];
    uint8_t siblings_storage[4 * 2 * 64];
    voleith_rs_path_t paths[4];
    voleith_rs_path_t path;
    uint8_t scope[12];
    uint8_t fixed_input[VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + 12 + 4];
    uint8_t t_tag[32];
    uint8_t *kdf_tmp;
    size_t fi_bytes;
    size_t kdf_buf;
    uint8_t vals[4][32];
    uint8_t nexts[4][32];
    uint8_t idxs[4][SPENT_INDEX_BYTES];
    voleith_imt_record_t imt[4];
    uint8_t spent_root[64];
    uint8_t spent_siblings[2 * 64];
    size_t adj_idx;
    uint8_t *witness;
    uint8_t *instance;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.scope_bytes = scope_bytes;
    cfg.depth_s = depth_s;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90 + i);

    c = voleith_gf8_circuit_new();
    check("spent-wide: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &layout) == 0);
    check("spent-wide: spent value width is 32",
          layout.spent_low_value_bytes == TV);

    MUST_OK_FP(voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths,
                                     siblings_storage));

    /* Wide nullifier T = KDF-CTR-CMAC(sk, scope), 32 bytes. */
    fi_bytes =
        build_nullifier_fixed_input(scope, scope_bytes, TV * 8u, fixed_input);
    kdf_buf = kdf_ctr_cmac_gf8_witness_bytes(sk_bytes, TV, fi_bytes);
    kdf_tmp = calloc(kdf_buf, 1);
    MUST_OK_FP(kdf_ctr_cmac_gf8_build_witness(sks, sk_bytes, fixed_input,
                                              fi_bytes, TV, kdf_tmp, t_tag));

    /* 4 IMT records partition the 256-bit range by the LE high byte
     * (byte 31), straddling all of it (rec[3] wraps to all-0xFF next). */
    for (size_t i = 0; i < n_spent; i++) {
        memset(vals[i], 0, TV);
        memset(nexts[i], 0, TV);
        vals[i][TV - 1] = (uint8_t)(0x40 * i);
        if (i == n_spent - 1)
            memset(nexts[i], 0xFF, TV);
        else
            nexts[i][TV - 1] = (uint8_t)(0x40 * (i + 1));
        memset(idxs[i], 0, SPENT_INDEX_BYTES);
        idxs[i][0] = (uint8_t)((i + 1) % n_spent);
        imt[i].value = vals[i];
        imt[i].next_value = nexts[i];
        imt[i].next_index = idxs[i];
    }

    MUST_OK_FP(voleith_imt_vt_build(vt, imt, n_spent, TV, SPENT_INDEX_BYTES,
                                    spent_root));
    MUST_OK_FP(voleith_imt_vt_lookup_nonmember(vt, imt, n_spent, TV,
                                               SPENT_INDEX_BYTES, t_tag,
                                               &adj_idx, spent_siblings));

    /* Pack via the superset packer (consistent leaf model for grostl512). */
    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    path.scope = scope;
    path.spent_adj_leaf_index = adj_idx;
    path.spent_siblings = spent_siblings;
    path.spent_low_value = vals[adj_idx];
    path.spent_low_next = nexts[adj_idx];
    path.spent_next_index = idxs[adj_idx];

    witness = calloc(layout.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_pack_witness(&cfg, &layout, sks, NULL, &path, NULL,
                                       NULL, witness));

    instance = calloc(layout.instance_bytes, 1);
    memcpy(instance + layout.membership.inst_root_off, root, W);
    memcpy(instance + layout.inst_scope_off, scope, scope_bytes);
    memcpy(instance + layout.inst_t_off, t_tag, TV);
    memcpy(instance + layout.inst_spent_root_off, spent_root, W);

    check("spent-wide: wide T not in set eval == 1",
          eval_circuit(c, witness, instance) == 1);

    instance[layout.inst_spent_root_off] ^= 0x01;
    check("spent-wide: tampered spent_root eval == 0",
          eval_circuit(c, witness, instance) == 0);
    instance[layout.inst_spent_root_off] ^= 0x01;

    witness[layout.spent_low_value_off] ^= 0x01;
    check("spent-wide: wrong adjacent record eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[layout.spent_low_value_off] ^= 0x01;

    free(witness);
    free(instance);
    free(kdf_tmp);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * V3.CIRC: extended leaf + attribute predicates.
 * ================================================================ */

/* Membership path inv_in walk from a leaf node (mirrors the path part of
 * voleith_rs_membership_pack_witness). */
static void
pack_path_invin(const voleith_node_hash_vt *vt, const uint8_t *leaf_node,
                const uint8_t *siblings, size_t leaf_index, size_t depth,
                uint8_t *out)
{
    size_t W = vt->node_bytes;
    size_t per = vt->inode_invin_bytes();
    uint8_t current[64], next[64];

    memcpy(current, leaf_node, W);
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = (uint8_t)((leaf_index >> k) & 1u);
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK_FP(vt->inode_build_witness(L, R, out + k * per));
        MUST_OK_FP(vt->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
}

/* Build a depth-2 ring whose signer (index 0) leaf is OWF(sk0 || attrs),
 * pack the full witness + instance, and eval.  If flip != 0, corrupt the
 * first attribute witness byte after packing (so it no longer matches the
 * leaf the circuit recomputes) to exercise attribute-to-leaf binding. */
static int
attr_full_eval(const voleith_node_hash_vt *vt, voleith_gf8_circuit_t *c,
               const voleith_rs_layout_t *L, size_t sk_bytes, size_t depth_m,
               const uint8_t *sk0, const uint8_t *attrs, size_t attr_bytes,
               const uint8_t *bounds, size_t bounds_bytes, int flip)
{
    size_t W = vt->node_bytes;
    size_t n = (size_t)1u << depth_m;
    uint8_t *leaf_nodes = calloc(n, W);
    uint8_t root[64];
    uint8_t *siblings = calloc(depth_m, W);
    uint8_t leaf0[64];
    uint8_t *wit = calloc(L->witness_bytes, 1);
    uint8_t *inst = calloc(L->instance_bytes, 1);
    int rc;

    for (size_t i = 0; i < n; i++) {
        uint8_t ski[64];
        memset(ski, 0x55, sk_bytes);
        if (i == 0)
            memcpy(ski, sk0, sk_bytes);
        else
            ski[0] = (uint8_t)(0xE0 + i); /* distinct filler members */
        MUST_OK_FP(rs_leaf_gf8_hash(vt, ski, sk_bytes, attrs, attr_bytes,
                                    leaf_nodes + i * W));
    }
    MUST_OK_FP(voleith_merkle_vt_build(vt, leaf_nodes, n, root));
    MUST_OK_FP(voleith_merkle_vt_compute_path(vt, leaf_nodes, n, 0, siblings));

    memcpy(wit + L->membership.sk_off, sk0, sk_bytes);
    memcpy(wit + L->attr_off, attrs, attr_bytes);
    /* leaf_index 0: all dir bits zero (calloc already). */
    memcpy(wit + L->membership.siblings_off, siblings, depth_m * W);
    MUST_OK_FP(rs_leaf_gf8_build_witness(vt, sk0, sk_bytes, attrs, attr_bytes,
                                         wit + L->membership.owf_invin_off));
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sk0, sk_bytes, attrs, attr_bytes, leaf0));
    pack_path_invin(vt, leaf0, siblings, 0, depth_m,
                    wit + L->membership.path_invin_off);

    if (flip)
        wit[L->attr_off] ^= 0x01;

    memcpy(inst + L->membership.inst_root_off, root, W);
    memcpy(inst + L->inst_bounds_off, bounds, bounds_bytes);

    rc = eval_circuit(c, wit, inst);

    free(leaf_nodes);
    free(siblings);
    free(wit);
    free(inst);
    return rc;
}

static void
test_rs_attributes(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t sk_bytes = 16;
    const size_t depth_m = 2;
    /* field 0: RANGE, 4 bytes; field 1: EQ, 2 bytes. */
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
        {2, VOLEITH_RS_ATTR_PRED_EQ},
    };
    voleith_rs_attr_schema_t schema = {fields, 2};
    voleith_rs_config_t cfg;
    voleith_rs_config_t base_cfg;
    voleith_rs_layout_t L;
    voleith_rs_layout_t Lbase;
    voleith_gf8_circuit_t *c;
    voleith_gf8_circuit_t *cbase;
    uint8_t sk0[16];
    /* attrs: field0 = 24 (LE), field1 = {0xAB, 0xCD}. */
    uint8_t attrs_ok[6] = {24, 0, 0, 0, 0xAB, 0xCD};
    uint8_t attrs_bad[6] = {64, 0, 0, 0, 0xAB, 0xCD}; /* field0 out of range */
    /* bounds: low0(4)=16, high0(4)=32, target1(2)={0xAB,0xCD}. */
    uint8_t bounds[10] = {16, 0, 0, 0, 32, 0, 0, 0, 0xAB, 0xCD};
    size_t delta;

    for (size_t i = 0; i < sk_bytes; i++)
        sk0[i] = (uint8_t)(0x21 + i);

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.attr_schema = &schema;

    c = voleith_gf8_circuit_new();
    check("attr: build_circuit ok", voleith_rs_build_circuit(c, &cfg, &L) == 0);
    check("attr: attr_bytes == 6", L.attr_bytes == 6);
    check("attr: inst_bounds_bytes == 10 (RANGE 8 + EQ 2)",
          L.inst_bounds_bytes == 10);

    /* Predicate gates add NO witnesses: the only witness growth over the
     * no-attribute baseline is the attribute payload + the widened leaf
     * inv_in. */
    base_cfg = cfg;
    base_cfg.attr_schema = NULL;
    cbase = voleith_gf8_circuit_new();
    MUST_OK_FP(voleith_rs_build_circuit(cbase, &base_cfg, &Lbase));
    delta = vt->leaf_invin_bytes(sk_bytes + 6) - vt->leaf_invin_bytes(sk_bytes);
    check("attr: predicate adds no witnesses",
          L.witness_bytes == Lbase.witness_bytes + 6 + delta);

    check("attr: satisfying attrs + leaf eval == 1",
          attr_full_eval(vt, c, &L, sk_bytes, depth_m, sk0, attrs_ok, 6, bounds,
                         10, 0) == 1);
    check("attr: out-of-range field eval == 0",
          attr_full_eval(vt, c, &L, sk_bytes, depth_m, sk0, attrs_bad, 6,
                         bounds, 10, 0) == 0);
    check("attr: attribute not bound into leaf eval == 0",
          attr_full_eval(vt, c, &L, sk_bytes, depth_m, sk0, attrs_ok, 6, bounds,
                         10, 1) == 0);

    voleith_gf8_circuit_free(c);
    voleith_gf8_circuit_free(cbase);
}

/* ================================================================
 * V4.CIRC: claimable commitment.
 * ================================================================ */
static void
test_rs_commitment(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_layout_t layout;
    voleith_gf8_circuit_t *c;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t W = 16;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t siblings_storage[4 * 2 * 16];
    voleith_rs_membership_path_t paths[4];
    uint8_t id[16];
    uint8_t rand[16];
    uint8_t idrand[32];
    uint8_t C[16];
    uint8_t *witness;
    uint8_t *instance;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < 16; i++) {
        id[i] = (uint8_t)(0xA0 + i);
        rand[i] = (uint8_t)(0x5C - i);
    }
    memcpy(idrand, id, 16);
    memcpy(idrand + 16, rand, 16);

    c = voleith_gf8_circuit_new();
    check("commit: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &layout) == 0);
    check("commit: C instance is node_bytes", layout.inst_commit_bytes == W);
    check("commit: rand offset follows id",
          layout.commit_rand_off == layout.commit_id_off + 16);

    MUST_OK_FP(voleith_rsv1_ring_build(&cfg.membership, sks, 4, root, paths,
                                       siblings_storage));

    /* C = tree_vt->leaf_hash(id || rand). */
    MUST_OK_FP(vt->leaf_hash(idrand, 32, C));

    witness = calloc(layout.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_membership_pack_witness(
        &cfg.membership, &layout.membership, sks, &paths[0], NULL, witness));
    memcpy(witness + layout.commit_id_off, id, 16);
    memcpy(witness + layout.commit_rand_off, rand, 16);
    MUST_OK_FP(
        vt->leaf_build_witness(idrand, 32, witness + layout.commit_invin_off));

    instance = calloc(layout.instance_bytes, 1);
    memcpy(instance + layout.membership.inst_root_off, root, W);
    memcpy(instance + layout.inst_commit_off, C, W);

    check("commit: correct (id, rand, C) eval == 1",
          eval_circuit(c, witness, instance) == 1);

    /* Wrong C: tamper the public commitment. */
    instance[layout.inst_commit_off] ^= 0x01;
    check("commit: wrong C eval == 0", eval_circuit(c, witness, instance) == 0);
    instance[layout.inst_commit_off] ^= 0x01;

    /* Wrong id: tamper the witness handle (commitment no longer opens). */
    witness[layout.commit_id_off] ^= 0x01;
    check("commit: wrong id eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[layout.commit_id_off] ^= 0x01;

    free(witness);
    free(instance);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * RS.PACK: unified superset packer + ring builder.
 * ================================================================ */

/* Build a 4-record MSB-partitioned IMT (value 16B, index 8B), compute its
 * root, and look up the non-member adjacent record for `target`. */
static void
build_imt4(const voleith_node_hash_vt *vt, uint8_t vals[4][16],
           uint8_t nexts[4][16], uint8_t idxs[4][8], uint8_t root[16],
           const uint8_t *target, size_t *adj_idx, uint8_t siblings[32])
{
    voleith_imt_record_t imt[4];

    spent_msb_value(vals[0], 0x00);
    spent_msb_value(nexts[0], 0x40);
    spent_le_index(idxs[0], 1);
    spent_msb_value(vals[1], 0x40);
    spent_msb_value(nexts[1], 0x80);
    spent_le_index(idxs[1], 2);
    spent_msb_value(vals[2], 0x80);
    spent_msb_value(nexts[2], 0xC0);
    spent_le_index(idxs[2], 3);
    spent_msb_value(vals[3], 0xC0);
    memset(nexts[3], 0xFF, 16);
    spent_le_index(idxs[3], 0);
    for (size_t i = 0; i < 4; i++) {
        imt[i].value = vals[i];
        imt[i].next_value = nexts[i];
        imt[i].next_index = idxs[i];
    }

    MUST_OK_FP(voleith_imt_vt_build(vt, imt, 4, 16, 8, root));
    MUST_OK_FP(voleith_imt_vt_lookup_nonmember(vt, imt, 4, 16, 8, target,
                                               adj_idx, siblings));
}

/*
 * Dedicated revocation negative test (V1 revocation branch).
 *
 * The revocation IMT proves the signer's membership leaf is NOT in the
 * revoked set.  This exercises the branch directly: a non-revoked signer
 * proves non-membership and the circuit accepts (eval == 1, with rev_root
 * and rev-witness tampers rejected), and a genuinely revoked signer (whose
 * leaf is a record value in the revocation set) cannot even produce a
 * lookup witness: voleith_imt_vt_lookup_nonmember returns -1.  Mirrors the
 * spent-set "member target rejected by lookup" assertion in test_rs_spent.
 */
static void
test_rs_revoked(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t W = 16;
    const size_t depth_m = 2;
    const size_t depth_r = 2;
    voleith_rs_config_t cfg;
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c;
    voleith_rs_path_t paths[4];
    voleith_rs_path_t path;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t sib_storage[4 * 2 * 16];
    uint8_t leaf0[16];
    /* Non-revoked revocation IMT (target = signer leaf, a non-member). */
    uint8_t rvals[4][16], rnexts[4][16], ridxs[4][8], rev_root[16], rev_sib[32];
    size_t rev_adj;
    /* Revoked revocation IMT (record value == signer leaf). */
    uint8_t zerov[16], ffv[16];
    uint8_t qvals[4][16], qnexts[4][16], qidxs[4][8], q_root[16], q_sib[32];
    voleith_imt_record_t qimt[4];
    size_t q_adj;
    uint8_t *witness, *instance;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = depth_m;
    cfg.membership.depth_r = depth_r;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);

    c = voleith_gf8_circuit_new();
    check("revoked: build_circuit ok",
          voleith_rs_build_circuit(c, &cfg, &L) == 0);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths, sib_storage));
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sks, 16, NULL, 0, leaf0));

    /* Non-revoked: signer leaf straddles an interval -> provable. */
    build_imt4(vt, rvals, rnexts, ridxs, rev_root, leaf0, &rev_adj, rev_sib);

    path = paths[0];
    path.membership.rev_adj_leaf_index = rev_adj;
    path.membership.rev_siblings = rev_sib;
    path.membership.rev_low_value = rvals[rev_adj];
    path.membership.rev_low_next = rnexts[rev_adj];
    path.membership.rev_next_index = ridxs[rev_adj];

    witness = calloc(L.witness_bytes, 1);
    MUST_OK_FP(voleith_rs_pack_witness(&cfg, &L, sks, NULL, &path, NULL, NULL,
                                       witness));

    instance = calloc(L.instance_bytes, 1);
    memcpy(instance + L.membership.inst_root_off, root, W);
    memcpy(instance + L.membership.inst_rev_root_off, rev_root, W);

    check("revoked: non-revoked signer eval == 1",
          eval_circuit(c, witness, instance) == 1);

    /* Tamper the public revocation root. */
    instance[L.membership.inst_rev_root_off] ^= 0x01;
    check("revoked: tampered rev_root eval == 0",
          eval_circuit(c, witness, instance) == 0);
    instance[L.membership.inst_rev_root_off] ^= 0x01;

    /* Tamper the adjacent record so it no longer straddles the leaf. */
    witness[L.membership.rev_low_value_off] ^= 0x01;
    check("revoked: wrong adjacent record eval == 0",
          eval_circuit(c, witness, instance) == 0);
    witness[L.membership.rev_low_value_off] ^= 0x01;

    /*
     * Revoked signer: build a valid IMT that genuinely contains leaf0 as a
     * record value (records 1..3 degenerate at leaf0, bracketed by the 0
     * and all-0xFF sentinels).  Non-membership of a present value is
     * unprovable: the lookup fails up front, so no witness can be produced.
     */
    memset(zerov, 0, 16);
    memset(ffv, 0xFF, 16);
    memcpy(qvals[0], zerov, 16);
    memcpy(qnexts[0], leaf0, 16);
    spent_le_index(qidxs[0], 1);
    memcpy(qvals[1], leaf0, 16);
    memcpy(qnexts[1], leaf0, 16);
    spent_le_index(qidxs[1], 2);
    memcpy(qvals[2], leaf0, 16);
    memcpy(qnexts[2], leaf0, 16);
    spent_le_index(qidxs[2], 3);
    memcpy(qvals[3], leaf0, 16);
    memcpy(qnexts[3], ffv, 16);
    spent_le_index(qidxs[3], 0);
    for (size_t i = 0; i < 4; i++) {
        qimt[i].value = qvals[i];
        qimt[i].next_value = qnexts[i];
        qimt[i].next_index = qidxs[i];
    }
    MUST_OK_FP(voleith_imt_vt_build(vt, qimt, 4, 16, 8, q_root));
    check("revoked: revoked member rejected by lookup",
          voleith_imt_vt_lookup_nonmember(vt, qimt, 4, 16, 8, leaf0, &q_adj,
                                          q_sib) == -1);

    free(witness);
    free(instance);
    voleith_gf8_circuit_free(c);
}

static void
test_rs_pack_full(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t W = 16;
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c;
    uint8_t sks[4 * 16];
    uint8_t attrs[4 * 4];
    uint8_t root[16];
    uint8_t sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4];
    uint8_t id[16], rand[16], idrand[32], Ccommit[16];
    uint8_t scope[12], t_tag[16];
    uint8_t cmac_tmp[16 + 2 * 200];
    uint8_t bounds[8] = {10, 0, 0, 0, 50, 0, 0, 0};
    uint8_t leaf0[16];
    /* rev IMT (target = signer leaf node) and spent IMT (target = T). */
    uint8_t rvals[4][16], rnexts[4][16], ridxs[4][8], rev_root[16], rev_sib[32];
    uint8_t svals[4][16], snexts[4][16], sidxs[4][8], spent_root[16],
        spent_sib[32];
    size_t rev_adj, spent_adj;
    uint8_t *witness, *instance;
    voleith_rs_path_t path;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.membership.depth_r = 2;
    cfg.attr_schema = &schema;
    cfg.scope_bytes = 12;
    cfg.depth_s = 2;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    /* signer (member 0) attribute in [10, 50]; others arbitrary. */
    memset(attrs, 0, sizeof(attrs));
    attrs[0] = 20;
    for (size_t i = 1; i < 4; i++)
        attrs[i * 4] = (uint8_t)(5 + i);
    for (size_t i = 0; i < 16; i++) {
        id[i] = (uint8_t)(0xA0 + i);
        rand[i] = (uint8_t)(0x5C - i);
        scope[i % 12] = (uint8_t)(0x90 + (i % 12));
    }
    memcpy(idrand, id, 16);
    memcpy(idrand + 16, rand, 16);

    c = voleith_gf8_circuit_new();
    check("pack: build_circuit ok", voleith_rs_build_circuit(c, &cfg, &L) == 0);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, attrs, 4, root, paths, sib_storage));

    MUST_OK_FP(vt->leaf_hash(idrand, 32, Ccommit));
    aes_cmac_gf8_build_witness(sks, 16, scope, 12, cmac_tmp, t_tag);
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sks, 16, attrs, 4, leaf0));

    build_imt4(vt, rvals, rnexts, ridxs, rev_root, leaf0, &rev_adj, rev_sib);
    build_imt4(vt, svals, snexts, sidxs, spent_root, t_tag, &spent_adj,
               spent_sib);

    /* Assemble the prover path. */
    path = paths[0];
    path.membership.rev_adj_leaf_index = rev_adj;
    path.membership.rev_siblings = rev_sib;
    path.membership.rev_low_value = rvals[rev_adj];
    path.membership.rev_low_next = rnexts[rev_adj];
    path.membership.rev_next_index = ridxs[rev_adj];
    path.scope = scope;
    path.spent_adj_leaf_index = spent_adj;
    path.spent_siblings = spent_sib;
    path.spent_low_value = svals[spent_adj];
    path.spent_low_next = snexts[spent_adj];
    path.spent_next_index = sidxs[spent_adj];

    witness = calloc(L.witness_bytes, 1);
    check("pack: pack_witness ok",
          voleith_rs_pack_witness(&cfg, &L, sks, attrs, &path, id, rand,
                                  witness) == 0);

    instance = calloc(L.instance_bytes, 1);
    memcpy(instance + L.membership.inst_root_off, root, W);
    memcpy(instance + L.inst_commit_off, Ccommit, W);
    memcpy(instance + L.inst_scope_off, scope, 12);
    memcpy(instance + L.inst_t_off, t_tag, 16);
    memcpy(instance + L.inst_bounds_off, bounds, 8);
    memcpy(instance + L.membership.inst_rev_root_off, rev_root, W);
    memcpy(instance + L.inst_spent_root_off, spent_root, W);

    check("pack: full-stack packed witness eval == 1",
          eval_circuit(c, witness, instance) == 1);

    /* Single-bit tamper in each section yields 0. */
    struct {
        const char *name;
        uint8_t *buf;
        size_t off;
    } tamp[] = {
        {"sk", witness, L.membership.sk_off},
        {"attr", witness, L.attr_off},
        {"id", witness, L.commit_id_off},
        {"sibling", witness, L.membership.siblings_off},
        {"C", instance, L.inst_commit_off},
        {"T", instance, L.inst_t_off},
        {"rev_root", instance, L.membership.inst_rev_root_off},
        {"spent_root", instance, L.inst_spent_root_off},
    };
    for (size_t i = 0; i < sizeof(tamp) / sizeof(tamp[0]); i++) {
        char name[96];
        tamp[i].buf[tamp[i].off] ^= 0x01;
        snprintf(name, sizeof(name), "pack: tamper %s eval == 0", tamp[i].name);
        check(name, eval_circuit(c, witness, instance) == 0);
        tamp[i].buf[tamp[i].off] ^= 0x01;
    }

    free(witness);
    free(instance);
    voleith_gf8_circuit_free(c);
}

/* Ring-build paths validate for every member (membership-only config). */
static void
test_rs_ring_members(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const size_t W = 16;
    voleith_rs_config_t cfg;
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4];
    int all_ok = 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x11 + i);

    c = voleith_gf8_circuit_new();
    MUST_OK_FP(voleith_rs_build_circuit(c, &cfg, &L));
    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths, sib_storage));

    for (size_t m = 0; m < 4; m++) {
        uint8_t *witness = calloc(L.witness_bytes, 1);
        uint8_t *instance = calloc(L.instance_bytes, 1);
        MUST_OK_FP(voleith_rs_pack_witness(&cfg, &L, sks + m * 16, NULL,
                                           &paths[m], NULL, NULL, witness));
        memcpy(instance + L.membership.inst_root_off, root, W);
        if (eval_circuit(c, witness, instance) != 1)
            all_ok = 0;
        free(witness);
        free(instance);
    }
    check("ring_build: every member's packed path eval == 1", all_ok);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * RS.FS: composed fs_seed.
 * ================================================================ */

#define RS_FS_KAT_PINNED 1
static void
test_rs_fs(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
        {2, VOLEITH_RS_ATTR_PRED_EQ},
    };
    voleith_rs_attr_schema_t schema = {fields, 2};
    voleith_rs_config_t cfg;
    voleith_rs_public_t pub;
    uint8_t root[16], rev[16], C[16], scope[12], T[16], spent[16];
    uint8_t bounds[10] = {5, 0, 0, 0, 50, 0, 0, 0, 0xAB, 0xCD};
    const uint8_t m[] = "fs-seed";
    size_t m_len = sizeof(m) - 1;
    uint8_t seed[VOLEITH_RS_FS_SEED_BYTES];
    uint8_t seed2[VOLEITH_RS_FS_SEED_BYTES];
    static const uint8_t kat_expected[VOLEITH_RS_FS_SEED_BYTES] = {
        0xa9, 0x53, 0xbd, 0xfd, 0xff, 0x97, 0x9f, 0xe0,
        0xdc, 0x4b, 0xcd, 0x9b, 0x60, 0xa9, 0x2d, 0xa6};

    for (size_t i = 0; i < 16; i++) {
        root[i] = (uint8_t)(0x10 + i);
        rev[i] = (uint8_t)(0x20 + i);
        C[i] = (uint8_t)(0x30 + i);
        T[i] = (uint8_t)(0x50 + i);
        spent[i] = (uint8_t)(0x60 + i);
    }
    for (size_t i = 0; i < 12; i++)
        scope[i] = (uint8_t)(0x40 + i);

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;
    cfg.membership.depth_r = 4;
    cfg.attr_schema = &schema;
    cfg.scope_bytes = 12;
    cfg.depth_s = 5;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    pub.membership_root = root;
    pub.revocation_root = rev;
    pub.commitment = C;
    pub.scope = scope;
    pub.nullifier = T;
    pub.spent_root = spent;
    pub.bounds = bounds;
    pub.bounds_len = sizeof(bounds);

    check("fs: compute ok",
          voleith_rs_compute_fs_seed(&cfg, &pub, m, m_len, seed) == 0);
    check("fs: deterministic",
          voleith_rs_compute_fs_seed(&cfg, &pub, m, m_len, seed2) == 0 &&
              memcmp(seed, seed2, sizeof(seed)) == 0);

    /* Required-arg / gating rejections. */
    pub.membership_root = NULL;
    check("fs: NULL membership_root rejected",
          voleith_rs_compute_fs_seed(&cfg, &pub, m, m_len, seed2) == -1);
    pub.membership_root = root;
    pub.nullifier = NULL;
    check("fs: NULL nullifier rejected",
          voleith_rs_compute_fs_seed(&cfg, &pub, m, m_len, seed2) == -1);
    pub.nullifier = T;
    check("fs: m NULL with m_len > 0 rejected",
          voleith_rs_compute_fs_seed(&cfg, &pub, NULL, 1, seed2) == -1);

    /* Field binding: flipping any absorbed public input changes the seed. */
#define FS_FLIP(label, buf, idx)                                               \
    do {                                                                       \
        (buf)[idx] ^= 0x01;                                                    \
        MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, m_len, seed2));   \
        check("fs: " label " bound", memcmp(seed, seed2, sizeof(seed)) != 0);  \
        (buf)[idx] ^= 0x01;                                                    \
    } while (0)
    FS_FLIP("membership_root", root, 0);
    FS_FLIP("revocation_root", rev, 0);
    FS_FLIP("commitment C", C, 0);
    FS_FLIP("scope", scope, 0);
    FS_FLIP("nullifier T", T, 0);
    FS_FLIP("spent_root", spent, 0);
    FS_FLIP("bounds", bounds, 0);
#undef FS_FLIP

    /* Message binding. */
    {
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, bad_m, m_len, seed2));
        check("fs: message bound", memcmp(seed, seed2, sizeof(seed)) != 0);
    }

    printf("  RS.FS all-modules fs_seed:");
    for (size_t i = 0; i < sizeof(seed); i++)
        printf(" %02x", seed[i]);
    printf("\n");
    if (RS_FS_KAT_PINNED) {
        check("fs: KAT matches pinned constant",
              memcmp(seed, kat_expected, sizeof(seed)) == 0);
    } else {
        printf("  (KAT not yet pinned: copy the bytes above into "
               "kat_expected and set RS_FS_KAT_PINNED to 1)\n");
        (void)kat_expected;
    }
}

/* ================================================================
 * RS.SIGN: sign / verify.
 * ================================================================ */

static void
test_rs_sign_membership(void)
{
    voleith_rs_config_t cfg;
    voleith_params_t params = voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4];
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    const uint8_t m[] = "rs membership roundtrip";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x31 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths, sib_storage));
    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;

    check("sign: membership-only sign ok",
          voleith_rs_sign(&sig, &cfg, &params, sks, NULL, &path, &pub, m,
                          m_len) == 0);
    check("sign: membership-only verify accepts",
          voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == 0);

    {
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        check("sign: tampered m rejected",
              voleith_rs_verify(&sig, &cfg, &params, &pub, bad_m, m_len) == -1);
    }
    voleith_rs_sig_free(&sig);

    /* Wrong sk: member 1's sk against member 0's path/root fails at sign
     * (X-10: prove_v2 runs circuit_eval first). */
    check("sign: wrong sk rejected at sign",
          voleith_rs_sign(&sig, &cfg, &params, sks + 16, NULL, &path, &pub, m,
                          m_len) == -1);
    voleith_rs_sig_free(&sig);
}

/*
 * End-to-end sign / verify on a 2^256-CR tree, exercising the 32-byte
 * KDF-CTR-CMAC nullifier through the full pipeline: voleith_rs_pack_witness
 * (wide inv_in branch), voleith_rs_compute_fs_seed (T(32) absorb), and
 * rs_fill_instance (inst_t_bytes == 32).
 */
static void
test_rs_sign_wide_nullifier(void)
{
    voleith_rs_config_t cfg;
    voleith_params_t params = voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl512_fixed;
    const size_t sk_bytes = 32;
    const size_t scope_bytes = 12;
    uint8_t sks[2 * 32];
    uint8_t root[64];
    uint8_t sib_storage[2 * 1 * 64];
    voleith_rs_path_t paths[2];
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    uint8_t scope[12];
    uint8_t fixed_input[VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + 12 + 4];
    uint8_t t_tag[32];
    uint8_t *kdf_tmp;
    size_t fi_bytes;
    size_t kdf_buf;
    const uint8_t m[] = "rs wide nullifier roundtrip";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = 1;
    cfg.scope_bytes = scope_bytes;
    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 2, root, paths, sib_storage));

    /* Signer (index 0) nullifier T = KDF-CTR-CMAC(sk, scope), 32 bytes. */
    fi_bytes =
        build_nullifier_fixed_input(scope, scope_bytes, 256u, fixed_input);
    kdf_buf = kdf_ctr_cmac_gf8_witness_bytes(sk_bytes, 32, fi_bytes);
    kdf_tmp = calloc(kdf_buf, 1);
    MUST_OK_FP(kdf_ctr_cmac_gf8_build_witness(sks, sk_bytes, fixed_input,
                                              fi_bytes, 32, kdf_tmp, t_tag));
    free(kdf_tmp);

    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    path.scope = scope;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.scope = scope;
    pub.nullifier = t_tag;

    check("sign-wide: wide-nullifier sign ok",
          voleith_rs_sign(&sig, &cfg, &params, sks, NULL, &path, &pub, m,
                          m_len) == 0);
    check("sign-wide: wide-nullifier verify accepts",
          voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == 0);

    /* Tampering the published 32-byte T desynchronises the verifier. */
    t_tag[31] ^= 0x01;
    check("sign-wide: tampered T rejected",
          voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == -1);
    t_tag[31] ^= 0x01;
    voleith_rs_sig_free(&sig);
}

static void
test_rs_sign_composite(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    voleith_params_t params = voleith_params_em_128f;
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;
    uint8_t sks[4 * 16], attrs[4 * 4];
    uint8_t root[16], sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4], path;
    uint8_t id[16], rand[16], idrand[32], C[16];
    uint8_t scope[12], t_tag[16], cmac_tmp[16 + 2 * 200];
    uint8_t bounds[8] = {10, 0, 0, 0, 50, 0, 0, 0};
    uint8_t leaf0[16];
    uint8_t rvals[4][16], rnexts[4][16], ridxs[4][8], rev_root[16], rev_sib[32];
    uint8_t svals[4][16], snexts[4][16], sidxs[4][8], spent_root[16],
        spent_sib[32];
    size_t rev_adj, spent_adj;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    const uint8_t m[] = "rs composite roundtrip";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.membership.depth_r = 2;
    cfg.attr_schema = &schema;
    cfg.scope_bytes = 12;
    cfg.depth_s = 2;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    memset(attrs, 0, sizeof(attrs));
    attrs[0] = 20;
    for (size_t i = 1; i < 4; i++)
        attrs[i * 4] = (uint8_t)(5 + i);
    for (size_t i = 0; i < 16; i++) {
        id[i] = (uint8_t)(0xA0 + i);
        rand[i] = (uint8_t)(0x5C - i);
    }
    for (size_t i = 0; i < 12; i++)
        scope[i] = (uint8_t)(0x90 + i);
    memcpy(idrand, id, 16);
    memcpy(idrand + 16, rand, 16);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, attrs, 4, root, paths, sib_storage));
    MUST_OK_FP(vt->leaf_hash(idrand, 32, C));
    aes_cmac_gf8_build_witness(sks, 16, scope, 12, cmac_tmp, t_tag);
    MUST_OK_FP(rs_leaf_gf8_hash(vt, sks, 16, attrs, 4, leaf0));
    build_imt4(vt, rvals, rnexts, ridxs, rev_root, leaf0, &rev_adj, rev_sib);
    build_imt4(vt, svals, snexts, sidxs, spent_root, t_tag, &spent_adj,
               spent_sib);

    path = paths[0];
    path.membership.rev_adj_leaf_index = rev_adj;
    path.membership.rev_siblings = rev_sib;
    path.membership.rev_low_value = rvals[rev_adj];
    path.membership.rev_low_next = rnexts[rev_adj];
    path.membership.rev_next_index = ridxs[rev_adj];
    path.scope = scope;
    path.commit_id = id;
    path.commit_rand = rand;
    path.spent_adj_leaf_index = spent_adj;
    path.spent_siblings = spent_sib;
    path.spent_low_value = svals[spent_adj];
    path.spent_low_next = snexts[spent_adj];
    path.spent_next_index = sidxs[spent_adj];

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.revocation_root = rev_root;
    pub.commitment = C;
    pub.scope = scope;
    pub.nullifier = t_tag;
    pub.spent_root = spent_root;
    pub.bounds = bounds;
    pub.bounds_len = sizeof(bounds);

    check("sign: composite sign ok",
          voleith_rs_sign(&sig, &cfg, &params, sks, attrs, &path, &pub, m,
                          m_len) == 0);
    check("sign: composite verify accepts",
          voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == 0);

    /* One tamper per public section: each flips the fs_seed / instance, so
     * verify rejects.  Restores the field after each. */
    {
        struct {
            const char *name;
            const uint8_t **field; /* pointer to the pub member to swap */
            const uint8_t *orig;
            size_t len;
        } sect[] = {
            {"membership_root", &pub.membership_root, root, 16},
            {"revocation_root", &pub.revocation_root, rev_root, 16},
            {"commitment", &pub.commitment, C, 16},
            {"nullifier", &pub.nullifier, t_tag, 16},
            {"spent_root", &pub.spent_root, spent_root, 16},
            {"bounds", &pub.bounds, bounds, sizeof(bounds)},
        };
        for (size_t i = 0; i < sizeof(sect) / sizeof(sect[0]); i++) {
            uint8_t bad[64];
            char name[80];
            memcpy(bad, sect[i].orig, sect[i].len);
            bad[0] ^= 0x01;
            *sect[i].field = bad;
            snprintf(name, sizeof(name), "sign: tampered %s rejected",
                     sect[i].name);
            check(name,
                  voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == -1);
            *sect[i].field = sect[i].orig;
        }
    }

    /* Tampered message rejects (Fiat-Shamir binds m). */
    {
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        check("sign: composite tampered m rejected",
              voleith_rs_verify(&sig, &cfg, &params, &pub, bad_m, m_len) == -1);
    }

    /* Cross-config: a different ring depth rebuilds a different circuit /
     * fs_seed, so verify rejects. */
    {
        voleith_rs_config_t cfg2 = cfg;
        cfg2.membership.depth_m = 3;
        check("sign: cross-config verify rejects",
              voleith_rs_verify(&sig, &cfg2, &params, &pub, m, m_len) == -1);
    }

    voleith_rs_sig_free(&sig);
}

/* ================================================================
 * RS.SER: "VRSC" serialization.
 * ================================================================ */
static void
test_rs_ser(void)
{
    voleith_rs_config_t cfg;
    voleith_params_t params = voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    uint8_t sks[4 * 16];
    uint8_t root[16];
    uint8_t sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4], path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    voleith_rs_sig_t sig2 = {NULL, 0};
    uint8_t *buf;
    size_t packed_len;
    size_t written = 0;
    const uint8_t m[] = "rs ser";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x71 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths, sib_storage));
    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    MUST_OK_FP(
        voleith_rs_sign(&sig, &cfg, &params, sks, NULL, &path, &pub, m, m_len));

    packed_len = voleith_rs_sig_packed_len(&sig);
    check("ser: packed_len == 41 + proof", packed_len == 41u + sig.len);
    buf = calloc(packed_len, 1);
    check("ser: pack ok", voleith_rs_sig_pack(buf, packed_len, &written, &sig,
                                              &cfg, &params) == 0 &&
                              written == packed_len);

    check("ser: unpack roundtrip matches",
          voleith_rs_sig_unpack(&sig2, buf, packed_len, &cfg, &params) == 0 &&
              sig2.len == sig.len && memcmp(sig2.data, sig.data, sig.len) == 0);
    check("ser: unpacked sig verifies",
          voleith_rs_verify(&sig2, &cfg, &params, &pub, m, m_len) == 0);
    voleith_rs_sig_free(&sig2);

    /* Tamper each header section -> unpack rejects. */
    struct {
        const char *name;
        size_t off;
    } tamp[] = {
        {"magic", 0},      {"version", 4}, {"cfg_fp", 5},
        {"params_fp", 21}, {"length", 37},
    };
    for (size_t i = 0; i < sizeof(tamp) / sizeof(tamp[0]); i++) {
        char name[80];
        buf[tamp[i].off] ^= 0x01;
        snprintf(name, sizeof(name), "ser: tamper %s rejected", tamp[i].name);
        check(name, voleith_rs_sig_unpack(&sig2, buf, packed_len, &cfg,
                                          &params) == -1);
        buf[tamp[i].off] ^= 0x01;
    }
    /* Tamper proof body: unpacks (header intact) but fails verify. */
    if (sig.len > 0) {
        buf[41] ^= 0x01;
        check(
            "ser: tamper proof body unpacks then fails verify",
            voleith_rs_sig_unpack(&sig2, buf, packed_len, &cfg, &params) == 0 &&
                voleith_rs_verify(&sig2, &cfg, &params, &pub, m, m_len) == -1);
        voleith_rs_sig_free(&sig2);
        buf[41] ^= 0x01;
    }
    /* Short buffer. */
    check("ser: short buffer rejected",
          voleith_rs_sig_unpack(&sig2, buf, 40, &cfg, &params) == -1);
    /* Wrong cfg -> cfg_fingerprint mismatch. */
    {
        voleith_rs_config_t cfg2 = cfg;
        cfg2.membership.depth_m = 3;
        check("ser: wrong cfg rejected",
              voleith_rs_sig_unpack(&sig2, buf, packed_len, &cfg2, &params) ==
                  -1);
    }

    free(buf);
    voleith_rs_sig_free(&sig);
}

/* ================================================================
 * V2.LINK: nullifier comparator + extractor.
 * ================================================================ */
static void
test_rs_link(void)
{
    uint8_t sk[16], sk2[16];
    uint8_t scope_a[12], scope_b[12];
    uint8_t cmac_tmp[16 + 2 * 200];
    uint8_t t_a1[16], t_a2[16], t_b[16], t_other[16];
    voleith_rs_config_t cfg;
    voleith_rs_public_t pub;

    for (size_t i = 0; i < 16; i++) {
        sk[i] = (uint8_t)(0x40 + i);
        sk2[i] = (uint8_t)(0xC0 + i);
    }
    for (size_t i = 0; i < 12; i++) {
        scope_a[i] = (uint8_t)(0x90 + i);
        scope_b[i] = (uint8_t)(0x11 + i);
    }

    /* Same signer + same scope -> equal T (computed independently twice). */
    aes_cmac_gf8_build_witness(sk, 16, scope_a, 12, cmac_tmp, t_a1);
    aes_cmac_gf8_build_witness(sk, 16, scope_a, 12, cmac_tmp, t_a2);
    check("link: same signer+scope yields equal T",
          voleith_rs_nullifier_equal(t_a1, t_a2, 16) == 1);

    /* Same signer, different scope -> unequal T (unlinkable across scopes). */
    aes_cmac_gf8_build_witness(sk, 16, scope_b, 12, cmac_tmp, t_b);
    check("link: same signer, different scope yields unequal T",
          voleith_rs_nullifier_equal(t_a1, t_b, 16) == 0);

    /* Different signer, same scope -> unequal T. */
    aes_cmac_gf8_build_witness(sk2, 16, scope_a, 12, cmac_tmp, t_other);
    check("link: different signer, same scope yields unequal T",
          voleith_rs_nullifier_equal(t_a1, t_other, 16) == 0);

    /* NULL / zero-length guards return 0 (not equal). */
    check("link: NULL args compare unequal",
          voleith_rs_nullifier_equal(NULL, t_a1, 16) == 0 &&
              voleith_rs_nullifier_equal(t_a1, NULL, 16) == 0 &&
              voleith_rs_nullifier_equal(t_a1, t_a1, 0) == 0);

    /* Extractor: returns T when the nullifier module is on, NULL when off. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    memset(&pub, 0, sizeof(pub));
    pub.nullifier = t_a1;

    cfg.scope_bytes = 12;
    check("link: extractor returns T when nullifier enabled",
          voleith_rs_nullifier(&cfg, &pub) == t_a1);
    cfg.scope_bytes = 0;
    check("link: extractor returns NULL when nullifier disabled",
          voleith_rs_nullifier(&cfg, &pub) == NULL);
    check("link: extractor NULL-safe",
          voleith_rs_nullifier(NULL, &pub) == NULL &&
              voleith_rs_nullifier(&cfg, NULL) == NULL);
}

/* ================================================================
 * V4.CLAIM: authorship-claim produce / verify.
 * ================================================================ */
static void
test_rs_claim(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    voleith_rs_config_t cfg;
    uint8_t id_a[16], rand_a[16], id_b[16], rand_b[16];
    uint8_t C_a[16], C_b[16];
    uint8_t idrand[32];
    voleith_rs_claim_t claim;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    for (size_t i = 0; i < 16; i++) {
        id_a[i] = (uint8_t)(0xA0 + i);
        rand_a[i] = (uint8_t)(0x5C - i);
        id_b[i] = (uint8_t)(0x10 + i);
        rand_b[i] = (uint8_t)(0xE7 - i);
    }

    /* Reference C for signature A (the value the signer bound into fs_seed). */
    memcpy(idrand, id_a, 16);
    memcpy(idrand + 16, rand_a, 16);
    MUST_OK_FP(vt->leaf_hash(idrand, 32, C_a));
    memcpy(idrand, id_b, 16);
    memcpy(idrand + 16, rand_b, 16);
    MUST_OK_FP(vt->leaf_hash(idrand, 32, C_b));

    /* produce: opening recorded, C recomputed matches the reference. */
    check("claim: produce ok",
          voleith_rs_claim_produce(&cfg, id_a, rand_a, &claim) == 0);
    check("claim: produce records opening + C",
          claim.id == id_a && claim.rand == rand_a &&
              claim.commitment_bytes == 16 &&
              memcmp(claim.commitment, C_a, 16) == 0);

    /* verify: correct opening against the right C. */
    check("claim: correct (id, rand) verifies",
          voleith_rs_claim_verify(&cfg, C_a, id_a, rand_a) == 0);

    /* wrong rand / wrong id fail. */
    {
        uint8_t bad[16];
        memcpy(bad, rand_a, 16);
        bad[0] ^= 0x01;
        check("claim: wrong rand fails",
              voleith_rs_claim_verify(&cfg, C_a, id_a, bad) == -1);
        memcpy(bad, id_a, 16);
        bad[3] ^= 0x80;
        check("claim: wrong id fails",
              voleith_rs_claim_verify(&cfg, C_a, bad, rand_a) == -1);
    }

    /* Non-transferability: A's opening against signature B's C fails. */
    check("claim: opening against another signature's C fails",
          voleith_rs_claim_verify(&cfg, C_b, id_a, rand_a) == -1);

    /* Commitment module disabled -> both helpers reject. */
    {
        voleith_rs_config_t off = cfg;
        off.enable_commitment = 0;
        check("claim: disabled module rejects produce",
              voleith_rs_claim_produce(&off, id_a, rand_a, &claim) == -1);
        check("claim: disabled module rejects verify",
              voleith_rs_claim_verify(&off, C_a, id_a, rand_a) == -1);
    }

    /* NULL guards. */
    check("claim: NULL args rejected",
          voleith_rs_claim_produce(&cfg, NULL, rand_a, &claim) == -1 &&
              voleith_rs_claim_verify(&cfg, NULL, id_a, rand_a) == -1);
}

/* ================================================================
 * RS.TEST: consolidated property matrix (sign-level rows not covered
 * by the per-module circuit-eval tests above).
 * ================================================================ */

/* V3 at sign level: predicate-satisfied accepts; predicate-violated fails
 * at sign (X-10); attribute swapped without re-deriving the leaf fails. */
static void
test_rs_v3_sign(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    voleith_params_t params = voleith_params_em_128f;
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE}, /* "age", proven in [low, high] */
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;
    uint8_t sks[4 * 16], attrs[4 * 4];
    uint8_t root[16], sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4], path;
    uint8_t bounds_ok[8] = {18, 0, 0, 0, 120, 0, 0, 0};  /* age in [18,120] */
    uint8_t bounds_bad[8] = {50, 0, 0, 0, 120, 0, 0, 0}; /* age in [50,120] */
    uint8_t attrs_swap[4] = {99, 0, 0, 0}; /* in range, but not member 0's */
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    const uint8_t m[] = "rs v3 sign";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.attr_schema = &schema;

    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x40 + i);
    memset(attrs, 0, sizeof(attrs));
    attrs[0] = 42; /* member 0 age */
    for (size_t i = 1; i < 4; i++)
        attrs[i * 4] = (uint8_t)(20 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, attrs, 4, root, paths, sib_storage));
    path = paths[0];
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.bounds = bounds_ok;
    pub.bounds_len = sizeof(bounds_ok);

    check("v3 sign: in-range age signs + verifies",
          voleith_rs_sign(&sig, &cfg, &params, sks, attrs, &path, &pub, m,
                          m_len) == 0 &&
              voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len) == 0);
    voleith_rs_sig_free(&sig);

    /* Predicate violated (age 42 not in [50,120]): fails at sign. */
    pub.bounds = bounds_bad;
    check("v3 sign: out-of-range age fails at sign",
          voleith_rs_sign(&sig, &cfg, &params, sks, attrs, &path, &pub, m,
                          m_len) == -1);
    voleith_rs_sig_free(&sig);
    pub.bounds = bounds_ok;

    /* Attribute not bound into the leaf: signing with a different attr than
     * the one enrolled into member 0's leaf breaks the membership relation,
     * even though attrs_swap satisfies the range. */
    check("v3 sign: swapped attribute (leaf mismatch) fails at sign",
          voleith_rs_sign(&sig, &cfg, &params, sks, attrs_swap, &path, &pub, m,
                          m_len) == -1);
    voleith_rs_sig_free(&sig);

    /* N10-2: bounds_len must match the schema-derived total (RANGE -> 2*width
     * = 8); a mismatch is rejected, not over-read. */
    pub.bounds = bounds_ok;
    pub.bounds_len = sizeof(bounds_ok) - 1; /* one short */
    check("v3 sign: mismatched bounds_len rejected",
          voleith_rs_sign(&sig, &cfg, &params, sks, attrs, &path, &pub, m,
                          m_len) == -1);
    voleith_rs_sig_free(&sig);
    pub.bounds_len = sizeof(bounds_ok);
}

/* Anonymity smoke: two distinct members sign the same m; both verify, the
 * bytestreams differ, and the proof length is identical (the layout is
 * fixed by cfg, never by which leaf index signed). */
static void
test_rs_anonymity_smoke(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    voleith_params_t params = voleith_params_em_128f;
    voleith_rs_config_t cfg;
    uint8_t sks[4 * 16];
    uint8_t root[16], sib_storage[4 * 2 * 16];
    voleith_rs_path_t paths[4];
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig0 = {NULL, 0}, sig1 = {NULL, 0};
    const uint8_t m[] = "same message, two signers";
    size_t m_len = sizeof(m) - 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    for (size_t i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x31 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root, paths, sib_storage));
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;

    MUST_OK_FP(voleith_rs_sign(&sig0, &cfg, &params, sks, NULL, &paths[0], &pub,
                               m, m_len));
    MUST_OK_FP(voleith_rs_sign(&sig1, &cfg, &params, sks + 16, NULL, &paths[1],
                               &pub, m, m_len));

    check("anon: both signers verify",
          voleith_rs_verify(&sig0, &cfg, &params, &pub, m, m_len) == 0 &&
              voleith_rs_verify(&sig1, &cfg, &params, &pub, m, m_len) == 0);
    check("anon: proof length independent of signer index",
          sig0.len == sig1.len);
    check("anon: bytestreams differ",
          sig0.len == sig1.len && memcmp(sig0.data, sig1.data, sig0.len) != 0);

    voleith_rs_sig_free(&sig0);
    voleith_rs_sig_free(&sig1);
}

/* Determinism: the same cfg yields a byte-identical layout and fingerprint
 * across independent build / fingerprint calls. */
static void
test_rs_determinism(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;
    voleith_rs_layout_t L1, L2;
    voleith_gf8_circuit_t *c1, *c2;
    uint8_t fp1[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 3;
    cfg.membership.depth_r = 2;
    cfg.attr_schema = &schema;
    cfg.scope_bytes = 12;
    cfg.depth_s = 2;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = 16;
    cfg.commit_rand_bytes = 16;

    /* Zero both first so any struct padding compares equal; build fills the
     * same named fields identically. */
    memset(&L1, 0, sizeof(L1));
    memset(&L2, 0, sizeof(L2));
    c1 = voleith_gf8_circuit_new();
    c2 = voleith_gf8_circuit_new();
    MUST_OK_FP(voleith_rs_build_circuit(c1, &cfg, &L1));
    MUST_OK_FP(voleith_rs_build_circuit(c2, &cfg, &L2));
    check("determinism: layout byte-identical across builds",
          memcmp(&L1, &L2, sizeof(L1)) == 0);

    MUST_OK_FP(voleith_rs_config_fingerprint(&cfg, fp1));
    MUST_OK_FP(voleith_rs_config_fingerprint(&cfg, fp2));
    check("determinism: fingerprint identical across calls",
          memcmp(fp1, fp2, sizeof(fp1)) == 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* Build a 4-leaf membership ring with the signer at leaf 0. */
static void
v6_build_ring4(const voleith_node_hash_vt *vt, const uint8_t *leaf0,
               uint8_t *root_out, uint8_t *sibs_out)
{
    size_t W = vt->node_bytes;
    uint8_t *leaves = calloc(4, W);
    memcpy(leaves, leaf0, W);
    for (size_t m = 1; m < 4; m++)
        for (size_t i = 0; i < W; i++)
            leaves[m * W + i] = (uint8_t)(0x11 * m + i);
    MUST_OK_FP(voleith_merkle_vt_build(vt, leaves, 4, root_out));
    MUST_OK_FP(voleith_merkle_vt_compute_path(vt, leaves, 4, 0, sibs_out));
    free(leaves);
}

/*
 * EP.CIRC: end-to-end build + pack + eval of the V6 epoch circuit for
 * V6-only, V6+V3(+salt), and V6+V2 configs, with wrong sk_t / sibling / t
 * rejected.  grostl-256-fixed tree (node 32), depth_e 3, depth_m 2.
 */
static void
test_rs_v6_circuit(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256_fixed;
    const size_t W = 32, DE = 3, DM = 2, SB = 32;
    uint8_t master[32];
    for (size_t i = 0; i < 32; i++)
        master[i] = (uint8_t)(0xC0 + i);

    /* ---- V6-only ---- */
    {
        voleith_rs_config_t cfg;
        voleith_rs_epoch_state_t st;
        voleith_rs_layout_t L;
        voleith_rs_path_t path;
        uint8_t epoch_root[32], sk_t[32], epoch_sibs[3 * 32];
        uint8_t mroot[32], msibs[2 * 32];
        uint64_t t = 5;
        uint8_t *witness, *instance;
        voleith_gf8_circuit_t *c;

        memset(&cfg, 0, sizeof(cfg));
        cfg.membership.tree_hash = vt;
        cfg.membership.depth_m = DM;
        cfg.membership.sk_bytes = 0;
        cfg.depth_e = DE;
        cfg.epoch_sk_bytes = SB;

        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
        MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, t, sk_t));
        MUST_OK_FP(voleith_rs_epoch_path(&st, t, epoch_sibs));

        v6_build_ring4(vt, epoch_root, mroot, msibs); /* leaf0 = epoch_root */

        c = voleith_gf8_circuit_new();
        check("v6-only: build_circuit ok",
              voleith_rs_build_circuit(c, &cfg, &L) == 0);
        check("v6-only: layout has epoch section",
              L.depth_e == DE && L.epoch_sk_bytes == SB &&
                  L.inst_epoch_dirs_bytes == DE);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.epoch_sk = sk_t;
        path.epoch_siblings = epoch_sibs;
        path.epoch = t;

        witness = calloc(L.witness_bytes, 1);
        check("v6-only: pack ok",
              voleith_rs_pack_witness(&cfg, &L, NULL, NULL, &path, NULL, NULL,
                                      witness) == 0);
        instance = calloc(L.instance_bytes, 1);
        for (size_t k = 0; k < DE; k++)
            instance[L.inst_epoch_dirs_off + k] = (uint8_t)((t >> k) & 1u);
        memcpy(instance + L.membership.inst_root_off, mroot, W);

        check("v6-only: eval == 1", eval_circuit(c, witness, instance) == 1);

        witness[L.epoch_sk_off] ^= 0x01;
        check("v6-only: wrong sk_t eval == 0",
              eval_circuit(c, witness, instance) == 0);
        witness[L.epoch_sk_off] ^= 0x01;

        witness[L.epoch_siblings_off] ^= 0x01;
        check("v6-only: wrong epoch sibling eval == 0",
              eval_circuit(c, witness, instance) == 0);
        witness[L.epoch_siblings_off] ^= 0x01;

        witness[L.membership.siblings_off] ^= 0x01;
        check("v6-only: wrong membership sibling eval == 0",
              eval_circuit(c, witness, instance) == 0);
        witness[L.membership.siblings_off] ^= 0x01;

        instance[L.inst_epoch_dirs_off] ^= 0x01;
        check("v6-only: wrong epoch t (dir) eval == 0",
              eval_circuit(c, witness, instance) == 0);
        instance[L.inst_epoch_dirs_off] ^= 0x01;

        free(witness);
        free(instance);
        voleith_gf8_circuit_free(c);
        voleith_rs_epoch_state_clear(&st);
    }

    /* ---- V6 + V3 + salt ---- */
    {
        static const voleith_rs_attr_field_t f[] = {
            {4, VOLEITH_RS_ATTR_PRED_NONE}};
        voleith_rs_attr_schema_t schema = {f, 1};
        voleith_rs_config_t cfg;
        voleith_rs_epoch_state_t st;
        voleith_rs_layout_t L;
        voleith_rs_path_t path;
        uint8_t epoch_root[32], sk_t[32], epoch_sibs[3 * 32];
        uint8_t mroot[32], msibs[2 * 32], leaf0[32], tail[12], salt[8];
        uint8_t attrs[4] = {7, 0, 0, 0};
        uint64_t t = 2;
        uint8_t *witness, *instance;
        voleith_gf8_circuit_t *c;

        for (size_t i = 0; i < 8; i++)
            salt[i] = (uint8_t)(0xE0 + i);

        memset(&cfg, 0, sizeof(cfg));
        cfg.membership.tree_hash = vt;
        cfg.membership.depth_m = DM;
        cfg.membership.sk_bytes = 0;
        cfg.depth_e = DE;
        cfg.epoch_sk_bytes = SB;
        cfg.attr_schema = &schema;
        cfg.leaf_salt_bytes = 8;

        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, salt, &st, epoch_root));
        MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, t, sk_t));
        MUST_OK_FP(voleith_rs_epoch_path(&st, t, epoch_sibs));

        /* leaf0 = OWF(epoch_root || attrs || salt) */
        memcpy(tail, attrs, 4);
        memcpy(tail + 4, salt, 8);
        MUST_OK_FP(rs_leaf_gf8_hash(vt, epoch_root, W, tail, 12, leaf0));
        v6_build_ring4(vt, leaf0, mroot, msibs);

        c = voleith_gf8_circuit_new();
        check("v6+v3: build_circuit ok",
              voleith_rs_build_circuit(c, &cfg, &L) == 0);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.epoch_sk = sk_t;
        path.epoch_salt = salt;
        path.epoch_siblings = epoch_sibs;
        path.epoch = t;

        witness = calloc(L.witness_bytes, 1);
        check("v6+v3: pack ok",
              voleith_rs_pack_witness(&cfg, &L, NULL, attrs, &path, NULL, NULL,
                                      witness) == 0);
        instance = calloc(L.instance_bytes, 1);
        for (size_t k = 0; k < DE; k++)
            instance[L.inst_epoch_dirs_off + k] = (uint8_t)((t >> k) & 1u);
        memcpy(instance + L.membership.inst_root_off, mroot, W);

        check("v6+v3: eval == 1", eval_circuit(c, witness, instance) == 1);

        witness[L.salt_off] ^= 0x01;
        check("v6+v3: wrong salt eval == 0",
              eval_circuit(c, witness, instance) == 0);
        witness[L.salt_off] ^= 0x01;

        witness[L.attr_off] ^= 0x01;
        check("v6+v3: wrong attr eval == 0",
              eval_circuit(c, witness, instance) == 0);
        witness[L.attr_off] ^= 0x01;

        free(witness);
        free(instance);
        voleith_gf8_circuit_free(c);
        voleith_rs_epoch_state_clear(&st);
    }

    /* ---- V6 + V2 (nullifier keyed off sk_t) ---- */
    {
        voleith_rs_config_t cfg;
        voleith_rs_epoch_state_t st;
        voleith_rs_layout_t L;
        voleith_rs_path_t path;
        uint8_t epoch_root[32], sk_t[32], epoch_sibs[3 * 32];
        uint8_t mroot[32], msibs[2 * 32], scope[12], t_tag[16];
        uint64_t t = 3;
        uint8_t *witness, *instance, *cmac_tmp;
        size_t cmac_buf;
        voleith_gf8_circuit_t *c;

        for (size_t i = 0; i < 12; i++)
            scope[i] = (uint8_t)(0x50 + i);

        memset(&cfg, 0, sizeof(cfg));
        cfg.membership.tree_hash = vt;
        cfg.membership.depth_m = DM;
        cfg.membership.sk_bytes = 0;
        cfg.depth_e = DE;
        cfg.epoch_sk_bytes = SB;
        cfg.scope_bytes = 12;

        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
        MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, t, sk_t));
        MUST_OK_FP(voleith_rs_epoch_path(&st, t, epoch_sibs));

        /* T = AES-CMAC(sk_t, scope) (16-byte, grostl-256-fixed cr128). */
        cmac_buf = aes_cmac_gf8_witness_bytes(SB, 12);
        cmac_tmp = calloc(cmac_buf, 1);
        aes_cmac_gf8_build_witness(sk_t, SB, scope, 12, cmac_tmp, t_tag);
        free(cmac_tmp);

        v6_build_ring4(vt, epoch_root, mroot, msibs);

        c = voleith_gf8_circuit_new();
        check("v6+v2: build_circuit ok",
              voleith_rs_build_circuit(c, &cfg, &L) == 0);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.epoch_sk = sk_t;
        path.epoch_siblings = epoch_sibs;
        path.epoch = t;
        path.scope = scope;

        witness = calloc(L.witness_bytes, 1);
        check("v6+v2: pack ok",
              voleith_rs_pack_witness(&cfg, &L, NULL, NULL, &path, NULL, NULL,
                                      witness) == 0);
        instance = calloc(L.instance_bytes, 1);
        for (size_t k = 0; k < DE; k++)
            instance[L.inst_epoch_dirs_off + k] = (uint8_t)((t >> k) & 1u);
        memcpy(instance + L.membership.inst_root_off, mroot, W);
        memcpy(instance + L.inst_scope_off, scope, 12);
        memcpy(instance + L.inst_t_off, t_tag, 16);

        check("v6+v2: eval == 1", eval_circuit(c, witness, instance) == 1);

        instance[L.inst_t_off] ^= 0x01;
        check("v6+v2: wrong T eval == 0",
              eval_circuit(c, witness, instance) == 0);
        instance[L.inst_t_off] ^= 0x01;

        free(witness);
        free(instance);
        voleith_gf8_circuit_free(c);
        voleith_rs_epoch_state_clear(&st);
    }
}

/* EP.SIGN: end-to-end epoch_sign -> verify roundtrips, wrong-epoch reject. */
static void
test_rs_v6_sign(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256_fixed;
    const size_t DE = 3, DM = 2, SB = 32;
    const voleith_params_t *params = &voleith_params_em_128f;
    const char *msg = "v6 sign";
    size_t mlen = strlen(msg);
    uint8_t master[32], epoch_root[32], mroot[32], msibs[2 * 32];
    voleith_rs_config_t cfg;
    voleith_rs_epoch_state_t st;
    uint64_t epochs[3] = {0, 4, 7}; /* T = 8: first, mid, last */

    for (size_t i = 0; i < 32; i++)
        master[i] = (uint8_t)(0x21 + i);

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.depth_m = DM;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = DE;
    cfg.epoch_sk_bytes = SB;

    MUST_OK_FP(voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
    v6_build_ring4(vt, epoch_root, mroot, msibs);

    for (size_t i = 0; i < 3; i++) {
        uint64_t e = epochs[i];
        voleith_rs_path_t path;
        voleith_rs_public_t pub, pub_bad;
        voleith_rs_sig_t sig;
        char name[64];

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        memset(&pub, 0, sizeof(pub));
        pub.membership_root = mroot;
        pub.epoch = e;
        memset(&sig, 0, sizeof(sig));

        snprintf(name, sizeof(name), "v6 sign: epoch %llu roundtrip",
                 (unsigned long long)e);
        check(name,
              voleith_rs_epoch_sign(&sig, &st, &cfg, params, NULL, &path, &pub,
                                    (const uint8_t *)msg, mlen) == 0 &&
                  voleith_rs_verify(&sig, &cfg, params, &pub,
                                    (const uint8_t *)msg, mlen) == 0);

        pub_bad = pub;
        pub_bad.epoch = e ^ 1u;
        snprintf(name, sizeof(name), "v6 sign: epoch %llu wrong-t reject",
                 (unsigned long long)e);
        check(name, voleith_rs_verify(&sig, &cfg, params, &pub_bad,
                                      (const uint8_t *)msg, mlen) != 0);

        voleith_rs_sig_free(&sig);
    }

    voleith_rs_epoch_state_clear(&st);
}

/* EP.SIGN: V6+V2 nullifier is per-epoch (keyed off sk_t). */
static void
test_rs_v6_nullifier_epoch(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256_fixed;
    const size_t DE = 3, DM = 2, SB = 32;
    const voleith_params_t *params = &voleith_params_em_128f;
    uint8_t master[32], epoch_root[32], mroot[32], msibs[2 * 32];
    uint8_t scope[12], sk0[32], sk1[32], T0[16], T0b[16], T1[16];
    uint8_t *cmac_tmp;
    size_t cbuf;
    voleith_rs_config_t cfg;
    voleith_rs_epoch_state_t st;

    for (size_t i = 0; i < 32; i++)
        master[i] = (uint8_t)(0x81 + i);
    for (size_t i = 0; i < 12; i++)
        scope[i] = (uint8_t)(0x30 + i);

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.depth_m = DM;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = DE;
    cfg.epoch_sk_bytes = SB;
    cfg.scope_bytes = 12;

    MUST_OK_FP(voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));

    cbuf = aes_cmac_gf8_witness_bytes(SB, 12);
    cmac_tmp = calloc(cbuf, 1);
    MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, 0, sk0));
    MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, 1, sk1));
    aes_cmac_gf8_build_witness(sk0, SB, scope, 12, cmac_tmp, T0);
    aes_cmac_gf8_build_witness(sk0, SB, scope, 12, cmac_tmp, T0b);
    aes_cmac_gf8_build_witness(sk1, SB, scope, 12, cmac_tmp, T1);
    check("v6+v2: same epoch, same scope -> equal T", memcmp(T0, T0b, 16) == 0);
    check("v6+v2: adjacent epochs -> unequal T", memcmp(T0, T1, 16) != 0);

    /* Full roundtrip at epoch 2 with the published T. */
    {
        uint8_t sk2[32], T2[16];
        voleith_rs_path_t path;
        voleith_rs_public_t pub;
        voleith_rs_sig_t sig;

        MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, 2, sk2));
        aes_cmac_gf8_build_witness(sk2, SB, scope, 12, cmac_tmp, T2);
        v6_build_ring4(vt, epoch_root, mroot, msibs);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.scope = scope;
        memset(&pub, 0, sizeof(pub));
        pub.membership_root = mroot;
        pub.scope = scope;
        pub.nullifier = T2;
        pub.epoch = 2;
        memset(&sig, 0, sizeof(sig));

        check("v6+v2: sign+verify roundtrip",
              voleith_rs_epoch_sign(&sig, &st, &cfg, params, NULL, &path, &pub,
                                    NULL, 0) == 0 &&
                  voleith_rs_verify(&sig, &cfg, params, &pub, NULL, 0) == 0);
        voleith_rs_sig_free(&sig);
    }

    free(cmac_tmp);
    voleith_rs_epoch_state_clear(&st);
}

/* EP.SIGN: epoch fs_seed section (bootstrap KAT + per-epoch distinctness). */
#define RS_V6_FS_KAT_PINNED 1
static void
test_rs_v6_fs_seed(void)
{
    voleith_rs_config_t cfg;
    voleith_rs_public_t pub;
    uint8_t mroot[32];
    uint8_t fs1[VOLEITH_RS_FS_SEED_BYTES], fs2[VOLEITH_RS_FS_SEED_BYTES];
    static const uint8_t kat[VOLEITH_RS_FS_SEED_BYTES] = {
        0x2c, 0xc3, 0x2e, 0x9d, 0x83, 0xd7, 0xbe, 0xa8,
        0x0e, 0x02, 0x87, 0x57, 0x94, 0x5c, 0x38, 0x15};
    const char *msg = "epoch fs";

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.depth_m = 3;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = 4;
    cfg.epoch_sk_bytes = 32;
    for (size_t i = 0; i < 32; i++)
        mroot[i] = (uint8_t)(0x11 + i);

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = mroot;
    pub.epoch = 5;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, (const uint8_t *)msg,
                                          strlen(msg), fs1));
    pub.epoch = 6;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, (const uint8_t *)msg,
                                          strlen(msg), fs2));
    check("v6 fs_seed: distinct epochs differ",
          memcmp(fs1, fs2, sizeof(fs1)) != 0);

    printf("  EP.SIGN epoch fs_seed (t=5):");
    for (size_t i = 0; i < sizeof(fs1); i++)
        printf(" %02x", fs1[i]);
    printf("\n");
    if (RS_V6_FS_KAT_PINNED)
        check("v6 fs_seed: matches pinned", memcmp(fs1, kat, sizeof(fs1)) == 0);
    else {
        printf("  (v6 fs_seed KAT not yet pinned: copy the t=5 bytes into kat "
               "and set RS_V6_FS_KAT_PINNED to 1)\n");
        (void)kat;
    }
}

/* All-modules-off (1.8.0) layout is unchanged by the V6 struct additions. */
static void
test_rs_v6_layout_off(void)
{
    voleith_rs_config_t cfg = canonical_cfg();
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    MUST_OK_FP(voleith_rs_build_circuit(c, &cfg, &L));
    check("v6-off: no epoch section in layout",
          L.depth_e == 0 && L.epoch_sk_off == 0 && L.epoch_sk_bytes == 0 &&
              L.salt_bytes == 0 && L.epoch_siblings_bytes == 0 &&
              L.epoch_leaf_invin_bytes == 0 && L.epoch_path_invin_bytes == 0 &&
              L.inst_epoch_dirs_bytes == 0);
    voleith_gf8_circuit_free(c);
}

/* Base aes-dm V6 config (node 16, epoch_sk 16), so the IMT / ring helpers
 * (all 16-byte) compose directly. */
static voleith_rs_config_t
v6_aesdm_cfg(void)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg.membership.depth_m = 2;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = 3;
    cfg.epoch_sk_bytes = 16;
    return cfg;
}

/* Does hay contain needle? (leak-detection smoke.) */
static int
mem_contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
             size_t needle_len)
{
    if (needle_len == 0 || needle_len > hay_len)
        return 0;
    for (size_t i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return 1;
    return 0;
}

/*
 * EP.TEST: forward security at the signature level.
 *   - state reload mid-lifecycle: sign@0, serialize, reload, advance, sign@3
 *   - advance-past-then-sign refusal (epoch_sign at a retired epoch)
 *   - thief: forging a retired epoch with a future seed fails at sign (X-10)
 */
static void
test_rs_v6_forward_security(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_params_t *params = &voleith_params_em_128f;
    const char *msg = "v6 fs";
    size_t mlen = strlen(msg);
    uint8_t master[16], epoch_root[16], mroot[16], msibs[2 * 16];
    voleith_rs_config_t cfg = v6_aesdm_cfg();
    voleith_rs_epoch_state_t st, st1;
    voleith_rs_path_t base_path;
    voleith_rs_public_t pub0, pub2, pub3;
    voleith_rs_sig_t sig0, sig3, sigx, sigt;
    uint8_t *buf;
    size_t need;
    uint8_t sk_wrong[16], sibs2[3 * 16];
    voleith_rs_path_t thief;

    for (size_t i = 0; i < 16; i++)
        master[i] = (uint8_t)(0x21 + i);

    MUST_OK_FP(voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
    v6_build_ring4(vt, epoch_root, mroot, msibs);

    memset(&base_path, 0, sizeof(base_path));
    base_path.membership.leaf_index = 0;
    base_path.membership.siblings = msibs;
    memset(&pub0, 0, sizeof(pub0));
    pub0.membership_root = mroot;
    pub0.epoch = 0;
    pub2 = pub0;
    pub2.epoch = 2;
    pub3 = pub0;
    pub3.epoch = 3;

    /* Serialize the fresh (t=0) state before signing / advancing. */
    need = voleith_rs_epoch_state_serialized_len(&st);
    buf = malloc(need);
    MUST_OK_FP(voleith_rs_epoch_state_serialize(&st, buf, need, NULL));

    memset(&sig0, 0, sizeof(sig0));
    check("v6 fs: sign@0 + verify",
          voleith_rs_epoch_sign(&sig0, &st, &cfg, params, NULL, &base_path,
                                &pub0, (const uint8_t *)msg, mlen) == 0 &&
              voleith_rs_verify(&sig0, &cfg, params, &pub0,
                                (const uint8_t *)msg, mlen) == 0);

    /* Reload a fresh copy, advance to 3, sign@3. */
    MUST_OK_FP(voleith_rs_epoch_state_load(&st1, &cfg, buf, need));
    MUST_OK_FP(voleith_rs_epoch_state_advance(&st1, 3));
    memset(&sig3, 0, sizeof(sig3));
    check("v6 fs: reload + advance, sign@3 + verify",
          voleith_rs_epoch_sign(&sig3, &st1, &cfg, params, NULL, &base_path,
                                &pub3, (const uint8_t *)msg, mlen) == 0 &&
              voleith_rs_verify(&sig3, &cfg, params, &pub3,
                                (const uint8_t *)msg, mlen) == 0);
    check("v6 fs: earlier sig@0 still verifies",
          voleith_rs_verify(&sig0, &cfg, params, &pub0, (const uint8_t *)msg,
                            mlen) == 0);

    /* Advance-past-then-sign refusal: st1 is at t=3, epoch 2 is retired. */
    memset(&sigx, 0, sizeof(sigx));
    check("v6 fs: advance-past sign refused",
          voleith_rs_epoch_sign(&sigx, &st1, &cfg, params, NULL, &base_path,
                                &pub2, (const uint8_t *)msg, mlen) == -1);

    /* Thief: forge epoch 2 with a future seed (sk_4) and epoch-2 siblings.
     * The epoch subtree yields the wrong h at position 2, so the epoch root
     * (hence the membership root assert) mismatches and sign fails. */
    MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, 4, sk_wrong)); /* st still t=0 */
    MUST_OK_FP(voleith_rs_epoch_path(&st, 2, sibs2));
    thief = base_path;
    thief.epoch_sk = sk_wrong;
    thief.epoch_siblings = sibs2;
    thief.epoch = 2;
    memset(&sigt, 0, sizeof(sigt));
    check("v6 fs: thief wrong-seed sign fails",
          voleith_rs_sign(&sigt, &cfg, params, NULL, NULL, &thief, &pub2,
                          (const uint8_t *)msg, mlen) == -1);

    voleith_rs_sig_free(&sig0);
    voleith_rs_sig_free(&sig3);
    free(buf);
    voleith_rs_epoch_state_clear(&st);
    voleith_rs_epoch_state_clear(&st1);
}

/*
 * EP.TEST: composition matrix.
 *   - V6 + V4: sign a claimable signature, then claim it (roundtrip + wrong).
 *   - V6 + V3 + salt: honest sign verifies; a wrong salt fails at sign.
 *   - V6 + revocation: non-revoked epoch root signs; a revoked epoch root
 *     cannot even produce a lookup witness; the pre-revocation sig verifies.
 */
static void
test_rs_v6_composition(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_params_t *params = &voleith_params_em_128f;
    uint8_t master[16];
    for (size_t i = 0; i < 16; i++)
        master[i] = (uint8_t)(0x33 + i);

    /* ---- V6 + V4 claim ---- */
    {
        voleith_rs_config_t cfg = v6_aesdm_cfg();
        voleith_rs_epoch_state_t st;
        voleith_rs_path_t path;
        voleith_rs_public_t pub;
        voleith_rs_sig_t sig;
        voleith_rs_claim_t claim;
        uint8_t epoch_root[16], mroot[16], msibs[2 * 16];
        uint8_t id[16], rand[16], idrand[32], C[16], bad[16];

        cfg.enable_commitment = 1;
        cfg.commit_id_bytes = 16;
        cfg.commit_rand_bytes = 16;
        for (size_t i = 0; i < 16; i++) {
            id[i] = (uint8_t)(0xA0 + i);
            rand[i] = (uint8_t)(0x5C - i);
        }
        memcpy(idrand, id, 16);
        memcpy(idrand + 16, rand, 16);

        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
        v6_build_ring4(vt, epoch_root, mroot, msibs);
        MUST_OK_FP(vt->leaf_hash(idrand, 32, C));

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.commit_id = id;
        path.commit_rand = rand;
        memset(&pub, 0, sizeof(pub));
        pub.membership_root = mroot;
        pub.commitment = C;
        pub.epoch = 1;
        memset(&sig, 0, sizeof(sig));

        check("v6+v4: sign + verify",
              voleith_rs_epoch_sign(&sig, &st, &cfg, params, NULL, &path, &pub,
                                    NULL, 0) == 0 &&
                  voleith_rs_verify(&sig, &cfg, params, &pub, NULL, 0) == 0);
        check("v6+v4: claim roundtrip",
              voleith_rs_claim_produce(&cfg, id, rand, &claim) == 0 &&
                  voleith_rs_claim_verify(&cfg, C, id, rand) == 0);
        memcpy(bad, rand, 16);
        bad[0] ^= 0x01;
        check("v6+v4: wrong claim opening rejected",
              voleith_rs_claim_verify(&cfg, C, id, bad) == -1);

        voleith_rs_sig_free(&sig);
        voleith_rs_epoch_state_clear(&st);
    }

    /* ---- V6 + V3 + salt: wrong salt fails at sign ---- */
    {
        static const voleith_rs_attr_field_t f[] = {
            {4, VOLEITH_RS_ATTR_PRED_NONE}};
        voleith_rs_attr_schema_t schema = {f, 1};
        voleith_rs_config_t cfg = v6_aesdm_cfg();
        voleith_rs_epoch_state_t st;
        voleith_rs_path_t path, badpath;
        voleith_rs_public_t pub;
        voleith_rs_sig_t sig, sigbad;
        uint8_t epoch_root[16], mroot[16], msibs[2 * 16], leaf0[16];
        uint8_t attrs[4] = {9, 0, 0, 0}, salt[8], wrong_salt[8];
        uint8_t sk_t[16], epoch_sibs[3 * 16], tail[12];

        cfg.attr_schema = &schema;
        cfg.leaf_salt_bytes = 8;
        for (size_t i = 0; i < 8; i++)
            salt[i] = (uint8_t)(0xE0 + i);

        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, salt, &st, epoch_root));
        memcpy(tail, attrs, 4);
        memcpy(tail + 4, salt, 8);
        MUST_OK_FP(rs_leaf_gf8_hash(vt, epoch_root, 16, tail, 12, leaf0));
        v6_build_ring4(vt, leaf0, mroot, msibs);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        memset(&pub, 0, sizeof(pub));
        pub.membership_root = mroot;
        pub.epoch = 1;
        memset(&sig, 0, sizeof(sig));
        check("v6+v3+salt: honest sign + verify",
              voleith_rs_epoch_sign(&sig, &st, &cfg, params, attrs, &path, &pub,
                                    NULL, 0) == 0 &&
                  voleith_rs_verify(&sig, &cfg, params, &pub, NULL, 0) == 0);

        /* Wrong salt via the explicit entry: the OWF leaf changes, so the
         * membership root assert fails and sign returns -1. */
        MUST_OK_FP(voleith_rs_epoch_derive_sk(&st, 1, sk_t));
        MUST_OK_FP(voleith_rs_epoch_path(&st, 1, epoch_sibs));
        memcpy(wrong_salt, salt, 8);
        wrong_salt[0] ^= 0x01;
        badpath = path;
        badpath.epoch_sk = sk_t;
        badpath.epoch_siblings = epoch_sibs;
        badpath.epoch_salt = wrong_salt;
        badpath.epoch = 1;
        memset(&sigbad, 0, sizeof(sigbad));
        check("v6+v3+salt: wrong salt fails at sign",
              voleith_rs_sign(&sigbad, &cfg, params, NULL, attrs, &badpath,
                              &pub, NULL, 0) == -1);

        voleith_rs_sig_free(&sig);
        voleith_rs_epoch_state_clear(&st);
    }

    /* ---- V6 + revocation ---- */
    {
        voleith_rs_config_t cfg = v6_aesdm_cfg();
        voleith_rs_epoch_state_t st;
        voleith_rs_path_t path;
        voleith_rs_public_t pub;
        voleith_rs_sig_t sig;
        uint8_t epoch_root[16], mroot[16], msibs[2 * 16];
        uint8_t rvals[4][16], rnexts[4][16], ridxs[4][8], rev_root[16],
            rev_sib[32];
        size_t rev_adj;
        /* revoked IMT with epoch_root present as a record value */
        uint8_t qvals[4][16], qnexts[4][16], qidxs[4][8], q_root[16], q_sib[32],
            ffv[16];
        voleith_imt_record_t qimt[4];
        size_t q_adj;

        cfg.membership.depth_r = 2;
        MUST_OK_FP(
            voleith_rs_epoch_keygen(&cfg, master, NULL, &st, epoch_root));
        v6_build_ring4(vt, epoch_root, mroot, msibs);
        build_imt4(vt, rvals, rnexts, ridxs, rev_root, epoch_root, &rev_adj,
                   rev_sib);

        memset(&path, 0, sizeof(path));
        path.membership.leaf_index = 0;
        path.membership.siblings = msibs;
        path.membership.rev_adj_leaf_index = rev_adj;
        path.membership.rev_siblings = rev_sib;
        path.membership.rev_low_value = rvals[rev_adj];
        path.membership.rev_low_next = rnexts[rev_adj];
        path.membership.rev_next_index = ridxs[rev_adj];
        memset(&pub, 0, sizeof(pub));
        pub.membership_root = mroot;
        pub.revocation_root = rev_root;
        pub.epoch = 1;
        memset(&sig, 0, sizeof(sig));
        check("v6+rev: non-revoked sign + verify",
              voleith_rs_epoch_sign(&sig, &st, &cfg, params, NULL, &path, &pub,
                                    NULL, 0) == 0 &&
                  voleith_rs_verify(&sig, &cfg, params, &pub, NULL, 0) == 0);

        /* Revoked: epoch_root is a member of the revocation set, so the
         * non-membership lookup fails and no signing witness exists. */
        memset(ffv, 0xFF, 16);
        memset(qvals[0], 0, 16);
        memcpy(qnexts[0], epoch_root, 16);
        spent_le_index(qidxs[0], 1);
        memcpy(qvals[1], epoch_root, 16);
        memcpy(qnexts[1], epoch_root, 16);
        spent_le_index(qidxs[1], 2);
        memcpy(qvals[2], epoch_root, 16);
        memcpy(qnexts[2], epoch_root, 16);
        spent_le_index(qidxs[2], 3);
        memcpy(qvals[3], epoch_root, 16);
        memcpy(qnexts[3], ffv, 16);
        spent_le_index(qidxs[3], 0);
        for (size_t i = 0; i < 4; i++) {
            qimt[i].value = qvals[i];
            qimt[i].next_value = qnexts[i];
            qimt[i].next_index = qidxs[i];
        }
        MUST_OK_FP(voleith_imt_vt_build(vt, qimt, 4, 16, 8, q_root));
        check("v6+rev: revoked epoch root cannot sign (no lookup witness)",
              voleith_imt_vt_lookup_nonmember(vt, qimt, 4, 16, 8, epoch_root,
                                              &q_adj, q_sib) == -1);
        check("v6+rev: pre-revocation signature still verifies",
              voleith_rs_verify(&sig, &cfg, params, &pub, NULL, 0) == 0);

        voleith_rs_sig_free(&sig);
        voleith_rs_epoch_state_clear(&st);
    }
}

/*
 * EP.TEST: anonymity smoke.  Two identities enrolled in one ring sign the
 * same message at the same epoch under identical public inputs; the proofs
 * are equal length, both verify, differ, and leak neither the signer's
 * epoch siblings nor its membership siblings.
 */
static void
test_rs_v6_anonymity(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_params_t *params = &voleith_params_em_128f;
    const size_t W = 16;
    const char *msg = "anon";
    size_t mlen = strlen(msg);
    voleith_rs_config_t cfg = v6_aesdm_cfg();
    voleith_rs_epoch_state_t stA, stB;
    uint8_t masterA[16], masterB[16], rootA[16], rootB[16];
    uint8_t leaves[4 * 16], mroot[16], sibsA[2 * 16], sibsB[2 * 16];
    uint8_t epsibsA[3 * 16];
    voleith_rs_path_t pathA, pathB;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sigA, sigB;
    uint64_t e = 2;

    for (size_t i = 0; i < 16; i++) {
        masterA[i] = (uint8_t)(0x11 + i);
        masterB[i] = (uint8_t)(0x91 + i);
    }
    MUST_OK_FP(voleith_rs_epoch_keygen(&cfg, masterA, NULL, &stA, rootA));
    MUST_OK_FP(voleith_rs_epoch_keygen(&cfg, masterB, NULL, &stB, rootB));

    memcpy(leaves, rootA, W);
    memcpy(leaves + W, rootB, W);
    for (size_t m = 2; m < 4; m++)
        for (size_t i = 0; i < W; i++)
            leaves[m * W + i] = (uint8_t)(0x40 * m + i);
    MUST_OK_FP(voleith_merkle_vt_build(vt, leaves, 4, mroot));
    MUST_OK_FP(voleith_merkle_vt_compute_path(vt, leaves, 4, 0, sibsA));
    MUST_OK_FP(voleith_merkle_vt_compute_path(vt, leaves, 4, 1, sibsB));

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = mroot;
    pub.epoch = e;

    memset(&pathA, 0, sizeof(pathA));
    pathA.membership.leaf_index = 0;
    pathA.membership.siblings = sibsA;
    memset(&pathB, 0, sizeof(pathB));
    pathB.membership.leaf_index = 1;
    pathB.membership.siblings = sibsB;

    memset(&sigA, 0, sizeof(sigA));
    memset(&sigB, 0, sizeof(sigB));
    MUST_OK_FP(voleith_rs_epoch_sign(&sigA, &stA, &cfg, params, NULL, &pathA,
                                     &pub, (const uint8_t *)msg, mlen));
    MUST_OK_FP(voleith_rs_epoch_sign(&sigB, &stB, &cfg, params, NULL, &pathB,
                                     &pub, (const uint8_t *)msg, mlen));

    check("v6 anon: both verify under identical pub",
          voleith_rs_verify(&sigA, &cfg, params, &pub, (const uint8_t *)msg,
                            mlen) == 0 &&
              voleith_rs_verify(&sigB, &cfg, params, &pub, (const uint8_t *)msg,
                                mlen) == 0);
    check("v6 anon: equal-length proofs", sigA.len == sigB.len);
    check("v6 anon: proofs differ",
          sigA.len == sigB.len && memcmp(sigA.data, sigB.data, sigA.len) != 0);

    MUST_OK_FP(voleith_rs_epoch_path(&stA, e, epsibsA));
    check("v6 anon: no epoch-sibling leak in proof",
          mem_contains(sigA.data, sigA.len, epsibsA, W) == 0);
    check("v6 anon: no membership-sibling leak in proof",
          mem_contains(sigA.data, sigA.len, sibsA, W) == 0);

    voleith_rs_sig_free(&sigA);
    voleith_rs_sig_free(&sigB);
    voleith_rs_epoch_state_clear(&stA);
    voleith_rs_epoch_state_clear(&stB);
}

/* Build a minimal opener cfg over the aes-dm vt at the smallest set (128_5).
 * Caller owns *M_out (Mlen bytes), filled with a fixed pseudo-pattern. */
static const voleith_rs_opener_argus_params_t *
opener_seal_cfg(voleith_rs_config_t *cfg, uint8_t **M_out, size_t *Mlen_out)
{
    const voleith_rs_opener_argus_set_t set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(set);
    size_t Mlen, i;
    uint8_t *M;

    if (op == NULL)
        return NULL;
    Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;
    M = malloc(Mlen);
    if (M == NULL)
        return NULL;
    for (i = 0; i < Mlen; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);

    memset(cfg, 0, sizeof(*cfg));
    cfg->membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg->membership.sk_bytes = 16;
    cfg->membership.depth_m = 2;
    cfg->enable_opener = 1;
    cfg->opener_set = set;
    cfg->opener_pk = M;
    cfg->opener_pk_bytes = Mlen;
    *M_out = M;
    *Mlen_out = Mlen;
    return op;
}

/* OP.SIGN: voleith_rs_opener_seal determinism, freshness, ground-truth
 * openability, and argument validation (no proof; fast).
 *
 * BOOTSTRAP KAT (vector 2): RS_OPENER_SEAL_KAT_PINNED starts at 0 so the first
 * build prints a SHA3-256 digest of the sealed (support || s || tag_ct); copy
 * the 32 bytes into seal_kat and flip to 1 to arm. */
#define RS_OPENER_SEAL_KAT_PINNED 1
static void
test_rs_opener_seal(void)
{
    voleith_rs_config_t cfg;
    uint8_t *M = NULL;
    size_t Mlen, i;
    const voleith_rs_opener_argus_params_t *op =
        opener_seal_cfg(&cfg, &M, &Mlen);
    uint8_t rnd[16], rnd2[16], id[16];
    uint32_t *sup1 = NULL, *sup2 = NULL;
    uint8_t *s1 = NULL, *s2 = NULL, *t1 = NULL, *t2 = NULL;
    int ok;

    if (op == NULL) {
        check("seal: 128_5 params present", 0);
        free(M);
        return;
    }
    sup1 = malloc((size_t)op->t * 4);
    sup2 = malloc((size_t)op->t * 4);
    s1 = malloc(op->block_bytes);
    s2 = malloc(op->block_bytes);
    t1 = malloc(op->key_bytes);
    t2 = malloc(op->key_bytes);
    if (!sup1 || !sup2 || !s1 || !s2 || !t1 || !t2) {
        check("seal: alloc", 0);
        goto done;
    }
    for (i = 0; i < 16; i++) {
        rnd[i] = (uint8_t)(0x11u + i);
        rnd2[i] = (uint8_t)(0x22u + i);
        id[i] = (uint8_t)(0xA0u + i);
    }

    check("seal: ok",
          voleith_rs_opener_seal(&cfg, rnd, 16, id, 16, sup1, s1, t1) == 0);
    check("seal: deterministic on same randomness",
          voleith_rs_opener_seal(&cfg, rnd, 16, id, 16, sup2, s2, t2) == 0 &&
              memcmp(sup1, sup2, (size_t)op->t * 4) == 0 &&
              memcmp(s1, s2, op->block_bytes) == 0 &&
              memcmp(t1, t2, op->key_bytes) == 0);

    MUST_OK_FP(voleith_rs_opener_seal(&cfg, rnd2, 16, id, 16, sup2, s2, t2));
    check("seal: fresh randomness -> different support",
          memcmp(sup1, sup2, (size_t)op->t * 4) != 0);
    check("seal: fresh randomness -> different s",
          memcmp(s1, s2, op->block_bytes) != 0);
    check("seal: fresh randomness -> different tag_ct",
          memcmp(t1, t2, op->key_bytes) != 0);

    ok = 1;
    for (i = 1; i < op->t; i++)
        if (sup1[i] <= sup1[i - 1])
            ok = 0;
    for (i = 0; i < op->t; i++)
        if (sup1[i] >= op->n)
            ok = 0;
    check("seal: support ascending, distinct, in range", ok);

    check("seal: output opens under argus_verify (ground truth)",
          voleith_rs_opener_argus_verify(op, M, s1, t1, op->prim_default, sup1,
                                         id, 16) == VOLEITH_RS_OPENER_OK);

    /* KAT (vector 2): SHA3-256 digest of the sealed (support || s || tag_ct)
     * over the fixed randomness/id/M.  A digest (not raw bytes) because these
     * are param-set-sized; support is absorbed 4-byte LE per index so the pin
     * is stable across endianness. */
    {
        ichor_hash_ctx_t hc;
        uint8_t dg[32], le[4];
        static const uint8_t seal_kat[32] = {
            0x8e, 0xcf, 0x3c, 0x3f, 0xba, 0xb5, 0x58, 0x37, 0x15, 0x29, 0x7c,
            0x2e, 0xb3, 0xa3, 0x1d, 0x0d, 0xf6, 0x36, 0x27, 0xb7, 0x9b, 0x59,
            0xb2, 0xd2, 0xb4, 0x4d, 0x6f, 0xf5, 0x5d, 0x7b, 0x32, 0x74};
        ichor_sha3_256_init(&hc);
        for (i = 0; i < op->t; i++) {
            le[0] = (uint8_t)(sup1[i]);
            le[1] = (uint8_t)(sup1[i] >> 8);
            le[2] = (uint8_t)(sup1[i] >> 16);
            le[3] = (uint8_t)(sup1[i] >> 24);
            (void)ichor_sha3_256_absorb(&hc, le, 4);
        }
        (void)ichor_sha3_256_absorb(&hc, s1, op->block_bytes);
        (void)ichor_sha3_256_absorb(&hc, t1, op->key_bytes);
        ichor_sha3_256_finalize(&hc, dg);
        printf("  RS.OPENER seal digest (support||s||tag_ct):");
        for (i = 0; i < sizeof(dg); i++)
            printf(" %02x", dg[i]);
        printf("\n");
        if (RS_OPENER_SEAL_KAT_PINNED) {
            check("kat: opener seal digest matches pinned",
                  memcmp(dg, seal_kat, sizeof(dg)) == 0);
        } else {
            printf("  (opener seal KAT not yet pinned: copy the bytes above "
                   "into seal_kat and set RS_OPENER_SEAL_KAT_PINNED to 1)\n");
            (void)seal_kat;
        }
    }

    check("seal: wrong randomness_len rejected",
          voleith_rs_opener_seal(&cfg, rnd, 15, id, 16, sup1, s1, t1) == -1);
    check("seal: wrong id_len rejected",
          voleith_rs_opener_seal(&cfg, rnd, 16, id, 15, sup1, s1, t1) == -1);
    cfg.enable_opener = 0;
    check("seal: opener-off rejected",
          voleith_rs_opener_seal(&cfg, rnd, 16, id, 16, sup1, s1, t1) == -1);

done:
    free(M);
    free(sup1);
    free(sup2);
    free(s1);
    free(s2);
    free(t1);
    free(t2);
}

/* OP.SIGN: fs_seed opener section binds s || tag_ct (bit 6 on) and is skipped
 * with the section absent when the opener is off (bit-6-off byte-identical).
 *
 * BOOTSTRAP KAT (vector 1): RS_OPENER_FS_KAT_PINNED starts at 0 so the first
 * build prints the opener-on fs_seed; copy the 16 bytes into opener_fs_kat and
 * flip to 1 to arm.  Same pattern as test_fingerprint_kat_pin. */
#define RS_OPENER_FS_KAT_PINNED 0
static void
test_rs_opener_fs_seed(void)
{
    voleith_rs_config_t cfg;
    uint8_t *M = NULL;
    size_t Mlen;
    const voleith_rs_opener_argus_params_t *op =
        opener_seal_cfg(&cfg, &M, &Mlen);
    uint8_t rnd[16], id[16];
    uint32_t *sup = NULL;
    uint8_t *s = NULL, *tag = NULL;
    uint8_t root[16];
    uint8_t seed0[VOLEITH_RS_FS_SEED_BYTES], seed1[VOLEITH_RS_FS_SEED_BYTES];
    uint8_t seed2[VOLEITH_RS_FS_SEED_BYTES], seed3[VOLEITH_RS_FS_SEED_BYTES];
    voleith_rs_public_t pub;
    const uint8_t m[] = "opener fs_seed";
    size_t i;

    if (op == NULL) {
        check("fs_seed: 128_5 params present", 0);
        free(M);
        return;
    }
    sup = malloc((size_t)op->t * 4);
    s = malloc(op->block_bytes);
    tag = malloc(op->key_bytes);
    if (!sup || !s || !tag) {
        check("fs_seed: alloc", 0);
        goto done;
    }
    for (i = 0; i < 16; i++) {
        rnd[i] = (uint8_t)(0x55u + i);
        id[i] = (uint8_t)(0x10u + i);
    }
    memset(root, 0x7c, sizeof(root));
    MUST_OK_FP(voleith_rs_opener_seal(&cfg, rnd, 16, id, 16, sup, s, tag));

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.opener_s = s;
    pub.opener_tag_ct = tag;

    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, sizeof(m) - 1, seed0));

    /* KAT (vector 1): opener-enabled fs_seed over the fixed opener cfg + fixed
     * s/tag_ct/message.  Captured before seed0 is reused below. */
    {
        static const uint8_t opener_fs_kat[VOLEITH_RS_FS_SEED_BYTES] = {
            0x0e, 0x76, 0xed, 0x57, 0x48, 0x0a, 0xeb, 0xd6,
            0x68, 0xa1, 0x53, 0x04, 0x01, 0x12, 0x92, 0x8c};
        printf("  RS.OPENER fs_seed (opener-on):");
        for (i = 0; i < sizeof(seed0); i++)
            printf(" %02x", seed0[i]);
        printf("\n");
        if (RS_OPENER_FS_KAT_PINNED) {
            check("kat: opener fs_seed matches pinned",
                  memcmp(seed0, opener_fs_kat, sizeof(seed0)) == 0);
        } else {
            printf(
                "  (opener fs_seed KAT not yet pinned: copy the bytes above "
                "into opener_fs_kat and set RS_OPENER_FS_KAT_PINNED to 1)\n");
            (void)opener_fs_kat;
        }
    }

    /* Flipping a public s bit changes the opener fs_seed. */
    s[0] ^= 0x01u;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, sizeof(m) - 1, seed1));
    s[0] ^= 0x01u;
    check("fs_seed: opener-on binds s",
          memcmp(seed0, seed1, sizeof(seed0)) != 0);

    /* Flipping a tag_ct byte changes the opener fs_seed. */
    tag[0] ^= 0x01u;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, sizeof(m) - 1, seed2));
    tag[0] ^= 0x01u;
    check("fs_seed: opener-on binds tag_ct",
          memcmp(seed0, seed2, sizeof(seed0)) != 0);

    /* Opener off: bit 6 clear, section skipped -> opener_s / opener_tag_ct are
     * ignored, and a garbage value in them does not move the seed.  Clear the
     * opener key too, else validate rejects opener-off-with-pk. */
    cfg.enable_opener = 0;
    cfg.opener_pk = NULL;
    cfg.opener_pk_bytes = 0;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, sizeof(m) - 1, seed0));
    s[0] ^= 0xFFu;
    tag[0] ^= 0xFFu;
    MUST_OK_FP(voleith_rs_compute_fs_seed(&cfg, &pub, m, sizeof(m) - 1, seed3));
    check("fs_seed: opener-off ignores opener fields (bit-6-off unchanged)",
          memcmp(seed0, seed3, sizeof(seed0)) == 0);

done:
    free(M);
    free(sup);
    free(s);
    free(tag);
}

/* OP.SIGN: streaming ring builder is byte-identical to the one-shot builder for
 * non-opener configs, order-free across fields, and validates enablement. */
static void
test_rs_ring_builder_stream(void)
{
    voleith_rs_config_t cfg;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    uint8_t sks[4 * 16];
    uint8_t root_a[16], root_b[16];
    uint8_t sib_a[4 * 2 * 16], sib_b[4 * 2 * 16];
    voleith_rs_path_t paths_a[4], paths_b[4];
    voleith_rs_ring_builder_t *b = NULL;
    size_t i;
    int ident;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    for (i = 0; i < sizeof(sks); i++)
        sks[i] = (uint8_t)(0x31 + i);

    MUST_OK_FP(
        voleith_rs_ring_build(&cfg, sks, NULL, 4, root_a, paths_a, sib_a));

    MUST_OK_FP(voleith_rs_ring_build_init(&b, &cfg, 4, root_b, paths_b, sib_b));
    for (i = 0; i < 4; i++) {
        MUST_OK_FP(voleith_rs_ring_member_begin(b));
        MUST_OK_FP(voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_SK,
                                              sks + i * 16, 16));
        MUST_OK_FP(voleith_rs_ring_member_end(b));
    }
    MUST_OK_FP(voleith_rs_ring_build_final(b)); /* consumes b */

    ident = memcmp(root_a, root_b, 16) == 0 &&
            memcmp(sib_a, sib_b, sizeof(sib_a)) == 0;
    check("builder: streaming == one-shot (root + siblings)", ident);

    /* Negatives on a fresh builder (abandon with free). */
    b = NULL;
    MUST_OK_FP(voleith_rs_ring_build_init(&b, &cfg, 4, root_b, paths_b, sib_b));
    MUST_OK_FP(voleith_rs_ring_member_begin(b));
    check("builder: member_end without sk rejected",
          voleith_rs_ring_member_end(b) == -1);
    check("builder: id field rejected when opener off",
          voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_ID, sks, 16) ==
              -1);
    check("builder: wrong sk width rejected",
          voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_SK, sks, 15) ==
              -1);
    voleith_rs_ring_build_free(b);
}

/* OP.SER: VRSC format_version 2 (tagged sections + opener tag blob).  Exercises
 * the serialization envelope only (synthetic proof bytes, no proving): builder
 * v1==legacy byte-identical, v2 roundtrip with the opener tag, legacy readers
 * read v2, generic sections, and the framing/tamper sweep.
 *
 * BOOTSTRAP KAT (vector 4): RS_SER_V2_KAT_PINNED starts at 0 so the first build
 * prints a SHA3-256 digest of the full v2 envelope bytes; copy the 32 bytes
 * into ser_v2_kat and flip to 1 to arm the wire-format regression pin. */
#define RS_SER_V2_KAT_PINNED 1
static void
test_rs_ser_v2(void)
{
    voleith_rs_config_t cfg;
    voleith_params_t params = voleith_params_em_128f;
    const voleith_rs_opener_argus_params_t *op;
    uint8_t *M = NULL;
    size_t Mlen = 0;
    uint8_t proof_bytes[48];
    voleith_rs_sig_t sig, sig2 = {NULL, 0};
    voleith_rs_public_t pub;
    uint8_t *s_buf, *tag_buf;
    voleith_rs_sig_packer_t *b = NULL;
    voleith_rs_sig_unpacker_t *u = NULL;
    uint8_t *v2 = NULL, *legacy = NULL;
    size_t v2_len = 0, legacy_len = 0, written = 0, i;

    op = opener_seal_cfg(&cfg, &M, &Mlen);
    if (op == NULL) {
        check("ser2: opener cfg", 0);
        return;
    }
    for (i = 0; i < sizeof(proof_bytes); i++)
        proof_bytes[i] = (uint8_t)(0x30u + i);
    sig.data = proof_bytes;
    sig.len = sizeof(proof_bytes);

    s_buf = calloc(op->block_bytes, 1);
    tag_buf = calloc(op->key_bytes, 1);
    if (s_buf == NULL || tag_buf == NULL) {
        check("ser2: alloc", 0);
        goto done;
    }
    for (i = 0; i < op->block_bytes; i++)
        s_buf[i] = (uint8_t)(0xA0u + i);
    for (i = 0; i < op->key_bytes; i++)
        tag_buf[i] = (uint8_t)(0x5Cu + i);
    memset(&pub, 0, sizeof(pub));
    pub.opener_s = s_buf;
    pub.opener_tag_ct = tag_buf;

    /* Legacy pack (v1) for the byte-identity comparison. */
    legacy_len = voleith_rs_sig_packed_len(&sig);
    legacy = calloc(legacy_len, 1);
    if (legacy == NULL) {
        check("ser2: alloc legacy", 0);
        goto done;
    }
    check("ser2: legacy pack ok",
          voleith_rs_sig_pack(legacy, legacy_len, &written, &sig, &cfg,
                              &params) == 0 &&
              written == legacy_len);

    /* Builder in V1 with only a proof == legacy bytes. */
    {
        uint8_t *b1;
        size_t b1_len;

        MUST_OK_FP(voleith_rs_sig_pack_init(&b, &cfg, &params,
                                            VOLEITH_RS_SIG_FORMAT_V1));
        MUST_OK_FP(voleith_rs_sig_pack_proof(b, &sig));
        b1_len = voleith_rs_sig_pack_len(b);
        check("ser2: builder v1 len == legacy", b1_len == legacy_len);
        b1 = calloc(b1_len ? b1_len : 1, 1);
        MUST_OK_FP(voleith_rs_sig_pack_final(b, b1, b1_len, NULL));
        b = NULL;
        check("ser2: builder v1 byte-identical to legacy",
              memcmp(b1, legacy, legacy_len) == 0);
        free(b1);
    }

    /* V1 must reject an opener section (openability opt-down guard). */
    MUST_OK_FP(
        voleith_rs_sig_pack_init(&b, &cfg, &params, VOLEITH_RS_SIG_FORMAT_V1));
    MUST_OK_FP(voleith_rs_sig_pack_proof(b, &sig));
    MUST_OK_FP(voleith_rs_sig_pack_opener(b, &pub));
    check("ser2: v1 + opener -> pack_len 0", voleith_rs_sig_pack_len(b) == 0);
    check("ser2: v1 + opener -> final rejects",
          voleith_rs_sig_pack_final(b, legacy, legacy_len, NULL) == -1);
    b = NULL; /* final frees on failure */

    /* AUTO with an opener section -> v2. */
    MUST_OK_FP(voleith_rs_sig_pack_init(&b, &cfg, &params,
                                        VOLEITH_RS_SIG_FORMAT_AUTO));
    MUST_OK_FP(voleith_rs_sig_pack_proof(b, &sig));
    MUST_OK_FP(voleith_rs_sig_pack_opener(b, &pub));
    v2_len = voleith_rs_sig_pack_len(b);
    check("ser2: v2 len == 37 + (5+proof) + (5+1+s+tag)",
          v2_len == 37u + (5u + sig.len) +
                        (5u + 1u + op->block_bytes + op->key_bytes));
    v2 = calloc(v2_len, 1);
    if (v2 == NULL) {
        voleith_rs_sig_pack_free(b);
        b = NULL;
        check("ser2: alloc v2", 0);
        goto done;
    }
    MUST_OK_FP(voleith_rs_sig_pack_final(b, v2, v2_len, &written));
    b = NULL;
    check("ser2: v2 written == len", written == v2_len);
    check("ser2: v2 version byte == 2", v2[4] == 2u);

    /* KAT (vector 4): SHA3-256 digest of the full v2 envelope, locking the exact
     * wire layout (section tags, lengths, ordering) for the frozen format. */
    {
        uint8_t dg[32];
        static const uint8_t ser_v2_kat[32] = {
            0xe3, 0xcb, 0x8b, 0xe7, 0x62, 0xb6, 0x23, 0x96, 0x01, 0x4e, 0xdb,
            0x1a, 0x5b, 0x8a, 0x9a, 0xb7, 0x03, 0x40, 0x36, 0x7a, 0x61, 0x5c,
            0xcc, 0x3c, 0x23, 0x9e, 0x85, 0x36, 0x46, 0xf8, 0xad, 0x49};
        ichor_sha3_256(dg, v2, v2_len);
        printf("  RS.SER v2 envelope digest:");
        for (i = 0; i < sizeof(dg); i++)
            printf(" %02x", dg[i]);
        printf("\n");
        if (RS_SER_V2_KAT_PINNED) {
            check("kat: v2 envelope digest matches pinned",
                  memcmp(dg, ser_v2_kat, sizeof(dg)) == 0);
        } else {
            printf("  (v2 envelope KAT not yet pinned: copy the bytes above "
                   "into ser_v2_kat and set RS_SER_V2_KAT_PINNED to 1)\n");
            (void)ser_v2_kat;
        }
    }

    /* v2 roundtrip: proof back + verify-shape (bytes match), opener tag blob. */
    MUST_OK_FP(voleith_rs_sig_unpack_init(&u, v2, v2_len, &cfg, &params));
    check("ser2: v2 unpack proof matches",
          voleith_rs_sig_unpack_proof(u, &sig2) == 0 && sig2.len == sig.len &&
              memcmp(sig2.data, sig.data, sig.len) == 0);
    voleith_rs_sig_free(&sig2);
    {
        const uint8_t *tag = NULL;
        size_t tag_len = 0;
        int ok;

        ok = voleith_rs_sig_unpack_opener(u, &tag, &tag_len) == 0;
        check("ser2: opener tag len == 1+s+tag_ct",
              ok && tag_len == 1u + op->block_bytes + op->key_bytes);
        if (ok) {
            check("ser2: opener tag hash_id", tag[0] == op->prim_default);
            check("ser2: opener tag s",
                  memcmp(tag + 1, s_buf, op->block_bytes) == 0);
            check("ser2: opener tag tag_ct",
                  memcmp(tag + 1 + op->block_bytes, tag_buf, op->key_bytes) ==
                      0);
        }
    }
    voleith_rs_sig_unpack_free(u);
    u = NULL;

    /* Legacy one-shot unpack reads a v2 blob and returns the proof. */
    check("ser2: legacy unpack reads v2 proof",
          voleith_rs_sig_unpack(&sig2, v2, v2_len, &cfg, &params) == 0 &&
              sig2.len == sig.len && memcmp(sig2.data, sig.data, sig.len) == 0);
    voleith_rs_sig_free(&sig2);

    /* Fixed-header tamper sweep -> unpack_init rejects. */
    {
        struct {
            const char *name;
            size_t off;
        } tamp[] = {
            {"magic", 0},
            {"version", 4},
            {"cfg_fp", 5},
            {"params_fp", 21},
        };
        for (i = 0; i < sizeof(tamp) / sizeof(tamp[0]); i++) {
            char name[80];

            v2[tamp[i].off] ^= 0x01;
            snprintf(name, sizeof(name), "ser2: tamper %s rejected",
                     tamp[i].name);
            check(name, voleith_rs_sig_unpack_init(&u, v2, v2_len, &cfg,
                                                   &params) == -1);
            v2[tamp[i].off] ^= 0x01;
        }
    }

    /* Truncated buffer (drop the last payload byte) -> reject. */
    check("ser2: truncation rejected",
          voleith_rs_sig_unpack_init(&u, v2, v2_len - 1, &cfg, &params) == -1);

    /* Tamper the OPENER section tag (byte after the proof section: at
     * 37 + 5 + proof) -> proof still reads, opener now missing. */
    {
        size_t opener_tag_off = 37u + 5u + sig.len;

        v2[opener_tag_off] ^= 0x01;
        check("ser2: tampered opener tag -> init ok, opener missing",
              voleith_rs_sig_unpack_init(&u, v2, v2_len, &cfg, &params) == 0);
        if (u != NULL) {
            const uint8_t *tag = NULL;
            size_t tag_len = 0;

            check("ser2: opener gone after tag tamper",
                  voleith_rs_sig_unpack_opener(u, &tag, &tag_len) == -1);
            check("ser2: proof survives opener tag tamper",
                  voleith_rs_sig_unpack_proof(u, &sig2) == 0 &&
                      sig2.len == sig.len);
            voleith_rs_sig_free(&sig2);
            voleith_rs_sig_unpack_free(u);
            u = NULL;
        }
        v2[opener_tag_off] ^= 0x01;
    }

    /* Tamper the proof section tag -> no proof -> init rejects. */
    check("ser2: tampered proof tag -> init rejects (no proof)",
          (v2[37] ^= 0x01,
           voleith_rs_sig_unpack_init(&u, v2, v2_len, &cfg, &params)) == -1);
    v2[37] ^= 0x01;

    /* Duplicate section: craft a blob with two OPENER sections -> reject. */
    {
        size_t opener_off = 37u + 5u + sig.len; /* start of opener section */
        size_t opener_sec_len = 5u + 1u + op->block_bytes + op->key_bytes;
        size_t dup_len = v2_len + opener_sec_len;
        uint8_t *dup = calloc(dup_len, 1);

        if (dup != NULL) {
            memcpy(dup, v2, v2_len);
            memcpy(dup + v2_len, v2 + opener_off, opener_sec_len);
            check("ser2: duplicate section rejected",
                  voleith_rs_sig_unpack_init(&u, dup, dup_len, &cfg, &params) ==
                      -1);
            free(dup);
        }
    }

    /* Generic section round-trips (future modules). */
    {
        const uint8_t extra[] = {0xDE, 0xAD, 0xBE, 0xEF};
        uint8_t *g;
        size_t g_len;
        const uint8_t *got = NULL;
        size_t got_len = 0;

        MUST_OK_FP(voleith_rs_sig_pack_init(&b, &cfg, &params,
                                            VOLEITH_RS_SIG_FORMAT_V2));
        MUST_OK_FP(voleith_rs_sig_pack_proof(b, &sig));
        MUST_OK_FP(voleith_rs_sig_pack_section(b, 0x10u, extra, sizeof(extra)));
        check("ser2: generic pack rejects reserved tag",
              voleith_rs_sig_pack_section(b, VOLEITH_RS_SIG_SECTION_OPENER,
                                          extra, sizeof(extra)) == -1);
        g_len = voleith_rs_sig_pack_len(b);
        g = calloc(g_len, 1);
        MUST_OK_FP(voleith_rs_sig_pack_final(b, g, g_len, NULL));
        b = NULL;
        MUST_OK_FP(voleith_rs_sig_unpack_init(&u, g, g_len, &cfg, &params));
        check("ser2: generic section roundtrips",
              voleith_rs_sig_unpack_section(u, 0x10u, &got, &got_len) == 0 &&
                  got_len == sizeof(extra) &&
                  memcmp(got, extra, sizeof(extra)) == 0);
        voleith_rs_sig_unpack_free(u);
        u = NULL;
        free(g);
    }

done:
    if (b != NULL)
        voleith_rs_sig_pack_free(b);
    if (u != NULL)
        voleith_rs_sig_unpack_free(u);
    free(v2);
    free(legacy);
    free(s_buf);
    free(tag_buf);
    free(M);
}

int
main(void)
{
    printf("test_rs_gf8: starting\n");
    test_module_bitmap();
    test_validate_accepts();
    test_validate_rejects();
    test_fingerprint_determinism();
    test_fingerprint_module_binding();
    test_fingerprint_field_binding();
    test_fingerprint_kat_pin();
    test_epoch_bitmap();
    test_epoch_validate();
    test_epoch_fingerprint();
    test_opener_bitmap();
    test_opener_validate();
    test_opener_fingerprint();
    test_opener_syndrome_reduced();
    test_opener_dem_aesdm_reduced();
    test_opener_dem_grostl_reduced();
    test_opener_circuit();
    test_rs_v6_circuit();
    test_rs_v6_sign();
    test_rs_v6_nullifier_epoch();
    test_rs_v6_fs_seed();
    test_rs_v6_forward_security();
    test_rs_v6_composition();
    test_rs_v6_anonymity();
    test_rs_v6_layout_off();
    test_rs_leaf();
    test_rs_nullifier();
    test_rs_nullifier_wide();
    test_rs_nullifier_disabled_matches_v1();
    test_rs_spent();
    test_rs_spent_wide();
    test_rs_attributes();
    test_rs_commitment();
    test_rs_pack_full();
    test_rs_revoked();
    test_rs_ring_members();
    test_rs_fs();
    test_rs_sign_membership();
    test_rs_sign_wide_nullifier();
    test_rs_sign_composite();
    test_rs_ser();
    test_rs_ser_v2();
    test_rs_link();
    test_rs_claim();
    test_rs_v3_sign();
    test_rs_anonymity_smoke();
    test_rs_determinism();
    test_rs_opener_seal();
    test_rs_opener_fs_seed();
    test_rs_ring_builder_stream();
    printf("test_rs_gf8: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
