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
 */

#include "rs_gf8.h"

#include "aes_cmac_gf8_circuit.h"
#include "gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"
#include "rs_gf8_circuit.h"
#include "rs_leaf_gf8_circuit.h"
#include "rs_membership_gf8_circuit.h"

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
    test_rs_link();
    test_rs_claim();
    test_rs_v3_sign();
    test_rs_anonymity_smoke();
    test_rs_determinism();
    printf("test_rs_gf8: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
