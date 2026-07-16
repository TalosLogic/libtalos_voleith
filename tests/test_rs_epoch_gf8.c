/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_epoch_gf8.c - EP.GGM: V6 forward-secure epoch key schedule.
 *
 * Coverage:
 *   - determinism KAT (fixed master -> pinned sk_0, sk_{T-1} at depth 4)
 *   - cover-vs-full-expansion: advance-then-derive over every epoch of a
 *     depth-6 tree equals an independent full-tree expansion
 *   - forward security: after advancing to tau, deriving any t < tau (and
 *     re-advancing backward) is refused
 *   - zeroization: the retired root seed is gone from the state after
 *     advance, and state_clear zeroizes the whole struct
 *   - keygen (EP.KEYGEN): epoch_root out == stored root, stored siblings
 *     validate against the root, advance leaves public nodes + salt intact,
 *     epoch-root KAT (bootstrap), salt storage/persistence
 *   - serialization (EP.STATE): roundtrip equality + post-reload derive/
 *     advance; reject wrong magic/version/cfg-fingerprint/cfg, truncated and
 *     overlong buffers; advanced-state roundtrip; zeroize-on-free
 */

#include "rs_epoch_gf8.h"

#include "../circuits/node_hash_vt.h"
#include "../core/prg.h"
#include "../core/util.h"

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

/*
 * Independent reference: expand the entire GGM tree iteratively (heap
 * index 1 = root .. 2T-1) and copy out the T leaf seeds.  Uses the same
 * PRG, IV, and heap-index tweak the module uses, but a wholly different
 * control structure (full level-order expansion vs the module's cover +
 * downward walk), so agreement is a real cross-check.
 */
static void
ref_full_expand(const uint8_t *master, size_t depth_e, size_t sb, int lambda,
                uint8_t *leaves_out /* T * sb */)
{
    static const uint8_t iv[16] = VOLEITH_RS_EPOCH_PRG_IV_TAG;
    uint64_t T = (uint64_t)1u << depth_e;
    uint8_t *nodes = calloc((size_t)(2u * T), sb);

    memcpy(nodes + 1u * sb, master, sb);
    for (uint64_t h = 1; h < T; h++) {
        voleith_prg_ctx_t prg;
        uint8_t out[2u * VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
        voleith_prg_init(&prg, nodes + h * sb, lambda);
        voleith_prg_gen(&prg, out, iv, (uint32_t)h, 2u * sb * 8u);
        voleith_prg_clear(&prg);
        memcpy(nodes + (2u * h) * sb, out, sb);
        memcpy(nodes + (2u * h + 1u) * sb, out + sb, sb);
    }
    for (uint64_t leaf = 0; leaf < T; leaf++)
        memcpy(leaves_out + leaf * sb, nodes + (T + leaf) * sb, sb);

    free(nodes);
}

/* Search a buffer for a needle; used to confirm a retired seed is gone. */
static int
contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
         size_t needle_len)
{
    if (needle_len > hay_len)
        return 0;
    for (size_t i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return 1;
    return 0;
}

static void
test_init_validation(void)
{
    voleith_rs_epoch_state_t st;
    uint8_t master[32];
    memset(master, 0xA5, sizeof(master));

    check("init: NULL state rejected",
          voleith_rs_epoch_state_init(NULL, 4, 16, master) == -1);
    check("init: NULL master rejected",
          voleith_rs_epoch_state_init(&st, 4, 16, NULL) == -1);
    check("init: depth 0 rejected",
          voleith_rs_epoch_state_init(&st, 0, 16, master) == -1);
    check("init: depth over cap rejected",
          voleith_rs_epoch_state_init(&st, VOLEITH_RS_EPOCH_MAX_DEPTH + 1, 16,
                                      master) == -1);
    check("init: epoch_sk_bytes 24 rejected",
          voleith_rs_epoch_state_init(&st, 4, 24, master) == -1);
    check("init: valid accepted",
          voleith_rs_epoch_state_init(&st, 4, 16, master) == 0);
    voleith_rs_epoch_state_clear(&st);
}

static void
test_cross_check(size_t depth_e, size_t sb)
{
    voleith_rs_epoch_state_t work;
    uint8_t master[32];
    uint64_t T = (uint64_t)1u << depth_e;
    uint8_t *ref = malloc((size_t)T * sb);
    uint8_t got[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    int all_ok = 1;
    char name[96];

    for (size_t i = 0; i < sb; i++)
        master[i] = (uint8_t)(0x30 + i);

    ref_full_expand(master, depth_e, sb, (int)(sb * 8u), ref);

    /* Fresh state covers [0, T): derive every leaf directly. */
    voleith_rs_epoch_state_init(&work, depth_e, sb, master);
    for (uint64_t t = 0; t < T; t++) {
        if (voleith_rs_epoch_derive_sk(&work, t, got) != 0 ||
            memcmp(got, ref + t * sb, sb) != 0) {
            all_ok = 0;
            break;
        }
    }
    snprintf(name, sizeof(name),
             "cross-check: fresh-state derive == full expansion (d=%zu,sb=%zu)",
             depth_e, sb);
    check(name, all_ok);
    voleith_rs_epoch_state_clear(&work);

    /* Advance forward through every epoch; the covered derive must still
     * match the independent reference at each step. */
    all_ok = 1;
    voleith_rs_epoch_state_init(&work, depth_e, sb, master);
    for (uint64_t t = 0; t < T; t++) {
        if (t > 0 && voleith_rs_epoch_state_advance(&work, t) != 0) {
            all_ok = 0;
            break;
        }
        if (voleith_rs_epoch_derive_sk(&work, t, got) != 0 ||
            memcmp(got, ref + t * sb, sb) != 0) {
            all_ok = 0;
            break;
        }
    }
    snprintf(
        name, sizeof(name),
        "cross-check: advance-then-derive == full expansion (d=%zu,sb=%zu)",
        depth_e, sb);
    check(name, all_ok);
    voleith_rs_epoch_state_clear(&work);

    free(ref);
}

static void
test_forward_security(void)
{
    voleith_rs_epoch_state_t st;
    uint8_t master[16];
    uint8_t sk[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    memset(master, 0x5C, sizeof(master));

    voleith_rs_epoch_state_init(&st, 6, 16, master); /* T = 64 */
    check("advance: to 20 succeeds",
          voleith_rs_epoch_state_advance(&st, 20) == 0);
    check("derive: current epoch 20 ok",
          voleith_rs_epoch_derive_sk(&st, 20, sk) == 0);
    check("derive: future epoch 63 ok",
          voleith_rs_epoch_derive_sk(&st, 63, sk) == 0);
    check("derive: retired epoch 19 refused",
          voleith_rs_epoch_derive_sk(&st, 19, sk) == -1);
    check("derive: retired epoch 0 refused",
          voleith_rs_epoch_derive_sk(&st, 0, sk) == -1);
    check("derive: out-of-range epoch T refused",
          voleith_rs_epoch_derive_sk(&st, 64, sk) == -1);

    check("advance: to current t refused",
          voleith_rs_epoch_state_advance(&st, 20) == -1);
    check("advance: backward refused",
          voleith_rs_epoch_state_advance(&st, 10) == -1);
    check("advance: to T refused",
          voleith_rs_epoch_state_advance(&st, 64) == -1);
    check("advance: past T refused",
          voleith_rs_epoch_state_advance(&st, 999) == -1);

    voleith_rs_epoch_state_clear(&st);
}

static void
test_zeroization(void)
{
    voleith_rs_epoch_state_t st;
    uint8_t master[32];
    for (size_t i = 0; i < sizeof(master); i++)
        master[i] = (uint8_t)(0xE0 + i);

    voleith_rs_epoch_state_init(&st, 6, 32, master);
    check("zeroize: root seed present before advance",
          contains(st.cover_seed, sizeof(st.cover_seed), master, 32) == 1);

    voleith_rs_epoch_state_advance(&st, 40);
    check("zeroize: retired root seed absent after advance",
          contains(st.cover_seed, sizeof(st.cover_seed), master, 32) == 0);

    voleith_rs_epoch_state_clear(&st);
    {
        uint8_t zero[sizeof(st)];
        memset(zero, 0, sizeof(zero));
        check("zeroize: state_clear zeros the whole struct",
              memcmp(&st, zero, sizeof(st)) == 0);
    }
}

/*
 * Determinism KAT (bootstrap).  Fixed master seed -> sk_0 and sk_{T-1} at
 * depth_e = 4.  Prints the computed seeds and, once EPOCH_GGM_KAT_PINNED
 * is flipped to 1 with the printed bytes copied in, hard-checks them.
 */
#define EPOCH_GGM_KAT_PINNED 1
static void
test_determinism_kat(void)
{
    voleith_rs_epoch_state_t a, b;
    uint8_t master[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t sk0_a[16], sk0_b[16], sklast[16];
    static const uint8_t kat_sk0[16] = {0xb9, 0x40, 0xa1, 0x22, 0xa1, 0x6d,
                                        0x05, 0x49, 0xa0, 0xa6, 0xe2, 0x08,
                                        0x07, 0x3e, 0x93, 0xc4};
    static const uint8_t kat_sklast[16] = {0xdd, 0xc3, 0x32, 0x97, 0x68, 0x8b,
                                           0x95, 0x44, 0xa2, 0x67, 0x4a, 0xeb,
                                           0x16, 0x20, 0xf6, 0x3e};

    voleith_rs_epoch_state_init(&a, 4, 16, master);
    voleith_rs_epoch_state_init(&b, 4, 16, master);
    check("kat: derive sk_0 (a)",
          voleith_rs_epoch_derive_sk(&a, 0, sk0_a) == 0);
    check("kat: derive sk_0 (b)",
          voleith_rs_epoch_derive_sk(&b, 0, sk0_b) == 0);
    check("kat: determinism (same master -> same sk_0)",
          memcmp(sk0_a, sk0_b, 16) == 0);
    check("kat: derive sk_{T-1}",
          voleith_rs_epoch_derive_sk(&a, 15, sklast) == 0);

    printf("  EP.GGM sk_0 :");
    for (size_t i = 0; i < 16; i++)
        printf(" %02x", sk0_a[i]);
    printf("\n  EP.GGM sk_15:");
    for (size_t i = 0; i < 16; i++)
        printf(" %02x", sklast[i]);
    printf("\n");

    if (EPOCH_GGM_KAT_PINNED) {
        check("kat: sk_0 matches pinned", memcmp(sk0_a, kat_sk0, 16) == 0);
        check("kat: sk_15 matches pinned", memcmp(sklast, kat_sklast, 16) == 0);
    } else {
        printf("  (EP.GGM KAT not yet pinned: copy the bytes above into "
               "kat_sk0/kat_sklast and set EPOCH_GGM_KAT_PINNED to 1)\n");
        (void)kat_sk0;
        (void)kat_sklast;
    }

    voleith_rs_epoch_state_clear(&a);
    voleith_rs_epoch_state_clear(&b);
}

/* Recompute the epoch root from a leaf node + sibling path and compare. */
static int
validate_epoch_path(const voleith_node_hash_vt *vt, const uint8_t *leaf_node,
                    const uint8_t *siblings, uint64_t t, size_t depth,
                    const uint8_t *root)
{
    size_t W = vt->node_bytes;
    uint8_t cur[64], nx[64];
    memcpy(cur, leaf_node, W);
    for (size_t k = 0; k < depth; k++) {
        unsigned dir = (unsigned)((t >> k) & 1u);
        const uint8_t *sib = siblings + k * W;
        const uint8_t *L = dir ? sib : cur;
        const uint8_t *R = dir ? cur : sib;
        if (vt->inode_hash(L, R, nx) != 0)
            return 0;
        memcpy(cur, nx, W);
    }
    return memcmp(cur, root, W) == 0;
}

#define EPOCH_KEYGEN_KAT_PINNED 1
static void
test_keygen(void)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_grostl256_fixed;
    size_t W = vt->node_bytes; /* 32 */
    voleith_rs_config_t cfg;
    voleith_rs_epoch_state_t st;
    uint8_t master[32], root[64], sk[32], hleaf[64];
    uint8_t sib[VOLEITH_RS_EPOCH_MAX_DEPTH * 64];
    static const uint8_t kat_root[64] = {
        0xc6, 0x2c, 0xe8, 0xdc, 0x07, 0xe3, 0x94, 0x19, 0x55, 0xf4, 0x77,
        0x31, 0xc9, 0x14, 0x06, 0xf6, 0x51, 0xe5, 0xea, 0x54, 0x15, 0x38,
        0xd6, 0xd1, 0xbc, 0x44, 0x38, 0x51, 0xe2, 0x2a, 0x83, 0xb5};
    uint64_t probe[3] = {0, 5, 15};
    int all;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.depth_m = 3;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = 4;
    cfg.epoch_sk_bytes = 32;
    for (size_t i = 0; i < 32; i++)
        master[i] = (uint8_t)(0x40 + i);

    check("keygen: succeeds",
          voleith_rs_epoch_keygen(&cfg, master, NULL, &st, root) == 0);
    check("keygen: epoch_root_out == state.epoch_root",
          memcmp(root, st.epoch_root, W) == 0);
    check("keygen: public store holds 2T-1 nodes",
          st.public_nodes_len == (size_t)(2u * 16u - 1u) * W);

    all = 1;
    for (size_t i = 0; i < 3; i++) {
        uint64_t t = probe[i];
        if (voleith_rs_epoch_derive_sk(&st, t, sk) != 0 ||
            vt->leaf_hash(sk, 32, hleaf) != 0 ||
            voleith_rs_epoch_path(&st, t, sib) != 0 ||
            !validate_epoch_path(vt, hleaf, sib, t, cfg.depth_e, root)) {
            all = 0;
            break;
        }
    }
    check("keygen: stored siblings validate against root (t=0,5,15)", all);

    /* Advance must leave the public tree intact and paths still valid. */
    {
        uint8_t *snap = malloc(st.public_nodes_len);
        memcpy(snap, st.public_nodes, st.public_nodes_len);
        voleith_rs_epoch_state_advance(&st, 8);
        check("keygen: advance leaves public nodes intact",
              memcmp(snap, st.public_nodes, st.public_nodes_len) == 0);
        free(snap);

        check("keygen: future-epoch path valid after advance",
              voleith_rs_epoch_derive_sk(&st, 10, sk) == 0 &&
                  vt->leaf_hash(sk, 32, hleaf) == 0 &&
                  voleith_rs_epoch_path(&st, 10, sib) == 0 &&
                  validate_epoch_path(vt, hleaf, sib, 10, cfg.depth_e, root));
    }

    printf("  EP.KEYGEN epoch_root:");
    for (size_t i = 0; i < W; i++)
        printf(" %02x", root[i]);
    printf("\n");
    if (EPOCH_KEYGEN_KAT_PINNED)
        check("keygen: epoch_root matches pinned",
              memcmp(root, kat_root, W) == 0);
    else {
        printf("  (EP.KEYGEN root KAT not yet pinned: copy the bytes above "
               "into kat_root and set EPOCH_KEYGEN_KAT_PINNED to 1)\n");
        (void)kat_root;
    }

    voleith_rs_epoch_state_clear(&st);
}

static void
test_keygen_salt(void)
{
    static const voleith_rs_attr_field_t f[] = {{8, VOLEITH_RS_ATTR_PRED_NONE}};
    voleith_rs_attr_schema_t schema = {f, 1};
    voleith_rs_config_t cfg;
    voleith_rs_epoch_state_t st, st2;
    uint8_t master[32], root[64];
    uint8_t salt[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.depth_m = 3;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = 4;
    cfg.epoch_sk_bytes = 32;
    cfg.attr_schema = &schema; /* V3 required for salt */
    cfg.leaf_salt_bytes = 8;   /* 32 root + 8 attr + 8 salt = 48 <= 64 */
    memset(master, 0x77, sizeof(master));

    check("keygen+salt: succeeds",
          voleith_rs_epoch_keygen(&cfg, master, salt, &st, root) == 0);
    check("keygen+salt: salt stored",
          st.leaf_salt_bytes == 8 && memcmp(st.leaf_salt, salt, 8) == 0);

    voleith_rs_epoch_state_advance(&st, 3);
    check("keygen+salt: advance leaves salt intact",
          st.leaf_salt_bytes == 8 && memcmp(st.leaf_salt, salt, 8) == 0);
    voleith_rs_epoch_state_clear(&st);

    check("keygen+salt: NULL salt when configured rejected",
          voleith_rs_epoch_keygen(&cfg, master, NULL, &st2, root) == -1);
}

/* grostl-256-fixed epoch cfg (node 32), depth_e 4, no salt. */
static voleith_rs_config_t
state_test_cfg(void)
{
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    cfg.membership.depth_m = 3;
    cfg.membership.sk_bytes = 0;
    cfg.depth_e = 4;
    cfg.epoch_sk_bytes = 32;
    return cfg;
}

static void
test_state_serialize(void)
{
    voleith_rs_config_t cfg = state_test_cfg();
    voleith_rs_epoch_state_t st, st2;
    uint8_t master[32], root[64], a[32], b[32];
    for (size_t i = 0; i < 32; i++)
        master[i] = (uint8_t)(0x90 + i);

    voleith_rs_epoch_keygen(&cfg, master, NULL, &st, root);

    size_t need = voleith_rs_epoch_state_serialized_len(&st);
    check("serialize: nonzero length", need > 0);

    uint8_t *buf = malloc(need + 1);
    size_t written = 0;
    check("serialize: succeeds",
          voleith_rs_epoch_state_serialize(&st, buf, need, &written) == 0 &&
              written == need);
    check("serialize: out_len mismatch rejected",
          voleith_rs_epoch_state_serialize(&st, buf, need - 1, NULL) == -1);

    /* Roundtrip: load, and check the reloaded state matches and behaves. */
    check("load: succeeds",
          voleith_rs_epoch_state_load(&st2, &cfg, buf, need) == 0);
    check("load: t / cover / salt / root match",
          st2.t == st.t && st2.n_cover == st.n_cover &&
              memcmp(st2.cover_heap, st.cover_heap,
                     st.n_cover * sizeof(st.cover_heap[0])) == 0 &&
              memcmp(st2.cover_seed, st.cover_seed,
                     st.n_cover * st.seed_bytes) == 0 &&
              memcmp(st2.epoch_root, st.epoch_root, st.node_bytes) == 0 &&
              st2.public_nodes_len == st.public_nodes_len &&
              memcmp(st2.public_nodes, st.public_nodes, st.public_nodes_len) ==
                  0);

    /* Behavioral equivalence: derive matches, and post-reload advance works. */
    check("load: derive matches original (t=3)",
          voleith_rs_epoch_derive_sk(&st, 3, a) == 0 &&
              voleith_rs_epoch_derive_sk(&st2, 3, b) == 0 &&
              memcmp(a, b, 32) == 0);
    check("load: advance + derive after reload",
          voleith_rs_epoch_state_advance(&st2, 5) == 0 &&
              voleith_rs_epoch_derive_sk(&st2, 5, b) == 0 &&
              voleith_rs_epoch_derive_sk(&st2, 4, a) == -1);
    voleith_rs_epoch_state_clear(&st2);

    /* Rejections. */
    {
        uint8_t *bad = malloc(need + 1);

        memcpy(bad, buf, need);
        bad[0] ^= 0xFF; /* magic */
        check("load: wrong magic rejected",
              voleith_rs_epoch_state_load(&st2, &cfg, bad, need) == -1);

        memcpy(bad, buf, need);
        bad[4] = 0x02; /* version */
        check("load: wrong version rejected",
              voleith_rs_epoch_state_load(&st2, &cfg, bad, need) == -1);

        memcpy(bad, buf, need);
        bad[5] ^= 0xFF; /* first cfg_fingerprint byte */
        check("load: wrong cfg_fingerprint rejected",
              voleith_rs_epoch_state_load(&st2, &cfg, bad, need) == -1);

        check("load: truncated buffer rejected",
              voleith_rs_epoch_state_load(&st2, &cfg, buf, need - 1) == -1);
        memcpy(bad, buf, need);
        bad[need] = 0x00;
        check("load: overlong buffer rejected",
              voleith_rs_epoch_state_load(&st2, &cfg, bad, need + 1) == -1);

        free(bad);
    }

    /* Wrong cfg (different epoch_hash name -> different fingerprint). */
    {
        voleith_rs_config_t cfg2 = state_test_cfg();
        cfg2.epoch_hash = &voleith_node_hash_hirose_fixed32; /* node 32 too */
        check("load: mismatched cfg rejected",
              voleith_rs_epoch_state_load(&st2, &cfg2, buf, need) == -1);
    }

    /* Serialize an advanced state and reload it. */
    voleith_rs_epoch_state_advance(&st, 6);
    {
        size_t need2 = voleith_rs_epoch_state_serialized_len(&st);
        uint8_t *buf2 = malloc(need2);
        voleith_rs_epoch_state_serialize(&st, buf2, need2, NULL);
        check("load: advanced-state roundtrip",
              voleith_rs_epoch_state_load(&st2, &cfg, buf2, need2) == 0 &&
                  st2.t == 6 && st2.n_cover == st.n_cover);
        voleith_rs_epoch_state_clear(&st2);
        free(buf2);
    }

    /* zeroize-on-free: load then clear scrubs the whole struct. */
    voleith_rs_epoch_state_load(&st2, &cfg, buf, need);
    voleith_rs_epoch_state_clear(&st2);
    {
        uint8_t zero[sizeof(st2)];
        memset(zero, 0, sizeof(zero));
        check("load: state_clear zeros the reloaded struct",
              memcmp(&st2, zero, sizeof(st2)) == 0);
    }

    free(buf);
    voleith_rs_epoch_state_clear(&st);
}

int
main(void)
{
    printf("test_rs_epoch_gf8: starting\n");
    test_init_validation();
    test_cross_check(6, 16);
    test_cross_check(6, 32);
    test_cross_check(4, 16);
    test_forward_security();
    test_zeroization();
    test_determinism_kat();
    test_keygen();
    test_keygen_salt();
    test_state_serialize();
    printf("test_rs_epoch_gf8: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
