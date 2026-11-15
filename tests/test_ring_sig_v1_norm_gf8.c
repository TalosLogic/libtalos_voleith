/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_ring_sig_v1_norm_gf8.c - RSv1 sign/verify coverage with the
 * norm-S-box node-hash vts.
 *
 * The frozen suite (test_ring_sig_v1_gf8.c) exercises the data layer,
 * builder, witness packer, serialization, fs_seed, and revocation paths
 * against the frozen node hashes.  That machinery is node-hash-agnostic,
 * so it is not re-run here.  What this file adds is the end-to-end
 * sign/verify round-trip (plus the documented tamper rejections and the
 * X-10 wrong-witness rejection) driven through each norm twin of the
 * node hashes the frozen suite uses as a tree hash:
 *
 *   frozen tree hash          norm twin exercised here
 *   voleith_node_hash_aes_dm          -> aes_dm_norm
 *   voleith_node_hash_aes_cmac128     -> aes_cmac128_norm
 *   voleith_node_hash_hirose          -> hirose_norm
 *   voleith_node_hash_hirose_fixed32  -> hirose_fixed32_norm
 *
 * This mirrors the node hashes the frozen V1 suite uses as a tree hash.
 * The only other node hash the frozen suite names is the DEPRECATED
 * variable-input Grostl (voleith_node_hash_grostl256, used there just as
 * an owf in a validate-rejection); it has no norm twin, so it is not
 * exercised here.
 *
 * Each norm ring is a DISTINCT ring config from its frozen counterpart
 * (the node-hash name feeds the cfg fingerprint), so the per-case
 * fingerprint check asserts norm_fp != frozen_fp rather than baking a
 * golden: the distinctness is the design contract, and it is verified
 * in-process without a hand-derived SHAKE constant.
 */

#include "ring_sig_v1_gf8.h"

#include "gf8_circuit.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "rs_membership_gf8_circuit.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wraps a fallible call so it is ALWAYS evaluated, even when NDEBUG
 * elides assert().  Same idiom as the rest of the test suite. */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

#define RING_DEPTH 3u
#define RING_N (1u << RING_DEPTH)
#define RING_SIGNER 5u

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
 * One norm ring-hash case: the norm vt under test, its frozen twin (for
 * the fingerprint-distinctness assertion), and the sk width the V1
 * OWF-leaf requires for that vt.
 */
typedef struct {
    const char *label;
    const voleith_node_hash_vt *norm;
    const voleith_node_hash_vt *frozen;
    size_t sk_bytes;
} norm_case_t;

static const norm_case_t CASES[] = {
    {"aes-dm", &voleith_node_hash_aes_dm_norm, &voleith_node_hash_aes_dm, 16},
    {"aes-cmac128", &voleith_node_hash_aes_cmac128_norm,
     &voleith_node_hash_aes_cmac128, 16},
    {"hirose", &voleith_node_hash_hirose_norm, &voleith_node_hash_hirose, 32},
    {"hirose-fixed32", &voleith_node_hash_hirose_fixed32_norm,
     &voleith_node_hash_hirose_fixed32, 32},
};

static voleith_params_t
case_params(void)
{
    return voleith_params_em_128f;
}

static voleith_rs_membership_config_t
case_cfg(const norm_case_t *tc)
{
    voleith_rs_membership_config_t cfg;
    cfg.tree_hash = tc->norm;
    cfg.owf_hash = NULL;
    cfg.sk_bytes = tc->sk_bytes;
    cfg.depth_m = RING_DEPTH;
    cfg.depth_r = 0;
    return cfg;
}

/* Build a RING_N-member depth-RING_DEPTH ring for cfg.  Caller frees all
 * four output buffers. */
static void
build_ring(const voleith_rs_membership_config_t *cfg, uint8_t **sks_out,
           uint8_t **root_out, voleith_rs_membership_path_t **paths_out,
           uint8_t **sib_storage_out)
{
    size_t W = cfg->tree_hash->node_bytes;
    size_t sk_bytes = cfg->sk_bytes;
    uint8_t *sks = calloc(RING_N * sk_bytes, 1);
    uint8_t *root = calloc(W, 1);
    voleith_rs_membership_path_t *paths =
        calloc(RING_N, sizeof(voleith_rs_membership_path_t));
    uint8_t *sib_storage = calloc(RING_N * cfg->depth_m * W, 1);
    assert(sks && root && paths && sib_storage);

    for (size_t i = 0; i < RING_N; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    MUST_OK(
        voleith_rsv1_ring_build(cfg, sks, RING_N, root, paths, sib_storage));

    *sks_out = sks;
    *root_out = root;
    *paths_out = paths;
    *sib_storage_out = sib_storage;
}

/* ================================================================
 * Per-case: cfg fingerprint is distinct from the frozen twin (the
 * norm ring is a different ring) and deterministic.
 * ================================================================ */
static void
test_case_fingerprint(const norm_case_t *tc)
{
    char label[96];
    voleith_rs_membership_config_t cfg = case_cfg(tc);
    voleith_rs_membership_config_t frozen = cfg;
    frozen.tree_hash = tc->frozen;

    uint8_t fp_norm1[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp_norm2[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t fp_frozen[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];

    MUST_OK(voleith_rsv1_config_fingerprint(&cfg, fp_norm1));
    MUST_OK(voleith_rsv1_config_fingerprint(&cfg, fp_norm2));
    MUST_OK(voleith_rsv1_config_fingerprint(&frozen, fp_frozen));

    snprintf(label, sizeof(label), "%s: norm fingerprint deterministic",
             tc->label);
    check(label, memcmp(fp_norm1, fp_norm2, sizeof(fp_norm1)) == 0);

    snprintf(label, sizeof(label), "%s: norm fingerprint != frozen twin",
             tc->label);
    check(label, memcmp(fp_norm1, fp_frozen, sizeof(fp_norm1)) != 0);
}

/* ================================================================
 * Per-case: sign/verify round-trip accepts, and the documented
 * tamper paths (sig bytes, root, message, cfg) all reject at verify.
 * ================================================================ */
static void
test_case_sign_verify(const norm_case_t *tc)
{
    char label[96];
    voleith_rs_membership_config_t cfg = case_cfg(tc);
    voleith_params_t params = case_params();
    size_t W = cfg.tree_hash->node_bytes;
    size_t sk_bytes = cfg.sk_bytes;
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};
    const uint8_t m[] = "norm ring round-trip";
    size_t m_len = sizeof(m) - 1;

    build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    int sign_rc =
        voleith_rsv1_sign(&sig, &cfg, &params, sks + RING_SIGNER * sk_bytes,
                          root, &paths[RING_SIGNER], NULL, NULL, m, m_len);
    snprintf(label, sizeof(label), "%s: sign succeeds", tc->label);
    check(label, sign_rc == 0);
    snprintf(label, sizeof(label), "%s: sig.data populated", tc->label);
    check(label, sig.data != NULL && sig.len > 0);

    if (sign_rc == 0) {
        snprintf(label, sizeof(label), "%s: verify accepts", tc->label);
        check(label, voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m,
                                         m_len) == 0);

        /* Tamper proof bytes. */
        sig.data[0] ^= 0x01;
        snprintf(label, sizeof(label), "%s: tampered sig rejects", tc->label);
        check(label, voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, m,
                                         m_len) == -1);
        sig.data[0] ^= 0x01;

        /* Tamper R. */
        uint8_t bad_root[MERKLE_VT_MAX_NODE_BYTES];
        memcpy(bad_root, root, W);
        bad_root[0] ^= 0x01;
        snprintf(label, sizeof(label), "%s: tampered R rejects", tc->label);
        check(label, voleith_rsv1_verify(&sig, &cfg, &params, bad_root, NULL, m,
                                         m_len) == -1);

        /* Tamper m. */
        uint8_t bad_m[sizeof(m)];
        memcpy(bad_m, m, m_len);
        bad_m[0] ^= 0x01;
        snprintf(label, sizeof(label), "%s: tampered m rejects", tc->label);
        check(label, voleith_rsv1_verify(&sig, &cfg, &params, root, NULL, bad_m,
                                         m_len) == -1);

        /* Tamper cfg: different depth_m -> different fingerprint ->
         * different fs_seed -> verifier challenges desynchronise. */
        voleith_rs_membership_config_t cfg_bad = cfg;
        cfg_bad.depth_m = cfg.depth_m + 1;
        snprintf(label, sizeof(label), "%s: tampered cfg rejects", tc->label);
        check(label, voleith_rsv1_verify(&sig, &cfg_bad, &params, root, NULL, m,
                                         m_len) == -1);
    }

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

/* ================================================================
 * Per-case: signing with the wrong sk (another member's) against the
 * signer's path presents a non-satisfying witness, which X-10 prove
 * rejects up-front (rc == -1, sig left zeroed).
 * ================================================================ */
static void
test_case_wrong_sk(const norm_case_t *tc)
{
    char label[96];
    voleith_rs_membership_config_t cfg = case_cfg(tc);
    voleith_params_t params = case_params();
    size_t sk_bytes = cfg.sk_bytes;
    uint8_t *sks, *root;
    voleith_rs_membership_path_t *paths;
    uint8_t *sib_storage;
    voleith_ring_sig_t sig = {NULL, 0};

    build_ring(&cfg, &sks, &root, &paths, &sib_storage);

    /* Member 2's sk at member 5's path slot: leaf computed from sk(2)
     * does not sit at index 5, eval fails, prove rejects. */
    int rc = voleith_rsv1_sign(&sig, &cfg, &params, sks + 2 * sk_bytes, root,
                               &paths[RING_SIGNER], NULL, NULL,
                               (const uint8_t *)"x", 1);
    snprintf(label, sizeof(label), "%s: wrong sk rejected at sign", tc->label);
    check(label, rc == -1);
    snprintf(label, sizeof(label), "%s: failed sign leaves sig zeroed",
             tc->label);
    check(label, sig.data == NULL && sig.len == 0);

    voleith_ring_sig_free(&sig);
    free(sks);
    free(root);
    free(paths);
    free(sib_storage);
}

int
main(void)
{
    size_t n_cases = sizeof(CASES) / sizeof(CASES[0]);

    printf("test_ring_sig_v1_norm_gf8: starting\n");
    for (size_t i = 0; i < n_cases; i++) {
        test_case_fingerprint(&CASES[i]);
        test_case_sign_verify(&CASES[i]);
        test_case_wrong_sk(&CASES[i]);
    }
    printf("test_ring_sig_v1_norm_gf8: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
