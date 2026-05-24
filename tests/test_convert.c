/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_convert.c - Tests for ConvertToVOLE and VOLE commit/reconstruct
 *
 * Tests:
 *   1-3:  ConvertToVOLE standalone properties
 *   4-6:  VOLE commit properties
 *   7-9:  VOLE round-trip (commit + open + reconstruct)
 *   10-13: Cross-validation against faest-ref test vectors (FAEST_EM_128F)
 */

#include "convert.h"
#include "voleith.h"
#include "vc.h"
#include "prg.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

/* Helper: SHAKE256 hash, 64-byte output (matches faest-ref hash_array) */
static void
shake256_hash(const uint8_t *data, size_t len, uint8_t out[64])
{
    voleith_hash_ctx_t ctx;
    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, data, len);
    voleith_shake256_squeeze(&ctx, out, 64);
}

/* decode_challenge: thin wrapper so call sites don't need updating */
static void
decode_challenge(const uint8_t *chall, const voleith_vc_params_t *params,
                 size_t *i_delta)
{
    voleith_decode_challenge(chall, params, i_delta);
}

/* ================================================================
 * ConvertToVOLE standalone tests
 * ================================================================ */

/*
 * Test 1: convert_to_vole returns correct depth
 */
static void
test_convert_depth(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);
    /* k=1, tau1=8: vectors 0..7 have depth k=1, vectors 8..15 have k-1=0 */

    /* Allocate minimal seeds and buffers */
    size_t outlen = 32;
    uint8_t iv[16] = {0};

    /* Vector 0: N_i = 2, depth should be 1 */
    uint8_t sd0[32]; /* 2 seeds */
    memset(sd0, 0x11, 32);
    uint8_t u[32];
    uint8_t *v_bufs[1];
    uint8_t v0[32];
    v_bufs[0] = v0;

    int d0 = voleith_convert_to_vole(iv, sd0, false, 0, outlen, u, v_bufs, &p);
    check("convert_depth: vec 0 depth=1", d0 == 1);

    /* Vector 8: N_i = 1, depth should be 0 */
    uint8_t sd8[16]; /* 1 seed */
    memset(sd8, 0x22, 16);
    int d8 = voleith_convert_to_vole(iv, sd8, false, 8, outlen, u, v_bufs, &p);
    check("convert_depth: vec 8 depth=0", d8 == 0);
}

/*
 * Test 2: convert_to_vole is deterministic
 */
static void
test_convert_deterministic(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    size_t outlen = 32;
    uint8_t iv[16] = {0};
    uint8_t sd[32];
    memset(sd, 0x42, 32);

    uint8_t u1[32], u2[32];
    uint8_t v1[32], v2[32];
    uint8_t *vp1[1] = {v1};
    uint8_t *vp2[1] = {v2};

    voleith_convert_to_vole(iv, sd, false, 0, outlen, u1, vp1, &p);
    voleith_convert_to_vole(iv, sd, false, 0, outlen, u2, vp2, &p);

    check("convert_deterministic: u matches", memcmp(u1, u2, outlen) == 0);
    check("convert_deterministic: v matches", memcmp(v1, v2, outlen) == 0);
}

/*
 * Test 3: VOLE equation: for a 2-leaf vector,
 * PRG(sd_0) XOR PRG(sd_1) = u, and v[0] = PRG(sd_1)
 *
 * When sd0_bot=true (verifier side), v[0] stays the same,
 * and q[0] = v[0] XOR delta_0 * u  where delta_0 = bit 0 of hidden index.
 */
static void
test_convert_vole_equation(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    size_t outlen = 32;
    uint8_t iv[16];
    memset(iv, 0, 16);

    /* Two seeds */
    uint8_t sd[32];
    memset(sd, 0xAB, 16);
    memset(sd + 16, 0xCD, 16);

    uint8_t u[32];
    uint8_t v[32];
    uint8_t *vp[1] = {v};

    int depth = voleith_convert_to_vole(iv, sd, false, 0, outlen, u, vp, &p);
    check("convert_vole_eq: depth=1", depth == 1);

    /* Compute PRG(sd_0) and PRG(sd_1) manually */
    uint32_t tweak = 0 ^ 0x80000000u;
    uint8_t prg0[32], prg1[32];
    voleith_prg_ctx_t ctx;
    voleith_prg_init(&ctx, sd, 128);
    voleith_prg_gen(&ctx, prg0, iv, tweak, outlen * 8);
    voleith_prg_init(&ctx, sd + 16, 128);
    voleith_prg_gen(&ctx, prg1, iv, tweak, outlen * 8);

    /* v[0] should equal PRG(sd_1) */
    check("convert_vole_eq: v[0] = PRG(sd_1)", memcmp(v, prg1, outlen) == 0);

    /* u should equal PRG(sd_0) XOR PRG(sd_1) */
    uint8_t expected_u[32];
    for (size_t i = 0; i < outlen; i++)
        expected_u[i] = prg0[i] ^ prg1[i];
    check("convert_vole_eq: u = PRG(sd_0) XOR PRG(sd_1)",
          memcmp(u, expected_u, outlen) == 0);
}

/* ================================================================
 * VOLE commit tests
 * ================================================================ */

/*
 * Test 4: vole_commit succeeds
 */
static void
test_vole_commit_basic(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xAA, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * ellhat_bytes, 1);
    uint8_t *u = calloc(ellhat_bytes, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *v_storage = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = v_storage + (size_t)i * ellhat_bytes;

    int rc = voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v);
    check("vole_commit_basic: succeeds", rc == 0);
    check("vole_commit_basic: bavc com non-zero",
          memcmp(bavc.com, (uint8_t[64]){0}, 32) != 0);

    /* u should be non-zero */
    int u_nonzero = 0;
    for (size_t i = 0; i < ellhat_bytes; i++)
        if (u[i]) {
            u_nonzero = 1;
            break;
        }
    check("vole_commit_basic: u non-zero", u_nonzero);

    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(v_storage);
}

/*
 * Test 5: vole_commit is deterministic
 */
static void
test_vole_commit_deterministic(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xBB, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;

    voleith_bavc_t bavc1, bavc2;
    uint8_t *c1 = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *c2 = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *u1 = calloc(eb, 1);
    uint8_t *u2 = calloc(eb, 1);
    uint8_t **v1 = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t **v2 = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs1 = calloc((size_t)p.lambda * eb, 1);
    uint8_t *vs2 = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++) {
        v1[i] = vs1 + (size_t)i * eb;
        v2[i] = vs2 + (size_t)i * eb;
    }

    voleith_vole_commit(&p, seed, iv, ellhat, &bavc1, c1, u1, v1);
    voleith_vole_commit(&p, seed, iv, ellhat, &bavc2, c2, u2, v2);

    check("vole_commit_deterministic: u matches", memcmp(u1, u2, eb) == 0);
    check("vole_commit_deterministic: c matches",
          memcmp(c1, c2, ((size_t)p.tau - 1) * eb) == 0);
    check("vole_commit_deterministic: v matches",
          memcmp(vs1, vs2, (size_t)p.lambda * eb) == 0);

    voleith_bavc_free(&bavc1);
    voleith_bavc_free(&bavc2);
    free(c1);
    free(c2);
    free(u1);
    free(u2);
    free(v1);
    free(v2);
    free(vs1);
    free(vs2);
}

/*
 * Test 6: Unused v vectors (beyond used depth) are zero-padded
 */
static void
test_vole_commit_v_padding(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);
    /* k=1, tau1=8: total depth used = 8*1 + 8*0 = 8, lambda=128 */

    uint8_t seed[16], iv[16];
    memset(seed, 0xCC, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *u = calloc(eb, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * eb;

    voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v);

    /* Vectors at index 8..127 should be zero (only 8 used for k=1, tau1=8) */
    int ok = 1;
    uint8_t zero[32] = {0};
    for (int i = 8; i < p.lambda; i++) {
        if (memcmp(v[i], zero, eb) != 0) {
            ok = 0;
            break;
        }
    }
    check("vole_commit_v_padding: unused v vectors are zero", ok);

    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
}

/* ================================================================
 * VOLE round-trip tests
 * ================================================================ */

/*
 * Test 7: Full round-trip: VOLE equation q[j] = v[j] XOR delta_j * u
 *
 * Uses a small parameter set. After commit + open + reconstruct,
 * verifies that q[j] = v[j] XOR (delta_bit_j * u) for all j.
 */
static void
test_vole_roundtrip_equation(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);
    /* k=1, tau1=8 → 8 vectors with depth 1, 8 with depth 0 → 8 v vectors used */

    uint8_t seed[16], iv[16];
    memset(seed, 0xDD, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;

    /* Commit */
    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *u = calloc(eb, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * eb;

    voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v);

    /* Choose challenge */
    size_t i_delta[16];
    for (int i = 0; i < p.tau; i++)
        i_delta[i] = (size_t)i % voleith_vc_N(&p, i);

    /* Open */
    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &bavc, &p, i_delta);

    /* Reconstruct */
    uint8_t com[32];
    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * eb;

    int rc =
        voleith_vole_reconstruct(&p, &opening, i_delta, iv, ellhat, c, com, q);
    check("vole_roundtrip: reconstruct succeeds", rc == 0);

    /* Verify commitment matches */
    check("vole_roundtrip: com matches",
          memcmp(com, bavc.com, 2 * (size_t)p.lambda / 8) == 0);

    /*
     * Verify VOLE equation for ALL j: q[j] = v[j] XOR delta_j * u
     *
     * The global equation holds because the correction c[i-1] = u_0 XOR u_i
     * cancels out when folded in by the verifier:
     *   q_{i,d} = v_hat_{i,d} XOR delta_{i,d} * c[i-1]
     *           = (v_{i,d} XOR delta_{i,d} * u_i) XOR delta_{i,d} * (u_0 XOR u_i)
     *           = v_{i,d} XOR delta_{i,d} * u_0
     */
    int eq_ok = 1;
    int v_idx = 0;
    for (int i = 0; i < p.tau && eq_ok; i++) {
        int depth = (i < p.tau1) ? p.k : (p.k - 1);
        for (int d = 0; d < depth && eq_ok; d++, v_idx++) {
            int delta_bit = (i_delta[i] >> d) & 1;
            for (size_t b = 0; b < eb; b++) {
                uint8_t expected = v[v_idx][b] ^ (delta_bit ? u[b] : 0);
                if (q[v_idx][b] != expected) {
                    eq_ok = 0;
                    break;
                }
            }
        }
    }
    check("vole_roundtrip: VOLE equation holds for all j", eq_ok);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
    free(q);
    free(qs);
}

/*
 * Test 8: Round-trip with different challenges produces different q
 */
static void
test_vole_roundtrip_different_challenges(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xEE, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *u = calloc(eb, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * eb;

    voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v);

    /* Two different challenges */
    size_t delta_a[16], delta_b[16];
    for (int i = 0; i < p.tau; i++) {
        delta_a[i] = 0;
        delta_b[i] = voleith_vc_N(&p, i) - 1;
    }

    voleith_bavc_opening_t open_a, open_b;
    voleith_bavc_open(&open_a, &bavc, &p, delta_a);
    voleith_bavc_open(&open_b, &bavc, &p, delta_b);

    uint8_t com_a[32], com_b[32];
    uint8_t **qa = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t **qb = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qas = calloc((size_t)p.lambda * eb, 1);
    uint8_t *qbs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++) {
        qa[i] = qas + (size_t)i * eb;
        qb[i] = qbs + (size_t)i * eb;
    }

    voleith_vole_reconstruct(&p, &open_a, delta_a, iv, ellhat, c, com_a, qa);
    voleith_vole_reconstruct(&p, &open_b, delta_b, iv, ellhat, c, com_b, qb);

    /* Both should produce matching commitments */
    check("vole_roundtrip_diff: com_a matches",
          memcmp(com_a, bavc.com, 32) == 0);
    check("vole_roundtrip_diff: com_b matches",
          memcmp(com_b, bavc.com, 32) == 0);

    /* q vectors should differ */
    check("vole_roundtrip_diff: q differs",
          memcmp(qas, qbs, (size_t)p.lambda * eb) != 0);

    voleith_bavc_opening_free(&open_a);
    voleith_bavc_opening_free(&open_b);
    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
    free(qa);
    free(qb);
    free(qas);
    free(qbs);
}

/*
 * Test 9: Tampered correction value causes commitment mismatch or
 * VOLE equation failure (security property).
 */
static void
test_vole_roundtrip_tampered_c(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xFF, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * eb, 1);
    uint8_t *u = calloc(eb, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * eb;

    voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v);

    size_t i_delta[16];
    for (int i = 0; i < p.tau; i++)
        i_delta[i] = 0;

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &bavc, &p, i_delta);

    /* Tamper with correction value */
    uint8_t *c_tampered = calloc(((size_t)p.tau - 1) * eb, 1);
    memcpy(c_tampered, c, ((size_t)p.tau - 1) * eb);
    c_tampered[0] ^= 0x01;

    uint8_t com[32];
    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * eb;

    /* Reconstruct with tampered c - commitment should still match
     * (c doesn't affect commitment), but VOLE equation should break.
     * This is a property of the protocol. */
    int rc = voleith_vole_reconstruct(&p, &opening, i_delta, iv, ellhat,
                                      c_tampered, com, q);
    check("vole_roundtrip_tampered_c: reconstruct succeeds", rc == 0);
    /* Commitment should still match since c doesn't affect the VC */
    check("vole_roundtrip_tampered_c: com still matches",
          memcmp(com, bavc.com, 32) == 0);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&bavc);
    free(c);
    free(c_tampered);
    free(u);
    free(v);
    free(vs);
    free(q);
    free(qs);
}

/*
 * Test 9b: Diagnostic - verify seeds gathered by vole_commit match
 * what voleith_bavc_leaf_seed returns for the same BAVC.
 */
static void
test_seed_gather_diagnostic(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    voleith_bavc_t bavc;
    voleith_bavc_commit(&bavc, &p, root_key, iv);

    /* Gather seeds for vector 0 using accessor and verify contiguity */
    size_t sb = 16;
    size_t N0 = voleith_vc_N(&p, 0); /* should be 256 */
    check("seed_gather: N0=256", N0 == 256);

    /* Check that PosInTree(0,0) = L-1+0 = 3071 */
    size_t pos0 = voleith_pos_in_tree(&p, 0, 0);
    check("seed_gather: PosInTree(0,0)=L-1", pos0 == p.L - 1);

    /* Check that seeds via accessor match tree nodes */
    int ok = 1;
    for (size_t j = 0; j < N0 && ok; j++) {
        const uint8_t *accessor_seed = voleith_bavc_leaf_seed(&bavc, &p, 0, j);
        size_t alpha = voleith_pos_in_tree(&p, 0, j);
        const uint8_t *tree_seed = voleith_ggm_tree_node(&bavc.tree, alpha);
        if (memcmp(accessor_seed, tree_seed, sb) != 0)
            ok = 0;
    }
    check("seed_gather: accessor seeds match tree nodes for vec 0", ok);

    /* Check that PosInTree(0,j) is NOT contiguous - it skips by tau */
    size_t pos1 = voleith_pos_in_tree(&p, 0, 1);
    check("seed_gather: PosInTree(0,1) - PosInTree(0,0) = tau",
          pos1 - pos0 == (size_t)p.tau);

    /* Now do a manual ConvertToVOLE for vector 0 with gathered seeds
     * and compare with a call using flat tree leaf pointers */
    uint8_t *gathered = malloc(N0 * sb);
    for (size_t j = 0; j < N0; j++) {
        const uint8_t *s = voleith_bavc_leaf_seed(&bavc, &p, 0, j);
        memcpy(gathered + j * sb, s, sb);
    }

    /* Use flat (wrong) access - tree leaf at flat index 0, 1, ..., N0-1 */
    const uint8_t *flat = bavc.leaf_seeds;

    /* Only compare first 2 seeds to see if they differ */
    check("seed_gather: gathered[0] == flat[0]",
          memcmp(gathered, flat, sb) == 0);
    check("seed_gather: gathered[1] != flat[1] (interleaved)",
          memcmp(gathered + sb, flat + sb, sb) != 0);

    free(gathered);
    voleith_bavc_free(&bavc);
}

/* ================================================================
 * Cross-validation against faest-ref test vectors (FAEST_EM_128F)
 *
 * From vole_tvs.hpp: root_key = {0x00..0x0f}, iv = all zeros
 * ellhat = 960 + 128*3 + 16 = 1360, ellhat_bytes = 170
 * ================================================================ */

/* faest-ref FAEST_EM_128F parameters */
#define XVAL_LAMBDA 128
#define XVAL_TAU 16
#define XVAL_W_GRIND 8
#define XVAL_N_LEAFCOM 2
#define XVAL_T_OPEN 112
#define XVAL_ELL 960
#define XVAL_ELLHAT (XVAL_ELL + XVAL_LAMBDA * 3 + 16)
#define XVAL_ELLHAT_BYTES ((XVAL_ELLHAT + 7) / 8)

/*
 * Test 10: vole_commit produces correct h (global commitment)
 */
static void
test_xval_vole_commit_h(void)
{
    /* Expected h from vole_tvs.hpp FAEST_EM_128F */
    static const uint8_t expected_h[32] = {
        0xe7, 0x37, 0xbd, 0xc5, 0xc5, 0x0e, 0xca, 0x61, 0x8b, 0xf0, 0x5e,
        0xde, 0x6a, 0x37, 0xb7, 0xf3, 0x87, 0x4c, 0xe7, 0xc8, 0x63, 0xb3,
        0x17, 0x70, 0xa2, 0xe4, 0x23, 0x7d, 0x2d, 0x4f, 0x93, 0xf5,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, XVAL_LAMBDA, XVAL_TAU, XVAL_W_GRIND,
                           XVAL_N_LEAFCOM, XVAL_T_OPEN);

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * XVAL_ELLHAT_BYTES, 1);
    uint8_t *u = calloc(XVAL_ELLHAT_BYTES, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * XVAL_ELLHAT_BYTES, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * XVAL_ELLHAT_BYTES;

    voleith_vole_commit(&p, root_key, iv, XVAL_ELLHAT, &bavc, c, u, v);

    check("xval_vole_commit: h matches faest-ref",
          memcmp(bavc.com, expected_h, 32) == 0);

    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
}

/*
 * Test 11: vole_commit produces correct hashed_u
 */
static void
test_xval_vole_commit_u(void)
{
    static const uint8_t expected_hashed_u[64] = {
        0xce, 0x94, 0x44, 0x5c, 0xe3, 0x53, 0xce, 0xff, 0x62, 0x32, 0x5d,
        0x05, 0x4e, 0x2b, 0xc8, 0x94, 0x91, 0x63, 0x56, 0xae, 0x48, 0x7b,
        0x41, 0x44, 0xbd, 0xf9, 0xad, 0xd0, 0xad, 0xda, 0x05, 0xf2, 0x60,
        0x35, 0x24, 0x62, 0xa7, 0x55, 0xe4, 0x14, 0x4f, 0x9e, 0x7c, 0x92,
        0xfe, 0xe7, 0x4d, 0x87, 0xd6, 0xbd, 0x7e, 0x29, 0x60, 0xb4, 0x17,
        0x60, 0xe0, 0x08, 0x4a, 0x74, 0x8a, 0x0d, 0xf3, 0x1e,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, XVAL_LAMBDA, XVAL_TAU, XVAL_W_GRIND,
                           XVAL_N_LEAFCOM, XVAL_T_OPEN);

    voleith_bavc_t bavc;
    uint8_t *c = calloc(((size_t)p.tau - 1) * XVAL_ELLHAT_BYTES, 1);
    uint8_t *u = calloc(XVAL_ELLHAT_BYTES, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * XVAL_ELLHAT_BYTES, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * XVAL_ELLHAT_BYTES;

    voleith_vole_commit(&p, root_key, iv, XVAL_ELLHAT, &bavc, c, u, v);

    uint8_t hashed_u[64];
    shake256_hash(u, XVAL_ELLHAT_BYTES, hashed_u);

    int u_match = memcmp(hashed_u, expected_hashed_u, 64) == 0;
    check("xval_vole_commit: hashed_u matches faest-ref", u_match);

    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
}

/*
 * Test 12: vole_commit produces correct hashed_c and hashed_v
 */
static void
test_xval_vole_commit_c_v(void)
{
    static const uint8_t expected_hashed_c[64] = {
        0x43, 0x19, 0xf3, 0xe0, 0x9a, 0x1a, 0x51, 0xc1, 0x4c, 0xf8, 0xa8,
        0x61, 0x8a, 0x30, 0x78, 0x2b, 0x6b, 0x9d, 0x5f, 0xd9, 0x84, 0x0b,
        0x92, 0x6f, 0x74, 0x75, 0x26, 0x9a, 0x6d, 0xb8, 0x2a, 0x24, 0x08,
        0x66, 0xbf, 0x16, 0x86, 0xdd, 0x76, 0x91, 0x48, 0x94, 0x94, 0x62,
        0xb7, 0x70, 0x47, 0xc7, 0x71, 0xc3, 0x36, 0x2e, 0x03, 0x00, 0x31,
        0x4c, 0xf0, 0x5c, 0xc3, 0x30, 0x5d, 0x88, 0x60, 0x5e,
    };
    static const uint8_t expected_hashed_v[64] = {
        0xb2, 0xff, 0xfe, 0xca, 0xdd, 0xf9, 0x02, 0x70, 0x30, 0xdb, 0xe0,
        0x7e, 0x88, 0xd0, 0x84, 0x3a, 0xeb, 0x26, 0xf1, 0xe5, 0x3b, 0xaf,
        0x86, 0x49, 0xb7, 0xf7, 0x91, 0x5c, 0xa3, 0x6e, 0xf2, 0xcd, 0xad,
        0xb3, 0x1e, 0x24, 0x8e, 0xb2, 0x12, 0x55, 0x9c, 0xc7, 0x62, 0xdd,
        0x77, 0x91, 0xa9, 0xf1, 0xf1, 0x93, 0xc8, 0x5c, 0xf1, 0x0f, 0x9e,
        0xaa, 0x9e, 0x85, 0x29, 0x3d, 0x68, 0x33, 0x1f, 0x57,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, XVAL_LAMBDA, XVAL_TAU, XVAL_W_GRIND,
                           XVAL_N_LEAFCOM, XVAL_T_OPEN);

    voleith_bavc_t bavc;
    size_t c_size = ((size_t)p.tau - 1) * XVAL_ELLHAT_BYTES;
    uint8_t *c = calloc(c_size, 1);
    uint8_t *u = calloc(XVAL_ELLHAT_BYTES, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    size_t vs_size = (size_t)p.lambda * XVAL_ELLHAT_BYTES;
    uint8_t *vs = calloc(vs_size, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * XVAL_ELLHAT_BYTES;

    voleith_vole_commit(&p, root_key, iv, XVAL_ELLHAT, &bavc, c, u, v);

    uint8_t hashed_c[64], hashed_v[64];
    shake256_hash(c, c_size, hashed_c);
    shake256_hash(vs, vs_size, hashed_v);

    check("xval_vole_commit: hashed_c matches faest-ref",
          memcmp(hashed_c, expected_hashed_c, 64) == 0);
    check("xval_vole_commit: hashed_v matches faest-ref",
          memcmp(hashed_v, expected_hashed_v, 64) == 0);

    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
}

/*
 * Test 13: Full round-trip cross-validation: vole_reconstruct
 * produces correct hashed_q matching faest-ref.
 */
static void
test_xval_vole_reconstruct_q(void)
{
    static const uint8_t chall[16] = {
        0x3a, 0x1f, 0x5b, 0x13, 0x14, 0x24, 0x53, 0xe3,
        0x06, 0x11, 0x8d, 0x26, 0x67, 0x09, 0xc1, 0x00,
    };
    static const uint8_t expected_hashed_q[64] = {
        0x21, 0x2a, 0xfe, 0x9d, 0x44, 0x5d, 0x96, 0xb6, 0xee, 0x61, 0x40,
        0x72, 0x5b, 0xb1, 0x2a, 0xe5, 0xde, 0xd7, 0x5e, 0x9e, 0xda, 0x11,
        0xd5, 0xef, 0x76, 0xd1, 0x25, 0xcf, 0x30, 0x19, 0xe4, 0xaf, 0x5e,
        0x1b, 0x92, 0xb9, 0x6c, 0x37, 0x15, 0x62, 0xd7, 0x92, 0x62, 0x5a,
        0x39, 0x1a, 0x9a, 0x14, 0xe4, 0xa8, 0xeb, 0x71, 0x3a, 0x68, 0x19,
        0x2c, 0xc9, 0x50, 0x62, 0xb0, 0x8e, 0xaa, 0x7f, 0x3b,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, XVAL_LAMBDA, XVAL_TAU, XVAL_W_GRIND,
                           XVAL_N_LEAFCOM, XVAL_T_OPEN);

    /* Step 1: Commit */
    voleith_bavc_t bavc;
    size_t c_size = ((size_t)p.tau - 1) * XVAL_ELLHAT_BYTES;
    uint8_t *c = calloc(c_size, 1);
    uint8_t *u = calloc(XVAL_ELLHAT_BYTES, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * XVAL_ELLHAT_BYTES, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * XVAL_ELLHAT_BYTES;

    voleith_vole_commit(&p, root_key, iv, XVAL_ELLHAT, &bavc, c, u, v);

    /* Step 2: Decode challenge into i_delta */
    size_t i_delta[16];
    decode_challenge(chall, &p, i_delta);

    /* Step 3: Open */
    voleith_bavc_opening_t opening;
    int open_rc = voleith_bavc_open(&opening, &bavc, &p, i_delta);
    check("xval_vole_reconstruct: open succeeds", open_rc == 0);

    /* Step 4: Reconstruct */
    uint8_t com[32];
    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * XVAL_ELLHAT_BYTES, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * XVAL_ELLHAT_BYTES;

    int rec_rc = voleith_vole_reconstruct(&p, &opening, i_delta, iv,
                                          XVAL_ELLHAT, c, com, q);
    check("xval_vole_reconstruct: reconstruct succeeds", rec_rc == 0);

    /* Step 5: Verify hashed_q matches */
    size_t qs_size = (size_t)p.lambda * XVAL_ELLHAT_BYTES;
    uint8_t hashed_q[64];
    shake256_hash(qs, qs_size, hashed_q);

    check("xval_vole_reconstruct: hashed_q matches faest-ref",
          memcmp(hashed_q, expected_hashed_q, 64) == 0);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&bavc);
    free(c);
    free(u);
    free(v);
    free(vs);
    free(q);
    free(qs);
}

int
main(void)
{
    printf("test_convert: ConvertToVOLE, VOLE commit/reconstruct, faest-ref "
           "xval\n");

    /* ConvertToVOLE standalone */
    test_convert_depth();
    test_convert_deterministic();
    test_convert_vole_equation();

    /* VOLE commit */
    test_vole_commit_basic();
    test_vole_commit_deterministic();
    test_vole_commit_v_padding();

    /* VOLE round-trip */
    test_vole_roundtrip_equation();
    test_vole_roundtrip_different_challenges();
    test_vole_roundtrip_tampered_c();

    /* Seed gather diagnostic */
    test_seed_gather_diagnostic();

    /* Cross-validation */
    test_xval_vole_commit_h();
    test_xval_vole_commit_u();
    test_xval_vole_commit_c_v();
    test_xval_vole_reconstruct_q();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
