/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_voleith.c - Tests for the VOLEitH protocol layer (vole/voleith.c)
 *
 * Tests:
 *   1: decode_challenge extracts correct indices
 *   2: Full round-trip: commit → decode → open → reconstruct (commitment check passes)
 *   3: VOLE equation holds for all j after round-trip
 *   4: Different challenges produce different q but same hcom
 *   5: Tampered opening causes commitment mismatch
 *   6: Tampered hcom causes commitment mismatch
 */

#include "voleith.h"
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

/*
 * Small parameter set used throughout:
 * lambda=128, tau=16, k=1, tau1=8 → 8 v/q vectors, small L
 */
static void
make_small_params(voleith_vc_params_t *p)
{
    voleith_vc_params_init(p, 128, 16, 120, 2, 24);
}

/*
 * Test 1: decode_challenge extracts bit groups correctly.
 *
 * With k=1, tau1=8: first 8 vectors get 1 bit each, next 8 get 0 bits each
 * (k-1=0, so depth is 0 and they contribute no index bits - they always
 * take index 0). The first 8 bits of delta map to i_delta[0..7].
 */
static void
test_decode_challenge_basic(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    /* delta = 0b10110100 ... (packed LE) → bits 0..7 = 0,0,1,0,1,1,0,1 */
    uint8_t delta[16] = {0xB4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t i_delta[16];
    voleith_decode_challenge(delta, &p, i_delta);

    /* k=1, so each of the first 8 vectors takes 1 bit */
    /* 0xB4 = 0b10110100, LE bit order: bit0=0,bit1=0,bit2=1,bit3=0,bit4=1,bit5=1,bit6=0,bit7=1 */
    static const size_t expected[8] = {0, 0, 1, 0, 1, 1, 0, 1};
    int ok = 1;
    for (int i = 0; i < 8; i++) {
        if (i_delta[i] != expected[i]) {
            ok = 0;
            break;
        }
    }
    /* vectors 8..15 have depth k-1=0, so they always get index 0 */
    for (int i = 8; i < 16; i++) {
        if (i_delta[i] != 0) {
            ok = 0;
            break;
        }
    }
    check("decode_challenge: basic bit extraction", ok);
}

/*
 * Test 1b: decode_challenge with k=8 (FAEST_EM_128F parameters).
 *
 * lambda=128, tau=16, k=8, tau1=8
 * Vectors 0..7 take 8 bits each (bits 0-63), vectors 8..15 take 7 bits each
 * (bits 64-119). The 7-bit windows cross byte boundaries, so individual bit
 * positions must be tracked carefully.
 */
static void
test_decode_challenge_k8(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    size_t i_delta[16];

    /* All-zero delta → all indices 0 */
    uint8_t delta[16];
    memset(delta, 0, 16);
    voleith_decode_challenge(delta, &p, i_delta);
    int ok = 1;
    for (int i = 0; i < 16; i++) {
        if (i_delta[i] != 0) {
            ok = 0;
            break;
        }
    }
    check("decode_challenge: k=8 all-zero → all indices 0", ok);

    /* Set only bits for vector 0 (bits 0-7) → i_delta[0] = 0xFF, rest = 0 */
    memset(delta, 0, 16);
    delta[0] = 0xFF;
    voleith_decode_challenge(delta, &p, i_delta);
    check("decode_challenge: k=8 vector 0 gets full 8-bit value",
          i_delta[0] == 255);
    ok = 1;
    for (int i = 1; i < 16; i++) {
        if (i_delta[i] != 0) {
            ok = 0;
            break;
        }
    }
    check("decode_challenge: k=8 only vector 0 affected", ok);

    /* Set only bits for vector 8 (bits 64-70) → i_delta[8] = 0x7F, rest = 0 */
    memset(delta, 0, 16);
    delta[8] = 0x7F; /* bits 64-70 all set (7 bits within byte 8) */
    voleith_decode_challenge(delta, &p, i_delta);
    check("decode_challenge: k=8 vector 8 gets full 7-bit value",
          i_delta[8] == 127);
    ok = 1;
    for (int i = 0; i < 16; i++) {
        if (i == 8)
            continue;
        if (i_delta[i] != 0) {
            ok = 0;
            break;
        }
    }
    check("decode_challenge: k=8 only vector 8 affected", ok);
}

/*
 * Test 2: Full round-trip - commit, decode, open, reconstruct.
 * Commitment check must pass.
 */
static void
test_roundtrip_commit_check(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0xAB, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    int ret = voleith_commit(&com, &state, &p, root_seed, iv, ellhat);
    check("roundtrip: commit succeeds", ret == 0);

    /* All-bits-set delta */
    uint8_t delta[16];
    memset(delta, 0xFF, 16);
    size_t i_delta[16];
    voleith_decode_challenge(delta, &p, i_delta);

    voleith_bavc_opening_t opening = {0};
    ret = voleith_open(&opening, &state, &p, i_delta);
    check("roundtrip: open succeeds", ret == 0);

    const size_t ellhat_bytes = (ellhat + 7) / 8;
    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * ellhat_bytes;

    ret = voleith_reconstruct(&com, &opening, &p, i_delta, iv, q);
    check("roundtrip: reconstruct commitment check passes", ret == 0);

    voleith_bavc_opening_free(&opening);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(q);
    free(qs);
}

/*
 * Test 3: VOLE equation q[j] = v[j] XOR delta_j * u holds for all j.
 */
static void
test_roundtrip_vole_equation(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0xCD, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    voleith_commit(&com, &state, &p, root_seed, iv, ellhat);

    /* Use alternating challenge bits */
    uint8_t delta[16];
    memset(delta, 0xAA, 16);
    size_t i_delta[16];
    voleith_decode_challenge(delta, &p, i_delta);

    voleith_bavc_opening_t opening = {0};
    voleith_open(&opening, &state, &p, i_delta);

    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * ellhat_bytes;

    voleith_reconstruct(&com, &opening, &p, i_delta, iv, q);

    /*
     * Global VOLE equation: q[j] = v[j] XOR delta_j * u for all j.
     * delta_j comes from i_delta bit decomposition across all vectors.
     */
    int eq_ok = 1;
    int j = 0;
    for (int i = 0; i < p.tau && eq_ok; i++) {
        int depth = (i < p.tau1) ? p.k : (p.k - 1);
        for (int d = 0; d < depth && eq_ok; d++, j++) {
            int delta_bit = (int)((i_delta[i] >> d) & 1);
            for (size_t b = 0; b < ellhat_bytes; b++) {
                uint8_t expected = state.v[j][b] ^ (delta_bit ? com.u[b] : 0);
                if (q[j][b] != expected) {
                    eq_ok = 0;
                    break;
                }
            }
        }
    }
    check("roundtrip: VOLE equation q[j] = v[j] XOR delta_j*u for all j",
          eq_ok);

    voleith_bavc_opening_free(&opening);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(q);
    free(qs);
}

/*
 * Test 4: Two different challenges produce different q but the same hcom.
 */
static void
test_roundtrip_two_challenges(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0x55, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    voleith_commit(&com, &state, &p, root_seed, iv, ellhat);

    uint8_t delta_a[16] = {0};
    uint8_t delta_b[16];
    memset(delta_b, 0xFF, 16);

    size_t i_delta_a[16], i_delta_b[16];
    voleith_decode_challenge(delta_a, &p, i_delta_a);
    voleith_decode_challenge(delta_b, &p, i_delta_b);

    voleith_bavc_opening_t open_a = {0}, open_b = {0};
    voleith_open(&open_a, &state, &p, i_delta_a);
    voleith_open(&open_b, &state, &p, i_delta_b);

    uint8_t **qa = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t **qb = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qas = calloc((size_t)p.lambda * ellhat_bytes, 1);
    uint8_t *qbs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++) {
        qa[i] = qas + (size_t)i * ellhat_bytes;
        qb[i] = qbs + (size_t)i * ellhat_bytes;
    }

    int ret_a = voleith_reconstruct(&com, &open_a, &p, i_delta_a, iv, qa);
    int ret_b = voleith_reconstruct(&com, &open_b, &p, i_delta_b, iv, qb);

    check("two_challenges: both reconstructs pass commitment check",
          ret_a == 0 && ret_b == 0);
    check("two_challenges: q vectors differ",
          memcmp(qas, qbs, (size_t)p.lambda * ellhat_bytes) != 0);

    voleith_bavc_opening_free(&open_a);
    voleith_bavc_opening_free(&open_b);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(qa);
    free(qb);
    free(qas);
    free(qbs);
}

/*
 * Test 5: Tampered opening (flip one byte in the decommitment data)
 * causes the commitment check to fail.
 */
static void
test_tampered_opening(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0x11, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    voleith_commit(&com, &state, &p, root_seed, iv, ellhat);

    size_t i_delta[16];
    uint8_t delta[16] = {0};
    voleith_decode_challenge(delta, &p, i_delta);

    voleith_bavc_opening_t opening = {0};
    voleith_open(&opening, &state, &p, i_delta);

    /* Tamper: flip a byte in the opening data */
    opening.data[0] ^= 0x01;

    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * ellhat_bytes;

    int ret = voleith_reconstruct(&com, &opening, &p, i_delta, iv, q);
    check("tampered_opening: commitment check fails", ret != 0);

    voleith_bavc_opening_free(&opening);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(q);
    free(qs);
}

/*
 * Test 6: Tampered hcom (flip one byte in the commitment hash)
 * causes the commitment check to fail.
 */
static void
test_tampered_hcom(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0x22, 16);
    memset(iv, 0, 16);

    unsigned int ellhat = 256;
    const size_t ellhat_bytes = (ellhat + 7) / 8;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    voleith_commit(&com, &state, &p, root_seed, iv, ellhat);

    size_t i_delta[16];
    uint8_t delta[16] = {0};
    voleith_decode_challenge(delta, &p, i_delta);

    voleith_bavc_opening_t opening = {0};
    voleith_open(&opening, &state, &p, i_delta);

    /* Tamper: flip a byte in hcom */
    com.hcom[0] ^= 0x01;

    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * ellhat_bytes;

    int ret = voleith_reconstruct(&com, &opening, &p, i_delta, iv, q);
    check("tampered_hcom: commitment check fails", ret != 0);

    voleith_bavc_opening_free(&opening);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(q);
    free(qs);
}

/*
 * Test 7: Fully non-interactive round-trip using voleith_challenge_from_commitment.
 *
 * No hardcoded delta - the challenge is derived from the commitment via SHAKE-256.
 * Verifies: determinism, commitment check passes, VOLE equation holds.
 */
static void
test_noninteractive_roundtrip(void)
{
    voleith_vc_params_t p;
    make_small_params(&p);

    uint8_t root_seed[16], iv[16];
    memset(root_seed, 0x77, 16);
    memset(iv, 0x00, 16);

    unsigned int ellhat = 256;
    const size_t ellhat_bytes = (ellhat + 7) / 8;
    const size_t lambda_bytes = (size_t)p.lambda / 8;

    voleith_commitment_t com = {0};
    voleith_prover_t state = {0};
    voleith_commit(&com, &state, &p, root_seed, iv, ellhat);

    /* Derive challenge from commitment (Fiat-Shamir) */
    uint8_t delta[16];
    voleith_challenge_from_commitment(iv, &com, delta);

    /* Determinism: same inputs → same delta */
    uint8_t delta2[16];
    voleith_challenge_from_commitment(iv, &com, delta2);
    check("noninteractive: challenge derivation is deterministic",
          memcmp(delta, delta2, lambda_bytes) == 0);

    size_t i_delta[16];
    voleith_decode_challenge(delta, &p, i_delta);

    voleith_bavc_opening_t opening = {0};
    voleith_open(&opening, &state, &p, i_delta);

    uint8_t **q = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *qs = calloc((size_t)p.lambda * ellhat_bytes, 1);
    for (int i = 0; i < p.lambda; i++)
        q[i] = qs + (size_t)i * ellhat_bytes;

    int ret = voleith_reconstruct(&com, &opening, &p, i_delta, iv, q);
    check("noninteractive: commitment check passes", ret == 0);

    /* VOLE equation holds */
    int eq_ok = 1;
    int j = 0;
    for (int i = 0; i < p.tau && eq_ok; i++) {
        int depth = (i < p.tau1) ? p.k : (p.k - 1);
        for (int d = 0; d < depth && eq_ok; d++, j++) {
            int delta_bit = (int)((i_delta[i] >> d) & 1);
            for (size_t b = 0; b < ellhat_bytes; b++) {
                uint8_t expected = state.v[j][b] ^ (delta_bit ? com.u[b] : 0);
                if (q[j][b] != expected) {
                    eq_ok = 0;
                    break;
                }
            }
        }
    }
    check("noninteractive: VOLE equation holds", eq_ok);

    /* Different iv → different delta */
    uint8_t iv2[16];
    memset(iv2, 0x01, 16);
    uint8_t delta3[16];
    voleith_challenge_from_commitment(iv2, &com, delta3);
    check("noninteractive: different iv → different challenge",
          memcmp(delta, delta3, lambda_bytes) != 0);

    voleith_bavc_opening_free(&opening);
    voleith_commitment_free(&com);
    voleith_prover_free(&state);
    free(q);
    free(qs);
}

int
main(void)
{
    printf("test_voleith: VOLEitH protocol layer\n");

    test_decode_challenge_basic();
    test_decode_challenge_k8();
    test_roundtrip_commit_check();
    test_roundtrip_vole_equation();
    test_roundtrip_two_challenges();
    test_tampered_opening();
    test_tampered_hcom();
    test_noninteractive_roundtrip();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
