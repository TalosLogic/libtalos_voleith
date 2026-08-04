/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf8_proof.c - End-to-end tests for the GF(2⁸) element-level VOLEitH proof system
 *
 * Tests:
 *   1. Proof byte size matches voleith_gf8_proof_byte_size
 *   2. MUL circuit roundtrip (two parameter sets)
 *   3. Wrong witness is rejected at prove time (constraint check in prover)
 *   4. Modified proof is rejected (one byte per section)
 *   5. Different fs_seeds give different but both valid proofs
 *   6. Chain MUL circuit (8 MUL gates)
 *   7. AES-128 GF8 element-level circuit round-trip (FIPS 197 Appendix B)
 *   8. SCALE_INSTANCE gate roundtrip + tampered-scalar rejection (GATE.QS)
 *   9. SCALE_INSTANCE vs add_mul: one-slot proof-size delta, both verify
 */

#include "gf8_proof.h"
#include "gf8_circuit.h"
#include "proof_header.h" /* VOLEITH_PROOF_HEADER_BYTES */
#include "gf8_circuit_fingerprint.h"
#include "gf8_prover.h"
#include "aes_gf8_circuit.h"
#include "fiat_shamir.h"
#include "../core/field.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ================================================================
 * Test helpers
 * ================================================================ */

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  PASS: %s\n", msg);                                       \
            g_pass++;                                                          \
        } else {                                                               \
            printf("  FAIL: %s (line %d)\n", msg, __LINE__);                   \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

/*
 * Simple MUL circuit: prove knowledge of (a, b) such that a*b == c (public).
 *
 *   w0 = witness(0) = a
 *   w1 = witness(1) = b
 *   w2 = mul(w0, w1)           (costs 1 VOLE slot → ell = n_witness + 1 = 3)
 *   w3 = instance(0) = c
 *   assert_equal(w2, w3)
 */
static voleith_gf8_circuit_t *
build_mul_circuit(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return NULL;

    gf8_wire_id w0 = voleith_gf8_add_witness(c);     /* a */
    gf8_wire_id w1 = voleith_gf8_add_witness(c);     /* b */
    gf8_wire_id w2 = voleith_gf8_add_mul(c, w0, w1); /* a*b (MUL gate) */
    gf8_wire_id w3 =
        voleith_gf8_add_instance(c); /* c (public expected product) */
    voleith_gf8_assert_equal(c, w2, w3);

    return c;
}

/*
 * Chain of MUL gates: w = a*b, w = w*a, ..., n_mul times total.
 * assert_zero(w): satisfied when a=0 or b=0 (product chain collapses to 0).
 */
static voleith_gf8_circuit_t *
build_chain_circuit(int n_mul)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return NULL;

    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id w = voleith_gf8_add_mul(c, a, b);
    for (int i = 1; i < n_mul; i++) {
        gf8_wire_id next = (i % 2 == 0) ? voleith_gf8_add_mul(c, w, a)
                                        : voleith_gf8_add_mul(c, w, b);
        w = next;
    }
    voleith_gf8_assert_zero(c, w);

    return c;
}

/* ================================================================
 * Test: proof_byte_size matches actual proof
 * ================================================================ */

static void
test_proof_size(void)
{
    printf("\n[gf8 proof_byte_size]\n");

    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    size_t ell = voleith_gf8_qs_ell(c);
    size_t computed = voleith_gf8_proof_byte_size(&voleith_params_em_128f, ell);

    /* 0x03 * 0x05 = 0x0F in GF(2^8) with AES polynomial x^8+x^4+x^3+x+1 */
    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x42, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int ret = voleith_gf8_prove(&proof, &voleith_params_em_128f, c, witness,
                                instance, fs_seed, sizeof(fs_seed));
    if (ret != 0) {
        printf("  FAIL: prove returned %d (line %d)\n", ret, __LINE__);
        g_fail++;
    } else {
        CHECK(proof.len == computed,
              "Proof size matches voleith_gf8_proof_byte_size");
        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: MUL circuit prove + verify round-trip
 * ================================================================ */

static void
test_mul_circuit_roundtrip(const voleith_params_t *params, const char *label)
{
    printf("\n[GF8 MUL circuit roundtrip: %s]\n", label);

    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    /* 0x03 * 0x05 = 0x0F in GF(2^8) */
    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0xAB, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness, instance, fs_seed,
                                 sizeof(fs_seed));
    CHECK(pret == 0, "Prove succeeds");

    if (pret == 0) {
        int vret = voleith_gf8_verify(&proof, params, c, instance, fs_seed,
                                      sizeof(fs_seed));
        CHECK(vret == 0, "Valid proof verifies");
        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Wrong witness is rejected at prove time
 *
 * The GF(2^8) prover calls voleith_gf8_qs_compute_d() which evaluates
 * the circuit and returns -1 if any constraint is violated.
 * ================================================================ */

static void
test_wrong_witness_rejected(void)
{
    printf("\n[GF8 wrong witness rejected]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    /* Correct: a=0x03, b=0x05, c=0x0F (0x03*0x05=0x0F in GF(2^8)) */
    uint8_t witness_ok[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    /* Wrong: b=0x07 → 0x03*0x07=0x09 ≠ 0x0F */
    uint8_t witness_bad[2] = {0x03, 0x07};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x77, sizeof(fs_seed));

    /* GF(2^8) prover checks circuit satisfaction - prove must fail for bad witness */
    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness_bad, instance,
                                 fs_seed, sizeof(fs_seed));
    CHECK(pret != 0, "Prove with wrong witness fails");

    /* Correct witness proves and verifies */
    memset(&proof, 0, sizeof(proof));
    pret = voleith_gf8_prove(&proof, params, c, witness_ok, instance, fs_seed,
                             sizeof(fs_seed));
    CHECK(pret == 0, "Prove with correct witness succeeds");
    if (pret == 0) {
        int vret = voleith_gf8_verify(&proof, params, c, instance, fs_seed,
                                      sizeof(fs_seed));
        CHECK(vret == 0, "Correct witness verifies");
        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Modified proof is rejected
 * ================================================================ */

static void
test_tamper_detection(void)
{
    printf("\n[GF8 tamper detection]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x55, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness, instance, fs_seed,
                                 sizeof(fs_seed));
    if (pret != 0) {
        printf("  SKIP: prove failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }

    CHECK(voleith_gf8_verify(&proof, params, c, instance, fs_seed,
                             sizeof(fs_seed)) == 0,
          "Clean proof verifies before tampering");

    size_t proof_len = proof.len;
    uint8_t *proof_data = proof.data;
    int all_rejected = 1;

    /* Compute section offsets matching proof_layout() in gf8_proof.c.
     * Key difference from bit-level: ell_bytes = ell (not ceil(ell/8)). */
    unsigned int nb = params->lambda / 8;
    size_t ell = voleith_gf8_qs_ell(c);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(c, params->lambda);
    size_t ell_bytes = ell;       /* d is one byte per element slot */
    size_t utilde_bytes = nb + 2; /* VOLEITH_VOLE_HASH_B = 2 */
    size_t decom_size =
        ((size_t)params->n_leafcom * params->tau + (size_t)params->T_open) * nb;

    size_t off_c = 0;
    size_t off_utilde = off_c + (params->tau - 1) * ellhat_bytes;
    size_t off_d = off_utilde + utilde_bytes;
    size_t off_a1 = off_d + ell_bytes;
    size_t off_a2 = off_a1 + nb;
    size_t off_decom = off_a2 + nb;
    size_t off_chall3 = off_decom + decom_size;
    size_t off_iv = off_chall3 + nb;
    size_t off_ctr = off_iv + 16;

    /* One byte per section */
    size_t positions[] = {
        off_c,      /* c[0]: VOLE correction values */
        off_utilde, /* u_tilde: compressed VOLE hash */
        off_d,      /* d: element-level VOLE correction (ell bytes) */
        off_a1,     /* a1_tilde: QuickSilver degree-1 hash */
        off_a2,     /* a2_tilde: QuickSilver degree-2 hash */
        off_decom,  /* decom_i: BAVC opening */
        off_chall3, /* chall_3: grinding challenge */
        off_iv,     /* iv: PRG initialisation vector */
        off_ctr,    /* ctr: grinding counter */
    };

    for (size_t pi = 0; pi < sizeof(positions) / sizeof(positions[0]); pi++) {
        size_t p = positions[pi];
        if (p >= proof_len)
            continue;

        uint8_t orig = proof_data[p];
        proof_data[p] ^= 0xFF;

        voleith_proof_t tampered = {proof_data, proof_len};
        int vret = voleith_gf8_verify(&tampered, params, c, instance, fs_seed,
                                      sizeof(fs_seed));
        if (vret == 0) {
            printf("  FAIL: byte at section offset %zu not rejected\n", p);
            all_rejected = 0;
        }

        proof_data[p] = orig;
    }

    CHECK(all_rejected, "Each proof section byte is rejected when tampered");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Different fs_seeds give different but valid proofs
 * ================================================================ */

static void
test_different_seeds(void)
{
    printf("\n[GF8 different fs_seeds]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP\n");
        return;
    }

    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t seed1[16], seed2[16];
    memset(seed1, 0x11, sizeof(seed1));
    memset(seed2, 0x22, sizeof(seed2));

    voleith_proof_t p1, p2;
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));

    int r1 = voleith_gf8_prove(&p1, params, c, witness, instance, seed1,
                               sizeof(seed1));
    int r2 = voleith_gf8_prove(&p2, params, c, witness, instance, seed2,
                               sizeof(seed2));

    CHECK(r1 == 0 && r2 == 0, "Both proves succeed");

    if (r1 == 0 && r2 == 0) {
        CHECK(p1.len == p2.len, "Proof sizes match");
        CHECK(memcmp(p1.data, p2.data, p1.len) != 0,
              "Different seeds produce different proofs");
        CHECK(voleith_gf8_verify(&p1, params, c, instance, seed1,
                                 sizeof(seed1)) == 0,
              "Proof 1 verifies with seed1");
        CHECK(voleith_gf8_verify(&p2, params, c, instance, seed2,
                                 sizeof(seed2)) == 0,
              "Proof 2 verifies with seed2");
        CHECK(voleith_gf8_verify(&p1, params, c, instance, seed2,
                                 sizeof(seed2)) != 0,
              "Proof 1 rejected with seed2");
        voleith_proof_free(&p1);
        voleith_proof_free(&p2);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Chain circuit (more MUL gates)
 * ================================================================ */

static void
test_chain_circuit(void)
{
    printf("\n[GF8 chain circuit: 8 MUL gates]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_chain_circuit(8);
    if (!c) {
        printf("  SKIP\n");
        return;
    }

    /* a=0, b=0: all products are 0 → assert_zero passes */
    uint8_t witness[2] = {0x00, 0x00};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x33, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness, NULL, fs_seed,
                                 sizeof(fs_seed));
    CHECK(pret == 0, "Chain circuit prove succeeds");

    if (pret == 0) {
        int vret = voleith_gf8_verify(&proof, params, c, NULL, fs_seed,
                                      sizeof(fs_seed));
        CHECK(vret == 0, "Chain circuit verifies");
        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Two-phase API helpers
 * ================================================================ */

/*
 * Derive chall_1 from fs_seed + instance + commitment blob.
 * Mirrors the internal derivation in voleith_gf8_prove() / voleith_gf8_verify():
 *   chall_1 = H_2^1(fs_seed || instance || blob)   [5λ/8+8 bytes]
 * In a shared-transcript system, both prover and verifier run this same
 * derivation; since blob contains hcom (prover) or hcom_rec (verifier),
 * consistency requires hcom == hcom_rec.
 */
static void
derive_chall_1(uint8_t *out, unsigned int lambda, const uint8_t *fs_seed,
               size_t fs_seed_len, const uint8_t *instance, size_t n_instance,
               const uint8_t *blob, size_t blob_size)
{
    voleith_transcript_t t;
    voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
    if (n_instance > 0)
        voleith_transcript_absorb(&t, instance, n_instance);
    voleith_transcript_absorb(&t, blob, blob_size);
    voleith_transcript_squeeze(&t, out, 5u * (lambda / 8u) + 8u);
}

/* ================================================================
 * Test: Two-phase prove/verify API round-trip
 *
 * Exercises the split-at-chall_1 mechanism used by hybrid proof systems
 * (e.g., Signal KVAC shared transcript).  Both prover and verifier derive
 * chall_1 by hashing their respective blobs (hcom||c||iv) through H_2^1.
 * A correct BAVC reconstruction guarantees hcom == hcom_rec, so the two
 * chall_1 values are identical and verification succeeds.
 *
 * Also checks that the commitment blobs from prove_commit and
 * verify_reconstruct are byte-for-byte identical.
 * ================================================================ */

static void
test_two_phase_roundtrip(void)
{
    printf("\n[GF8 two-phase API: round-trip]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0xC0, sizeof(fs_seed));

    unsigned int lambda = params->lambda;
    size_t n_instance = voleith_gf8_circuit_instance_count(c);
    size_t blob_size = voleith_gf8_commit_blob_size(params, c);

    uint8_t *blob_p = malloc(blob_size);
    uint8_t *blob_v = malloc(blob_size);
    if (!blob_p || !blob_v) {
        printf("  SKIP: malloc failed\n");
        free(blob_p);
        free(blob_v);
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Phase 1 (Prove) */
    voleith_gf8_prover_commit_t *pctx = NULL;
    int ret = voleith_gf8_prove_commit(&pctx, params, c, witness, instance,
                                       fs_seed, sizeof(fs_seed), blob_p);
    CHECK(ret == 0, "prove_commit succeeds");
    if (ret != 0) {
        free(blob_p);
        free(blob_v);
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Shared transcript: derive chall_1 from prover's blob */
    uint8_t chall_1_p[5 * 32 + 8];
    derive_chall_1(chall_1_p, lambda, fs_seed, sizeof(fs_seed), instance,
                   n_instance, blob_p, blob_size);

    /* Phase 2 (Prove) */
    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    ret = voleith_gf8_prove_respond(&proof, pctx, c, witness, instance,
                                    chall_1_p);
    voleith_gf8_prover_commit_free(pctx);
    CHECK(ret == 0, "prove_respond succeeds");
    if (ret != 0) {
        free(blob_p);
        free(blob_v);
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Phase 1 (Verify) */
    voleith_gf8_verifier_reconstruct_t *vctx = NULL;
    ret = voleith_gf8_verify_reconstruct(&vctx, &proof, params, c, blob_v);
    CHECK(ret == 0, "verify_reconstruct succeeds");
    if (ret != 0) {
        free(blob_p);
        free(blob_v);
        voleith_proof_free(&proof);
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Blobs must be identical: hcom == hcom_rec proves the BAVC reconstruction
     * is consistent with the prover's original commitment */
    CHECK(memcmp(blob_p, blob_v, blob_size) == 0,
          "prover blob == verifier reconstructed blob");

    /* Shared transcript: derive chall_1 from verifier's reconstructed blob */
    uint8_t chall_1_v[5 * 32 + 8];
    derive_chall_1(chall_1_v, lambda, fs_seed, sizeof(fs_seed), instance,
                   n_instance, blob_v, blob_size);

    /* Phase 2 (Verify) */
    ret = voleith_gf8_verify_respond(vctx, c, instance, chall_1_v);
    CHECK(ret == 0, "verify_respond succeeds");

    voleith_gf8_verifier_reconstruct_free(vctx);
    voleith_proof_free(&proof);
    free(blob_p);
    free(blob_v);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Wrong chall_1 is rejected by verify_respond
 *
 * Creates a valid proof via the two-phase API, then passes an incorrect
 * chall_1 to verify_respond.  The wrong chall_1 produces a wrong chall_2,
 * which produces a wrong a0_tilde_out, which produces chall_3' ≠ chall_3
 * in the proof → verify_respond returns -1.
 * ================================================================ */

static void
test_two_phase_wrong_chall1(void)
{
    printf("\n[GF8 two-phase API: wrong chall_1 rejected]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0xD0, sizeof(fs_seed));

    unsigned int lambda = params->lambda;
    size_t n_instance = voleith_gf8_circuit_instance_count(c);
    size_t blob_size = voleith_gf8_commit_blob_size(params, c);

    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        printf("  SKIP: malloc failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Build a valid proof via two-phase API */
    voleith_gf8_prover_commit_t *pctx = NULL;
    int ret = voleith_gf8_prove_commit(&pctx, params, c, witness, instance,
                                       fs_seed, sizeof(fs_seed), blob);
    if (ret != 0) {
        printf("  SKIP: prove_commit failed\n");
        free(blob);
        voleith_gf8_circuit_free(c);
        return;
    }

    uint8_t chall_1_correct[5 * 32 + 8];
    derive_chall_1(chall_1_correct, lambda, fs_seed, sizeof(fs_seed), instance,
                   n_instance, blob, blob_size);
    free(blob);

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    ret = voleith_gf8_prove_respond(&proof, pctx, c, witness, instance,
                                    chall_1_correct);
    voleith_gf8_prover_commit_free(pctx);
    if (ret != 0) {
        printf("  SKIP: prove_respond failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Reconstruct on verifier side */
    uint8_t *blob_v = malloc(blob_size);
    if (!blob_v) {
        printf("  SKIP: malloc failed\n");
        voleith_proof_free(&proof);
        voleith_gf8_circuit_free(c);
        return;
    }
    voleith_gf8_verifier_reconstruct_t *vctx = NULL;
    ret = voleith_gf8_verify_reconstruct(&vctx, &proof, params, c, blob_v);
    free(blob_v);
    if (ret != 0) {
        printf("  SKIP: verify_reconstruct failed\n");
        voleith_proof_free(&proof);
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Feed a wrong (all-zeros) chall_1 - must be rejected */
    uint8_t chall_1_wrong[5 * 32 + 8];
    memset(chall_1_wrong, 0x00, sizeof(chall_1_wrong));
    ret = voleith_gf8_verify_respond(vctx, c, instance, chall_1_wrong);
    CHECK(ret != 0, "verify_respond with wrong chall_1 fails");

    voleith_gf8_verifier_reconstruct_free(vctx);
    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: Wrong instance is rejected at verify time
 *
 * Instance is not stored in the proof - it is absorbed into chall_1
 * by both prover and verifier.  Verifying with a modified instance
 * changes chall_1, which cascades through chall_2 → a0_tilde_out →
 * chall_3' ≠ chall_3 in the proof → verification fails.
 * ================================================================ */

static void
test_wrong_instance_rejected(void)
{
    printf("\n[GF8 wrong instance rejected]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    /* Correct: a=0x03, b=0x05, c=0x0F (0x03*0x05=0x0F in GF(2^8)) */
    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance_ok[1] = {0x0F};
    /* Wrong instance: different expected product value */
    uint8_t instance_bad[1] = {0x11};
    uint8_t fs_seed[16];
    memset(fs_seed, 0xBB, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness, instance_ok,
                                 fs_seed, sizeof(fs_seed));
    if (pret != 0) {
        printf("  SKIP: prove failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }

    /* Correct instance verifies */
    int vret_ok = voleith_gf8_verify(&proof, params, c, instance_ok, fs_seed,
                                     sizeof(fs_seed));
    CHECK(vret_ok == 0, "Proof verifies with correct instance");

    /* Wrong instance rejected: instance is absorbed into chall_1, so any
     * change propagates through the entire Fiat-Shamir transcript */
    int vret_bad = voleith_gf8_verify(&proof, params, c, instance_bad, fs_seed,
                                      sizeof(fs_seed));
    CHECK(vret_bad != 0, "Proof rejected with wrong instance");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: AES-128 GF8 element-level circuit round-trip
 *
 * Proves knowledge of an AES-128 key that encrypts a public plaintext
 * to a public ciphertext (FIPS 197 Appendix B test vector).
 *
 * Circuit:
 *   - 16 witness wires: key bytes
 *   - 16 instance wires: plaintext bytes
 *   - aes128_gf8_circuit(): adds 200 inv_in witness wires, output[16]
 *   - 16 instance wires: expected ciphertext bytes
 *   - assert_equal(output[i], ct_inst[i]) for i=0..15
 *
 * witness = key[16] || inv_in[200] = 216 bytes (from aes128_gf8_build_witness)
 * instance = plaintext[16] || ciphertext[16] = 32 bytes
 * ell = 216 (all witness slots: 16 key + 200 inv_in; 0 add_mul gates)
 * ================================================================ */

static void
test_aes128_gf8_roundtrip(void)
{
    printf("\n[AES-128 GF8 element-level proof round-trip]\n");

    /* FIPS 197 Appendix B */
    static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    static const uint8_t pt[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    static const uint8_t ct_expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };

    /* Build circuit */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    gf8_wire_id key_wires[16], pt_wires[16], ct_wires[16], output[16];
    for (int i = 0; i < 16; i++)
        key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);
    aes128_gf8_circuit(c, key_wires, pt_wires, output);
    for (int i = 0; i < 16; i++)
        ct_wires[i] = voleith_gf8_add_instance(c);
    for (int i = 0; i < 16; i++)
        voleith_gf8_assert_equal(c, output[i], ct_wires[i]);

    if (!voleith_gf8_circuit_ok(c)) {
        printf("  SKIP: circuit build failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }

    size_t ell = voleith_gf8_qs_ell(c);
    CHECK(ell == 216,
          "AES-128 GF8 ell == 216 (16 key + 200 inv_in witness slots)");

    /* Build witness: key bytes + 200 inv_in values */
    uint8_t witness[216];
    uint8_t ct_actual[16];
    aes128_gf8_build_witness(key, pt, witness, ct_actual);
    CHECK(memcmp(ct_actual, ct_expected, 16) == 0,
          "aes128_gf8_build_witness ciphertext matches FIPS 197 Appendix B");

    /* instance = plaintext || ciphertext */
    uint8_t instance[32];
    memcpy(instance, pt, 16);
    memcpy(instance + 16, ct_expected, 16);

    /* Prove and verify at lambda=128 (em_128f) */
    uint8_t fs_seed[16];
    memset(fs_seed, 0xCA, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, &voleith_params_em_128f, c, witness,
                                 instance, fs_seed, sizeof(fs_seed));
    CHECK(pret == 0, "AES-128 GF8 prove succeeds");

    if (pret == 0) {
        int vret = voleith_gf8_verify(&proof, &voleith_params_em_128f, c,
                                      instance, fs_seed, sizeof(fs_seed));
        CHECK(vret == 0, "AES-128 GF8 proof verifies");

        /* Proof size formula check */
        size_t computed =
            voleith_gf8_proof_byte_size(&voleith_params_em_128f, ell);
        CHECK(proof.len == computed, "AES-128 GF8 proof size matches formula");

        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: M-N3 length-validated entry points (GF(2^8) variant).
 *
 * GF(2^8) uses one byte per witness / instance wire (no bit-packing),
 * so the expected length is the wire count directly.
 * ================================================================ */
static void
test_v2_length_validation(void)
{
    printf("\n[v2 length validation (M-N3, GF8)]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *c = build_mul_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    /* build_mul_circuit: 2 witness bytes, 1 instance byte. */
    size_t expected_w = voleith_gf8_circuit_witness_count(c);
    size_t expected_i = voleith_gf8_circuit_instance_count(c);

    uint8_t witness[2] = {0x03, 0x05};
    uint8_t instance[1] = {0x0F};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x5C, sizeof(fs_seed));

    /* Happy path. */
    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    CHECK(voleith_gf8_prove_v2(&proof, params, c, witness, expected_w, instance,
                               expected_i, fs_seed, sizeof(fs_seed)) == 0,
          "gf8_prove_v2 with correct lengths succeeds");
    CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, expected_i,
                                fs_seed, sizeof(fs_seed)) == 0,
          "gf8_verify_v2 with correct length succeeds");

    /* prove_v2: wrong witness_len. */
    voleith_proof_t bad_proof;
    memset(&bad_proof, 0, sizeof(bad_proof));
    CHECK(voleith_gf8_prove_v2(&bad_proof, params, c, witness, expected_w - 1,
                               instance, expected_i, fs_seed,
                               sizeof(fs_seed)) != 0,
          "gf8_prove_v2 rejects witness_len too small");
    CHECK(voleith_gf8_prove_v2(&bad_proof, params, c, witness, expected_w + 1,
                               instance, expected_i, fs_seed,
                               sizeof(fs_seed)) != 0,
          "gf8_prove_v2 rejects witness_len too large");

    /* prove_v2: wrong instance_len. */
    CHECK(voleith_gf8_prove_v2(&bad_proof, params, c, witness, expected_w,
                               instance, expected_i + 1, fs_seed,
                               sizeof(fs_seed)) != 0,
          "gf8_prove_v2 rejects instance_len too large");

    /* verify_v2: wrong instance_len. */
    CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, expected_i + 1,
                                fs_seed, sizeof(fs_seed)) != 0,
          "gf8_verify_v2 rejects instance_len too large");
    CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, 0, fs_seed,
                                sizeof(fs_seed)) != 0,
          "gf8_verify_v2 rejects instance_len = 0 when n_instance > 0");

    /* NULL circuit. */
    CHECK(voleith_gf8_prove_v2(&bad_proof, params, NULL, witness, 0, instance,
                               0, fs_seed, sizeof(fs_seed)) != 0,
          "gf8_prove_v2 rejects NULL circuit");
    CHECK(voleith_gf8_verify_v2(&proof, params, NULL, instance, 0, fs_seed,
                                sizeof(fs_seed)) != 0,
          "gf8_verify_v2 rejects NULL circuit");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: GF(2⁸) byte-len helpers.
 *
 * GF(2⁸) circuits use one byte per witness / instance wire, so the
 * helpers return the wire count directly with no bit-packing math.
 * Exercises NULL, empty, and a handful of nonzero counts.
 * ================================================================ */
static void
test_byte_len_helpers(void)
{
    printf("\n[byte-len helpers (GF(2^8))]\n");

    CHECK(voleith_gf8_circuit_witness_byte_len(NULL) == 0,
          "gf8 witness_byte_len(NULL) == 0");
    CHECK(voleith_gf8_circuit_instance_byte_len(NULL) == 0,
          "gf8 instance_byte_len(NULL) == 0");

    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        CHECK(voleith_gf8_circuit_witness_byte_len(c) == 0,
              "gf8 empty circuit → 0 witness bytes");
        CHECK(voleith_gf8_circuit_instance_byte_len(c) == 0,
              "gf8 empty circuit → 0 instance bytes");
        voleith_gf8_circuit_free(c);
    }

    {
        int counts[] = {1, 7, 8, 9, 16, 100};
        for (size_t k = 0; k < sizeof(counts) / sizeof(counts[0]); k++) {
            voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
            for (int i = 0; i < counts[k]; i++)
                (void)voleith_gf8_add_witness(c);
            char msg[64];
            snprintf(msg, sizeof(msg), "gf8: %d witness wires → %d bytes",
                     counts[k], counts[k]);
            CHECK(voleith_gf8_circuit_witness_byte_len(c) == (size_t)counts[k],
                  msg);
            voleith_gf8_circuit_free(c);
        }
    }

    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        for (int i = 0; i < 9; i++)
            (void)voleith_gf8_add_instance(c);
        CHECK(voleith_gf8_circuit_instance_byte_len(c) == 9,
              "gf8: 9 instance wires → 9 bytes");
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * SCALE_INSTANCE gate (GATE.QS): a scale-by-instance product feeding a
 * MUL gate and an equality assert.
 *
 *   w0 = witness(a)
 *   b  = instance(0)                 public scalar
 *   s  = scale_instance(w0, b) = a*b (free: no VOLE slot)
 *   w1 = witness(d)
 *   m  = mul(s, w1) = a*b*d          (one VOLE slot)
 *   e  = instance(1)                 expected a*b*d
 *   assert_equal(m, e)
 *
 * When use_mul is set, s is built with add_mul instead (b stays the instance
 * operand), giving a structurally identical circuit that costs one more slot.
 * ell = 2 witnesses + (use_mul ? 2 : 1) mul gates.
 * ================================================================ */
static voleith_gf8_circuit_t *
build_scale_circuit(int use_mul)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return NULL;

    gf8_wire_id w0 = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_instance(c);
    gf8_wire_id s = use_mul ? voleith_gf8_add_mul(c, w0, b)
                            : voleith_gf8_add_scale_instance(c, w0, b);
    gf8_wire_id w1 = voleith_gf8_add_witness(c);
    gf8_wire_id m = voleith_gf8_add_mul(c, s, w1);
    gf8_wire_id e = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, m, e);

    return c;
}

static void
test_scale_gate_roundtrip(const voleith_params_t *params, const char *label)
{
    printf("\n[GF8 SCALE_INSTANCE roundtrip: %s]\n", label);

    voleith_gf8_circuit_t *c = build_scale_circuit(0);
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }
    CHECK(voleith_gf8_circuit_ok(c), "scale circuit builds");
    CHECK(voleith_gf8_qs_ell(c) == 3, "scale circuit ell == 3 (2 wit + 1 mul)");

    uint8_t a = 0x03, d = 0x07, bpub = 0x05;
    uint8_t prod = voleith_gf8_mul(voleith_gf8_mul(a, bpub), d);
    uint8_t witness[2] = {a, d};
    uint8_t instance[2] = {bpub, prod};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x71, sizeof(fs_seed));

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    int pret = voleith_gf8_prove(&proof, params, c, witness, instance, fs_seed,
                                 sizeof(fs_seed));
    CHECK(pret == 0, "scale circuit prove succeeds");

    if (pret == 0) {
        CHECK(voleith_gf8_verify(&proof, params, c, instance, fs_seed,
                                 sizeof(fs_seed)) == 0,
              "scale circuit verifies");

        /* Tamper the public scalar b: the verifier rebuilds a different
         * x -> b*x matrix, so key propagation diverges and verify fails
         * (design Q2 review item b). */
        uint8_t instance_bad[2] = {(uint8_t)(bpub ^ 0x01), prod};
        CHECK(voleith_gf8_verify(&proof, params, c, instance_bad, fs_seed,
                                 sizeof(fs_seed)) != 0,
              "tampered scale-instance byte rejected at verify");

        voleith_proof_free(&proof);
    }

    voleith_gf8_circuit_free(c);
}

static void
test_scale_vs_mul_slot(void)
{
    printf("\n[GF8 SCALE_INSTANCE vs add_mul: one-slot delta]\n");

    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_gf8_circuit_t *cs = build_scale_circuit(0);
    voleith_gf8_circuit_t *cm = build_scale_circuit(1);
    if (!cs || !cm) {
        printf("  SKIP: circuit alloc failed\n");
        voleith_gf8_circuit_free(cs);
        voleith_gf8_circuit_free(cm);
        return;
    }

    size_t ell_s = voleith_gf8_qs_ell(cs);
    size_t ell_m = voleith_gf8_qs_ell(cm);
    CHECK(ell_m == ell_s + 1, "add_mul variant costs exactly one more slot");

    /* Structurally identical circuits differ only in the one gate kind, so
     * the fingerprint distinguishes them. */
    uint8_t fp_s[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp_m[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    voleith_gf8_circuit_fingerprint(cs, fp_s);
    voleith_gf8_circuit_fingerprint(cm, fp_m);
    CHECK(memcmp(fp_s, fp_m, sizeof(fp_s)) != 0,
          "scale vs mul variant fingerprints differ");

    uint8_t a = 0x03, d = 0x07, bpub = 0x05;
    uint8_t prod = voleith_gf8_mul(voleith_gf8_mul(a, bpub), d);
    uint8_t witness[2] = {a, d};
    uint8_t instance[2] = {bpub, prod};
    uint8_t fs_seed[16];
    memset(fs_seed, 0x9E, sizeof(fs_seed));

    voleith_proof_t ps, pm;
    memset(&ps, 0, sizeof(ps));
    memset(&pm, 0, sizeof(pm));
    int rs = voleith_gf8_prove(&ps, params, cs, witness, instance, fs_seed,
                               sizeof(fs_seed));
    int rm = voleith_gf8_prove(&pm, params, cm, witness, instance, fs_seed,
                               sizeof(fs_seed));
    CHECK(rs == 0 && rm == 0, "both variants prove");

    if (rs == 0 && rm == 0) {
        CHECK(ps.len == voleith_gf8_proof_byte_size(params, ell_s),
              "scale proof size matches formula(ell)");
        CHECK(pm.len == voleith_gf8_proof_byte_size(params, ell_m),
              "mul proof size matches formula(ell+1)");
        CHECK(pm.len > ps.len, "mul-variant proof is larger by the slot");
        CHECK(voleith_gf8_verify(&ps, params, cs, instance, fs_seed,
                                 sizeof(fs_seed)) == 0,
              "scale variant verifies");
        CHECK(voleith_gf8_verify(&pm, params, cm, instance, fs_seed,
                                 sizeof(fs_seed)) == 0,
              "mul variant verifies");
        voleith_proof_free(&ps);
        voleith_proof_free(&pm);
    }

    voleith_gf8_circuit_free(cs);
    voleith_gf8_circuit_free(cm);
}

/* ================================================================
 * Test: full two-phase proof over a degree-(w+1) less-than circuit.
 *
 * This drives the whole public proof pipeline (prove_v2 -> verify_v2:
 * commit, serialize, transcript, decommit) at opening degree d = w+1 > 2 -
 * the serialization / sizing / transcript path that the QS-primitive tests
 * do NOT exercise, and the path that would have caught the n_bit_cols bug on
 * its own.  Asserts A < B over w witness bit wires (MSB-first).
 * ================================================================ */
static voleith_gf8_circuit_t *
build_lt_proof_circuit(unsigned int w)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return NULL;
    gf8_wire_id a_bits[32], b_bits[32];
    for (unsigned int i = 0; i < w; i++)
        a_bits[i] = voleith_gf8_add_witness(c);
    for (unsigned int i = 0; i < w; i++)
        b_bits[i] = voleith_gf8_add_witness(c);
    voleith_gf8_assert_lt(c, a_bits, b_bits, w);
    return c;
}

static void
fill_lt_bits(uint8_t *buf, unsigned int w, unsigned int A, unsigned int B)
{
    for (unsigned int i = 0; i < w; i++)
        buf[i] = (uint8_t)((A >> (w - 1 - i)) & 1u);
    for (unsigned int i = 0; i < w; i++)
        buf[w + i] = (uint8_t)((B >> (w - 1 - i)) & 1u);
}

static void
test_lt_two_phase(const voleith_params_t *params, unsigned int w,
                  unsigned int A, unsigned int B, const char *label)
{
    printf("\n[two-phase LT full proof: %s]\n", label);

    voleith_gf8_circuit_t *c = build_lt_proof_circuit(w);
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }
    size_t nwit = voleith_gf8_circuit_witness_count(c);
    uint8_t witness[64];
    fill_lt_bits(witness, w, A, B);
    uint8_t fs_seed[16];
    memset(fs_seed, 0x27, sizeof(fs_seed));

    /* Opening degree really is w+1 (> 2). */
    CHECK(voleith_gf8_circuit_qs_degree(c) == w + 1,
          "qs_degree == w+1 (>2) on the proof circuit");

    /* Happy path: A < B verifies through the full pipeline. */
    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    CHECK(voleith_gf8_prove_v2(&proof, params, c, witness, nwit, NULL, 0,
                               fs_seed, sizeof(fs_seed)) == 0,
          "prove_v2 succeeds (A<B)");
    CHECK(voleith_gf8_verify_v2(&proof, params, c, NULL, 0, fs_seed,
                                sizeof(fs_seed)) == 0,
          "verify_v2 accepts valid d>2 proof");

    /* Degree-aware size helper matches the actual d>2 proof length. */
    CHECK(voleith_gf8_proof_byte_size_circuit(params, c) == proof.len,
          "proof_byte_size_circuit matches d>2 proof len");

    /* Tampered proof body must be rejected. */
    if (proof.data && proof.len > VOLEITH_PROOF_HEADER_BYTES) {
        uint8_t saved = proof.data[proof.len - 1];
        proof.data[proof.len - 1] ^= 0x40u;
        CHECK(voleith_gf8_verify_v2(&proof, params, c, NULL, 0, fs_seed,
                                    sizeof(fs_seed)) != 0,
              "verify_v2 rejects tampered d>2 proof");
        proof.data[proof.len - 1] = saved;
    }

    /* Wrong FS seed must be rejected. */
    uint8_t bad_seed[16];
    memset(bad_seed, 0x99, sizeof(bad_seed));
    CHECK(voleith_gf8_verify_v2(&proof, params, c, NULL, 0, bad_seed,
                                sizeof(bad_seed)) != 0,
          "verify_v2 rejects wrong FS seed on d>2 proof");

    voleith_proof_free(&proof);

    /* A >= B: the checked prover must refuse (eval rejects the witness). */
    voleith_gf8_circuit_t *c2 = build_lt_proof_circuit(w);
    uint8_t bad_wit[64];
    fill_lt_bits(bad_wit, w, B, A); /* swapped -> A>=B when A<B originally */
    voleith_proof_t bad_proof;
    memset(&bad_proof, 0, sizeof(bad_proof));
    CHECK(voleith_gf8_prove_v2(&bad_proof, params, c2, bad_wit, nwit, NULL, 0,
                               fs_seed, sizeof(fs_seed)) != 0,
          "prove_v2 refuses A>=B witness");
    voleith_proof_free(&bad_proof);
    voleith_gf8_circuit_free(c2);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test: full two-phase proof over a degree-idx_bits syndrome circuit
 * (s = M*e^T).  Exercises the serialization / sizing / transcript path at
 * opening degree d = idx_bits > 2 through the public pipeline, plus the
 * instance binding of the public syndrome s.
 * ================================================================ */
static void
syn_oracle(uint8_t *s, uint32_t p, uint32_t n0, uint32_t t,
           const uint32_t *indices, const uint8_t *M)
{
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    uint8_t *e = calloc((size_t)n0 * p, 1);
    for (uint32_t k = 0; k < t; k++)
        e[indices[k]] = 1;
    for (uint32_t j = 0; j < p; j++)
        s[j] = e[(size_t)(n0 - 1u) * p + j];
    for (uint32_t b = 0; b + 1u < n0; b++) {
        const uint8_t *mb = M + (size_t)b * block_bytes;
        for (uint32_t a = 0; a < p; a++)
            if ((mb[a >> 3] >> (a & 7u)) & 1u)
                for (uint32_t cpos = 0; cpos < p; cpos++)
                    s[(a + cpos) % p] ^= e[(size_t)b * p + cpos];
    }
    free(e);
}

static voleith_gf8_circuit_t *
build_syn_proof_circuit(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
                        const uint32_t *indices, const uint8_t *M,
                        uint8_t *witness, uint8_t *instance, const uint8_t *s)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *idx_w = malloc((size_t)t * idx_bits * sizeof(gf8_wire_id));
    gf8_wire_id *s_w = malloc((size_t)p * sizeof(gf8_wire_id));
    for (uint32_t k = 0; k < t; k++)
        for (uint32_t b = 0; b < idx_bits; b++) {
            idx_w[k * idx_bits + b] = voleith_gf8_add_witness(c);
            witness[k * idx_bits + b] =
                (uint8_t)((indices[k] >> (idx_bits - 1u - b)) & 1u);
        }
    for (uint32_t j = 0; j < p; j++) {
        s_w[j] = voleith_gf8_add_instance(c);
        instance[j] = (uint8_t)(s[j] & 1u);
    }
    voleith_gf8_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);
    free(idx_w);
    free(s_w);
    return c;
}

static void
test_syndrome_two_phase(const voleith_params_t *params, uint32_t p, uint32_t n0,
                        uint32_t t, uint32_t idx_bits, const uint32_t *indices,
                        const uint8_t *M, const char *label)
{
    printf("\n[two-phase syndrome full proof: %s]\n", label);

    uint8_t s[64];
    syn_oracle(s, p, n0, t, indices, M);

    uint8_t witness[128], instance[64];
    voleith_gf8_circuit_t *c = build_syn_proof_circuit(
        p, n0, t, idx_bits, indices, M, witness, instance, s);
    size_t nwit = voleith_gf8_circuit_witness_count(c);
    uint8_t fs_seed[16];
    memset(fs_seed, 0x3b, sizeof(fs_seed));

    CHECK(voleith_gf8_circuit_qs_degree(c) == idx_bits,
          "qs_degree == idx_bits (>2) on the syndrome proof circuit");

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    CHECK(voleith_gf8_prove_v2(&proof, params, c, witness, nwit, instance, p,
                               fs_seed, sizeof(fs_seed)) == 0,
          "prove_v2 succeeds (honest support + s)");
    CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, p, fs_seed,
                                sizeof(fs_seed)) == 0,
          "verify_v2 accepts valid d>2 syndrome proof");
    CHECK(voleith_gf8_proof_byte_size_circuit(params, c) == proof.len,
          "proof_byte_size_circuit matches d>2 syndrome proof len");

    /* Tampered proof body must be rejected. */
    if (proof.data && proof.len > VOLEITH_PROOF_HEADER_BYTES) {
        uint8_t saved = proof.data[proof.len - 1];
        proof.data[proof.len - 1] ^= 0x40u;
        CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, p, fs_seed,
                                    sizeof(fs_seed)) != 0,
              "verify_v2 rejects tampered d>2 syndrome proof");
        proof.data[proof.len - 1] = saved;
    }

    /* Wrong FS seed must be rejected. */
    uint8_t bad_seed[16];
    memset(bad_seed, 0x99, sizeof(bad_seed));
    CHECK(voleith_gf8_verify_v2(&proof, params, c, instance, p, bad_seed,
                                sizeof(bad_seed)) != 0,
          "verify_v2 rejects wrong FS seed on syndrome proof");

    /* Wrong public s at verify time (flip one bit): the instance is bound. */
    {
        uint8_t bad_inst[64];
        memcpy(bad_inst, instance, p);
        bad_inst[1] ^= 1u;
        CHECK(voleith_gf8_verify_v2(&proof, params, c, bad_inst, p, fs_seed,
                                    sizeof(fs_seed)) != 0,
              "verify_v2 rejects a tampered public syndrome s");
    }
    voleith_proof_free(&proof);

    /* Inconsistent (support, s): the checked prover must refuse (eval fails). */
    {
        uint8_t bad_s[64];
        memcpy(bad_s, s, p);
        bad_s[2] ^= 1u;
        uint8_t w2[128], i2[64];
        voleith_gf8_circuit_t *c2 = build_syn_proof_circuit(
            p, n0, t, idx_bits, indices, M, w2, i2, bad_s);
        voleith_proof_t bad_proof;
        memset(&bad_proof, 0, sizeof(bad_proof));
        CHECK(voleith_gf8_prove_v2(&bad_proof, params, c2, w2, nwit, i2, p,
                                   fs_seed, sizeof(fs_seed)) != 0,
              "prove_v2 refuses support inconsistent with s");
        voleith_proof_free(&bad_proof);
        voleith_gf8_circuit_free(c2);
    }
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Main
 * ================================================================ */

int
main(void)
{
    printf("=== test_gf8_proof ===\n");

    test_proof_size();
    test_mul_circuit_roundtrip(&voleith_params_em_128f, "em_128f");
    test_mul_circuit_roundtrip(&voleith_params_em_128s, "em_128s");
    test_wrong_witness_rejected();
    test_tamper_detection();
    test_different_seeds();
    test_chain_circuit();
    test_two_phase_roundtrip();
    test_two_phase_wrong_chall1();
    test_wrong_instance_rejected();
    test_aes128_gf8_roundtrip();
    test_v2_length_validation();
    test_byte_len_helpers();
    test_scale_gate_roundtrip(&voleith_params_em_128f, "em_128f");
    test_scale_gate_roundtrip(&voleith_params_em_128s, "em_128s");
    test_scale_vs_mul_slot();
    test_lt_two_phase(&voleith_params_em_128f, 4, 5, 12, "em_128f w=4");
    test_lt_two_phase(&voleith_params_em_256f, 15, 0x1234, 0x5678,
                      "em_256f w=15 (d=16)");

    {
        static const uint8_t M7[1] = {0x5a}; /* p=7 circulant first row */
        static const uint32_t idx7[2] = {2, 9};
        test_syndrome_two_phase(&voleith_params_em_128f, 7, 2, 2, 4, idx7, M7,
                                "em_128f p=7 n0=2 t=2 (d=4)");
        static const uint8_t M13[2] = {0x2d, 0x0a}; /* p=13 first row */
        static const uint32_t idx13[3] = {3, 11, 19};
        test_syndrome_two_phase(&voleith_params_em_256f, 13, 2, 3, 5, idx13,
                                M13, "em_256f p=13 n0=2 t=3 (d=5)");
    }

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
