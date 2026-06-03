/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_legacy_verify.c - Tests for the dual-path verifier dispatch
 *                        introduced by the v1 proof metadata header.
 *
 * Covers the attack-table tampering paths from
 * docs/PROOF_METADATA_HEADER_DESIGN.md:
 *
 *   - Header strip:    take a v1 proof, lop off the leading 48 bytes;
 *                      verify must reject (under VOLEITH_LEGACY_VERIFY=ON
 *                      via chall_3 mismatch on the legacy path, under
 *                      OFF via the early return).
 *   - Fake header:     prepend / overwrite a structurally-valid v1
 *                      header with mismatched fingerprints; verify must
 *                      reject at the identity check.
 *   - Header tamper:   flip a byte in the parsed-constraint region of
 *                      the header (magic, version, flags, reserved);
 *                      verify must reject either at parse (-> legacy
 *                      fallback -> size mismatch) or chall_3.
 *
 * Documented gap (deferred to a future release): a positive "real
 * pre-v1 proof verifies on the legacy path" test requires either
 * checked-in binary fixtures from a pre-v1.3.0 release build or a
 * tests-only legacy prover that bypasses the v1 header machinery.
 * Neither is in scope for the initial 1.3.0 landing.  The dispatch
 * code path is exercised by the header-strip test below: it routes
 * through the legacy verifier, runs full body reconstruction, and
 * rejects on the expected chall_3 mismatch - so the legacy path is
 * reachable and behaves correctly on adversarial input.
 */

#include "proof.h"
#include "proof_header.h"
#include "circuit.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

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
 * Minimal AND circuit reused across tests: a, b witness; c instance;
 * assert (a AND b) XOR c == 0.  Small enough that proof generation is
 * fast and the proof byte count fits comfortably in any buffer.
 */
static voleith_circuit_t *
build_test_circuit(void)
{
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c)
        return NULL;
    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_witness(c);
    wire_id ab = voleith_circuit_add_and(c, a, b);
    wire_id cw = voleith_circuit_add_instance(c);
    wire_id x = voleith_circuit_add_xor(c, ab, cw);
    voleith_circuit_assert_zero(c, x);
    return c;
}

/*
 * Mint a fresh v1 proof for the test circuit using fixed witness +
 * instance + fs_seed.  Returns 0 on success, -1 on error.  Caller
 * must voleith_proof_free.
 */
static int
mint_v1_proof(voleith_proof_t *proof, const voleith_params_t *params,
              voleith_circuit_t *circuit)
{
    uint8_t witness[1] = {0x03};
    uint8_t instance[1] = {0x01};
    uint8_t fs_seed[16];
    memset(fs_seed, 0xA7, sizeof(fs_seed));

    memset(proof, 0, sizeof(*proof));
    return voleith_prove(proof, params, circuit, witness, instance, fs_seed,
                         sizeof(fs_seed));
}

/* Same fs_seed used in mint_v1_proof so verify can be called with it. */
static const uint8_t test_fs_seed[16] = {
    0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7,
    0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7, 0xA7,
};
static const uint8_t test_instance[1] = {0x01};

/* ================================================================
 * Test: sanity baseline - the freshly-minted v1 proof verifies.
 *
 * Required to establish that the rejection tests below are actually
 * exercising rejection, not failing on some unrelated issue.
 * ================================================================ */
static void
test_v1_baseline_verifies(void)
{
    printf("\n[legacy/baseline: clean v1 verifies]\n");

    voleith_circuit_t *c = build_test_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    voleith_proof_t proof;
    int rc = mint_v1_proof(&proof, &voleith_params_em_128f, c);
    CHECK(rc == 0, "mint v1 proof");
    if (rc == 0) {
        int vrc =
            voleith_verify(&proof, &voleith_params_em_128f, c, test_instance,
                           test_fs_seed, sizeof(test_fs_seed));
        CHECK(vrc == 0, "untampered v1 proof verifies");
        voleith_proof_free(&proof);
    }
    voleith_circuit_free(c);
}

/* ================================================================
 * Test: header strip.
 *
 * Take a v1 proof, present only its body (proof->data + 48,
 * proof->len - 48) to voleith_verify.  Under both build modes the
 * call must reject:
 *
 *   - With VOLEITH_LEGACY_VERIFY=ON: leading 48 bytes (which are
 *     actually the start of c[0]) fail the v1 parser, dispatch falls
 *     to the legacy path, which runs the body through the verifier
 *     with no header mixed into chall_1.  The body was minted under
 *     header-mixed FS, so chall_3 mismatches and verify returns -1.
 *
 *   - With VOLEITH_LEGACY_VERIFY=OFF: dispatch rejects immediately on
 *     the failed v1 parse.
 *
 * The test asserts only the rejection outcome, which is identical
 * across build modes.
 * ================================================================ */
static void
test_header_strip_rejected(void)
{
    printf("\n[legacy/tamper: header-stripped v1 proof]\n");

    voleith_circuit_t *c = build_test_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    voleith_proof_t proof;
    if (mint_v1_proof(&proof, &voleith_params_em_128f, c) != 0) {
        printf("  SKIP: mint failed\n");
        voleith_circuit_free(c);
        return;
    }

    /* Construct a body-only view of the proof.  Body starts at offset 48. */
    voleith_proof_t stripped;
    stripped.data = proof.data + VOLEITH_PROOF_HEADER_BYTES;
    stripped.len = proof.len - VOLEITH_PROOF_HEADER_BYTES;

    int rc = voleith_verify(&stripped, &voleith_params_em_128f, c,
                            test_instance, test_fs_seed, sizeof(test_fs_seed));
    CHECK(rc != 0, "header-stripped v1 proof rejected");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test: corrupted circuit fingerprint.
 *
 * Take a v1 proof and zero its CIRCUIT_FP region (bytes 16..31).
 * The fixed prefix still parses cleanly (magic, version, enums,
 * flags, reserved all untouched), so the v1 dispatch path runs and
 * check_identity is invoked; it computes the expected fingerprint
 * over the caller's circuit, compares against the zeroed bytes, and
 * returns -1.  Verify reports failure before any body crypto runs.
 * ================================================================ */
static void
test_corrupted_circuit_fp_rejected(void)
{
    printf("\n[legacy/tamper: corrupted CIRCUIT_FP]\n");

    voleith_circuit_t *c = build_test_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    voleith_proof_t proof;
    if (mint_v1_proof(&proof, &voleith_params_em_128f, c) != 0) {
        printf("  SKIP: mint failed\n");
        voleith_circuit_free(c);
        return;
    }

    /* Zero the 16 bytes at offset 16 (CIRCUIT_FP region). */
    memset(proof.data + 16, 0, VOLEITH_PROOF_FINGERPRINT_BYTES);

    int rc = voleith_verify(&proof, &voleith_params_em_128f, c, test_instance,
                            test_fs_seed, sizeof(test_fs_seed));
    CHECK(rc != 0, "v1 proof with zeroed CIRCUIT_FP rejected");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test: corrupted params fingerprint.
 *
 * Same as the CIRCUIT_FP test, but corrupting bytes 32..47 (PARAMS_FP).
 * Rejection path is identical: parse succeeds, check_identity fails.
 * ================================================================ */
static void
test_corrupted_params_fp_rejected(void)
{
    printf("\n[legacy/tamper: corrupted PARAMS_FP]\n");

    voleith_circuit_t *c = build_test_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    voleith_proof_t proof;
    if (mint_v1_proof(&proof, &voleith_params_em_128f, c) != 0) {
        printf("  SKIP: mint failed\n");
        voleith_circuit_free(c);
        return;
    }

    memset(proof.data + 32, 0xFF, VOLEITH_PROOF_FINGERPRINT_BYTES);

    int rc = voleith_verify(&proof, &voleith_params_em_128f, c, test_instance,
                            test_fs_seed, sizeof(test_fs_seed));
    CHECK(rc != 0, "v1 proof with corrupted PARAMS_FP rejected");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test: tampered fixed-prefix bytes (magic, version, enums, flags,
 * reserved).  These all fail v1 parse and fall through to legacy
 * dispatch (when LEGACY_VERIFY=ON), where the byte count no longer
 * matches the expected legacy body size and the call rejects.  With
 * LEGACY_VERIFY=OFF the parse failure rejects immediately.
 * ================================================================ */
static void
test_tampered_fixed_prefix_rejected(void)
{
    printf("\n[legacy/tamper: fixed-prefix bytes]\n");

    voleith_circuit_t *c = build_test_circuit();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }

    voleith_proof_t proof;
    if (mint_v1_proof(&proof, &voleith_params_em_128f, c) != 0) {
        printf("  SKIP: mint failed\n");
        voleith_circuit_free(c);
        return;
    }

    /*
     * Try each byte in the fixed-prefix region (offsets 0..15).
     * Tamper, verify, restore.  Every offset must be detected.
     */
    int all_rejected = 1;
    for (size_t off = 0; off < 16; off++) {
        uint8_t orig = proof.data[off];
        proof.data[off] = orig ^ 0xFF;
        int rc =
            voleith_verify(&proof, &voleith_params_em_128f, c, test_instance,
                           test_fs_seed, sizeof(test_fs_seed));
        if (rc == 0) {
            printf("  FAIL: tamper at offset %zu not rejected\n", off);
            all_rejected = 0;
        }
        proof.data[off] = orig;
    }
    CHECK(all_rejected, "every fixed-prefix tamper is rejected");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test: VOLEITH_LEGACY_VERIFY compile-mode reporting.
 *
 * Informational - the actual mode is fixed at compile time.  Print
 * which mode the build is in so the test log records it; CI builds
 * exercising both modes can grep for these lines.
 * ================================================================ */
static void
test_compile_mode_reported(void)
{
    printf("\n[legacy/build mode]\n");
#ifdef VOLEITH_LEGACY_VERIFY
    printf(
        "  INFO: VOLEITH_LEGACY_VERIFY = ON (legacy fallback compiled in)\n");
#else
    printf(
        "  INFO: VOLEITH_LEGACY_VERIFY = OFF (legacy fallback compiled out)\n");
#endif
    /* Compile-mode visibility is not a pass/fail assertion - all
     * tampering tests above succeed regardless of mode.  A separate
     * CI matrix step builds with -DVOLEITH_LEGACY_VERIFY=OFF and
     * re-runs this whole test binary; both modes must pass. */
}

int
main(void)
{
    printf("=== test_legacy_verify ===\n");
    test_v1_baseline_verifies();
    test_header_strip_rejected();
    test_corrupted_circuit_fp_rejected();
    test_corrupted_params_fp_rejected();
    test_tampered_fixed_prefix_rejected();
    test_compile_mode_reported();
    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
