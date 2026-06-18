/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_dispatch.c - mechanism tests for the W8.2 + W8.3a
 * Tier 2a witness-backend dispatch registry (parsers/shipshape_witgen_dispatch.c).
 *
 * Uses stdlib/crypto/aes/sbox (the smallest FIXED entry: 1 inv witness) as
 * the primary test vehicle.  Three dispatch cases:
 *
 *   Case A: register with the correct (name, body_hash); assert the backend
 *           is invoked, the witness equals the generic baseline, and the ext
 *           slice delivered to the backend contains the correct input value.
 *   Case B: register with a deliberately wrong hash; assert the backend is
 *           NOT invoked (hash mismatch falls through) and the witness equals
 *           the generic baseline.
 *   Case C: no registration; assert no invocation and witness equals baseline.
 *
 * Also covers: register returns nonzero on NULL args; register returns nonzero
 * on a full table; reset clears the count.
 *
 * W8.3a-specific additions:
 *   - region inputs recording: assert n_inputs and inputs != NULL after parse.
 *   - ext assembly: assert backend receives ext_len == 1 and ext[0] == 0x53.
 *   - PARAMETRIC recording: cmac/aes_128 with a small msg; assert n_inputs
 *     equals 16 (key) + N (msg) even though PARAMETRIC does not dispatch.
 */

#include "field.h"
#include "shipshape.h"
#include "shipshape_registry.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"

#include <stddef.h>
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
 * A minimal crypto-v1 circuit: one external witness byte (%a), one call to
 * aes/sbox producing %b.  The sbox adds one internal inv-witness (slot 1).
 * Total witness count = 2; external count = 1.
 */
#define SBOX_SRC                                                               \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %a : byte\n"                                                   \
    "stdlib/crypto/aes/sbox(%a) -> %b\n"

/* Registry index of "stdlib/crypto/aes/sbox" (FIXED, index 0). */
#define SBOX_REGISTRY_IDX 0u

/*
 * A small PARAMETRIC circuit: cmac/aes_128 with a 4-byte message.
 * Inputs: key byte[16] + msg byte[4] = 20 input wires total.
 * Used only to verify that n_inputs is recorded for PARAMETRIC entries.
 */
#define CMAC_MSG_LEN 4
#define CMAC_SRC                                                               \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[16]\n"                                             \
    "WITNESS -> %msg : byte[4]\n"                                              \
    "stdlib/crypto/cmac/aes_128(%key, %msg) -> %tag\n"

/* Static invocation counter and captured ext for the observable test backend. */
static int s_backend_call_count = 0;
static uint8_t s_captured_ext[32];
static size_t s_captured_ext_len = 0;

/*
 * Test backend for stdlib/crypto/aes/sbox.  Increments s_backend_call_count
 * and captures the ext slice delivered by the dispatcher.  Under the W8.4
 * interleaved skip the backend is AUTHORITATIVE: the forward pass skips the
 * brute-force inverse for the dispatched slot, so this backend must write the
 * correct inv-witness (inv(ext[0])) for Case A to match the baseline.
 */
static int
test_sbox_backend(const voleith_shipshape_region_t *region, const uint8_t *ext,
                  size_t ext_len, uint8_t *full)
{
    s_backend_call_count++;
    if (ext_len <= sizeof(s_captured_ext))
        memcpy(s_captured_ext, ext != NULL ? ext : (uint8_t *)"", ext_len);
    s_captured_ext_len = ext_len;
    if (ext != NULL && ext_len == 1 && region->n_witness == 1)
        full[region->first_witness] = (uint8_t)voleith_gf8_inv(ext[0]);
    return 0;
}

/* ================================================================
 * Group A: registration API sanity
 * ================================================================ */

static void
test_register_api(void)
{
    uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
    int r;

    voleith_shipshape_witgen_reset();

    /* NULL fqn, body_hash, fn each trigger -1. */
    memset(hash, 0, sizeof(hash));
    check("register: NULL fqn returns nonzero",
          voleith_shipshape_witgen_register(NULL, hash, test_sbox_backend) !=
              0);
    check("register: NULL hash returns nonzero",
          voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", NULL,
                                            test_sbox_backend) != 0);
    check("register: NULL fn returns nonzero",
          voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                            NULL) != 0);

    /* Valid registration returns 0. */
    r = voleith_shipshape_registry_body_hash(SBOX_REGISTRY_IDX, 0, hash);
    check("register: body_hash lookup succeeds", r == 0);
    check("register: valid registration returns 0",
          voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                            test_sbox_backend) == 0);

    /* reset clears the count so we can register again. */
    voleith_shipshape_witgen_reset();
    check("reset: can re-register after reset",
          voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                            test_sbox_backend) == 0);

    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Helper: run voleith_shipshape_witness_gen on SBOX_SRC with a known
 * external input.  Writes witness bytes to *out (caller frees).
 * Returns 0 on success.
 * ================================================================ */

static int
run_witness_gen(uint8_t **out, size_t *out_len)
{
    voleith_shipshape_parsed_t p = {0};
    int r;
    static const uint8_t ext[1] = {0x53}; /* arbitrary test value */

    r = voleith_shipshape_parse_buffer(&p, SBOX_SRC, 0, NULL);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return r;
    }
    r = voleith_shipshape_witness_gen(&p, ext, 1, NULL, 0, 0, out, out_len);
    voleith_shipshape_parsed_free(&p);
    return r;
}

/* ================================================================
 * Group B: dispatch Case C (no registration) and Case B (wrong hash).
 * ================================================================ */

static void
test_case_c_no_registration(void)
{
    uint8_t *full = NULL;
    size_t full_len = 0;
    int r;

    voleith_shipshape_witgen_reset();
    s_backend_call_count = 0;

    r = run_witness_gen(&full, &full_len);
    check("case C: witness_gen succeeds (no backend)", r == 0);
    check("case C: backend was NOT invoked", s_backend_call_count == 0);
    check("case C: witness length is 2", full_len == 2);

    free(full);
}

static void
test_case_b_wrong_hash(void)
{
    uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
    uint8_t *baseline = NULL, *dispatched = NULL;
    size_t baseline_len = 0, dispatched_len = 0;
    int r;

    /* Get the baseline first (no backend). */
    voleith_shipshape_witgen_reset();
    r = run_witness_gen(&baseline, &baseline_len);
    if (r != 0 || baseline == NULL) {
        check("case B: baseline witness_gen succeeded", 0);
        free(baseline);
        return;
    }
    check("case B: baseline witness_gen succeeded", 1);

    /* Obtain the correct hash and flip one byte to make it wrong. */
    r = voleith_shipshape_registry_body_hash(SBOX_REGISTRY_IDX, 0, hash);
    check("case B: body_hash lookup succeeds", r == 0);
    hash[0] ^= 0xff; /* deliberate corruption */

    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                          test_sbox_backend);
    check("case B: registration with wrong hash succeeds", r == 0);

    s_backend_call_count = 0;
    r = run_witness_gen(&dispatched, &dispatched_len);
    check("case B: witness_gen succeeds (hash mismatch falls through)", r == 0);
    check("case B: backend was NOT invoked (hash mismatch)",
          s_backend_call_count == 0);
    check("case B: witness matches baseline",
          dispatched != NULL && dispatched_len == baseline_len &&
              memcmp(dispatched, baseline, baseline_len) == 0);

    free(baseline);
    free(dispatched);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Group C: dispatch Case A (correct name + hash) with ext assertion.
 * ================================================================ */

static void
test_case_a_correct_hash(void)
{
    uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
    voleith_shipshape_parsed_t p = {0};
    uint8_t *baseline = NULL, *dispatched = NULL;
    size_t baseline_len = 0, dispatched_len = 0;
    static const uint8_t ext[1] = {0x53};
    int r;

    /* Get the baseline with no backend. */
    voleith_shipshape_witgen_reset();
    r = run_witness_gen(&baseline, &baseline_len);
    if (r != 0 || baseline == NULL) {
        check("case A: baseline witness_gen succeeded", 0);
        free(baseline);
        return;
    }
    check("case A: baseline witness_gen succeeded", 1);

    /*
     * Parse SBOX_SRC and check the region's recorded inputs before running
     * dispatch.  This validates Deliverable 2 independently.
     */
    r = voleith_shipshape_parse_buffer(&p, SBOX_SRC, 0, NULL);
    check("case A: parse SBOX_SRC succeeds", r == 0);
    if (r == 0) {
        check("case A: region count is 1", p.n_regions == 1);
        check("case A: region inputs != NULL",
              p.n_regions >= 1 && p.regions[0].inputs != NULL);
        check("case A: region n_inputs == 1",
              p.n_regions >= 1 && p.regions[0].n_inputs == 1);
    }

    /*
     * Register with the correct hash, obtained the same way the dispatcher
     * resolves it: via voleith_shipshape_registry_body_hash.  The frozen
     * table hash (bodies_0[0].hash) and the computed hash MUST agree, which
     * the registry freeze CI enforces; this test confirms they match
     * incidentally.
     */
    r = voleith_shipshape_registry_body_hash(SBOX_REGISTRY_IDX, 0, hash);
    check("case A: body_hash lookup succeeds", r == 0);

    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                          test_sbox_backend);
    check("case A: registration returns 0", r == 0);

    s_backend_call_count = 0;
    s_captured_ext_len = 0;
    memset(s_captured_ext, 0, sizeof(s_captured_ext));

    r = voleith_shipshape_witness_gen(&p, ext, 1, NULL, 0, 0, &dispatched,
                                      &dispatched_len);
    check("case A: witness_gen succeeds with backend registered", r == 0);
    check("case A: backend WAS invoked (call count == 1)",
          s_backend_call_count == 1);
    check("case A: witness matches baseline byte-for-byte",
          dispatched != NULL && dispatched_len == baseline_len &&
              memcmp(dispatched, baseline, baseline_len) == 0);

    /* W8.3a: assert the assembled ext slice was correct. */
    check("case A: ext_len delivered to backend is 1", s_captured_ext_len == 1);
    check("case A: ext[0] delivered to backend is 0x53",
          s_captured_ext_len >= 1 && s_captured_ext[0] == 0x53);

    free(baseline);
    free(dispatched);
    voleith_shipshape_parsed_free(&p);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Group D: table capacity enforcement.
 * ================================================================ */

static void
test_table_full(void)
{
    uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
    int i, r;
    static const char *dummy = "dummy/fqn";

    voleith_shipshape_witgen_reset();
    memset(hash, 0, sizeof(hash));

    /* Fill the table (capacity 32). */
    for (i = 0; i < 32; i++) {
        r = voleith_shipshape_witgen_register(dummy, hash, test_sbox_backend);
        if (r != 0)
            break;
    }
    check("table full: 32 registrations succeed", i == 32);

    /* The 33rd must fail. */
    r = voleith_shipshape_witgen_register(dummy, hash, test_sbox_backend);
    check("table full: 33rd registration returns nonzero", r != 0);

    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Group E: PARAMETRIC recording (W8.3a).
 *
 * cmac/aes_128(%key, %msg) with key=byte[16], msg=byte[4].
 * n_inputs must be 16+4 = 20.  PARAMETRIC does not dispatch in W8.3a,
 * but inputs MUST be recorded by the parser.
 * ================================================================ */

static void
test_parametric_inputs_recorded(void)
{
    voleith_shipshape_parsed_t p = {0};
    int r;

    r = voleith_shipshape_parse_buffer(&p, CMAC_SRC, 0, NULL);
    check("parametric: parse cmac/aes_128 circuit succeeds", r == 0);

    if (r == 0) {
        check("parametric: region count is 1", p.n_regions == 1);
        check("parametric: inputs != NULL",
              p.n_regions >= 1 && p.regions[0].inputs != NULL);
        /*
         * cmac/aes_128 signature: (key : byte[16], msg : byte[n]).
         * With %key byte[16] and %msg byte[4], total inputs = 16 + 4 = 20.
         */
        check("parametric: n_inputs == 20 (16 key + 4 msg)",
              p.n_regions >= 1 && p.regions[0].n_inputs == 16 + CMAC_MSG_LEN);
    }

    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    printf("test_shipshape_witgen_dispatch\n");

    test_register_api();
    test_case_c_no_registration();
    test_case_b_wrong_hash();
    test_case_a_correct_hash();
    test_table_full();
    test_parametric_inputs_recorded();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
