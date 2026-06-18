/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_failclosed.c - W8.4 fail-closed property test for the
 * Tier 2a interleaved-skip witness dispatch.
 *
 * Under the W8.4 skip a registered backend is AUTHORITATIVE: the generic
 * forward pass no longer recomputes the inverse for a dispatched slot, so a
 * WRONG backend produces a wrong witness.  The fail-closed guarantee
 * (docs/CIRC_WITNESS_GEN.md SECTION 7) is that a wrong backend can only yield
 * an INVALID proof, never a verifier accept:
 *
 *   1. With SELF_CHECK, witness_gen rejects the corrupted witness at gen time.
 *   2. Without SELF_CHECK, witness_gen succeeds (bad witness) but the prover
 *      refuses the unsatisfied circuit (or, failing that, verify rejects).
 *   3. Control: the REAL backend reproduces the generic witness byte-for-byte,
 *      and that witness proves and verifies (the skip is transparent).
 *
 * Vehicle: stdlib/crypto/aes/sbox (one inv witness), registered with the
 * CORRECT frozen body hash so the wrong backend IS selected.
 */

#include "field.h"
#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "shipshape.h"
#include "shipshape_registry.h"
#include "shipshape_witgen_aes.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stddef.h>
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

#define SBOX_SRC                                                               \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %x : byte\n"                                                   \
    "stdlib/crypto/aes/sbox(%x) -> %y\n"

/* Registry index of "stdlib/crypto/aes/sbox" (FIXED, index 0). */
#define SBOX_REGISTRY_IDX 0u

/* Nonzero S-box input so inv(x) is well defined and a flipped byte differs. */
static const uint8_t EXT[1] = {0x53};

static const uint8_t FS_SEED[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                                    0xDD, 0xEE, 0xFF, 0x01};

static void
zfree(uint8_t *buf, size_t len)
{
    if (buf != NULL && len > 0)
        voleith_secure_zero(buf, len);
    free(buf);
}

/*
 * Wrong backend: writes a CORRUPTED inverse (true inverse XOR 0x01).  Selected
 * via the correct frozen body hash, it must still yield an invalid proof.
 */
static int
wrong_sbox_backend(const voleith_shipshape_region_t *region, const uint8_t *ext,
                   size_t ext_len, uint8_t *full)
{
    if (ext == NULL || ext_len != 1 || region->n_witness != 1)
        return -1;
    full[region->first_witness] = (uint8_t)voleith_gf8_inv(ext[0]) ^ 0x01;
    return 0;
}

/* Register wrong_sbox_backend under the correct (name, frozen hash). */
static int
register_wrong_backend(void)
{
    uint8_t hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];

    if (voleith_shipshape_registry_body_hash(SBOX_REGISTRY_IDX, 0, hash) != 0)
        return -1;
    return voleith_shipshape_witgen_register("stdlib/crypto/aes/sbox", hash,
                                             wrong_sbox_backend);
}

static void
test_self_check_rejects_wrong_backend(void)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p, SBOX_SRC, 0, NULL);
    check("self-check: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    voleith_shipshape_witgen_reset();
    check("self-check: wrong backend registers", register_wrong_backend() == 0);

    r = voleith_shipshape_witness_gen(&p, EXT, 1, NULL, 0,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    check("self-check: gen with SELF_CHECK rejects corrupted witness", r != 0);
    check("self-check: no buffer handed back on failure", wit == NULL);

    zfree(wit, wit_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

static void
test_prove_rejects_wrong_backend(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p = {0};
    voleith_proof_t proof;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p, SBOX_SRC, 0, NULL);
    check("prove-reject: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    voleith_shipshape_witgen_reset();
    check("prove-reject: wrong backend registers",
          register_wrong_backend() == 0);

    /* No SELF_CHECK: a bad witness is produced without complaint. */
    r = voleith_shipshape_witness_gen(&p, EXT, 1, NULL, 0, 0, &wit, &wit_len);
    check("prove-reject: gen without self-check succeeds (bad witness)",
          r == 0 && wit != NULL && wit_len == 2);

    if (r == 0 && wit != NULL) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, NULL,
                                 0, FS_SEED, sizeof(FS_SEED));
        if (r != 0) {
            /* Prover refused the unsatisfied circuit: fail-closed. */
            check("prove-reject: prover refuses unsatisfied circuit", 1);
        } else {
            /* If prove unexpectedly succeeds, verify MUST reject. */
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, NULL, 0,
                                      FS_SEED, sizeof(FS_SEED));
            check("prove-reject: verify rejects bad-witness proof", r != 0);
            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

static void
test_real_backend_transparent(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p = {0};
    voleith_proof_t proof;
    uint8_t *baseline = NULL, *dispatched = NULL;
    size_t baseline_len = 0, dispatched_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p, SBOX_SRC, 0, NULL);
    check("control: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* Baseline: no backend. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witness_gen(&p, EXT, 1, NULL, 0,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &baseline, &baseline_len);
    check("control: baseline gen succeeds", r == 0 && baseline != NULL);

    /* Real backend registered. */
    voleith_shipshape_witgen_reset();
    check("control: real AES backend registers",
          voleith_shipshape_witgen_register_aes() == 0);
    r = voleith_shipshape_witness_gen(&p, EXT, 1, NULL, 0,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &dispatched, &dispatched_len);
    check("control: dispatched gen succeeds", r == 0 && dispatched != NULL);

    /* Skip is transparent: byte-for-byte identical to the baseline. */
    check("control: dispatched witness equals baseline",
          baseline != NULL && dispatched != NULL &&
              baseline_len == dispatched_len &&
              memcmp(baseline, dispatched, baseline_len) == 0);

    /* The dispatched (correct) witness proves and verifies. */
    if (dispatched != NULL) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, dispatched,
                                 dispatched_len, NULL, 0, FS_SEED,
                                 sizeof(FS_SEED));
        check("control: correct witness proves", r == 0);
        if (r == 0) {
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, NULL, 0,
                                      FS_SEED, sizeof(FS_SEED));
            check("control: proof verifies", r == 0);
            voleith_proof_free(&proof);
        }
    }

    zfree(baseline, baseline_len);
    zfree(dispatched, dispatched_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    printf("test_shipshape_witgen_failclosed\n");

    test_self_check_rejects_wrong_backend();
    test_prove_rejects_wrong_backend();
    test_real_backend_transparent();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
